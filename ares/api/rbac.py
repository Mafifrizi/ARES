"""
ARES API RBAC + Rate Limiting — v3.0.0

Roles:
    team_lead   — full access
    operator    — run modules, view findings, manage campaigns
    recon       — enum-only modules, read-only campaigns/graph
    reporter    — read-only findings, reports, telemetry

Rate Limiting strategy (priority order):
    1. Redis sliding-window (if ARES_REDIS_URL is set)  ← multi-pod safe
    2. In-process token bucket (fallback for single-pod / dev)

Redis rate limit key format: ares:rl:{bucket}:{key}
Uses ZADD + ZREMRANGEBYSCORE + ZCARD — atomic in single pipeline call.
TTL auto-expires keys after 120s to prevent memory leaks.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from ares.core.logger import get_logger

logger = get_logger("ares.api.rbac")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


# ── Role source of truth ───────────────────────────────────────────────────────
# OperatorRole enum and ROLE_PERMISSIONS live in collab/manager.py.
# rbac.py imports from there so there is exactly one definition of roles.
from ares.collab.manager import (   # noqa: E402
    OperatorRole,
    ROLE_PERMISSIONS,
    ROLE_ORDER,
    can_role_run_module,
)

# ── User model ─────────────────────────────────────────────────────────────────

@dataclass
class AuthenticatedUser:
    username: str
    role:     str   # team_lead | operator | recon | reporter

    @property
    def operator_role(self) -> OperatorRole:
        """Convert string role to OperatorRole enum (safe — defaults to REPORTER)."""
        try:
            return OperatorRole(self.role)
        except ValueError:
            return OperatorRole.REPORTER

    def can_run_module(self, module_id: str, registry: "Any | None" = None) -> bool:
        """Delegate to single-source-of-truth can_role_run_module()."""
        return can_role_run_module(self.operator_role, module_id, registry)


# ── Rate limit configs ─────────────────────────────────────────────────────────

RATE_LIMITS: dict[str, int] = {
    "global":           60,
    "auth":             10,
    "module_run":       20,
    "report":            5,
    "register":          3,
    "campaign_create":  10,   # POST /campaigns
    "vault_restore":     5,   # POST /campaigns/{id}/restore-vault
}


# ── In-process fallback (single-pod / dev / Redis unavailable) ─────────────────

class _InProcessLimiter:
    """Sliding-window in-process rate limiter. Not safe for multi-pod."""

    def __init__(self) -> None:
        self._windows: defaultdict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

    def is_allowed(self, key: str, max_per_minute: int) -> tuple[bool, int]:
        now    = time.time()
        window = self._windows[key]
        while window and window[0] < now - 60:
            window.popleft()
        count = len(window)
        if count >= max_per_minute:
            return False, 0
        window.append(now)
        return True, max_per_minute - count - 1

    def check_or_raise(self, key: str, max_per_minute: int, detail: str = "") -> None:
        allowed, remaining = self.is_allowed(key, max_per_minute)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=detail or "Rate limit exceeded. Retry in ~60s.",
                headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
            )


# ── Redis rate limiter (multi-pod safe) ────────────────────────────────────────

class _RedisRateLimiter:
    """
    Redis sliding-window rate limiter.
    Uses sorted set: ZADD key score=timestamp member=uuid
    Atomic via pipeline (MULTI/EXEC).

    Key: ares:rl:{bucket}:{identifier}
    TTL: 120s (auto-eviction even if key not queried)
    """

    def __init__(self, redis_client: Any) -> None:
        self._r = redis_client

    async def is_allowed_async(self, key: str, max_per_minute: int) -> tuple[bool, int]:
        import uuid as _uuid
        now        = time.time()
        window_key = f"ares:rl:{key}"
        cutoff     = now - 60.0
        member     = str(_uuid.uuid4())

        async with self._r.pipeline(transaction=True) as pipe:
            # 1. Remove entries older than 60s
            pipe.zremrangebyscore(window_key, "-inf", cutoff)
            # 2. Count current window
            pipe.zcard(window_key)
            # 3. Add this request
            pipe.zadd(window_key, {member: now})
            # 4. Expire key after 120s
            pipe.expire(window_key, 120)
            results = await pipe.execute()

        # results[1] = count BEFORE this request was added
        count = int(results[1])
        if count >= max_per_minute:
            # Over limit — remove the member we just added
            await self._r.zrem(window_key, member)
            return False, 0

        remaining = max_per_minute - count - 1
        return True, max(0, remaining)


# ── Unified APIRateLimiter facade ─────────────────────────────────────────────────

class APIRateLimiter:
    """
    Unified rate limiter facade.
    Automatically uses Redis if available, falls back to in-process.

    Call init_redis(redis_client) at startup to enable Redis mode.
    """

    def __init__(self) -> None:
        self._inprocess    = _InProcessLimiter()
        self._redis: _RedisRateLimiter | None = None
        self._redis_mode   = False

    def init_redis(self, redis_client: Any) -> None:
        """Wire in a Redis client. Must be called before first request."""
        self._redis      = _RedisRateLimiter(redis_client)
        self._redis_mode = True
        logger.info("rate_limiter_mode", backend="redis")

    def is_allowed(self, key: str, max_per_minute: int) -> tuple[bool, int]:
        """Sync fallback — used by global middleware (which can't easily await)."""
        return self._inprocess.is_allowed(key, max_per_minute)

    async def is_allowed_async(self, key: str, max_per_minute: int) -> tuple[bool, int]:
        """Async check — preferred for endpoint dependencies."""
        if self._redis_mode and self._redis:
            try:
                return await self._redis.is_allowed_async(key, max_per_minute)
            except Exception as exc:
                logger.warning("redis_rate_limit_error", error=str(exc)[:80],
                               fallback="in_process")
                # Fall through to in-process on Redis failure
        return self._inprocess.is_allowed(key, max_per_minute)

    async def check_or_raise_async(self, key: str, max_per_minute: int,
                                    detail: str = "") -> int:
        """Check limit, raise HTTP 429 if exceeded. Returns remaining count."""
        allowed, remaining = await self.is_allowed_async(key, max_per_minute)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=detail or "Rate limit exceeded. Retry in ~60s.",
                headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
            )
        return remaining

    def check_or_raise(self, key: str, max_per_minute: int, detail: str = "") -> int:
        """Sync version of check_or_raise — used in non-async contexts."""
        allowed, remaining = self.is_allowed(key, max_per_minute)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=detail or "Rate limit exceeded. Retry in ~60s.",
                headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
            )
        return remaining

    @property
    def _windows(self) -> "defaultdict[str, deque[float]]":
        """Expose in-process sliding windows (for testing)."""
        return self._inprocess._windows

    def get_config(self) -> dict[str, Any]:
        return RATE_LIMITS


# Module-level singleton
_limiter = APIRateLimiter()


def get_limiter() -> APIRateLimiter:
    """Return the shared rate limiter instance."""
    return _limiter


# ── FastAPI dependency factory ─────────────────────────────────────────────────

def rate_limit(bucket: str = "global") -> Any:
    """
    FastAPI async dependency — checks rate limit for request IP.
    Uses Redis if available, otherwise in-process.

    Usage:
        @app.post("/modules/{id}/run")
        async def run(_=Depends(rate_limit("module_run"))):
            ...
    """
    async def _check(request: Request) -> None:
        ip  = request.client.host if request.client else "unknown"
        key = f"{bucket}:{ip}"
        await _limiter.check_or_raise_async(key, RATE_LIMITS.get(bucket, 60))
    return _check


# ── RBAC permission matrix ─────────────────────────────────────────────────────

# Role level map derived from canonical ROLE_ORDER (single source of truth)
_ROLE_LEVELS: dict[str, int] = {r.value: i for i, r in enumerate(ROLE_ORDER)}

# Paths recon role is NOT allowed to POST/DELETE to
_RECON_BLOCKED_WRITE_PATTERNS = [
    "/auth/register", "/auth/",
    "/modules/lateral", "/modules/ad.dcsync", "/modules/ad.kerberoast",
]


def _role_can_access(role: str, method: str, path: str) -> bool:
    """
    Return True if `role` may call `method` on `path`.

    Rules:
      team_lead  — full access to everything
      operator   — GET/POST/DELETE on most paths except /auth/register
      recon      — GET only (except enumeration modules); no write access
      reporter   — GET only on /campaigns, /findings, /reports, /telemetry
    """
    role = role.lower()
    method = method.upper()

    if role == "team_lead":
        return True

    if role == "operator":
        return not (method == "POST" and "/auth/register" in path)

    if role == "recon":
        if method == "GET":
            return True
        # Allow POST only on recon-friendly module paths
        if method == "POST":
            if "/auth/" in path or "register" in path:
                return False
            # Block lateral/destructive modules
            for blocked in _RECON_BLOCKED_WRITE_PATTERNS:
                if blocked in path:
                    return False
            # Block arbitrary module runs that aren't recon
            if "/run" in path:
                return False
        return False

    if role == "reporter":
        if method != "GET":
            return False
        allowed_prefixes = ("/campaigns", "/findings", "/reports",
                            "/telemetry", "/graph", "/hosts")
        return any(path.startswith(p) for p in allowed_prefixes)

    return False


def _role_level(role: str) -> int:
    return _ROLE_LEVELS.get(role, 0)


# ── Auth dependency ────────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    token:   str | None = Depends(oauth2_scheme),
) -> AuthenticatedUser | None:
    """Decode JWT. Returns None (not raises) so API-key auth can fallback."""
    if not token:
        return None
    from ares.core.config import get_settings
    from ares.core.security import decode_access_token
    settings = get_settings()
    payload = decode_access_token(token, settings.secret_key_value,
                                   settings.ares_jwt_algorithm)
    if not payload:
        return None
    # Check if this access token has been explicitly revoked (e.g. on logout).
    # Use the DB connection from app.state (already open) — no new connection per request.
    jti = payload.get("jti")
    if jti:
        try:
            db = getattr(getattr(request, "app", None), "state", None)
            db = getattr(db, "db", None) if db else None
            if db is None:
                # Fallback: open a short-lived connection (dev / test context)
                from ares.db.database import AresDatabase
                async with await AresDatabase.create(settings.db_path) as _db:
                    if await _db.is_access_token_revoked(jti):
                        return None
            else:
                if await db.is_access_token_revoked(jti):
                    return None
        except Exception:
            pass   # DB unavailable — don't block auth on infra failure
    username = payload.get("sub", "")
    role     = payload.get("role", "reporter")
    return AuthenticatedUser(username=username, role=role)


def require_role(*allowed_roles: str) -> Any:
    async def _check(actor: AuthenticatedUser | None = Depends(get_current_user)) -> AuthenticatedUser:
        if not actor:
            raise HTTPException(401, "Not authenticated",
                                headers={"WWW-Authenticate": "Bearer"})
        if actor.role not in allowed_roles:
            raise HTTPException(
                403, f"Role {actor.role!r} insufficient. Required: {list(allowed_roles)}"
            )
        return actor
    return _check


def require_operator() -> Any:
    return require_role("operator", "team_lead")


def require_team_lead() -> Any:
    return require_role("team_lead")


def require_any_auth() -> Any:
    return require_role("reporter", "recon", "operator", "team_lead")


def check_endpoint_access(actor: AuthenticatedUser, method: str, path: str) -> None:
    min_level = 2 if method in ("POST", "PUT", "DELETE", "PATCH") else 0
    if _role_level(actor.role) < min_level:
        raise HTTPException(403, f"Role {actor.role!r} cannot {method} {path}")


# ── Backward-compat shim ───────────────────────────────────────────────────────

def init_user_store(store: dict) -> None:
    """
    Backward-compatibility shim — intentional no-op.

    In ARES ≥ 0.5 all users are managed by AresDatabase.
    This function is retained so older integrations do not break.
    Emits a DeprecationWarning and returns immediately.
    """
    import warnings as _warnings
    _warnings.warn(
        "init_user_store() is deprecated and has no effect in ARES ≥ 0.5. "
        "User management is handled by AresDatabase automatically.",
        DeprecationWarning,
        stacklevel=2,
    )

# Backward-compat alias
RateLimiter = APIRateLimiter  # noqa
