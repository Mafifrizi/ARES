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

import math
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from ares.core.logger import get_logger
from ares.core.token_sessions import is_canonical_family_id
from ares.db.websocket_tickets import BearerTicketSource

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
    auth_type: str = "bearer"
    api_key_id: str | None = None
    api_key_scopes: tuple[str, ...] = ()
    websocket_ticket_source: BearerTicketSource | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @property
    def is_api_key(self) -> bool:
        return self.auth_type == "api_key"

    def has_api_scope(self, *allowed: str) -> bool:
        return bool(set(allowed).intersection(self.api_key_scopes))

    @property
    def canonical_user_id(self) -> str | None:
        """Return the immutable bearer identity; usernames are never identity."""
        source = self.websocket_ticket_source
        return source.user_id if source is not None else None

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

class PrincipalDecisionStatus(str, Enum):
    AUTHORIZED = "authorized"
    INVALID = "invalid"
    BACKEND_UNAVAILABLE = "backend_unavailable"


@dataclass(frozen=True)
class AuthoritativePrincipal:
    user_id: str
    username: str
    role: str
    websocket_ticket_source: BearerTicketSource = field(
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class PrincipalDecision:
    status: PrincipalDecisionStatus
    principal: AuthoritativePrincipal | None = None


_VALID_PRINCIPAL_ROLES = frozenset(role.value for role in ROLE_ORDER)


async def resolve_bearer_principal(
    token: str,
    *,
    db: Any,
    secret_key: str,
    algorithm: str,
) -> PrincipalDecision:
    """Resolve a bearer token against one authoritative database snapshot."""
    from ares.core.security import decode_access_token

    try:
        payload = decode_access_token(token, secret_key, algorithm)
    except (TypeError, OverflowError):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    if not isinstance(payload, Mapping):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)

    subject = payload.get("sub")
    family_id = payload.get("sid")
    auth_epoch = payload.get("ver")
    jti = payload.get("jti")
    expires_at = payload.get("exp")
    if (
        not isinstance(subject, str)
        or not subject.strip()
        or not isinstance(jti, str)
        or not jti.strip()
        or not isinstance(family_id, str)
        or not is_canonical_family_id(family_id)
        or isinstance(auth_epoch, bool)
        or not isinstance(auth_epoch, int)
        or auth_epoch < 1
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
    ):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    try:
        expires_at_is_finite = math.isfinite(float(expires_at))
        source_expiry = datetime.fromtimestamp(float(expires_at), timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    if not expires_at_is_finite:
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)

    if db is None:
        logger.warning("auth_backend_principal_lookup_unavailable")
        return PrincipalDecision(PrincipalDecisionStatus.BACKEND_UNAVAILABLE)

    try:
        row = await db.resolve_access_token_principal(
            subject,
            jti,
            family_id,
            auth_epoch,
        )
    except Exception as exc:
        logger.warning(
            "auth_backend_principal_lookup_failed",
            error_type=type(exc).__name__,
        )
        return PrincipalDecision(PrincipalDecisionStatus.BACKEND_UNAVAILABLE)

    if not isinstance(row, Mapping):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)

    user_id = row.get("id")
    username = row.get("username")
    role = row.get("role")
    if (
        not isinstance(user_id, str)
        or not user_id.strip()
        or not isinstance(username, str)
        or username != subject
        or not isinstance(role, str)
        or role not in _VALID_PRINCIPAL_ROLES
    ):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)

    return PrincipalDecision(
        PrincipalDecisionStatus.AUTHORIZED,
        AuthoritativePrincipal(
            user_id=user_id,
            username=username,
            role=role,
            websocket_ticket_source=BearerTicketSource(
                user_id=user_id,
                subject=subject,
                jti=jti,
                expires_at=source_expiry,
                family_id=family_id,
                auth_epoch=auth_epoch,
            ),
        ),
    )


async def revalidate_bearer_principal(
    source: BearerTicketSource,
    *,
    db: Any,
) -> PrincipalDecision:
    """Revalidate retained non-secret bearer facts without retaining the token."""
    if type(source) is not BearerTicketSource:
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    if source.expires_at <= datetime.now(timezone.utc):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    if db is None:
        return PrincipalDecision(PrincipalDecisionStatus.BACKEND_UNAVAILABLE)
    try:
        row = await db.resolve_access_token_principal(
            source.subject,
            source.jti,
            source.family_id,
            source.auth_epoch,
        )
    except Exception as exc:
        logger.warning(
            "auth_backend_principal_revalidation_failed",
            error_type=type(exc).__name__,
        )
        return PrincipalDecision(PrincipalDecisionStatus.BACKEND_UNAVAILABLE)
    if not isinstance(row, Mapping):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    user_id = row.get("id")
    username = row.get("username")
    role = row.get("role")
    row_epoch = row.get("auth_epoch")
    if (
        user_id != source.user_id
        or username != source.subject
        or role not in _VALID_PRINCIPAL_ROLES
        or type(row_epoch) is not int
        or row_epoch != source.auth_epoch
    ):
        return PrincipalDecision(PrincipalDecisionStatus.INVALID)
    return PrincipalDecision(
        PrincipalDecisionStatus.AUTHORIZED,
        AuthoritativePrincipal(
            user_id=source.user_id,
            username=source.subject,
            role=str(role),
            websocket_ticket_source=source,
        ),
    )


async def resolve_execution_actor_authority_revision(
    db: Any,
    user_id: str,
) -> int | None:
    """Read the current lifecycle actor revision without widening DB APIs.

    The lifecycle store deliberately keeps authority derivation internal.  The
    live coordinator nevertheless needs the already-persisted actor revision
    for its point-in-time QUEUED transition.  Keep this read-only adapter here,
    beside bearer revalidation, and fail closed for unknown database backends.
    """
    try:
        if db.__class__.__module__ == "ares.db.database":
            connection = db._require_connected()
            async with connection.execute(
                "SELECT revision FROM execution_actor_authority_revisions "
                "WHERE user_id=?",
                (user_id,),
            ) as cursor:
                row = await cursor.fetchone()
            value = None if row is None else row["revision"]
        elif db.__class__.__module__ == "ares.db.postgres":
            pool = db._pool
            if pool is None:
                return None
            async with pool.acquire() as connection:
                value = await connection.fetchval(
                    "SELECT revision FROM execution_actor_authority_revisions "
                    "WHERE user_id=$1",
                    user_id,
                )
        else:
            resolver = getattr(db, "resolve_execution_actor_authority_revision", None)
            if not callable(resolver):
                return None
            value = await resolver(user_id)
    except Exception as exc:
        logger.warning(
            "execution_actor_authority_revision_lookup_failed",
            error_type=type(exc).__name__,
        )
        return None
    if type(value) is not int or not 0 <= value < 9_007_199_254_740_991:
        return None
    return value


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
    """Resolve an explicitly supplied bearer token against the live auth database."""
    if not token:
        return None
    from ares.core.config import get_settings

    settings = get_settings()
    state = getattr(getattr(request, "app", None), "state", None)
    db = getattr(state, "db", None) if state is not None else None
    decision = await resolve_bearer_principal(
        token,
        db=db,
        secret_key=settings.secret_key_value,
        algorithm=settings.ares_jwt_algorithm,
    )
    if decision.status is PrincipalDecisionStatus.BACKEND_UNAVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        )
    if decision.status is not PrincipalDecisionStatus.AUTHORIZED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    principal = decision.principal
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return AuthenticatedUser(
        username=principal.username,
        role=principal.role,
        websocket_ticket_source=principal.websocket_ticket_source,
    )


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


def require_live_operator() -> Any:
    """Bearer-only live authority with an explicit API-key denial."""

    async def _check(
        request: Request,
        actor: AuthenticatedUser | None = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if actor is None:
            if request.headers.get("X-API-Key"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="api_key_execution_denied",
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if actor.role not in {"operator", "team_lead"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="live_execution_role_denied",
            )
        if actor.websocket_ticket_source is None or actor.canonical_user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return actor

    return _check


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
