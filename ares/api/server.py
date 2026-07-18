"""
ARES API Server v6.0.0
FastAPI — DB-persistent, WebSocket events, refresh tokens, API key auth, pagination.

v6.0.0 changes vs v1.0.0:
  ✓ AresDatabase injected via app.state — no more in-memory dicts
  ✓ Persistent user store (users table, DB-backed)
  ✓ Refresh token endpoint + rotation on use
  ✓ API key auth (X-API-Key header) for CI/CD automation
  ✓ WebSocket /ws/campaigns/{id}/events — real-time module progress
  ✓ Pagination on /campaigns, /campaigns/{id}/findings
  ✓ X-RateLimit-Remaining + X-Total-Count response headers
  ✓ JWT-only account management and API-key lifecycle endpoints
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles

from ares.__version__ import __version__ as _ares_version
from ares.api.rbac import (
    RATE_LIMITS,
    AuthenticatedUser,
    _limiter,
    get_current_user,
    rate_limit,
    require_any_auth,
    require_operator,
    require_team_lead,
)
from ares.core.campaign import Campaign, Finding
from ares.core.config import AresSettings, get_settings
from ares.core.engine import AresEngine
from ares.core.logger import get_logger
from ares.core.security import create_access_token
from ares.modules.base import normalize_module_metadata
from ares.core.tracing import get_current_trace_id, instrument_fastapi, setup_tracing
from ares.db.database import AresDatabase

logger = get_logger("ares.api.server")


def _campaign_from_db_row(row: dict[str, Any]) -> Campaign:
    data = {k: v for k, v in row.items() if k in Campaign.model_fields}
    if "scope" not in data and row.get("scope_json"):
        import json as _json

        try:
            scope = _json.loads(str(row["scope_json"]))
            if isinstance(scope, list):
                data["scope"] = scope
        except (TypeError, ValueError):
            data["scope"] = []
    if "targets" not in data and row.get("targets_json"):
        import json as _json

        try:
            targets = _json.loads(str(row["targets_json"]))
            if isinstance(targets, list):
                data["targets"] = targets
        except (TypeError, ValueError):
            data["targets"] = []
    return Campaign(**data)


def _finding_from_db_row(row: dict[str, Any], *, report_confirmed: bool = False) -> Finding:
    import json as _json

    evidence: dict[str, Any] = {}
    raw_evidence = row.get("evidence_json")
    if isinstance(raw_evidence, str) and raw_evidence.strip():
        try:
            parsed = _json.loads(raw_evidence)
            evidence = parsed if isinstance(parsed, dict) else {"raw": parsed}
        except (TypeError, ValueError):
            evidence = {"raw": raw_evidence}
    elif isinstance(raw_evidence, dict):
        evidence = raw_evidence

    data = {
        "id": row.get("id", ""),
        "title": row.get("title", ""),
        "description": row.get("description", ""),
        "severity": row.get("severity", "info"),
        "confidence": row.get("confidence", 1.0) or 1.0,
        "mitre_technique": row.get("mitre_technique"),
        "mitre_tactic": row.get("mitre_tactic"),
        "evidence": evidence,
        "remediation": row.get("remediation") or "",
        "false_positive": bool(row.get("false_positive", False)),
        "validated": bool(row.get("validated", False)) or report_confirmed,
        "host": row.get("host"),
        "module_id": row.get("module_id") or "",
        "cvss_score": row.get("cvss_score", 0.0) or 0.0,
        "cvss_vector": row.get("cvss_vector") or "",
        "trace_id": row.get("trace_id") or "",
    }
    if row.get("discovered_at"):
        data["discovered_at"] = row["discovered_at"]
    return Finding(**data)


async def _campaign_for_report(db: AresDatabase, row: dict[str, Any]) -> Campaign:
    campaign = _campaign_from_db_row(row)
    # Reports must use the same persisted findings visible in the dashboard. Older
    # DB rows and some module-run paths may not have the validated flag populated,
    # but API-triggered module results are already confirmed before persistence.
    rows, _ = await db.list_findings(
        campaign.id,
        page=1,
        per_page=10000,
        false_positive=False,
    )
    campaign.findings = [
        _finding_from_db_row(finding_row, report_confirmed=True)
        for finding_row in rows
    ]
    return campaign


def _setup_otel(app: FastAPI, settings: Any) -> None:
    """Initialize OpenTelemetry tracing if endpoint is configured."""
    if not settings.ares_otel_endpoint:
        return
    configured = setup_tracing(
        service_name=settings.ares_otel_service,
        otel_endpoint=settings.ares_otel_endpoint,
        sample_rate=settings.ares_otel_sample_rate,
    )
    if configured:
        instrument_fastapi(app)


# ── App-level singletons ──────────────────────────────────────────────────────
_engine: AresEngine | None = None
_db: AresDatabase | None = None

# WebSocket connection registry: campaign_id → set of WebSocket connections
_ws_connections: dict[str, set[WebSocket]] = {}
_active_engagements: dict[str, str] = {}  # engagement_id → campaign_id
_MAX_CONCURRENT_ENGAGEMENTS = 3  # operator-configurable via ARES_MAX_ENGAGEMENTS

# Asyncio lock for atomic engagement registration (prevents TOCTOU race)
_engagement_lock: asyncio.Lock | None = None


class DashboardStaticFiles(StaticFiles):
    """Serve Vite assets and fall back to index.html for dashboard SPA routes."""

    async def get_response(self, path: str, scope: Any) -> Any:
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def _dashboard_dist_dir() -> Path:
    configured = os.environ.get("ARES_DASHBOARD_DIST", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _mount_dashboard(app: FastAPI) -> None:
    app.mount(
        "/dashboard",
        DashboardStaticFiles(
            directory=str(_dashboard_dist_dir()), html=True, check_dir=False
        ),
        name="dashboard",
    )


async def _get_engagement_lock() -> asyncio.Lock:
    """Lazily create a singleton asyncio.Lock for engagement concurrency control."""
    global _engagement_lock
    if _engagement_lock is None:
        _engagement_lock = asyncio.Lock()
    return _engagement_lock


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _engine, _db
    settings = get_settings()
    _db = await AresDatabase.create(
        db_path=settings.db_path,
        encryption_key=settings.encryption_key_value,
    )
    app.state.db = _db
    await _db.ensure_default_admin(settings.ares_default_admin_password)

    # Share DB with dashboard sub-app so it reuses the same connection
    try:
        from ares.api.dashboard.app import dashboard_app as _dash_app

        _dash_app.state.db = _db
    except Exception as exc:
        logger.debug("legacy_dashboard_db_share_skipped", error=str(exc))
        pass  # dashboard not loaded — silently skip

    # Wire ARES_RATE_LIMIT_RPM setting into global rate limit bucket
    # Without this, operator changes to ARES_RATE_LIMIT_RPM have no effect
    from ares.api.rbac import RATE_LIMITS as _RL

    _RL["global"] = settings.ares_rate_limit_rpm

    _engine = AresEngine(settings=settings)
    _engine.load_modules()
    app.state.engine = _engine

    # ── Redis rate limiter (optional) ────────────────────────────────────
    if settings.ares_redis_url:
        try:
            import redis.asyncio as aioredis  # type: ignore[import-untyped]

            _redis = await aioredis.from_url(
                settings.ares_redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await _redis.ping()
            _limiter.init_redis(_redis)
            app.state.redis = _redis
            logger.info("redis_rate_limiter_active", url=settings.ares_redis_url)
        except Exception as exc:
            logger.warning(
                "redis_rate_limiter_unavailable",
                error=str(exc)[:80],
                fallback="in_process",
            )
    else:
        logger.info(
            "rate_limiter_mode",
            backend="in_process",
            note="Set ARES_REDIS_URL for multi-pod safety",
        )

    # ── OpenTelemetry ────────────────────────────────────────────────────
    _setup_otel(app, settings)

    # Startup security audit
    try:
        from ares.security.audit import startup_audit

        await startup_audit("WARN")
    except Exception as exc:
        logger.warning("startup_audit_failed", error=str(exc))

    logger.info("ARES API v6.0.0 started", db=settings.ares_database_url)

    # Background task: purge expired tokens every hour
    async def _token_cleanup():
        while True:
            await asyncio.sleep(3600)
            try:
                n = await _db.purge_expired_tokens()
                if n > 0:
                    logger.debug("purged_expired_tokens", count=n)
            except Exception as exc:
                logger.debug("token_purge_error", error=str(exc))

    _cleanup_task = asyncio.create_task(_token_cleanup())

    yield

    # Graceful shutdown — cancel background task before closing DB
    _cleanup_task.cancel()
    await asyncio.gather(_cleanup_task, return_exceptions=True)
    await _db.close()
    logger.info("ARES API shutdown complete")


_debug = False
try:
    _debug = get_settings().ares_debug
except Exception as exc:
    logger.debug("settings_debug_resolution_failed", error=str(exc))

app = FastAPI(
    title="ARES API",
    description="Automated Red team Engagement System — v6.0.0",
    version=_ares_version,
    lifespan=lifespan,
    docs_url="/docs" if _debug else None,
    redoc_url="/redoc" if _debug else None,
)


@app.get("/health", tags=["health"])
async def health(request: Request) -> dict[str, Any]:
    db_ok = getattr(request.app.state, "db", None) is not None
    return {
        "status": "ok" if db_ok else "degraded",
        "version": _ares_version,
        "db": "connected" if db_ok else "unavailable",
    }


_mount_dashboard(app)


@app.middleware("http")
async def _block_docs_in_production(request: Request, call_next: Any) -> Any:
    """Return 404 for /docs, /redoc, /openapi.json when ares_debug=False.
    Evaluated at request time — not baked at import.
    """
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        try:
            if not get_settings().ares_debug:
                from fastapi.responses import JSONResponse

                return JSONResponse(status_code=404, content={"detail": "Not Found"})
        except Exception:
            from fastapi.responses import JSONResponse

            return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await call_next(request)


# ── Middleware ────────────────────────────────────────────────────────────────

# ── Request body size limit — prevent DoS via oversized payloads ──────────────
_MAX_BODY_MB = 10  # 10 MB — enough for module payloads, rejects abuse
_MAX_BODY_BYTES = _MAX_BODY_MB * 1024 * 1024


class _BodySizeLimitMiddleware(_BaseHTTPMiddleware):
    """
    Hard limit on request body size (default 10 MB).

    Uses BaseHTTPMiddleware + request.body() which caches the body internally.
    This approach works correctly in both production (uvicorn) and testing
    (Starlette TestClient / httpx ASGITransport), unlike the previous
    @app.middleware("http") + request._receive patching approach which
    failed in TestClient because call_next() creates a new Request that
    doesn't inherit the patched _receive attribute.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        # request.body() reads and caches the full body;
        # subsequent reads (by FastAPI/Pydantic) also use the cache.
        body = await request.body()
        if len(body) > _MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "code": 413,
                    "detail": f"Request body exceeds {_MAX_BODY_MB} MB limit",
                    "type": "payload_too_large",
                },
            )
        return await call_next(request)


# Convenience name kept for any code that references it
limit_request_body = _BodySizeLimitMiddleware


# Load CORS origins and trusted hosts from settings (configurable via .env)
try:
    from ares.core.config import get_settings as _get_settings

    _s = _get_settings()
    _cors_origins = _s.cors_origins_list
    _trusted_hosts = _s.trusted_hosts_list
except Exception:
    _cors_origins = ["http://localhost:3000", "http://localhost:8080"]
    _trusted_hosts = ["localhost", "127.0.0.1"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=_trusted_hosts,  # No wildcard — must be explicit
)
# Body size limit — registered after TrustedHost so it runs on trusted requests only.
# BaseHTTPMiddleware approach (vs @app.middleware) works in both uvicorn and TestClient.
app.add_middleware(_BodySizeLimitMiddleware)


@app.middleware("http")
async def security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    # HSTS is only meaningful on HTTPS — don't send on plain HTTP
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    for _hdr in ("server", "Server", "x-powered-by", "X-Powered-By"):
        if _hdr in response.headers:
            del response.headers[_hdr]
    return response


@app.middleware("http")
async def trace_id_header_middleware(request: Request, call_next: Any) -> Any:
    """Inject X-Trace-Id into every response for client-side correlation."""
    response = await call_next(request)
    trace_id = get_current_trace_id()
    if trace_id:
        response.headers["X-Trace-Id"] = trace_id
    return response


@app.middleware("http")
async def global_rate_limit_middleware(request: Request, call_next: Any) -> Any:
    ip = request.client.host if request.client else "unknown"
    allowed, remaining = await _limiter.is_allowed_async(
        f"global:{ip}", RATE_LIMITS["global"]
    )
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={
                "code": 429,
                "detail": "Global rate limit exceeded.",
                "type": "rate_limit",
            },
            headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
        )
    response = await call_next(request)
    response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
    return response


# ── Shared dependencies ───────────────────────────────────────────────────────


async def _require_campaign_access(
    campaign: dict,
    actor: AuthenticatedUser,
) -> None:
    """Raise 404 (not 403) if actor cannot access campaign — avoids campaign enumeration."""
    if actor.role != "team_lead" and campaign.get("operator") != actor.username:
        raise HTTPException(404, "Campaign not found")


def get_db(request: Request) -> AresDatabase:
    return request.app.state.db


def get_engine(request: Request) -> AresEngine:
    engine = request.app.state.engine
    if not engine:
        raise HTTPException(503, "Engine not ready")
    return engine


async def get_current_user_or_apikey(
    request: Request,
    bearer: AuthenticatedUser | None = Depends(get_current_user),
) -> AuthenticatedUser:
    """Accept JWT bearer token OR X-API-Key header."""
    if bearer:
        return bearer
    api_key = request.headers.get("X-API-Key")
    if api_key:
        db = get_db(request)
        data = await db.verify_api_key(api_key)
        if data:
            return AuthenticatedUser(
                username=data["username"],
                role=data["role"],
                auth_type="api_key",
                api_key_id=data.get("key_id") or data.get("id"),
                api_key_scopes=_normalize_api_key_scopes(data.get("scopes")),
            )
    raise HTTPException(401, "Not authenticated. Provide Bearer token or X-API-Key.")


def _normalize_api_key_scopes(raw_scopes: Any) -> tuple[str, ...]:
    if raw_scopes is None:
        return ()
    if isinstance(raw_scopes, str):
        return tuple(
            scope.strip()
            for scope in raw_scopes.replace(",", " ").split()
            if scope.strip()
        )
    if isinstance(raw_scopes, (list, tuple, set)):
        return tuple(str(scope).strip() for scope in raw_scopes if str(scope).strip())
    return ()


def require_api_key_scope(*allowed_scopes: str) -> Any:
    async def _check(
        actor: AuthenticatedUser = Depends(get_current_user_or_apikey),
    ) -> AuthenticatedUser:
        if actor.is_api_key and not actor.has_api_scope(*allowed_scopes):
            raise HTTPException(
                403,
                "API key scope insufficient. "
                f"Required one of: {', '.join(allowed_scopes)}",
            )
        return actor

    return _check


_api_key_read_dep = Depends(require_api_key_scope("read", "write", "admin"))
_api_key_write_dep = Depends(require_api_key_scope("write", "admin"))
_current_user_or_apikey_dep = _api_key_read_dep
_db_dep = Depends(get_db)


# ── Error schema ──────────────────────────────────────────────────────────────


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.status_code, "detail": exc.detail, "type": "api_error"},
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler — prevents stack trace leaking in 500 responses."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        exc=str(exc)[:200],
        exc_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={
            "code": 500,
            "detail": "Internal server error",
            "type": "internal_error",
        },
    )


# ── Auth ──────────────────────────────────────────────────────────────────────


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int = 3600
    role: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/token", response_model=TokenResponse, tags=["auth"])
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> TokenResponse:
    """Authenticate. Returns access_token (60m) + refresh_token (30d)."""
    ip = request.client.host if request.client else "unknown"
    # Double-check: per-IP AND per-username to block both distributed and targeted attacks
    allowed_ip, _ = await _limiter.is_allowed_async(f"auth:{ip}", RATE_LIMITS["auth"])
    allowed_user, _ = await _limiter.is_allowed_async(
        f"auth:u:{form.username}", RATE_LIMITS["auth"]
    )
    if not allowed_ip or not allowed_user:
        raise HTTPException(
            429,
            "Too many login attempts. Try again in 60s.",
            headers={"Retry-After": "60"},
        )

    # Guard against bcrypt DoS — OAuth2PasswordRequestForm has no max_length
    if len(form.password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")

    user = await db.verify_user(form.username, form.password)
    if not user:
        await db.audit(
            "system",
            "login_failed",
            f"username={form.username}",
        )
        raise HTTPException(401, "Invalid credentials")

    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        secret_key=settings.secret_key_value,
        algorithm=settings.ares_jwt_algorithm,
        expires_minutes=settings.ares_jwt_expire_minutes,
    )
    refresh_token = await db.create_refresh_token(user["id"])
    await db.audit(user["username"], "login_success")
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user["role"],
        expires_in=settings.ares_jwt_expire_minutes * 60,
    )


@app.post("/auth/refresh", response_model=TokenResponse, tags=["auth"])
async def refresh_access_token(
    request: Request,
    body: RefreshRequest,
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> TokenResponse:
    """Rotate refresh token. Old token revoked; new access + refresh token issued."""
    ip = request.client.host if request.client else "unknown"
    allowed, _ = await _limiter.is_allowed_async(f"refresh:{ip}", RATE_LIMITS["auth"])
    if not allowed:
        raise HTTPException(
            429,
            "Too many refresh attempts. Try again in 60s.",
            headers={"Retry-After": "60"},
        )
    user, new_refresh = await db.rotate_refresh_token(body.refresh_token)
    if not user:
        raise HTTPException(401, "Refresh token invalid or expired")

    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        secret_key=settings.secret_key_value,
        algorithm=settings.ares_jwt_algorithm,
        expires_minutes=settings.ares_jwt_expire_minutes,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        role=user["role"],
        expires_in=settings.ares_jwt_expire_minutes * 60,
    )


@app.post("/auth/logout", tags=["auth"])
async def logout(
    request: Request,
    actor: AuthenticatedUser = Depends(require_any_auth()),
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    """Revoke all refresh tokens + blacklist the current access token jti."""
    user = await db.get_user(actor.username)
    if user:
        await db.revoke_all_refresh_tokens(user["id"])
        # Also revoke the current access token by jti so it cannot be reused
        # within its remaining 60-minute window
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if token:

            from ares.core.security import decode_access_token

            payload = decode_access_token(
                token,
                settings.secret_key_value,
                settings.ares_jwt_algorithm,
            )
            if payload and payload.get("jti"):
                import datetime as _dt

                exp_ts = payload.get("exp", 0)
                exp_iso = (
                    _dt.datetime.fromtimestamp(exp_ts, tz=_dt.timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    if exp_ts
                    else ""
                )
                await db.revoke_access_token(payload["jti"], user["id"], exp_iso)
        await db.audit(actor.username, "logout")
    return {"status": "ok"}


def _validate_password_complexity(v: str) -> str:
    """Enforce password complexity: min 12 chars, upper+lower+digit+special."""
    import re

    if len(v) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", v):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[^A-Za-z0-9]", v):
        raise ValueError("Password must contain at least one special character")
    return v


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field("reporter")

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        return _validate_password_complexity(v)


@app.post("/auth/register", tags=["auth"])
async def register(
    body: RegisterRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(require_team_lead()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    """Register new operator. Requires: team_lead role + rate limit."""
    # Rate-limit registration even for team_leads — prevents abuse if token stolen
    ip = request.client.host if request.client else "unknown"
    await _limiter.check_or_raise_async(
        f"register:{ip}",
        RATE_LIMITS["register"],
        detail="Too many registration attempts. Retry in ~60s.",
    )
    valid_roles = {"team_lead", "operator", "recon", "reporter"}
    if body.role not in valid_roles:
        raise HTTPException(400, f"Invalid role. Must be one of: {sorted(valid_roles)}")
    if await db.user_exists(body.username):
        raise HTTPException(409, "Username already taken")
    await db.create_user(
        body.username, body.password, body.role, created_by=actor.username
    )
    await db.audit(
        actor.username, "user_registered", f"new_user={body.username} role={body.role}"
    )
    return {"status": "created", "username": body.username, "role": body.role}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def new_password_complexity(cls, v: str) -> str:
        return _validate_password_complexity(v)


@app.post("/auth/change-password", tags=["auth"])
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    actor: AuthenticatedUser = Depends(require_any_auth()),
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    if len(body.current_password) > 128:
        raise HTTPException(status_code=400, detail="Password too long")
    user = await db.verify_user(actor.username, body.current_password)
    if not user:
        raise HTTPException(401, "Current password incorrect")
    from ares.core.security import hash_password

    await db.update_password(user["id"], hash_password(body.new_password))
    await db.revoke_all_refresh_tokens(user["id"])
    # Revoke the current access token by jti — same as logout() —
    # so the old token cannot be reused within its remaining expiry window.
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if token:
        import datetime as _dt

        from ares.core.security import decode_access_token

        payload = decode_access_token(
            token, settings.secret_key_value, settings.ares_jwt_algorithm
        )
        if payload and payload.get("jti"):
            exp_ts = payload.get("exp", 0)
            exp_iso = (
                _dt.datetime.fromtimestamp(exp_ts, tz=_dt.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if exp_ts
                else ""
            )
            await db.revoke_access_token(payload["jti"], user["id"], exp_iso)
    await db.audit(actor.username, "password_changed")
    return {"status": "ok", "note": "All existing sessions revoked"}


@app.get("/auth/me", tags=["auth"])
async def whoami(
    actor: AuthenticatedUser = _api_key_read_dep,
) -> dict:
    return {"username": actor.username, "role": actor.role}


# ── API Keys ──────────────────────────────────────────────────────────────────


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    scopes: str = Field("read", pattern=r"^(read|write|admin)$")
    expires_days: int | None = Field(None, ge=1, le=365)


@app.post("/auth/api-keys", tags=["auth"])
async def create_api_key(
    body: CreateAPIKeyRequest,
    actor: AuthenticatedUser = Depends(require_any_auth()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    """Create API key for CI/CD automation. Key is shown ONCE — save it."""
    user = await db.get_user(actor.username)
    if not user:
        raise HTTPException(404, "User not found")
    key_id, raw_key = await db.create_api_key(
        user["id"], body.name, body.scopes, body.expires_days
    )
    await db.audit(actor.username, "api_key_created", f"name={body.name}")
    return {
        "id": key_id,
        "key": raw_key,
        "note": "Save this key — it will NOT be shown again.",
        "prefix": raw_key[:12],
    }


@app.get("/auth/api-keys", tags=["auth"])
async def list_api_keys(
    actor: AuthenticatedUser = Depends(require_any_auth()),
    db: AresDatabase = Depends(get_db),
) -> list[dict]:
    user = await db.get_user(actor.username)
    if not user:
        return []
    return await db.list_api_keys(user["id"])


@app.delete("/auth/api-keys/{key_id}", tags=["auth"])
async def revoke_api_key(
    key_id: str,
    actor: AuthenticatedUser = Depends(require_any_auth()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    user = await db.get_user(actor.username)
    if not user:
        raise HTTPException(404, "User not found")
    await db.revoke_api_key(key_id, user["id"])
    await db.audit(actor.username, "api_key_revoked", f"key_id={key_id}")
    return {"status": "revoked"}


# ── Campaigns ─────────────────────────────────────────────────────────────────


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    client: str = Field("Internal", max_length=128)
    targets: list[str] = Field(default_factory=list, max_length=256)
    scope_cidrs: list[str] = Field(default_factory=list, max_length=256)
    noise_profile: str = Field("stealth", pattern=r"^(stealth|normal|aggressive)$")

    @field_validator("noise_profile", mode="before")
    @classmethod
    def normalize_noise_profile(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Campaign name must not contain filesystem-dangerous characters."""
        import re as _re

        if _re.search(r'[<>:"/\\|?*\x00]', v):
            raise ValueError(
                'Campaign name must not contain: < > : " / \\ | ? * or null bytes'
            )
        return v.strip()

    @field_validator("targets", mode="before")
    @classmethod
    def validate_targets(cls, v: list) -> list[str]:
        """
        Validate every target entry is a valid IP, CIDR, or hostname.
        Rejects path traversal, null bytes, and other dangerous values.
        Max 256 entries.
        """
        from ares.core.security import sanitize_hostname, validate_ip_or_cidr

        if not isinstance(v, list):
            raise ValueError("targets must be a list")
        if len(v) > 256:
            raise ValueError("targets: maximum 256 entries allowed")
        cleaned: list[str] = []
        for i, entry in enumerate(v):
            if entry is None:
                raise ValueError(f"targets[{i}]: null values not allowed")
            if not isinstance(entry, str):
                raise ValueError(
                    f"targets[{i}]: must be a string, not {type(entry).__name__}"
                )
            entry = entry.strip()
            if not entry:
                continue  # silently drop empty strings
            # Accept valid IP or CIDR directly
            if validate_ip_or_cidr(entry):
                cleaned.append(entry)
                continue
            if "/" in entry or "\\" in entry or ".." in entry:
                raise ValueError(f"targets[{i}]: path traversal not allowed")
            # Otherwise validate as hostname
            sanitized = sanitize_hostname(entry)
            if not sanitized:
                raise ValueError(
                    f"targets[{i}]: {entry!r} is not a valid IP, CIDR, or hostname. "
                    "Examples: '10.0.0.1', '192.168.1.0/24', 'dc01.corp.local'"
                )
            cleaned.append(sanitized)
        return cleaned

    @field_validator("scope_cidrs", mode="before")
    @classmethod
    def validate_scope_cidrs(cls, v: list) -> list[str]:
        """
        Validate campaign scope before endpoint logic constructs ScopeEntry.
        This keeps invalid operator input on the normal HTTP 422 path instead
        of surfacing as an unhandled server exception.
        """
        from netaddr import AddrFormatError, IPNetwork

        if not isinstance(v, list):
            raise ValueError("scope_cidrs must be a list")
        if len(v) > 256:
            raise ValueError("scope_cidrs: maximum 256 entries allowed")
        cleaned: list[str] = []
        for i, entry in enumerate(v):
            if entry is None:
                raise ValueError(f"scope_cidrs[{i}]: null values not allowed")
            if not isinstance(entry, str):
                raise ValueError(
                    f"scope_cidrs[{i}]: must be a string, not {type(entry).__name__}"
                )
            entry = entry.strip()
            if not entry:
                continue
            try:
                IPNetwork(entry)
            except (AddrFormatError, ValueError) as exc:
                raise ValueError(
                    f"scope_cidrs[{i}]: {entry!r} is not a valid CIDR or IP range. "
                    "Examples: '10.0.0.0/24', '192.168.1.10/32'"
                ) from exc
            cleaned.append(entry)
        return cleaned


@app.post("/campaigns", tags=["campaigns"])
async def create_campaign(
    request: Request,
    body: CampaignCreate,
    actor: AuthenticatedUser = Depends(require_operator()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    ip = request.client.host if request.client else "unknown"
    allowed, _ = await _limiter.is_allowed_async(
        f"campaign_create:{ip}", RATE_LIMITS["campaign_create"]
    )
    if not allowed:
        raise HTTPException(429, "Campaign creation rate limit exceeded.")
    from ares.core.campaign import ScopeEntry

    scope = [ScopeEntry(cidr=c) for c in body.scope_cidrs]
    c = Campaign(
        name=body.name,
        client=body.client,
        targets=body.targets,
        scope=scope,
        operator=actor.username,
        noise_profile=body.noise_profile,
    )
    await db.save_campaign(c)
    await db.audit(actor.username, "campaign_created", f"id={c.id} name={c.name}", c.id)
    return c.model_dump()


@app.get("/campaigns", tags=["campaigns"])
async def list_campaigns(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> JSONResponse:
    """List campaigns with pagination. Returns X-Total-Count header.
    Non-team_lead users only see their own campaigns.
    """
    # team_lead sees all; operators/recon/reporter see only their own campaigns
    operator_filter = None if actor.role == "team_lead" else actor.username
    rows, total = await db.list_campaigns(page, per_page, operator=operator_filter)
    return JSONResponse(
        content=rows,
        headers={
            "X-Total-Count": str(total),
            "X-Page": str(page),
            "X-Per-Page": str(per_page),
        },
    )


@app.get("/campaigns/{campaign_id}", tags=["campaigns"])
async def get_campaign(
    campaign_id: str,
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    c = await db.get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(c, actor)
    return c


@app.delete("/campaigns/{campaign_id}", tags=["campaigns"])
async def delete_campaign(
    campaign_id: str,
    actor: AuthenticatedUser = Depends(require_team_lead()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    c = await db.get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")

    deleted = await db.delete_campaign(campaign_id)
    if not deleted:
        raise HTTPException(404, "Campaign not found")

    deleted_reports = _delete_report_artifacts_for_campaign(campaign_id)
    await db.audit(
        actor.username,
        "campaign_deleted",
        f"id={campaign_id} name={c.get('name', '')} reports_deleted={deleted_reports}",
        None,
    )
    return {"status": "deleted", "campaign_id": campaign_id}


@app.post("/campaigns/{campaign_id}/restore-vault", tags=["campaigns"])
async def restore_campaign_vault(
    request: Request,
    campaign_id: str,
    actor: AuthenticatedUser = Depends(require_operator()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Restore CredentialVault from DB for a campaign after restart or crash.
    Returns count of credentials re-hydrated into memory.
    The vault is attached to the running engine's campaign object.
    """
    ip = request.client.host if request.client else "unknown"
    allowed, _ = await _limiter.is_allowed_async(
        f"vault_restore:{ip}", RATE_LIMITS["vault_restore"]
    )
    if not allowed:
        raise HTTPException(429, "Vault restore rate limit exceeded.")
    c = await db.get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(c, actor)

    records = await db.load_credentials_raw(campaign_id)
    if not records:
        return {
            "restored": 0,
            "campaign_id": campaign_id,
            "message": "No credentials found in DB for this campaign",
        }

    from ares.credential.vault import CredentialVault

    settings = get_settings()
    vault = CredentialVault(encryption_key=settings.encryption_key_value)
    count = vault.restore_from_db_records(records)

    await db.audit(
        actor.username,
        "vault_restored",
        f"campaign={campaign_id} count={count}",
        campaign_id,
    )
    return {"restored": count, "campaign_id": campaign_id}


@app.get("/campaigns/{campaign_id}/findings", tags=["campaigns"])
async def list_findings(
    campaign_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    false_positive: bool | None = None,
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> JSONResponse:
    """Paginated findings. Filters: severity, false_positive."""
    c = await db.get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(c, actor)
    rows, total = await db.list_findings(
        campaign_id, page, per_page, severity, false_positive
    )
    return JSONResponse(
        content=rows,
        headers={
            "X-Total-Count": str(total),
            "X-Page": str(page),
            "X-Per-Page": str(per_page),
        },
    )


# ── Modules ───────────────────────────────────────────────────────────────────


@app.get("/modules", tags=["modules"])
async def list_modules(
    actor: AuthenticatedUser = _api_key_read_dep,
    engine: AresEngine = Depends(get_engine),
) -> list[dict]:
    from ares.modules.params import MODULE_PARAMS

    modules = engine.list_modules()
    enriched: list[dict[str, Any]] = []
    for meta in modules:
        module_meta = dict(meta)
        module_id = (
            module_meta.get("id")
            or module_meta.get("module_id")
            or module_meta.get("MODULE_ID")
            or ""
        )
        cls = engine.registry.get(str(module_id)) if module_id else None
        params_model = MODULE_PARAMS.get(str(module_id))
        param_schema = (
            params_model.schema_for_api() if params_model else {}
        )
        if cls:
            module_meta = normalize_module_metadata(
                cls, param_schema=param_schema, base=module_meta
            )
            module_meta.setdefault("category", getattr(cls, "MODULE_CATEGORY", ""))
            module_meta.setdefault(
                "description", getattr(cls, "MODULE_DESCRIPTION", "")
            )
            opsec = getattr(cls, "OPSEC_LEVEL", None)
            if opsec is not None and not module_meta.get("opsec_level"):
                module_meta["opsec_level"] = getattr(opsec, "value", str(opsec))
            mitre = list(getattr(cls, "MITRE_TECHNIQUES", []))
            module_meta.setdefault("mitre_list", mitre)
            module_meta.setdefault("mitre", ", ".join(mitre))
        else:
            module_meta["param_schema"] = param_schema
        enriched.append(module_meta)
    return enriched


@app.get("/modules/execution-chains", tags=["modules"])
async def list_execution_chains(
    actor: AuthenticatedUser = _api_key_read_dep,
) -> list[dict[str, Any]]:
    """Return read-only execution-chain guidance for the Modules page."""
    from ares.core.execution_chains import list_execution_chains as get_chains

    return get_chains()


class RunRequest(BaseModel):
    campaign_id: str
    params: dict[str, Any] = {}
    dry_run: bool = False  # validate + preview without touching target


class PlanRunRequest(BaseModel):
    """Body for POST /campaigns/{id}/run (plan-level execution)."""

    plan: dict[str, Any]
    global_params: dict[str, Any] = {}
    dry_run: bool = False


@app.post("/modules/{module_id}/run", tags=["modules"])
async def run_module(
    module_id: str,
    body: RunRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(require_operator()),
    _rate: None = Depends(rate_limit("module_run")),
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """Run module. HIGH_NOISE requires team_lead. Rate limited: 20/min."""
    from ares.modules.base import OpsecLevel

    # Use the engine's already-loaded registry — avoids rescanning disk on every request
    cls = engine.registry.get(module_id)
    if cls and getattr(cls, "OPSEC_LEVEL", None) == OpsecLevel.HIGH_NOISE:
        if actor.role != "team_lead":
            raise HTTPException(403, f"{module_id!r} is HIGH_NOISE — team_lead only.")

    # Validate params against Pydantic schema
    from pydantic import ValidationError as PydanticValidationError

    from ares.modules.params import validate_module_params

    try:
        validated_params = validate_module_params(module_id, body.params)
    except PydanticValidationError as exc:
        # Surface field-level validation errors as 422 with detail
        errors = [
            {"field": ".".join(str(x) for x in e["loc"]), "msg": e["msg"]}
            for e in exc.errors()
        ]
        if body.dry_run:
            missing = [item["field"] for item in errors]
            return engine.dry_run_module(
                module_id,
                body.params,
                missing_params=missing,
            )
        raise HTTPException(
            status_code=422,
            detail={
                "message": f"Invalid params for module {module_id!r}",
                "errors": errors,
            },
        )
    # Replace raw params with validated (type-coerced, secret-wrapped) params
    body = body.model_copy(update={"params": validated_params})

    campaign = await db.get_campaign(body.campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)

    # Reconstruct Campaign object from DB row.
    c_obj = _campaign_from_db_row(campaign)

    # Unwrap SecretStr objects → plain strings before handing to modules.
    # Pydantic wraps secret fields after validation; libraries like impacket / ldap3
    # expect plain str — passing SecretStr causes silent auth failures.
    from pydantic import SecretStr as _SecretStr

    def _unwrap_secrets(params: dict) -> dict:
        return {
            k: (v.get_secret_value() if isinstance(v, _SecretStr) else v)
            for k, v in params.items()
        }

    safe_params = _unwrap_secrets(body.params)

    # Dry-run: validate + preview without touching target
    if getattr(body, "dry_run", False):
        return engine.dry_run_module(module_id, safe_params)

    result = await engine.run_module(
        module_id, c_obj, safe_params, actor_role=actor.role
    )
    await db.audit(
        actor.username, "module_run", f"module={module_id}", body.campaign_id, module_id
    )

    # Keep the operational telemetry panel in sync with API-triggered executions.
    try:
        from ares.telemetry.collector import get_collector

        status = str(getattr(result, "status", "")).lower()
        success = status in {"modulestatus.done", "done", "success", "partial"}
        get_collector().record_execution(
            module_id,
            float(getattr(result, "duration_ms", 0.0) or 0.0),
            success=success,
            campaign_id=body.campaign_id,
        )
        if result.findings:
            get_collector().record_finding(len(result.findings))
    except Exception as exc:
        logger.debug("telemetry_record_failed", module_id=module_id, error=str(exc))

    # Enrich findings with CVSS scores and trace ID before persisting
    from ares.core.cvss import enrich_finding_with_cvss
    from ares.core.tracing import get_current_trace_id

    _trace_id = get_current_trace_id() or ""
    for finding in result.findings:
        enrich_finding_with_cvss(finding)
        if _trace_id:
            finding.trace_id = _trace_id

    # Persist findings to DB
    for finding in result.findings:
        await db.save_finding(body.campaign_id, finding, module_id)

    # Broadcast to WebSocket subscribers
    await _broadcast_event(
        body.campaign_id,
        {
            "type": "module_complete",
            "module_id": module_id,
            "findings": len(result.findings),
            "status": result.status,
        },
    )

    return result.model_dump()


# ── WebSocket ─────────────────────────────────────────────────────────────────


# ── Bypass Outcome Report ─────────────────────────────────────────────────────


class BypassOutcomeReport(BaseModel):
    """Request body for reporting EDR bypass technique outcome."""

    technique_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Bypass technique ID (e.g. amsi-patch-reflection)",
    )
    edr_vendor: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="EDR vendor (crowdstrike, sentinelone, etc)",
    )
    edr_version: str = Field(default="", max_length=128)
    success: bool
    campaign_id: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=500)


@app.post("/edr/bypass/report", tags=["edr"], status_code=200)
async def report_bypass_outcome(
    body: BypassOutcomeReport,
    actor: AuthenticatedUser = Depends(require_operator()),
) -> dict:
    """
    Report whether an EDR bypass technique succeeded or was blocked.
    Updates cross-session knowledge base for all future engagements.
    """
    if _db:
        await _db.save_bypass_outcome(
            technique_id=body.technique_id,
            edr_vendor=body.edr_vendor,
            edr_version=body.edr_version,
            success=body.success,
            campaign_id=body.campaign_id,
            notes=body.notes,
        )
        rate = await _db.get_bypass_success_rate(body.technique_id, body.edr_vendor)
        warning = None
        if rate is not None and rate < 0.25:
            warning = (
                f"Technique '{body.technique_id}' success rate is only {rate:.0%} "
                f"against {body.edr_vendor} — likely patched or detected."
            )
        return {"saved": True, "historical_rate": rate, "warning": warning}
    return {"saved": False, "error": "Database not available"}


@app.get("/edr/bypass/stats", tags=["edr"])
async def get_bypass_stats(
    technique_id: str | None = None,
    edr_vendor: str | None = None,
    actor: AuthenticatedUser = Depends(require_operator()),
) -> dict:
    """
    Get historical bypass technique success rates.
    Filter by technique_id or edr_vendor, or get all stats.
    """
    if not _db:
        return {"stats": [], "error": "Database not available"}
    rate = None
    if technique_id and edr_vendor:
        rate = await _db.get_bypass_success_rate(technique_id, edr_vendor)
    return {
        "technique_id": technique_id,
        "edr_vendor": edr_vendor,
        "success_rate": rate,
        "message": (
            f"Historical rate for {technique_id} vs {edr_vendor}: {rate:.0%}"
            if rate is not None
            else "Not enough data (min 3 samples)"
        ),
    }


# ── Autonomous Engagement (StrategyEngine) ─────────────────────────────────


class AutonomousEngagementRequest(BaseModel):
    """Request body to start an autonomous multi-round red team engagement."""

    campaign_id: str = Field(..., min_length=1, max_length=64)
    goal: str = Field(
        default="domain_admin",
        pattern=r"^(domain_admin|enterprise_admin|cloud_admin|data_exfil|persistence|full_compromise)$",
    )
    max_rounds: int = Field(default=5, ge=1, le=20)
    max_detection_probability: float = Field(default=0.60, ge=0.1, le=0.95)
    confidence_threshold: float = Field(default=0.50, ge=0.1, le=0.95)
    llm_backend: str = Field(default="claude", pattern=r"^(claude|openai|local)$")
    secondary_backend: str = Field(default="", pattern=r"^(claude|openai|local|)$")
    adversarial_sim: bool = Field(default=False)
    authorizations: list[str] = Field(
        default_factory=list,
        description="Modules needing explicit auth (e.g. ad.dcsync)",
    )
    forbidden_modules: list[str] = Field(default_factory=list)
    allow_persistence: bool = Field(default=False)


def _strategy_llm_configuration_error(backend: str) -> str:
    if backend == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        return (
            "Strategy with llm_backend=claude requires ANTHROPIC_API_KEY in the "
            "ARES server environment. Set it before starting Strategy, or choose "
            "llm_backend=openai/local."
        )
    if backend == "openai" and not os.environ.get("OPENAI_API_KEY"):
        return (
            "Strategy with llm_backend=openai requires OPENAI_API_KEY in the "
            "ARES server environment. Set it before starting Strategy, or choose "
            "llm_backend=claude/local."
        )
    return ""


@app.post("/strategy/engage", tags=["strategy"], status_code=202)
async def start_autonomous_engagement(
    body: AutonomousEngagementRequest,
    actor: AuthenticatedUser = Depends(require_operator()),
) -> dict:
    """
    Start an autonomous multi-round red team engagement via StrategyEngine.
    Uses AI planning + EDR bypass + coverage prediction in a continuous loop.
    Returns immediately — monitor via WebSocket /ws/campaigns/{id}/events.
    ConstitutionEnforcer enforces authorizations list server-side.
    """
    if not _db or not _engine:
        raise HTTPException(status_code=503, detail="Engine or database not available")

    # FIX 3: ALWAYS_REQUIRE_AUTH modules need team_lead role
    from ares.strategy.enforcer import ALWAYS_REQUIRE_AUTH

    restricted = [m for m in body.authorizations if m in ALWAYS_REQUIRE_AUTH]
    if restricted and actor.role != "team_lead":
        raise HTTPException(
            status_code=403,
            detail=(
                f"Authorizing {restricted} requires team_lead role. "
                f"Current role: {actor.role!r}. "
                "Contact your team lead to run this engagement."
            ),
        )

    for backend in (body.llm_backend, body.secondary_backend):
        if backend:
            config_error = _strategy_llm_configuration_error(backend)
            if config_error:
                raise HTTPException(status_code=422, detail=config_error)

    # FIX 2: Concurrent engagement limit — atomic via asyncio.Lock (Issue 14)
    _max = int(os.environ.get("ARES_MAX_ENGAGEMENTS", _MAX_CONCURRENT_ENGAGEMENTS))
    _lock = await _get_engagement_lock()
    async with _lock:
        active_for_campaign = sum(
            1 for cid in _active_engagements.values() if cid == body.campaign_id
        )
        # Per-campaign limit: one active engagement at a time per campaign
        if active_for_campaign >= 1:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Campaign {body.campaign_id!r} already has an active engagement. "
                    "Wait for it to complete before starting a new one."
                ),
            )
        # Global limit
        if len(_active_engagements) >= _max:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Maximum concurrent engagements ({_max}) reached. "
                    "Wait for an active engagement to complete or increase "
                    "ARES_MAX_ENGAGEMENTS env var."
                ),
            )
        # Register inside lock — atomically with checks above
        import time as _time_reg

        engagement_id = f"engage_{body.campaign_id[:8]}_{int(_time_reg.time())}"
        _active_engagements[engagement_id] = body.campaign_id

    campaign_data = await _db.get_campaign(body.campaign_id)
    if not campaign_data:
        raise HTTPException(
            status_code=404, detail=f"Campaign {body.campaign_id!r} not found"
        )
    # Enforce campaign ownership — same as all other campaign endpoints
    await _require_campaign_access(campaign_data, actor)
    campaign = (
        _campaign_from_db_row(campaign_data)
        if isinstance(campaign_data, dict)
        else campaign_data
    )

    async def _run() -> None:
        from ares.strategy import OperatorNotifier, StrategyEngine

        async def _notify(msg: dict) -> None:
            for ws in list(_ws_connections.get(body.campaign_id, [])):
                try:
                    await ws.send_json({"type": "strategy_event", "data": msg})
                except Exception as exc:
                    logger.debug("strategy_event_ws_send_failed", error=str(exc))

        notifier = OperatorNotifier(notify_fn=_notify)
        se = StrategyEngine(
            ares_engine=_engine, settings=get_settings(), notifier=notifier
        )
        try:
            result = await se.run_autonomous_engagement(
                campaign=campaign,
                goal=body.goal,
                max_rounds=body.max_rounds,
                max_detection_probability=body.max_detection_probability,
                confidence_threshold=body.confidence_threshold,
                llm_backend=body.llm_backend,
                secondary_backend=body.secondary_backend,
                adversarial_sim=body.adversarial_sim,
                actor_role=actor.role,
                authorizations=body.authorizations,
                forbidden_modules=set(body.forbidden_modules),
                allow_persistence=body.allow_persistence,
            )
            await _notify(
                {
                    "event": "engagement_complete",
                    "engagement_id": engagement_id,
                    "final_status": result.final_status,
                    "rounds": result.total_rounds,
                    "detection_score": result.final_detection_score,
                    "succeeded": result.modules_succeeded,
                }
            )
        except Exception as exc:
            logger.error(
                "autonomous_engagement_error", id=engagement_id, error=str(exc)[:200]
            )
            await _notify(
                {
                    "event": "engagement_error",
                    "engagement_id": engagement_id,
                    "error": str(exc)[:200],
                }
            )
        finally:
            _active_engagements.pop(engagement_id, None)  # deregister on completion

    import asyncio as _aio

    _aio.ensure_future(_run())
    return {
        "engagement_id": engagement_id,
        "status": "started",
        "campaign_id": body.campaign_id,
        "goal": body.goal,
        "max_rounds": body.max_rounds,
        "authorizations": body.authorizations,
        "note": (
            "Running in background. Monitor via WebSocket "
            "/ws/campaigns/{campaign_id}/events for strategy_event updates."
        ),
    }


@app.get("/strategy/active", tags=["strategy"])
async def list_active_engagements(
    actor: AuthenticatedUser = Depends(require_operator()),
) -> dict:
    """List currently running autonomous engagements and slot availability."""
    _max = int(
        __import__("os").environ.get(
            "ARES_MAX_ENGAGEMENTS", _MAX_CONCURRENT_ENGAGEMENTS
        )
    )
    return {
        "active_engagements": dict(_active_engagements),
        "count": len(_active_engagements),
        "max_allowed": _max,
        "slots_available": max(0, _max - len(_active_engagements)),
    }


@app.websocket("/ws/campaigns/{campaign_id}/events")
async def campaign_events(
    websocket: WebSocket,
    campaign_id: str,
    token: str | None = Query(None),
    api_key: str | None = Query(None),
) -> None:
    """
    Real-time campaign events stream.
    Auth: ?token=<access_token> or ?api_key=<key>
    Events: module_start, module_complete, finding_discovered, campaign_status_change

    Security note: WebSocket protocol does not support Authorization headers,
    so tokens are passed as query params — a known limitation. The token will
    appear in nginx access logs. Mitigations applied:
      1. nginx log_format redacts ?token= and ?api_key= values (see nginx.conf)
      2. Token is short-lived (ARES_JWT_EXPIRE_MINUTES, default 60 min)
      3. nginx access logs should be stored with restricted permissions
    """
    # Auth check before accepting — extract actor identity for ownership check
    actor: AuthenticatedUser | None = None
    if token:
        try:
            settings = get_settings()
            from ares.core.security import decode_access_token

            payload = decode_access_token(
                token, settings.secret_key_value, settings.ares_jwt_algorithm
            )
            if payload:
                # Check token revocation — same logic as HTTP get_current_user
                jti = payload.get("jti")
                if jti and _db and await _db.is_access_token_revoked(jti):
                    await websocket.close(code=4001, reason="Token revoked")
                    return
                actor = AuthenticatedUser(
                    username=payload.get("sub", ""),
                    role=payload.get("role", "operator"),
                )
        except Exception as exc:
            logger.debug("ws_token_auth_failed", error=str(exc))
    if not actor and api_key and _db:
        user = await _db.verify_api_key(api_key)
        if user:
            actor = AuthenticatedUser(username=user["username"], role=user["role"])

    if not actor:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    # Campaign ownership check — same semantics as HTTP endpoints (404 to avoid enumeration)
    if _db:
        campaign = await _db.get_campaign(campaign_id)
        if not campaign:
            await websocket.close(code=4004, reason="Campaign not found")
            return
        if actor.role != "team_lead" and campaign.get("operator") != actor.username:
            await websocket.close(code=4004, reason="Campaign not found")
            return

    await websocket.accept()
    if campaign_id not in _ws_connections:
        _ws_connections[campaign_id] = set()
    _ws_connections[campaign_id].add(websocket)
    logger.info("ws_connected", campaign_id=campaign_id)

    try:
        await websocket.send_json({"type": "connected", "campaign_id": campaign_id})
        while True:
            # Keep alive — wait for disconnect or ping
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "keepalive"})
                except (RuntimeError, ConnectionError):
                    break  # connection gone — exit loop cleanly
    except WebSocketDisconnect:
        logger.info("ws_disconnected", campaign_id=campaign_id)
    finally:
        _ws_connections.get(campaign_id, set()).discard(websocket)


async def _broadcast_event(campaign_id: str, event: dict[str, Any]) -> None:
    """Broadcast event to all WebSocket subscribers of a campaign."""
    dead: set[WebSocket] = set()
    # Iterate over a snapshot — prevents RuntimeError if set is modified during await
    for ws in set(_ws_connections.get(campaign_id, set())):
        try:
            await ws.send_json(event)
        except (RuntimeError, ConnectionError):
            dead.add(ws)
    for ws in dead:
        _ws_connections.get(campaign_id, set()).discard(ws)


# ── CVSS summary endpoint ────────────────────────────────────────────────────


@app.get("/campaigns/{campaign_id}/cvss", tags=["campaigns"])
async def get_cvss_summary(
    campaign_id: str,
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """CVSS v3.1 score summary for a campaign — for compliance reports (PCI-DSS, ISO 27001)."""
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    rows, _ = await db.list_findings(campaign_id, page=1, per_page=1000)
    # Build lightweight finding-like objects from DB rows
    from dataclasses import make_dataclass as _mdc

    from ares.core.cvss import CVSSSummary, get_cvss_for_finding

    _F = _mdc("_F", ["cvss_score", "cvss_vector"])
    findings_objs = []
    for r in rows:
        _cs = r.get("cvss_score", 0.0) or 0.0
        _cv = r.get("cvss_vector", "")
        f = _F(cvss_score=_cs, cvss_vector=_cv)
        if not f.cvss_score:
            # Auto-compute from technique + severity if not stored
            score, vec = get_cvss_for_finding(
                r.get("mitre_technique"), r.get("severity", "info")
            )
            f.cvss_score, f.cvss_vector = score, vec
        findings_objs.append(f)
    summary = CVSSSummary.from_findings(findings_objs)
    return {
        "campaign_id": campaign_id,
        "cvss_summary": summary.to_dict(),
        "findings_with_scores": [
            {
                "id": r["id"],
                "title": r["title"],
                "cvss_score": r.get("cvss_score", 0.0) or 0.0,
                "cvss_vector": r.get("cvss_vector", ""),
                "severity": r.get("severity", "info"),
                "mitre": r.get("mitre_technique"),
            }
            for r in rows[:100]  # Cap at 100 for response size
        ],
    }


# ── Reports ───────────────────────────────────────────────────────────────────

_REPORT_EXTENSIONS = {"html", "pdf", "markdown", "json", "md"}
_REPORT_BULK_DELETE_EXTENSIONS = {"html", "pdf", "json", "md"}


def _report_slug(name: str) -> str:
    import re as _re

    return _re.sub(r"[^\w\-]", "_", name)[:64].strip("_") or "campaign"


def _report_prefixes(campaign_id: str, campaign: dict[str, Any]) -> set[str]:
    import re as _re

    safe_campaign_id = _re.sub(r"[^\w\-]", "_", campaign_id)[:64].strip("_")
    return {
        f"{safe_campaign_id}_",
        f"{_report_slug(str(campaign.get('name') or 'campaign'))}_",
    }


def _report_root() -> Path:
    from ares.modules.reporting.report_gen import ReportGenerator

    return ReportGenerator().output_dir.resolve()


def _ensure_report_filename_belongs(
    filename: str,
    *,
    campaign_id: str,
    campaign: dict[str, Any],
) -> str:
    decoded = unquote(filename)
    if (
        not decoded
        or decoded in {".", ".."}
        or "\x00" in decoded
        or "/" in decoded
        or "\\" in decoded
        or decoded != Path(decoded).name
        or Path(decoded).is_absolute()
    ):
        raise HTTPException(400, "Invalid report filename")
    if not any(
        decoded.startswith(prefix) for prefix in _report_prefixes(campaign_id, campaign)
    ):
        raise HTTPException(404, "Report not found")
    suffix = Path(decoded).suffix.lstrip(".").lower()
    if suffix not in _REPORT_EXTENSIONS:
        raise HTTPException(404, "Report not found")
    return decoded


def _safe_report_file_path(
    filename: str,
    *,
    campaign_id: str,
    campaign: dict[str, Any],
) -> Path:
    safe_filename = _ensure_report_filename_belongs(
        filename,
        campaign_id=campaign_id,
        campaign=campaign,
    )
    root = _report_root().resolve()
    candidate = (root / safe_filename).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise HTTPException(400, "Invalid report path") from None
    if not candidate.is_file():
        raise HTTPException(404, "Report not found")
    return candidate


def _iter_report_files_for_campaign(
    *,
    campaign_id: str,
    campaign: dict[str, Any],
    extensions: set[str] | None = None,
) -> list[Path]:
    root = _report_root().resolve()
    if not root.exists():
        return []
    prefixes = _report_prefixes(campaign_id, campaign)
    allowed_extensions = extensions or _REPORT_EXTENSIONS
    files: list[Path] = []
    for path in sorted(root.glob("*")):
        if not path.is_file():
            continue
        if path.suffix.lstrip(".").lower() not in allowed_extensions:
            continue
        if not any(path.name.startswith(prefix) for prefix in prefixes):
            continue
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        files.append(resolved)
    return files


def _delete_report_artifacts_for_campaign(campaign_id: str) -> int:
    root = _report_root().resolve()
    if not root.exists():
        return 0
    prefix = f"{_report_slug(campaign_id)}_"
    deleted = 0
    for path in root.iterdir():
        if not path.is_file():
            continue
        if not path.name.startswith(prefix):
            continue
        if path.suffix.lstrip(".").lower() not in _REPORT_EXTENSIONS:
            continue
        try:
            path.unlink()
        except OSError as exc:
            logger.warning(
                "report_artifact_delete_failed", path=str(path), error=str(exc)
            )
            continue
        deleted += 1
    return deleted


@app.post("/reports/{campaign_id}", tags=["reports"])
async def generate_report(
    campaign_id: str,
    fmt: str = Query("html", pattern="^(html|pdf|markdown|json)$"),
    include_sensitive_evidence: bool = Query(False),
    actor: AuthenticatedUser = _api_key_write_dep,
    _rate: None = Depends(rate_limit("report")),
    db: AresDatabase = Depends(get_db),
) -> dict[str, str]:
    from ares.modules.reporting.report_gen import ReportDependencyError, ReportGenerator

    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    if include_sensitive_evidence and actor.role != "team_lead":
        raise HTTPException(
            status_code=403,
            detail="Including sensitive report evidence requires team_lead role.",
        )
    c_obj = await _campaign_for_report(db, campaign)
    gen = ReportGenerator(include_sensitive_evidence=include_sensitive_evidence)
    valid_fmts = {"html", "pdf", "markdown", "json"}
    if fmt not in valid_fmts:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown format '{fmt}'. Choose: {sorted(valid_fmts)}",
        )
    try:
        path = gen.generate(c_obj, fmt=fmt)
    except ReportDependencyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    await db.audit(actor.username, "report_generated", f"format={fmt}", campaign_id)
    # Issue 19: return filename only, not full server filesystem path
    return {
        "filename": (
            str(path.name) if hasattr(path, "name") else str(path).split("/")[-1]
        ),
        "format": fmt,
    }


@app.get("/reports/{campaign_id}", tags=["reports"])
async def list_reports(
    campaign_id: str,
    actor: AuthenticatedUser = _current_user_or_apikey_dep,
    db: AresDatabase = _db_dep,
) -> dict[str, Any]:
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    reports: list[dict[str, Any]] = []
    for resolved in _iter_report_files_for_campaign(
        campaign_id=campaign_id,
        campaign=campaign,
    ):
        stat = resolved.stat()
        reports.append(
            {
                "filename": resolved.name,
                "format": resolved.suffix.lstrip(".").lower(),
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
            }
        )
    return {"campaign_id": campaign_id, "reports": reports}


@app.delete("/reports/{campaign_id}", tags=["reports"])
async def delete_reports(
    campaign_id: str,
    actor: AuthenticatedUser = _api_key_write_dep,
    db: AresDatabase = _db_dep,
) -> dict[str, Any]:
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    deleted = 0
    for path in _iter_report_files_for_campaign(
        campaign_id=campaign_id,
        campaign=campaign,
        extensions=_REPORT_BULK_DELETE_EXTENSIONS,
    ):
        try:
            path.unlink()
        except OSError as exc:
            logger.warning(
                "report_artifact_delete_failed", path=str(path), error=str(exc)
            )
            continue
        deleted += 1
    await db.audit(
        actor.username,
        "reports_deleted",
        f"count={deleted}",
        campaign_id,
    )
    return {"status": "deleted", "campaign_id": campaign_id, "deleted": deleted}


@app.get("/reports/{campaign_id}/files/{filename}", tags=["reports"])
async def download_report(
    campaign_id: str,
    filename: str,
    actor: AuthenticatedUser = _current_user_or_apikey_dep,
    db: AresDatabase = _db_dep,
) -> FileResponse:
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    path = _safe_report_file_path(filename, campaign_id=campaign_id, campaign=campaign)
    return FileResponse(path, filename=path.name)


@app.delete("/reports/{campaign_id}/files/{filename}", tags=["reports"])
async def delete_report(
    campaign_id: str,
    filename: str,
    actor: AuthenticatedUser = _api_key_write_dep,
    db: AresDatabase = _db_dep,
) -> dict[str, str]:
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    path = _safe_report_file_path(filename, campaign_id=campaign_id, campaign=campaign)
    try:
        path.unlink()
    except FileNotFoundError:
        raise HTTPException(404, "Report not found") from None
    except OSError as exc:
        logger.warning("report_artifact_delete_failed", path=str(path), error=str(exc))
        raise HTTPException(500, "Report could not be deleted") from exc
    await db.audit(
        actor.username,
        "report_deleted",
        f"filename={path.name}",
        campaign_id,
    )
    return {"status": "deleted", "campaign_id": campaign_id, "filename": path.name}


# ── Telemetry ─────────────────────────────────────────────────────────────────


@app.get("/stats/monthly", tags=["telemetry"])
async def get_monthly_stats(
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """Return confirmed findings grouped by day in the current calendar month."""
    return await db.get_monthly_confirmed_finding_stats()


@app.get("/telemetry", tags=["telemetry"])
async def get_telemetry(
    actor: AuthenticatedUser = _api_key_read_dep,
) -> dict[str, Any]:
    from ares.telemetry.collector import get_collector

    return get_collector().snapshot().to_dict()


@app.get("/telemetry/prometheus", tags=["telemetry"])
async def get_prometheus(
    actor: AuthenticatedUser = _api_key_read_dep,
) -> Any:
    from fastapi.responses import PlainTextResponse

    from ares.telemetry.collector import get_collector

    return PlainTextResponse(
        content=get_collector().snapshot().to_prometheus(),
        media_type="text/plain; version=0.0.4",
    )


# ── Campaign graph ────────────────────────────────────────────────────────────


@app.get("/graph/{campaign_id}", tags=["visualization"])
async def campaign_graph(
    campaign_id: str,
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    from ares.api.graph import build_campaign_graph

    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    from ares.core.campaign import Campaign as CM

    c_obj = CM(**{k: v for k, v in campaign.items() if k in CM.model_fields})
    return build_campaign_graph(c_obj)


@app.get("/graph/{campaign_id}/attack-paths", tags=["visualization"])
async def campaign_attack_paths(
    campaign_id: str,
    top_n: int = 5,
    source: str | None = None,
    target: str | None = None,
    actor: AuthenticatedUser = _api_key_read_dep,
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Compute attack paths from the campaign's artifact graph.

    - Without source/target: returns top-N easiest paths to high-value nodes.
    - With source + target: returns shortest path between those two labels.

    Response includes per-step attack modules, edge labels, and difficulty scores.
    """
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)

    try:
        from ares.graph.attack_graph import AttackGraph
        from ares.normalize.artifacts import ArtifactStore
    except ImportError as e:
        logger.warning(
            "attack_graph_unavailable", error=str(e), hint="pip install networkx"
        )
        raise HTTPException(
            503,
            "Attack graph temporarily unavailable. "
            "Ensure networkx is installed: pip install ares-redteam",
        )

    # Build graph from campaign findings stored in DB
    rows, _ = await db.list_findings(campaign_id, page=1, per_page=10000)
    hosts = await db.get_hosts(campaign_id)

    store = ArtifactStore()
    from ares.normalize.artifacts import HostArtifact

    for h in hosts:
        store.add(
            HostArtifact(
                ip_address=h.get("ip_address", ""),
                hostname=h.get("hostname", ""),
                is_dc=h.get("is_dc", False),
                os=h.get("os", ""),
            )
        )

    graph = AttackGraph()
    graph.build_from_store(store)

    if not graph.stats()["nodes"]:
        return {
            "campaign_id": campaign_id,
            "message": "No artifact data yet — run recon modules first",
            "paths": [],
            "stats": graph.stats(),
        }

    # Specific path query
    if source and target:
        path = graph.find_path(source, target)
        if not path:
            return {
                "campaign_id": campaign_id,
                "source": source,
                "target": target,
                "path": None,
                "message": f"No path found from '{source}' to '{target}'",
            }
        return {
            "campaign_id": campaign_id,
            "source": source,
            "target": target,
            "path": graph.path_to_report(path),
        }

    # Top-N paths to high-value nodes
    top = graph.top_paths(n=top_n)
    return {
        "campaign_id": campaign_id,
        "top_n": top_n,
        "paths_found": len(top),
        "paths": top,
        "stats": graph.stats(),
    }


# ── Security audit ────────────────────────────────────────────────────────────


@app.get("/security/audit", tags=["security"])
async def dependency_audit(
    actor: AuthenticatedUser = Depends(require_team_lead()),
) -> dict[str, Any]:
    from ares.security.audit import run_dependency_audit

    return await run_dependency_audit()


@app.get("/security/users", tags=["security"])
async def list_users(
    actor: AuthenticatedUser = Depends(require_team_lead()),
    db: AresDatabase = Depends(get_db),
) -> list[dict]:
    return await db.list_users()


# ── Campaign plan run + dry-run ──────────────────────────────────────────────


@app.post("/campaigns/{campaign_id}/run", tags=["campaigns"])
async def run_campaign_plan(
    campaign_id: str,
    body: PlanRunRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(require_operator()),
    _rate: None = Depends(rate_limit("module_run")),
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Execute (or dry-run) a full ExecutionPlan against a campaign.

    Dry-run returns execution preview + param errors + dependency warnings without
    touching any target system.

    POST /campaigns/{id}/run
    {"plan": {...}, "global_params": {...}, "dry_run": true}
    """
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)

    from ares.core.engine import ExecutionPlan

    try:
        plan = ExecutionPlan.from_dict(body.plan)
    except Exception as exc:
        raise HTTPException(422, f"Invalid plan: {exc}")

    if body.dry_run:
        return engine.dry_run_plan(plan, body.global_params)

    c_obj = _campaign_from_db_row(campaign)
    results = await engine.run_plan(plan, c_obj, body.global_params, actor_role=actor.role)
    return {
        "campaign_id": campaign_id,
        "modules_run": len(results),
        "results": {
            mid: {
                "status": (
                    r.status.value if hasattr(r.status, "value") else str(r.status)
                ),
                "findings_count": len(r.findings),
                "error": r.error,
                "duration_ms": r.duration_ms,
            }
            for mid, r in results.items()
        },
    }


# ── Campaign diff ─────────────────────────────────────────────────────────────


@app.get("/campaigns/{campaign_id}/diff/{other_id}", tags=["campaigns"])
async def campaign_diff(
    campaign_id: str,
    other_id: str,
    actor: AuthenticatedUser = Depends(require_any_auth()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Delta report comparing two campaigns.

    Returns:
        new_findings    — in campaign_id but not other_id (new issues)
        fixed_findings  — in other_id but not campaign_id (remediated)
        severity_changed — same finding, CVSS score changed ≥ 1.0
        summary         — risk_improved bool, delta counts per severity

    Findings matched by normalized title (case-insensitive).
    Useful for: "what changed since last month's engagement?"
    """
    c1_row = await db.get_campaign(campaign_id)
    c2_row = await db.get_campaign(other_id)
    if not c1_row:
        raise HTTPException(404, f"Campaign {campaign_id!r} not found")
    if not c2_row:
        raise HTTPException(404, f"Campaign {other_id!r} not found")
    await _require_campaign_access(c1_row, actor)
    await _require_campaign_access(c2_row, actor)

    # Load confirmed findings for each campaign
    c1_findings, _ = await db.list_findings(campaign_id, page=1, per_page=10000)
    c2_findings, _ = await db.list_findings(other_id, page=1, per_page=10000)

    return _diff_findings(campaign_id, other_id, c1_findings, c2_findings)


def _diff_findings(
    curr_id: str,
    base_id: str,
    curr_rows: list[dict[str, Any]],
    base_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute finding diff between two finding row-sets from DB."""

    def key(row: dict) -> str:
        return (row.get("title") or "").strip().lower()

    def summary(row: dict) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "title": row.get("title"),
            "severity": row.get("severity"),
            "cvss_score": row.get("cvss_score") or 0.0,
            "cvss_vector": row.get("cvss_vector", ""),
            "mitre": row.get("mitre_technique"),
            "module_id": row.get("module_id", ""),
            "host": row.get("host"),
        }

    curr_map = {key(r): r for r in curr_rows}
    base_map = {key(r): r for r in base_rows}
    curr_keys = set(curr_map)
    base_keys = set(base_map)

    new_findings = [summary(curr_map[k]) for k in curr_keys - base_keys]
    fixed_findings = [summary(base_map[k]) for k in base_keys - curr_keys]

    severity_changed = []
    for k in curr_keys & base_keys:
        cr, br = curr_map[k], base_map[k]
        c_score = cr.get("cvss_score") or 0.0
        b_score = br.get("cvss_score") or 0.0
        c_sev = cr.get("severity", "")
        b_sev = br.get("severity", "")
        if c_sev != b_sev or abs(c_score - b_score) >= 1.0:
            severity_changed.append(
                {
                    "title": cr.get("title"),
                    "was": {"severity": b_sev, "cvss_score": b_score},
                    "now": {"severity": c_sev, "cvss_score": c_score},
                    "direction": "worse" if c_score > b_score else "better",
                }
            )

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity_changed.sort(key=lambda x: -sev_order.get(x["now"]["severity"], 0))

    def sev_counts(rows: list) -> dict[str, int]:
        c: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            c[r.get("severity", "info")] = c.get(r.get("severity", "info"), 0) + 1
        return c

    cc = sev_counts(curr_rows)
    bc = sev_counts(base_rows)
    delta = {
        k: cc.get(k, 0) - bc.get(k, 0)
        for k in ("critical", "high", "medium", "low", "info")
    }

    risk_improved = (
        delta["critical"] <= 0
        and delta["high"] <= 0
        and len(fixed_findings) > len(new_findings)
    )

    return {
        "campaign_id": curr_id,
        "baseline_id": base_id,
        "new_findings": sorted(new_findings, key=lambda f: -(f["cvss_score"] or 0)),
        "fixed_findings": sorted(fixed_findings, key=lambda f: -(f["cvss_score"] or 0)),
        "severity_changed": severity_changed,
        "summary": {
            "risk_improved": risk_improved,
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "changed_count": len(severity_changed),
            "delta_critical": delta["critical"],
            "delta_high": delta["high"],
            "delta_medium": delta["medium"],
            "delta_low": delta["low"],
            "current_total": len(curr_rows),
            "baseline_total": len(base_rows),
        },
    }


# ── Health ────────────────────────────────────────────────────────────────────

# ── Campaign Templates ────────────────────────────────────────────────────────


@app.get("/templates", tags=["campaigns"])
async def list_templates(
    actor: AuthenticatedUser = _api_key_read_dep,
) -> list[dict]:
    """List available campaign templates."""
    from ares.core.engine import list_campaign_templates

    return list_campaign_templates()


@app.post("/templates/{template_name}/plan", tags=["campaigns"])
async def plan_from_template_endpoint(
    template_name: str,
    body: dict[str, Any] = {},
    actor: AuthenticatedUser = Depends(require_operator()),
) -> dict[str, Any]:
    """
    Generate an ExecutionPlan from a named template.
    Optionally pass global_params in the body (dc, domain, username, password).
    Returns the plan ready for POST /campaigns/{id}/run.
    """
    from ares.core.engine import get_campaign_template, plan_from_template

    template = get_campaign_template(template_name)
    if not template:
        from ares.core.engine import CAMPAIGN_TEMPLATES

        raise HTTPException(
            404,
            f"Template '{template_name}' not found. "
            f"Available: {list(CAMPAIGN_TEMPLATES.keys())}",
        )
    plan = plan_from_template(template_name, body.get("global_params"))
    return {
        "template": template_name,
        "description": template["description"],
        "plan": {
            "stages": [
                {
                    "name": s["name"],
                    "modules": s["modules"],
                    "params": s.get("params", {}),
                }
                for s in plan.stages
            ]
        },
        "global_params": body.get("global_params", {}),
        "note": "Use this plan with POST /campaigns/{id}/run",
    }


# ── Bloodhound Ingest ────────────────────────────────────────────────────────


class BloodhoundIngestRequest(BaseModel):
    json_path: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Path to BloodHound JSON file or directory",
    )


@app.post("/graph/{campaign_id}/bloodhound", tags=["visualization"])
async def ingest_bloodhound(
    campaign_id: str,
    body: BloodhoundIngestRequest,
    actor: AuthenticatedUser = Depends(require_operator()),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Import BloodHound/SharpHound JSON into the campaign's attack graph.
    After ingest, use GET /graph/{id}/attack-paths to compute paths to DA.
    """
    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)

    from ares.core.security import sanitize_path

    try:
        safe_path = sanitize_path(body.json_path)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid path: {str(exc)[:200]}")

    try:
        from ares.graph.attack_graph import AttackGraph

        graph = AttackGraph()
        result = graph.ingest_bloodhound(safe_path)
        if result.get("error"):
            raise HTTPException(422, result["error"])

        # Compute shortest path to DA after ingest
        da_path = graph.shortest_path_to_da()

        await db.audit(
            actor.username,
            "bloodhound_ingest",
            f"nodes={result['nodes_added']} edges={result['edges_added']}",
            campaign_id,
        )
        return {
            "campaign_id": campaign_id,
            "ingest_result": result,
            "shortest_to_da": da_path,
            "graph_stats": graph.stats(),
        }
    except ImportError:
        raise HTTPException(503, "networkx required — pip install networkx")
    except Exception as exc:
        raise HTTPException(500, f"Bloodhound ingest failed: {str(exc)[:200]}")


# ── Startup ───────────────────────────────────────────────────────────────────


def start() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "ares.api.server:app",
        host=settings.ares_api_host,
        port=settings.ares_api_port,
        reload=settings.ares_debug,
        log_level=settings.ares_log_level.lower(),
    )
