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
from collections.abc import AsyncGenerator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from uuid import UUID

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
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
from ares.api.findings import redact_finding_response_rows
from ares.api.rbac import (
    RATE_LIMITS,
    AuthenticatedUser,
    PrincipalDecisionStatus,
    _limiter,
    get_current_user,
    rate_limit,
    require_any_auth,
    require_live_operator,
    require_operator,
    require_team_lead,
    resolve_execution_actor_authority_revision,
    revalidate_bearer_principal,
)
from ares.core.browser_sessions import (
    BrowserRequestContext,
    BrowserSessionBoundaryMiddleware,
    BrowserSessionPolicy,
    build_browser_session_policy,
    canonical_noncredentialed_origins,
    clear_session_cookies,
    publish_prelogin_csrf,
    publish_session_cookies,
)
from ares.core.campaign import Campaign, Finding
from ares.core.config import AresSettings, get_settings
from ares.core.engine import AresEngine
from ares.core.execution_admission import (
    DispatchDispositionV1,
    DispatchOutcomeV1,
    DispatchRequestV1,
    ExecutionAdmissionCoordinatorV1,
    RevalidatedPrincipalV1,
    canonical_intent_digest,
)
from ares.core.logger import get_logger
from ares.core.security import create_access_token
from ares.core.token_sessions import (
    RefreshRotationStatus,
    SessionIssueStatus,
    SessionRevocationStatus,
)
from ares.core.tracing import get_current_trace_id, instrument_fastapi, setup_tracing
from ares.db.database import AresDatabase
from ares.db.execution_lifecycle import FixedResult, TrustedPrincipal
from ares.db.websocket_tickets import (
    ApiKeyTicketSource,
    BearerTicketSource,
    ConsumedWebSocketTicket,
    WebSocketTicketPrincipal,
    is_canonical_websocket_ticket,
)
from ares.modules.base import normalize_module_metadata

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


_SUCCESSFUL_MODULE_OUTCOMES = {
    "modulestatus.done",
    "done",
    "success",
    "partial",
    "confirmed_findings",
    "completed_no_findings",
    "dry_run_ok",
}


def _module_outcome_value(value: Any) -> str:
    """Normalize enum/string result values for telemetry classification."""
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        value = enum_value
    return str(value or "").strip().lower()


def _is_successful_module_outcome(status: Any) -> bool:
    """Return whether a module outcome is operationally successful."""
    return _module_outcome_value(status) in _SUCCESSFUL_MODULE_OUTCOMES


def _safe_module_result_payload(result: Any) -> dict[str, Any]:
    """Redact sensitive runtime evidence before returning a module result."""
    from ares.modules.reporting.report_gen import _redact_sensitive_evidence

    payload = result.model_dump()
    safe_payload = _redact_sensitive_evidence(payload)
    return safe_payload if isinstance(safe_payload, dict) else {}


async def _record_module_run(
    db: AresDatabase,
    campaign_id: str,
    module_id: str,
    *,
    outcome: str,
    success: bool,
    duration_ms: float,
) -> None:
    """Persist only safe execution metadata; telemetry must not block the result."""
    try:
        await db.record_module_run(
            campaign_id=campaign_id,
            module_id=module_id,
            outcome=str(outcome)[:64],
            success=success,
            duration_ms=duration_ms,
        )
    except Exception as exc:
        logger.warning(
            "module_run_telemetry_persist_failed",
            module_id=module_id,
            error=str(exc)[:120],
        )


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


async def _hydrate_campaign_graph_data(
    db: AresDatabase,
    engine: AresEngine,
    row: dict[str, Any],
) -> tuple[Campaign, Any, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Rebuild the safe campaign view used by both graph endpoints."""
    campaign = _campaign_from_db_row(row)
    finding_rows, _ = await db.list_findings(
        campaign.id,
        page=1,
        per_page=10000,
        false_positive=False,
    )
    campaign.findings = [
        _finding_from_db_row(finding_row, report_confirmed=True)
        for finding_row in finding_rows
    ]
    hosts = await db.get_hosts(campaign.id)
    credentials = await db.get_credentials(campaign.id, decrypt=False)
    runtime_state = await engine.ensure_campaign_runtime(campaign, db)
    return campaign, runtime_state, finding_rows, hosts, credentials


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

# WebSocket registry: campaign_id → opaque authenticated connection contexts.
@dataclass(eq=False)
class _CampaignWebSocketConnection:
    """Opaque main-WebSocket state; ticket material must never be retained."""

    websocket: WebSocket = field(repr=False)
    campaign_id: str = field(repr=False)
    ticket_handle: ConsumedWebSocketTicket = field(repr=False)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    closed: bool = False


_ws_connections: dict[str, set[_CampaignWebSocketConnection]] = {}
_active_engagements: dict[str, str] = {}  # engagement_id → campaign_id
_engagement_tasks: dict[str, asyncio.Task[None]] = {}
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


class _CLiveRuntime:
    """One process-local store with request-scoped coordinator callbacks."""

    def __init__(self, db: Any, engine: Any) -> None:
        self.db = db
        self.engine = engine
        self.store = db.execution_lifecycle_store()

    def bind(
        self,
        actor: AuthenticatedUser,
    ) -> tuple[TrustedPrincipal, ExecutionAdmissionCoordinatorV1]:
        source = actor.websocket_ticket_source
        if type(source) is not BearerTicketSource:
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        principal = TrustedPrincipal(source.user_id, source.user_id)

        async def revalidate(
            candidate: TrustedPrincipal,
            campaign_id: str,
            module_id: str,
        ) -> RevalidatedPrincipalV1 | None:
            del campaign_id, module_id
            if candidate is not principal:
                return None
            decision = await revalidate_bearer_principal(source, db=self.db)
            if (
                decision.status is not PrincipalDecisionStatus.AUTHORIZED
                or decision.principal is None
                or decision.principal.user_id != principal.user_id
                or decision.principal.role not in {"operator", "team_lead"}
            ):
                return None
            revision = await resolve_execution_actor_authority_revision(
                self.db,
                principal.user_id,
            )
            if revision is None:
                return None
            return RevalidatedPrincipalV1(
                principal=principal,
                authority_revision=revision,
                role=decision.principal.role,
            )

        return principal, ExecutionAdmissionCoordinatorV1(
            self.store,
            self.engine,
            revalidate,
        )


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _engine, _db
    settings = get_settings()
    app.state.browser_policy = build_browser_session_policy(settings)
    canonical_noncredentialed_origins(settings.cors_origins_list)
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

    _engine = AresEngine(settings=settings, db=_db)
    _engine.load_modules()
    app.state.engine = _engine
    app.state.c_live_runtime = _CLiveRuntime(_db, _engine)

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
    app.state.c_live_runtime = None
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
    _cors_origins = canonical_noncredentialed_origins(_s.cors_origins_list)
    _trusted_hosts = _s.trusted_hosts_list
except Exception:
    _cors_origins = ["http://localhost:3000", "http://localhost:8080"]
    _trusted_hosts = ["localhost", "127.0.0.1"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "X-API-Key",
        "X-ARES-CSRF",
    ],
    expose_headers=[
        "X-ARES-Attempt-Id",
        "X-ARES-Logical-Execution-Id",
        "X-ARES-Submission-Id",
    ],
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


# Registered last so browser-auth validation and scrubbing is the first ASGI
# operation for its five routes, before body parsing, logging, or database work.
app.add_middleware(
    BrowserSessionBoundaryMiddleware,
    settings_provider=get_settings,
)


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
    if isinstance(engine, AresEngine):
        try:
            engine.bind_database(request.app.state.db)
        except RuntimeError as exc:
            logger.error("engine_database_binding_mismatch", error=str(exc))
            raise HTTPException(503, "Engine persistence is not ready") from exc
    return engine


def get_c_live_runtime(request: Request) -> Any:
    """Return the lifespan-owned store wrapper; never create one per request."""
    runtime = getattr(request.app.state, "c_live_runtime", None)
    if runtime is None or not callable(getattr(runtime, "bind", None)):
        raise HTTPException(503, "Execution admission is not ready")
    return runtime


_C_LIVE_IDEMPOTENCY_HEADER = "Idempotency-Key"
_C_LIVE_SECRET_NAMES = frozenset(
    {
        "access_key",
        "api_key",
        "credential",
        "krbtgt_hash",
        "lm_hash",
        "nt_hash",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "ssh_pass",
        "token",
    }
)


def _require_c_live_idempotency_key(request: Request) -> str:
    values = request.headers.getlist(_C_LIVE_IDEMPOTENCY_HEADER)
    if not values or (len(values) == 1 and values[0] == ""):
        raise HTTPException(status_code=422, detail="idempotency_key_required")
    if len(values) != 1:
        raise HTTPException(status_code=422, detail="idempotency_key_invalid")
    value = values[0]
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="idempotency_key_invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise HTTPException(status_code=422, detail="idempotency_key_invalid")
    return value


def _contains_c_live_raw_secret(value: Any, *, field_name: str = "") -> bool:
    from pydantic import SecretStr

    if isinstance(value, SecretStr):
        return bool(value.get_secret_value())
    normalized = field_name.strip().lower().replace("-", "_")
    if normalized in _C_LIVE_SECRET_NAMES and value not in (None, "", (), [], {}):
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_c_live_raw_secret(item, field_name=str(key))
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(
            _contains_c_live_raw_secret(item, field_name=field_name)
            for item in value
        )
    return False


def _c_live_descriptor_gate(module_id: str, role: str) -> str | None:
    """Production-only descriptor gate; tests may replace this private seam."""
    from ares.modules.descriptors import get_descriptor

    descriptor = get_descriptor(module_id)
    if descriptor is None or not descriptor.future_gateway_eligible:
        return "descriptor_unavailable"
    minimum_role = descriptor.minimum_role.value
    if minimum_role == "team_lead" and role != "team_lead":
        return "execution_not_dispatchable"
    return None


def _c_live_identity_payload(outcome: DispatchOutcomeV1) -> dict[str, str]:
    identity = outcome.identity
    if identity is None:
        return {}
    return {
        "submission_id": identity.submission_id,
        "logical_execution_id": identity.logical_execution_id,
        "attempt_id": identity.attempt_id,
    }


def _c_live_identity_headers(outcome: DispatchOutcomeV1) -> dict[str, str]:
    identity = outcome.identity
    if identity is None:
        return {}
    return {
        "X-ARES-Submission-Id": identity.submission_id,
        "X-ARES-Logical-Execution-Id": identity.logical_execution_id,
        "X-ARES-Attempt-Id": identity.attempt_id,
    }


def _c_live_fixed_result(outcome: DispatchOutcomeV1) -> FixedResult:
    value = outcome.lifecycle_result
    return value if type(value) is FixedResult else FixedResult(str(value))


def _c_live_error_response(
    outcome: DispatchOutcomeV1,
    *,
    override: str | None = None,
) -> JSONResponse:
    result = _c_live_fixed_result(outcome)
    if override == "descriptor_unavailable":
        status_code, error_type = 409, "descriptor_unavailable"
    elif override == "execution_not_dispatchable":
        status_code, error_type = 409, "execution_not_dispatchable"
    elif (
        outcome.disposition is DispatchDispositionV1.INDETERMINATE
        or (outcome.effect_started and not outcome.terminal_committed)
    ):
        status_code, error_type = 503, "execution_settlement_unconfirmed"
    elif outcome.disposition is DispatchDispositionV1.REPLAYED or result in {
        FixedResult.REPLAYED,
        FixedResult.REPLAYED_BOUND_CHILD,
        FixedResult.REPLAYED_CLOSED,
    }:
        status_code, error_type = 409, "execution_replayed_no_redispatch"
    elif result is FixedResult.CONFLICT_OPERATION:
        status_code, error_type = 409, "idempotency_conflict"
    elif result is FixedResult.INVALID_CONTRACT:
        status_code, error_type = 422, "invalid_contract"
    elif result is FixedResult.AUTHORITY_STALE:
        status_code, error_type = 409, "execution_authority_stale"
    elif result is FixedResult.CAPACITY_UNAVAILABLE:
        status_code, error_type = 429, "execution_capacity_unavailable"
    elif result is FixedResult.INCONSISTENT_BUDGET_SET:
        status_code, error_type = 503, "execution_budget_set_unavailable"
    elif result is FixedResult.NOT_FOUND_OR_PURGED:
        status_code, error_type = 410, "execution_not_found_or_purged"
    elif result is FixedResult.INVARIANT_FAILURE:
        status_code, error_type = 500, "execution_invariant_failure"
    else:
        status_code, error_type = 409, "execution_not_dispatchable"
    content: dict[str, Any] = {
        "code": status_code,
        "detail": error_type,
        "type": error_type,
        "result": result.value,
        "redispatched": False,
        "outcome": "unavailable",
    }
    identity = _c_live_identity_payload(outcome)
    if identity:
        content["execution"] = identity
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=_c_live_identity_headers(outcome),
    )


def _c_live_unavailable_response(error_type: str) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "code": 409,
            "detail": error_type,
            "type": error_type,
            "result": FixedResult.CONFLICT_STATE.value,
            "redispatched": False,
            "outcome": "unavailable",
        },
    )


def _apply_c_live_identity_headers(response: Response, outcome: DispatchOutcomeV1) -> None:
    for name, value in _c_live_identity_headers(outcome).items():
        response.headers[name] = value


async def get_current_user_or_apikey(
    request: Request,
    bearer: AuthenticatedUser | None = Depends(get_current_user),
) -> AuthenticatedUser:
    """Accept JWT bearer token OR X-API-Key header."""
    if bearer:
        return bearer
    api_key = request.headers.get("X-API-Key")
    if api_key:
        try:
            db = get_db(request)
            data = await db.verify_api_key(api_key)
        except Exception as exc:
            logger.warning(
                "auth_backend_api_key_lookup_failed",
                error_type=type(exc).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="Authentication service unavailable",
            ) from None
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
_auth_rate_dep = Depends(rate_limit("auth"))


class WebSocketTicketResponse(BaseModel):
    ticket: str
    expires_in: int


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
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int = 3600
    role: str = ""
    refresh_generation: int
    session_coordination_key: str


def _browser_context(request: Request) -> BrowserRequestContext:
    context = getattr(request.state, "browser_session", None)
    if not isinstance(context, BrowserRequestContext):
        raise HTTPException(403, "Browser request rejected")
    return context


def _browser_policy(request: Request) -> BrowserSessionPolicy:
    policy = getattr(request.state, "browser_policy", None)
    if not isinstance(policy, BrowserSessionPolicy):
        raise HTTPException(503, "Browser authentication unavailable")
    return policy


def _token_response_content(session: Any, settings: AresSettings) -> dict[str, Any]:
    return {
        "access_token": session.access_token,
        "token_type": "bearer",
        "expires_in": settings.ares_jwt_expire_minutes * 60,
        "role": session.role,
        "refresh_generation": session.refresh_generation,
        "session_coordination_key": session.coordination_key,
    }


def _auth_json_response(content: dict[str, Any], *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/auth/csrf", status_code=204, tags=["auth"])
async def bootstrap_browser_csrf(request: Request) -> Response:
    response = Response(
        status_code=204,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
    publish_prelogin_csrf(response, _browser_policy(request))
    return response


@app.post("/auth/token", tags=["auth"])
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> JSONResponse:
    """Authenticate and publish the committed refresh session as cookies."""
    _browser_context(request)
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

    def _token_factory(claims: Mapping[str, Any]) -> str:
        return create_access_token(
            data=dict(claims),
            secret_key=settings.secret_key_value,
            algorithm=settings.ares_jwt_algorithm,
            expires_minutes=settings.ares_jwt_expire_minutes,
        )

    try:
        result = await db.create_login_session(
            form.username,
            form.password,
            _token_factory,
        )
    except Exception as exc:
        logger.warning("login_transaction_failed", error_type=type(exc).__name__)
        raise HTTPException(503, "Authentication service unavailable") from None
    if result.status is not SessionIssueStatus.ISSUED or result.session is None:
        raise HTTPException(401, "Invalid credentials")
    session = result.session
    response = _auth_json_response(_token_response_content(session, settings))
    if not publish_session_cookies(
        response,
        _browser_policy(request),
        refresh_token=session.refresh_token,
        absolute_expiry=session.absolute_expires_at,
    ):
        raise HTTPException(401, "Session is not valid")
    return response


@app.post("/auth/refresh", tags=["auth"])
async def refresh_access_token(
    request: Request,
    settings: AresSettings = Depends(get_settings),
    db: AresDatabase = Depends(get_db),
) -> JSONResponse:
    """Rotate the single canonical refresh cookie."""
    context = _browser_context(request)
    policy = _browser_policy(request)
    if context.refresh_token is None:
        response = _auth_json_response(
            {"code": 401, "detail": "Session is not valid", "type": "api_error"},
            status_code=401,
        )
        clear_session_cookies(response, policy)
        return response
    ip = request.client.host if request.client else "unknown"
    allowed, _ = await _limiter.is_allowed_async(f"refresh:{ip}", RATE_LIMITS["auth"])
    if not allowed:
        raise HTTPException(
            429,
            "Too many refresh attempts. Try again in 60s.",
            headers={"Retry-After": "60"},
        )
    def _token_factory(claims: Mapping[str, Any]) -> str:
        return create_access_token(
            data=dict(claims),
            secret_key=settings.secret_key_value,
            algorithm=settings.ares_jwt_algorithm,
            expires_minutes=settings.ares_jwt_expire_minutes,
        )

    try:
        result = await db.rotate_refresh_session(context.refresh_token, _token_factory)
    except Exception as exc:
        logger.warning("refresh_transaction_failed", error_type=type(exc).__name__)
        raise HTTPException(503, "Authentication service unavailable") from None
    if result.status is not RefreshRotationStatus.ROTATED or result.session is None:
        response = _auth_json_response(
            {"code": 401, "detail": "Session is not valid", "type": "api_error"},
            status_code=401,
        )
        clear_session_cookies(response, policy)
        return response
    session = result.session
    response = _auth_json_response(_token_response_content(session, settings))
    if not publish_session_cookies(
        response,
        policy,
        refresh_token=session.refresh_token,
        absolute_expiry=session.absolute_expires_at,
    ):
        raise HTTPException(401, "Session is not valid")
    return response


@app.post("/auth/logout", tags=["auth"])
async def logout(
    request: Request,
    db: AresDatabase = Depends(get_db),
) -> Response:
    """Idempotently revoke the family named by the refresh cookie."""
    context = _browser_context(request)
    policy = _browser_policy(request)
    if context.refresh_token is not None:
        try:
            await db.revoke_refresh_cookie_session(context.refresh_token)
        except Exception as exc:
            logger.warning("logout_current_failed", error_type=type(exc).__name__)
            raise HTTPException(503, "Authentication service unavailable") from None
    response = Response(
        status_code=204,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
    clear_session_cookies(response, policy)
    return response


@app.post("/auth/logout-all", tags=["auth"])
async def logout_all(
    request: Request,
    actor: AuthenticatedUser = Depends(require_any_auth()),  # noqa: B008
    db: AresDatabase = Depends(get_db),  # noqa: B008
) -> Response:
    """Revoke every bearer family by incrementing the user's auth epoch."""
    _browser_context(request)
    policy = _browser_policy(request)
    source = actor.websocket_ticket_source
    if actor.is_api_key or source is None:
        raise HTTPException(401, "Not authenticated")
    try:
        result = await db.revoke_all_sessions(
            user_id=source.user_id,
            jti=source.jti,
            expires_at=source.expires_at,
        )
    except Exception as exc:
        logger.warning("logout_all_failed", error_type=type(exc).__name__)
        raise HTTPException(503, "Authentication service unavailable") from None
    if result.status is SessionRevocationStatus.INVALID:
        raise HTTPException(401, "Not authenticated")
    response = Response(
        status_code=204,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
    clear_session_cookies(response, policy)
    return response


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

    del request, settings
    changed = await db.apply_user_security_event(
        user_id=user["id"],
        reason="password_change",
        new_password_hash=hash_password(body.new_password),
    )
    if not changed:
        raise HTTPException(401, "Not authenticated")
    # Revoke the current access token by jti — same as logout() —
    # so the old token cannot be reused within its remaining expiry window.
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


@app.post(
    "/campaigns/{campaign_id}/websocket-ticket",
    tags=["campaigns"],
    response_model=WebSocketTicketResponse,
    status_code=201,
)
async def issue_campaign_websocket_ticket(
    campaign_id: str,
    response: Response,
    actor: AuthenticatedUser = _api_key_read_dep,
    _rate: None = _auth_rate_dep,
    db: AresDatabase = _db_dep,
) -> WebSocketTicketResponse:
    """Issue one committed, campaign-bound WebSocket handshake ticket."""
    try:
        campaign = await db.get_campaign(campaign_id)
    except Exception as exc:
        logger.warning(
            "websocket_ticket_campaign_lookup_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(503, "Authentication service unavailable") from None
    if not isinstance(campaign, Mapping):
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)

    source = actor.websocket_ticket_source
    if actor.is_api_key:
        key_id = actor.api_key_id
        if not isinstance(key_id, str) or not key_id.strip():
            raise HTTPException(401, "Not authenticated")
        try:
            owner = await db.get_user(actor.username)
        except Exception as exc:
            logger.warning(
                "websocket_ticket_owner_lookup_failed",
                error_type=type(exc).__name__,
            )
            raise HTTPException(503, "Authentication service unavailable") from None
        if not isinstance(owner, Mapping):
            raise HTTPException(401, "Not authenticated")
        owner_id = owner.get("id")
        owner_name = owner.get("username")
        owner_role = owner.get("role")
        if (
            not isinstance(owner_id, str)
            or not owner_id.strip()
            or owner_name != actor.username
            or owner_role != actor.role
        ):
            raise HTTPException(401, "Not authenticated")
        source = ApiKeyTicketSource(
            user_id=owner_id,
            api_key_id=key_id,
        )
    elif source is None:
        raise HTTPException(401, "Not authenticated")

    try:
        issued = await db.issue_websocket_ticket(campaign_id, source)
    except Exception as exc:
        logger.warning(
            "websocket_ticket_issue_failed",
            error_type=type(exc).__name__,
        )
        raise HTTPException(503, "Authentication service unavailable") from None
    if issued is None:
        raise HTTPException(401, "Not authenticated")
    raw_ticket, expires_in = issued
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return WebSocketTicketResponse(ticket=raw_ticket, expires_in=expires_in)


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
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Restore CredentialVault from DB for a campaign after restart or crash.
    Returns count of credentials re-hydrated into memory.
    The vault is attached to the running engine's campaign object.
    """
    if isinstance(engine, AresEngine):
        engine.bind_database(db)
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

    # Restore into the engine-owned per-campaign state, rather than into a
    # local vault object that disappears as soon as this request completes.
    count = await engine.restore_campaign_vault(_campaign_from_db_row(c))

    await db.audit(
        actor.username,
        "vault_restored",
        f"campaign={campaign_id} count={count}",
        campaign_id,
    )
    return {
        "restored": count,
        "campaign_id": campaign_id,
        "message": "Vault restored into the active campaign runtime state",
    }


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
        content=redact_finding_response_rows(rows),
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


_INVALID_PLAN_MODULE_IDS_DETAIL = (
    "Invalid plan: every stage must contain a modules list of non-empty "
    "string module IDs."
)


def _collect_plan_module_ids_for_authorization(
    plan_data: Mapping[str, Any],
) -> list[str]:
    """Validate raw plan module structure and return sorted unique IDs."""
    stages = plan_data.get("stages", [])
    if not isinstance(stages, list):
        raise HTTPException(
            status_code=422,
            detail=_INVALID_PLAN_MODULE_IDS_DETAIL,
        )

    module_ids: list[str] = []
    for stage in stages:
        if not isinstance(stage, Mapping) or "modules" not in stage:
            raise HTTPException(
                status_code=422,
                detail=_INVALID_PLAN_MODULE_IDS_DETAIL,
            )
        stage_module_ids = stage["modules"]
        if not isinstance(stage_module_ids, list):
            raise HTTPException(
                status_code=422,
                detail=_INVALID_PLAN_MODULE_IDS_DETAIL,
            )
        for module_id in stage_module_ids:
            if not isinstance(module_id, str) or not module_id.strip():
                raise HTTPException(
                    status_code=422,
                    detail=_INVALID_PLAN_MODULE_IDS_DETAIL,
                )
            module_ids.append(module_id)

    return sorted(set(module_ids))


def _prepare_c_live_plan_children(
    plan: Any,
    global_params: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Validate and freeze the complete ordered fan-out before any effect."""
    from pydantic import ValidationError as PydanticValidationError

    from ares.modules.params import validate_module_params

    children: list[dict[str, Any]] = []
    occurrences: dict[str, int] = {}
    absolute_ordinal = 0
    for stage_ordinal, stage in enumerate(plan.stages):
        stage_params = stage.get("params", {})
        if not isinstance(stage_params, Mapping):
            raise HTTPException(status_code=422, detail="Invalid plan: stage params must be a map")
        for module_ordinal, module_id in enumerate(stage["modules"]):
            raw_module_params = stage_params.get(module_id, {})
            if not isinstance(raw_module_params, Mapping):
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid plan params for module {module_id!r}",
                )
            raw_params = {**dict(global_params), **dict(raw_module_params)}
            if _contains_c_live_raw_secret(raw_params):
                raise HTTPException(status_code=422, detail="raw_secret_material_forbidden")
            try:
                validated_params = validate_module_params(module_id, raw_params)
            except PydanticValidationError as exc:
                errors = [
                    {"field": ".".join(str(item) for item in error["loc"]), "msg": error["msg"]}
                    for error in exc.errors()
                ]
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": f"Invalid params for module {module_id!r}",
                        "errors": errors,
                    },
                ) from None
            if _contains_c_live_raw_secret(validated_params):
                raise HTTPException(status_code=422, detail="raw_secret_material_forbidden")
            occurrence = occurrences.get(module_id, 0)
            occurrences[module_id] = occurrence + 1
            children.append(
                {
                    "module_id": module_id,
                    "raw_parameters": validated_params,
                    "occurrence": occurrence,
                    "stage_ordinal": stage_ordinal,
                    "decision_ordinal": 0,
                    "module_ordinal": module_ordinal,
                    "absolute_ordinal": absolute_ordinal,
                }
            )
            absolute_ordinal += 1
    return children


def _require_high_noise_module_access(
    module_ids: Iterable[Any],
    actor: AuthenticatedUser,
    engine: AresEngine,
) -> None:
    """Require team_lead for every registered HIGH_NOISE module."""
    from ares.modules.base import OpsecLevel

    validated_module_ids: set[str] = set()
    for module_id in module_ids:
        if not isinstance(module_id, str) or not module_id.strip():
            raise HTTPException(
                status_code=422,
                detail=_INVALID_PLAN_MODULE_IDS_DETAIL,
            )
        validated_module_ids.add(module_id)

    rejected = [
        module_id
        for module_id in sorted(validated_module_ids)
        if (
            (module_cls := engine.registry.get(module_id)) is not None
            and getattr(module_cls, "OPSEC_LEVEL", None) == OpsecLevel.HIGH_NOISE
        )
    ]
    if actor.role == "team_lead" or not rejected:
        return

    if len(rejected) == 1:
        detail = f"{rejected[0]!r} is HIGH_NOISE — team_lead only."
    else:
        detail = (
            f"{', '.join(repr(module_id) for module_id in rejected)} "
            "are HIGH_NOISE — team_lead only."
        )
    raise HTTPException(status_code=403, detail=detail)


@app.post("/modules/{module_id}/run", tags=["modules"])
async def run_module(
    module_id: str,
    body: RunRequest,
    request: Request,
    response: Response,
    actor: AuthenticatedUser = Depends(require_live_operator()),
    _rate: None = Depends(rate_limit("module_run")),
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
    c_live_runtime: Any = Depends(get_c_live_runtime),
) -> dict[str, Any]:
    """Dispatch one live module only through durable v3 admission."""
    if isinstance(engine, AresEngine):
        engine.bind_database(db)

    campaign = await db.get_campaign(body.campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    raw_params = dict(body.params)

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
        ) from None
    # Dry-run: validate + preview without touching target
    if getattr(body, "dry_run", False):
        return engine.dry_run_module(module_id, validated_params)

    idempotency_key = _require_c_live_idempotency_key(request)
    if _contains_c_live_raw_secret(raw_params) or _contains_c_live_raw_secret(
        validated_params
    ):
        raise HTTPException(status_code=422, detail="raw_secret_material_forbidden")
    descriptor_result = _c_live_descriptor_gate(module_id, actor.role)
    if descriptor_result is not None:
        return _c_live_unavailable_response(descriptor_result)

    c_obj = _campaign_from_db_row(campaign)
    principal, coordinator = c_live_runtime.bind(actor)
    outcome = await coordinator.execute_module(
        principal,
        DispatchRequestV1(
            campaign_id=body.campaign_id,
            module_id=module_id,
            ingress_code="api_module",
            idempotency_key=idempotency_key,
            raw_parameters=validated_params,
            whole_intent_digest=canonical_intent_digest(
                {
                    "campaign_id": body.campaign_id,
                    "module_id": module_id,
                    "params": raw_params,
                }
            ),
        ),
        c_obj,
    )
    if (
        outcome.disposition is not DispatchDispositionV1.TERMINAL
        or not outcome.terminal_committed
        or outcome.module_result is None
    ):
        return _c_live_error_response(outcome)

    await _broadcast_event(
        body.campaign_id,
        {
            "type": "module_complete",
            "module_id": module_id,
            "findings": len(outcome.module_result.findings),
            "status": outcome.module_result.status,
        },
    )
    _apply_c_live_identity_headers(response, outcome)
    payload = _safe_module_result_payload(outcome.module_result)
    payload["execution"] = _c_live_identity_payload(outcome)
    return payload


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


def _strategy_test_plan(body: AutonomousEngagementRequest) -> dict[str, Any] | None:
    """Private pure-plan seam. Production always returns non-dispatchable."""
    del body
    return None


@app.post("/strategy/engage", tags=["strategy"], status_code=200)
async def start_autonomous_engagement(
    body: AutonomousEngagementRequest,
    request: Request,
    response: Response,
    actor: AuthenticatedUser = Depends(require_live_operator()),
    _rate: None = Depends(rate_limit("module_run")),
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
    c_live_runtime: Any = Depends(get_c_live_runtime),
) -> dict:
    """Synchronously dispatch only a pre-supplied pure deterministic test plan."""
    campaign_data = await db.get_campaign(body.campaign_id)
    if not campaign_data:
        raise HTTPException(
            status_code=404, detail=f"Campaign {body.campaign_id!r} not found"
        )
    idempotency_key = _require_c_live_idempotency_key(request)
    plan_data = _strategy_test_plan(body)
    if plan_data is None:
        return _c_live_unavailable_response("descriptor_unavailable")
    if not isinstance(plan_data, Mapping):
        raise HTTPException(status_code=422, detail="invalid_contract")
    from ares.core.engine import ExecutionPlan

    _collect_plan_module_ids_for_authorization(plan_data)
    try:
        plan = ExecutionPlan.from_dict(dict(plan_data))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid plan: {exc}") from None
    children = _prepare_c_live_plan_children(plan, {})
    if not children:
        return _c_live_error_response(
            DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                None,
                FixedResult.INVALID_CONTRACT,
                None,
            )
        )
    for child in children:
        child["decision_ordinal"] = child["stage_ordinal"]
        descriptor_result = _c_live_descriptor_gate(child["module_id"], actor.role)
        if descriptor_result is not None:
            return _c_live_unavailable_response(descriptor_result)

    whole_intent_digest = canonical_intent_digest(
        {
            "campaign_id": body.campaign_id,
            "request": body.model_dump(mode="json"),
            "strategy_plan": plan_data,
        }
    )
    campaign = (
        _campaign_from_db_row(campaign_data)
        if isinstance(campaign_data, dict)
        else campaign_data
    )
    principal, coordinator = c_live_runtime.bind(actor)
    result_rows: list[dict[str, Any]] = []
    final_outcome: DispatchOutcomeV1 | None = None
    for child in children:
        outcome = await coordinator.execute_module(
            principal,
            DispatchRequestV1(
                campaign_id=body.campaign_id,
                module_id=child["module_id"],
                ingress_code="strategy",
                idempotency_key=idempotency_key,
                raw_parameters=child["raw_parameters"],
                whole_intent_digest=whole_intent_digest,
                occurrence=child["occurrence"],
                stage_ordinal=child["stage_ordinal"],
                decision_ordinal=child["decision_ordinal"],
                module_ordinal=child["module_ordinal"],
            ),
            campaign,
        )
        if (
            outcome.disposition is not DispatchDispositionV1.TERMINAL
            or not outcome.terminal_committed
            or outcome.module_result is None
        ):
            return _c_live_error_response(outcome)
        result_rows.append(
            {
                "module_id": child["module_id"],
                "occurrence": child["occurrence"],
                "stage_ordinal": child["stage_ordinal"],
                "decision_ordinal": child["decision_ordinal"],
                "module_ordinal": child["module_ordinal"],
                "status": (
                    outcome.module_result.status.value
                    if hasattr(outcome.module_result.status, "value")
                    else str(outcome.module_result.status)
                ),
                "findings_count": len(outcome.module_result.findings),
                "error": outcome.module_result.error,
                "duration_ms": outcome.module_result.duration_ms,
                "execution": _c_live_identity_payload(outcome),
            }
        )
        final_outcome = outcome
    await _broadcast_event(
        body.campaign_id,
        {
            "type": "strategy_complete",
            "modules_run": len(result_rows),
            "status": "completed",
        },
    )
    if final_outcome is not None:
        _apply_c_live_identity_headers(response, final_outcome)
    return {
        "status": "completed",
        "campaign_id": body.campaign_id,
        "goal": body.goal,
        "modules_run": len(result_rows),
        "children": result_rows,
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


_WS_AUTH_CLOSE_CODE = 4001
_WS_BACKEND_CLOSE_CODE = 1013
_WS_AUTH_CLOSE_REASON = "Authentication or authorization failed"
_WS_BACKEND_CLOSE_REASON = "Authentication service unavailable"


def _websocket_database(connection: _CampaignWebSocketConnection) -> Any | None:
    app_instance = connection.websocket.scope.get("app")
    state = getattr(app_instance, "state", None)
    return getattr(state, "db", None)


async def _authorize_campaign_websocket(
    connection: _CampaignWebSocketConnection,
) -> PrincipalDecisionStatus:
    """Revalidate the consumed ticket's source authority and campaign access."""
    db = _websocket_database(connection)
    if db is None:
        logger.warning("campaign_websocket_auth_backend_unavailable")
        return PrincipalDecisionStatus.BACKEND_UNAVAILABLE

    try:
        principal = await db.resolve_websocket_ticket_principal(
            connection.ticket_handle
        )
    except Exception as exc:
        logger.warning(
            "campaign_websocket_principal_lookup_failed",
            error_type=type(exc).__name__,
        )
        return PrincipalDecisionStatus.BACKEND_UNAVAILABLE
    if not isinstance(principal, WebSocketTicketPrincipal):
        return PrincipalDecisionStatus.INVALID
    if principal.user_id != connection.ticket_handle.user_id:
        return PrincipalDecisionStatus.INVALID
    return PrincipalDecisionStatus.AUTHORIZED


def _take_campaign_websocket_ticket(websocket: WebSocket) -> str | None:
    """Scrub and parse the exact ticket-only query shape without awaiting."""
    private_query = memoryview(
        websocket.scope.get("query_string", b"")
    ).tobytes()
    websocket.scope["query_string"] = b""
    raw_ticket: str | None = None
    try:
        prefix = b"ticket="
        if len(private_query) != len(prefix) + 43 or not private_query.startswith(
            prefix
        ):
            return None
        try:
            candidate = private_query[len(prefix) :].decode("ascii")
        except UnicodeDecodeError:
            return None
        if not is_canonical_websocket_ticket(candidate):
            return None
        raw_ticket = candidate
    finally:
        private_query = b""
    return raw_ticket


def _websocket_close_details(
    status: PrincipalDecisionStatus,
) -> tuple[int, str]:
    if status is PrincipalDecisionStatus.BACKEND_UNAVAILABLE:
        return _WS_BACKEND_CLOSE_CODE, _WS_BACKEND_CLOSE_REASON
    return _WS_AUTH_CLOSE_CODE, _WS_AUTH_CLOSE_REASON


def _unregister_websocket(connection: _CampaignWebSocketConnection) -> None:
    connections = _ws_connections.get(connection.campaign_id)
    if connections is None:
        return
    connections.discard(connection)
    if not connections:
        _ws_connections.pop(connection.campaign_id, None)


async def _close_websocket_handshake(
    websocket: WebSocket,
    status: PrincipalDecisionStatus,
) -> None:
    code, reason = _websocket_close_details(status)
    try:
        await websocket.close(code=code, reason=reason)
    except Exception as exc:
        logger.debug(
            "campaign_websocket_handshake_close_failed",
            error_type=type(exc).__name__,
        )


async def _close_registered_websocket_locked(
    connection: _CampaignWebSocketConnection,
    status: PrincipalDecisionStatus,
) -> None:
    if connection.closed:
        _unregister_websocket(connection)
        return
    connection.closed = True
    _unregister_websocket(connection)
    code, reason = _websocket_close_details(status)
    try:
        await connection.websocket.close(code=code, reason=reason)
    except Exception as exc:
        logger.debug(
            "campaign_websocket_close_failed",
            error_type=type(exc).__name__,
        )


async def _send_protected_websocket_event(
    connection: _CampaignWebSocketConnection,
    event: dict[str, Any],
) -> bool:
    """Atomically revalidate and either send one event or retire the connection."""
    async with connection.send_lock:
        if connection.closed:
            _unregister_websocket(connection)
            return False
        status = await _authorize_campaign_websocket(connection)
        if status is not PrincipalDecisionStatus.AUTHORIZED:
            await _close_registered_websocket_locked(connection, status)
            return False
        try:
            await connection.websocket.send_json(event)
        except Exception as exc:
            connection.closed = True
            _unregister_websocket(connection)
            logger.debug(
                "campaign_websocket_send_failed",
                error_type=type(exc).__name__,
            )
            return False
        return True


async def _disconnect_websocket(
    connection: _CampaignWebSocketConnection,
) -> None:
    async with connection.send_lock:
        connection.closed = True
        _unregister_websocket(connection)


@app.websocket("/ws/campaigns/{campaign_id}/events")
async def campaign_events(
    websocket: WebSocket,
    campaign_id: str,
) -> None:
    """Real-time campaign events authenticated by one single-use ticket."""
    raw_ticket = _take_campaign_websocket_ticket(websocket)
    if raw_ticket is None:
        await _close_websocket_handshake(
            websocket,
            PrincipalDecisionStatus.INVALID,
        )
        return

    app_instance = websocket.scope.get("app")
    state = getattr(app_instance, "state", None)
    db = getattr(state, "db", None)
    if db is None:
        await _close_websocket_handshake(
            websocket,
            PrincipalDecisionStatus.BACKEND_UNAVAILABLE,
        )
        return
    try:
        ticket_handle = await db.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
    except Exception as exc:
        logger.warning(
            "campaign_websocket_ticket_consume_failed",
            error_type=type(exc).__name__,
        )
        await _close_websocket_handshake(
            websocket,
            PrincipalDecisionStatus.BACKEND_UNAVAILABLE,
        )
        return
    finally:
        raw_ticket = ""
    if not isinstance(ticket_handle, ConsumedWebSocketTicket):
        await _close_websocket_handshake(
            websocket,
            PrincipalDecisionStatus.INVALID,
        )
        return

    connection = _CampaignWebSocketConnection(
        websocket=websocket,
        campaign_id=campaign_id,
        ticket_handle=ticket_handle,
    )
    status = await _authorize_campaign_websocket(connection)
    if status is not PrincipalDecisionStatus.AUTHORIZED:
        await _close_websocket_handshake(websocket, status)
        return

    await websocket.accept()
    _ws_connections.setdefault(campaign_id, set()).add(connection)
    logger.info("campaign_websocket_connected")

    try:
        if not await _send_protected_websocket_event(
            connection,
            {"type": "connected", "campaign_id": campaign_id},
        ):
            return
        while True:
            # Keep alive — wait for disconnect or ping
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    if not await _send_protected_websocket_event(
                        connection,
                        {"type": "pong"},
                    ):
                        break
            except asyncio.TimeoutError:
                if not await _send_protected_websocket_event(
                    connection,
                    {"type": "keepalive"},
                ):
                    break
    except (WebSocketDisconnect, RuntimeError, ConnectionError):
        logger.info("campaign_websocket_disconnected")
    finally:
        await _disconnect_websocket(connection)


async def _broadcast_event(campaign_id: str, event: dict[str, Any]) -> None:
    """Broadcast event to all WebSocket subscribers of a campaign."""
    # Snapshot before spawning because connections may unregister during awaits.
    connections = set(_ws_connections.get(campaign_id, set()))
    async with asyncio.TaskGroup() as tasks:
        for connection in connections:
            tasks.create_task(_send_protected_websocket_event(connection, event))


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
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    from ares.telemetry.collector import get_collector

    snapshot = get_collector().snapshot().to_dict()
    try:
        persisted = await db.get_telemetry_stats()
    except Exception as exc:
        logger.warning("telemetry_persisted_aggregate_failed", error=str(exc)[:120])
        return snapshot

    for key in ("modules", "latency_ms", "throughput", "hosts"):
        if isinstance(persisted.get(key), dict):
            current = snapshot.get(key)
            snapshot[key] = {
                **(current if isinstance(current, dict) else {}),
                **persisted[key],
            }
    if isinstance(persisted.get("findings"), int):
        snapshot["findings"] = persisted["findings"]
    return snapshot


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
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    from ares.api.graph import build_campaign_graph, merge_durable_attack_graph

    campaign = await db.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await _require_campaign_access(campaign, actor)
    c_obj, runtime_state, _findings, _hosts, _credentials = await _hydrate_campaign_graph_data(
        db, engine, campaign
    )
    snapshot = await db.get_campaign_graph(campaign_id)
    if snapshot is None and getattr(runtime_state, "attack_graph", None) is not None:
        snapshot = runtime_state.attack_graph.to_d3_json()
    return merge_durable_attack_graph(build_campaign_graph(c_obj), snapshot)


@app.get("/graph/{campaign_id}/attack-paths", tags=["visualization"])
async def campaign_attack_paths(
    campaign_id: str,
    top_n: int = 5,
    source: str | None = None,
    target: str | None = None,
    actor: AuthenticatedUser = _api_key_read_dep,
    engine: AresEngine = Depends(get_engine),
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
    except ImportError as e:
        logger.warning(
            "attack_graph_unavailable", error=str(e), hint="pip install networkx"
        )
        raise HTTPException(
            503,
            "Attack graph temporarily unavailable. "
            "Ensure networkx is installed: pip install ares-redteam",
        )

    _campaign, runtime_state, rows, hosts, credentials = await _hydrate_campaign_graph_data(
        db, engine, campaign
    )
    snapshot = await db.get_campaign_graph(campaign_id)
    if snapshot:
        graph = AttackGraph.from_d3_json(snapshot)
    elif getattr(runtime_state, "attack_graph", None) is not None:
        graph = runtime_state.attack_graph
    else:
        graph = AttackGraph()
        graph.build_from_store(runtime_state.artifact_store)
    # These rows are durable evidence, not merely a preflight check.  Add their
    # safe metadata so attack-path queries cannot silently ignore persisted data.
    graph.add_persisted_campaign_data(hosts, rows, credentials)
    runtime_state.attack_graph = graph

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
    response: Response,
    actor: AuthenticatedUser = Depends(require_live_operator()),
    _rate: None = Depends(rate_limit("module_run")),
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
    c_live_runtime: Any = Depends(get_c_live_runtime),
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

    from ares.core.engine import ExecutionPlan

    _collect_plan_module_ids_for_authorization(body.plan)
    try:
        plan = ExecutionPlan.from_dict(body.plan)
    except Exception as exc:
        raise HTTPException(422, f"Invalid plan: {exc}") from None

    if body.dry_run:
        return engine.dry_run_plan(plan, body.global_params)

    idempotency_key = _require_c_live_idempotency_key(request)
    children = _prepare_c_live_plan_children(plan, body.global_params)
    if not children:
        return _c_live_error_response(
            DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                None,
                FixedResult.INVALID_CONTRACT,
                None,
            )
        )
    for child in children:
        descriptor_result = _c_live_descriptor_gate(child["module_id"], actor.role)
        if descriptor_result is not None:
            return _c_live_unavailable_response(descriptor_result)

    whole_intent_digest = canonical_intent_digest(
        {
            "campaign_id": campaign_id,
            "global_params": body.global_params,
            "plan": body.plan,
        }
    )
    c_obj = _campaign_from_db_row(campaign)
    principal, coordinator = c_live_runtime.bind(actor)
    result_rows: list[dict[str, Any]] = []
    final_outcome: DispatchOutcomeV1 | None = None
    for child in children:
        outcome = await coordinator.execute_module(
            principal,
            DispatchRequestV1(
                campaign_id=campaign_id,
                module_id=child["module_id"],
                ingress_code="api_campaign_plan",
                idempotency_key=idempotency_key,
                raw_parameters=child["raw_parameters"],
                whole_intent_digest=whole_intent_digest,
                occurrence=child["occurrence"],
                stage_ordinal=child["stage_ordinal"],
                decision_ordinal=child["decision_ordinal"],
                module_ordinal=child["module_ordinal"],
            ),
            c_obj,
        )
        if (
            outcome.disposition is not DispatchDispositionV1.TERMINAL
            or not outcome.terminal_committed
            or outcome.module_result is None
        ):
            return _c_live_error_response(outcome)
        await _broadcast_event(
            campaign_id,
            {
                "type": "module_complete",
                "module_id": child["module_id"],
                "findings": len(outcome.module_result.findings),
                "status": outcome.module_result.status,
            },
        )
        result_rows.append(
            {
                "module_id": child["module_id"],
                "occurrence": child["occurrence"],
                "stage_ordinal": child["stage_ordinal"],
                "decision_ordinal": child["decision_ordinal"],
                "module_ordinal": child["module_ordinal"],
                "status": (
                    outcome.module_result.status.value
                    if hasattr(outcome.module_result.status, "value")
                    else str(outcome.module_result.status)
                ),
                "findings_count": len(outcome.module_result.findings),
                "error": outcome.module_result.error,
                "duration_ms": outcome.module_result.duration_ms,
                "execution": _c_live_identity_payload(outcome),
            }
        )
        final_outcome = outcome
    if final_outcome is not None:
        _apply_c_live_identity_headers(response, final_outcome)
    return {
        "campaign_id": campaign_id,
        "modules_run": len(result_rows),
        "children": result_rows,
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
    engine: AresEngine = Depends(get_engine),
    db: AresDatabase = Depends(get_db),
) -> dict[str, Any]:
    """
    Import BloodHound/SharpHound JSON into the campaign's attack graph.
    After ingest, use GET /graph/{id}/attack-paths to compute paths to DA.
    """
    if isinstance(engine, AresEngine):
        engine.bind_database(db)
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

        _campaign, runtime_state, _findings, _hosts, _credentials = await _hydrate_campaign_graph_data(
            db, engine, campaign
        )
        snapshot = await db.get_campaign_graph(campaign_id)
        if snapshot:
            graph = AttackGraph.from_d3_json(snapshot)
        elif getattr(runtime_state, "attack_graph", None) is not None:
            graph = runtime_state.attack_graph
        else:
            graph = AttackGraph()
            graph.build_from_store(runtime_state.artifact_store)
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
        runtime_state.attack_graph = graph
        await db.save_campaign_graph(campaign_id, graph.to_d3_json())
        return {
            "campaign_id": campaign_id,
            "ingest_result": result,
            "shortest_to_da": da_path,
            "graph_stats": graph.stats(),
        }
    except ImportError:
        raise HTTPException(503, "networkx required — pip install networkx")
    except HTTPException:
        raise
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
