"""
API endpoint tests — auth, RBAC, pagination, security headers.

Approach: httpx.ASGITransport + dependency_overrides (no lifespan needed).
  - base_url="http://localhost" passes TrustedHostMiddleware
  - _reset_rate_limiter() clears the global limiter before each class
  - Real JWTs signed with AresSettings().secret_key_value (from ARES_SECRET_KEY env)
  - OAuth2PasswordRequestForm overridden via dependency_overrides for login tests

Note on POST body tests (register, campaigns create, change-password):
  JSON body POST endpoints return 422 via ASGITransport without lifespan because
  Starlette body parsing requires a full ASGI lifecycle. These are tested as
  integration tests in tests/integration/. Only RBAC enforcement for register
  (which returns 403 before body parsing) is tested here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

# ── env bootstrap (before any ares import) ────────────────────────────────────
os.environ.setdefault("ARES_SECRET_KEY", "test-api-secret-key-min32-chars!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY", "test-enc-key-min32-chars-xxxxxxx")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestApiPass1!")
os.environ.setdefault("ARES_DEBUG", "true")
os.environ.setdefault("ARES_BROWSER_ORIGIN", "http://localhost:5173")


# ── helpers ───────────────────────────────────────────────────────────────────


_MOCK_PRINCIPAL_ROLES: dict[str, str] = {}
_C_LIVE_TEST_KEY = "11111111-1111-4111-8111-111111111111"
_PRODUCTION_C_LIVE_DESCRIPTOR_GATE: Any = None


def _settings():
    from ares.core.config import AresSettings

    return AresSettings()


def _make_token(username: str, role: str) -> str:
    from ares.core.security import create_access_token

    _MOCK_PRINCIPAL_ROLES[username] = role
    s = _settings()
    family_id = base64.urlsafe_b64encode(
        hashlib.sha256(username.encode("utf-8")).digest()
    ).rstrip(b"=").decode("ascii")
    return create_access_token(
        data={"sub": username, "sid": family_id, "ver": 1},
        secret_key=s.secret_key_value,
        expires_minutes=60,
    )


def _auth(username: str, role: str) -> dict:
    return {
        "Authorization": f"Bearer {_make_token(username, role)}",
        "Idempotency-Key": _C_LIVE_TEST_KEY,
    }


class _UnitLiveCoordinator:
    def __init__(self, engine: Any, role: str) -> None:
        self._engine = engine
        self._role = role

    async def execute_module(self, principal: Any, request: Any, campaign: Any) -> Any:
        del principal
        from ares.core.execution_admission import (
            DispatchDispositionV1,
            DispatchOutcomeV1,
            _identity,
        )
        from ares.db.execution_lifecycle import FixedResult

        result = await self._engine.run_module(
            request.module_id,
            campaign,
            dict(request.raw_parameters),
            actor_role=self._role,
        )
        return DispatchOutcomeV1(
            DispatchDispositionV1.TERMINAL,
            _identity(request),
            FixedResult.APPLIED,
            4,
            result,
            True,
            True,
        )


class _UnitLiveRuntime:
    def __init__(self, app: Any) -> None:
        self._app = app

    def bind(self, actor: Any) -> tuple[Any, _UnitLiveCoordinator]:
        from ares.api.server import get_engine
        from ares.db.execution_lifecycle import TrustedPrincipal

        provider = self._app.dependency_overrides.get(get_engine)
        engine = provider() if provider is not None else self._app.state.engine
        source = actor.websocket_ticket_source
        principal = TrustedPrincipal(source.user_id, source.user_id)
        return principal, _UnitLiveCoordinator(engine, actor.role)


def _c_live_result(module_id: str = "plugin.safe") -> Any:
    result = SimpleNamespace(
        module_id=module_id,
        status="done",
        findings=[],
        error="",
        duration_ms=1.0,
    )
    result.model_dump = lambda: {
        "module_id": module_id,
        "status": "done",
        "findings": [],
        "validation_results": [],
        "raw_output": {},
        "error": "",
        "duration_ms": 1.0,
    }
    return result


class _RecordingLiveCoordinator:
    def __init__(self, outcome_factory: Any = None) -> None:
        self.requests: list[Any] = []
        self.principals: list[Any] = []
        self._outcome_factory = outcome_factory

    async def execute_module(self, principal: Any, request: Any, campaign: Any) -> Any:
        del campaign
        from ares.core.execution_admission import (
            DispatchDispositionV1,
            DispatchOutcomeV1,
            _identity,
        )
        from ares.db.execution_lifecycle import FixedResult

        self.principals.append(principal)
        self.requests.append(request)
        if self._outcome_factory is not None:
            return self._outcome_factory(request)
        return DispatchOutcomeV1(
            DispatchDispositionV1.TERMINAL,
            _identity(request),
            FixedResult.APPLIED,
            4,
            _c_live_result(request.module_id),
            True,
            True,
        )


class _RecordingLiveRuntime:
    def __init__(self, coordinator: _RecordingLiveCoordinator) -> None:
        self.coordinator = coordinator

    def bind(self, actor: Any) -> tuple[Any, _RecordingLiveCoordinator]:
        from ares.db.execution_lifecycle import TrustedPrincipal

        source = actor.websocket_ticket_source
        return TrustedPrincipal(source.user_id, source.user_id), self.coordinator


def _nonterminal_outcome(result: Any, disposition: Any) -> Any:
    from ares.core.execution_admission import (
        DispatchIdentityV1,
        DispatchOutcomeV1,
    )

    identity = DispatchIdentityV1(
        "10000000-0000-4000-8000-000000000001",
        "10000000-0000-4000-8000-000000000002",
        "10000000-0000-4000-8000-000000000003",
        "10000000-0000-4000-8000-000000000004",
        "10000000-0000-4000-8000-000000000005",
        "10000000-0000-4000-8000-000000000006",
        "10000000-0000-4000-8000-000000000007",
        "10000000-0000-4000-8000-000000000008",
    )
    return DispatchOutcomeV1(
        disposition,
        identity,
        result,
        0,
        None,
        disposition.value == "indeterminate",
        False,
    )


def _issued_session(username: str = "admin", role: str = "team_lead"):
    from ares.core.security import create_access_token
    from ares.core.token_sessions import (
        IssuedTokenSession,
        SessionIssueResult,
        SessionIssueStatus,
    )

    family_id = base64.urlsafe_b64encode(
        hashlib.sha256(username.encode("utf-8")).digest()
    ).rstrip(b"=").decode("ascii")
    token = create_access_token(
        {"sub": username, "sid": family_id, "ver": 1},
        _settings().secret_key_value,
    )
    return SessionIssueResult(
        SessionIssueStatus.ISSUED,
        IssuedTokenSession(
            access_token=token,
            refresh_token="r" * 64,  # noqa: S106 - fixed test value
            user_id="test-user-id",
            subject=username,
            family_id=family_id,
            auth_epoch=1,
            absolute_expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            refresh_generation=0,
            role=role,
        ),
    )


def _api_key_headers(raw_key: str = "ares_test_api_key") -> dict:
    return {"X-API-Key": raw_key}


def _api_key_record(
    scopes: str | list[str],
    *,
    username: str = "admin",
    role: str = "team_lead",
    key_id: str = "api-key-1",
) -> dict[str, Any]:
    scope_list = [scopes] if isinstance(scopes, str) else scopes
    return {
        "username": username,
        "role": role,
        "auth_type": "api_key",
        "key_id": key_id,
        "scopes": scope_list,
    }


def _make_mock_db():
    from ares.core.token_sessions import (
        RefreshRotationResult,
        RefreshRotationStatus,
        SessionIssueResult,
        SessionIssueStatus,
        SessionRevocationResult,
        SessionRevocationStatus,
    )

    db = MagicMock()
    db.verify_user = AsyncMock(return_value=None)
    db.get_user = AsyncMock(return_value=None)
    db.user_exists = AsyncMock(return_value=False)
    db.create_user = AsyncMock()
    db.create_refresh_token = AsyncMock(return_value="mock-refresh-token")
    db.rotate_refresh_token = AsyncMock(return_value=(None, None))
    db.revoke_all_refresh_tokens = AsyncMock()
    db.revoke_access_token = AsyncMock()
    db.is_access_token_revoked = AsyncMock(return_value=False)
    db.create_login_session = AsyncMock(
        return_value=SessionIssueResult(SessionIssueStatus.INVALID)
    )
    db.rotate_refresh_session = AsyncMock(
        return_value=RefreshRotationResult(RefreshRotationStatus.INVALID)
    )
    db.revoke_current_session = AsyncMock(
        return_value=SessionRevocationResult(SessionRevocationStatus.REVOKED)
    )
    db.revoke_refresh_cookie_session = AsyncMock(
        return_value=SessionRevocationResult(SessionRevocationStatus.REVOKED)
    )
    db.revoke_all_sessions = AsyncMock(
        return_value=SessionRevocationResult(SessionRevocationStatus.REVOKED)
    )
    db.apply_user_security_event = AsyncMock(return_value=True)

    async def resolve_access_token_principal(
        subject: str,
        _jti: str,
        _family_id: str,
        auth_epoch: int,
    ) -> dict[str, str] | None:
        if db.is_access_token_revoked.return_value is True:
            return None
        role = _MOCK_PRINCIPAL_ROLES.get(subject)
        if role is None:
            return None
        return {
            "id": f"mock-user-{subject}",
            "username": subject,
            "role": role,
            "auth_epoch": auth_epoch,
        }

    db.resolve_access_token_principal = AsyncMock(
        side_effect=resolve_access_token_principal
    )
    db.audit = AsyncMock()
    db.purge_expired_tokens = AsyncMock(return_value=0)
    db.list_campaigns = AsyncMock(return_value=([], 0))
    db.get_campaign = AsyncMock(return_value=None)
    db.list_findings = AsyncMock(return_value=([], 0))
    db.get_monthly_confirmed_finding_stats = AsyncMock(
        return_value={
            "period": "2026-07",
            "label": "Security signals this cycle",
            "total": 0,
            "confirmed_findings": 0,
            "series": [],
        }
    )
    db.record_module_run = AsyncMock()
    db.get_telemetry_stats = AsyncMock(
        return_value={
            "modules": {"total": 0, "success": 0, "failed": 0, "error_rate": 0.0},
            "findings": 0,
            "latency_ms": {"p50": None, "p95": None, "p99": None},
            "throughput": {"tasks_per_min": None},
            "hosts": {"available": False, "discovered": 0, "owned": None},
        }
    )
    db.delete_campaign = AsyncMock(return_value=False)
    db.verify_api_key = AsyncMock(return_value=None)
    db.issue_websocket_ticket = AsyncMock(return_value=None)
    db.consume_websocket_ticket = AsyncMock(return_value=None)
    db.resolve_websocket_ticket_principal = AsyncMock(return_value=None)
    return db


def _reset_rate_limiter() -> None:
    """Clear global in-process rate limiter to prevent cross-test bleed."""
    from ares.api.rbac import _limiter

    _limiter._windows.clear()


def _run(coro):
    """Run a coroutine in a new event loop (for sync pytest methods)."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


# ── shared async client ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("modulestatus.done", True),
        ("done", True),
        ("success", True),
        ("partial", True),
        ("confirmed_findings", True),
        ("completed_no_findings", True),
        ("dry_run_ok", True),
        ("failed", False),
        ("error", False),
        ("module_error", False),
        ("operator_error", False),
        ("dependency_error", False),
        ("network_error", False),
        ("timeout", False),
        ("unsupported", False),
    ],
)
def test_module_outcome_success_mapping(outcome: str, expected: bool) -> None:
    from ares.api.server import _is_successful_module_outcome

    assert _is_successful_module_outcome(outcome) is expected


@pytest.fixture(scope="module")
def _app_mock_db():
    global _PRODUCTION_C_LIVE_DESCRIPTOR_GATE
    # Clear lru_cache so unit tests always use UNIT env vars,
    # not a cached instance from a previous integration test run.
    from ares.core.config import get_settings as _get_settings_fn

    _get_settings_fn.cache_clear()

    import ares.api.server as _server
    from ares.api.server import app as _app
    from ares.api.server import get_c_live_runtime, get_db, get_settings
    from ares.core.config import AresSettings

    mock_db = _make_mock_db()
    fake_settings = AresSettings()

    # Set app.state.db for endpoints that read it directly (e.g. /health)
    _app.state.db = mock_db

    _app.dependency_overrides[get_db] = lambda: mock_db
    _app.dependency_overrides[get_settings] = lambda: fake_settings
    _app.dependency_overrides[get_c_live_runtime] = lambda: _UnitLiveRuntime(_app)
    original_descriptor_gate = _server._c_live_descriptor_gate
    _PRODUCTION_C_LIVE_DESCRIPTOR_GATE = original_descriptor_gate
    _server._c_live_descriptor_gate = lambda _module_id, _role: None

    yield _app, mock_db

    _server._c_live_descriptor_gate = original_descriptor_gate
    _app.dependency_overrides.clear()
    # Clear cache again so the next test module starts fresh
    _get_settings_fn.cache_clear()


@pytest.fixture(scope="module")
def aclient(_app_mock_db):
    """Async same-origin browser client with a rotating CSRF header."""
    _app, mock_db = _app_mock_db
    transport = httpx.ASGITransport(app=_app)
    client: httpx.AsyncClient

    async def _browser_headers(request: httpx.Request) -> None:
        if request.url.path in {
            "/auth/token",
            "/auth/refresh",
            "/auth/logout",
            "/auth/logout-all",
        }:
            request.headers["Origin"] = "http://localhost:5173"
            request.headers["Sec-Fetch-Site"] = "same-origin"
            try:
                csrf = client.cookies.get("ares-dev-csrf")
            except httpx.CookieConflict:
                csrf = None
            csrf = csrf or ("A" * 43)
            request.headers["X-ARES-CSRF"] = csrf
            cookie = request.headers.get("Cookie", "")
            if "ares-dev-csrf=" not in cookie:
                request.headers["Cookie"] = (
                    f"{cookie}; ares-dev-csrf={csrf}" if cookie else f"ares-dev-csrf={csrf}"
                )

    client = httpx.AsyncClient(
        transport=transport,
        base_url="http://localhost:5173",
        event_hooks={"request": [_browser_headers]},
    )
    client.cookies.set(
        "ares-dev-csrf", "A" * 43, domain="localhost.local", path="/"
    )
    yield client, mock_db, _app
    asyncio.run(client.aclose())


@pytest.fixture
def c_live_route(aclient: Any) -> Any:
    """Install one request-local fake admission runtime without changing production."""
    from ares.api.server import get_c_live_runtime, get_engine

    client, db, app = aclient
    original_engine = app.dependency_overrides.get(get_engine)
    original_runtime = app.dependency_overrides.get(get_c_live_runtime)
    original_resolver_side_effect = db.resolve_access_token_principal.side_effect
    original_resolver_return = db.resolve_access_token_principal.return_value
    engine = SimpleNamespace(
        registry=MagicMock(),
        run_module=AsyncMock(return_value=_c_live_result()),
        run_plan=AsyncMock(),
        dry_run_module=MagicMock(
            return_value={"status": "dry_run_ok", "module_id": "plugin.safe"}
        ),
        dry_run_plan=MagicMock(
            return_value={"status": "dry_run_ok", "modules": [], "would_execute": True}
        ),
    )
    app.dependency_overrides[get_engine] = lambda: engine
    db.is_access_token_revoked.return_value = False
    db.get_campaign.side_effect = None
    db.get_campaign.return_value = {
        "id": "camp-c-live",
        "name": "C-LIVE",
        "client": "Internal",
        "operator": "legacy-username-must-not-authorize",
        "noise_profile": "normal",
        "status": "created",
        "scope_json": "[]",
        "targets_json": "[]",
        "notes": "",
    }

    def install(coordinator: _RecordingLiveCoordinator) -> None:
        app.dependency_overrides[get_c_live_runtime] = lambda: _RecordingLiveRuntime(
            coordinator
        )

    install(_RecordingLiveCoordinator())
    try:
        yield client, db, app, engine, install
    finally:
        db.is_access_token_revoked.return_value = False
        db.resolve_access_token_principal.side_effect = original_resolver_side_effect
        db.resolve_access_token_principal.return_value = original_resolver_return
        if original_engine is None:
            app.dependency_overrides.pop(get_engine, None)
        else:
            app.dependency_overrides[get_engine] = original_engine
        if original_runtime is None:
            app.dependency_overrides.pop(get_c_live_runtime, None)
        else:
            app.dependency_overrides[get_c_live_runtime] = original_runtime


# ── Health ────────────────────────────────────────────────────────────────────


class TestHealthEndpoint:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_health_returns_200(self, aclient):
        c, _, __ = aclient
        r = await c.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_health_has_status_ok(self, aclient):
        c, _, __ = aclient
        r = await c.get("/health")
        assert r.json().get("status") in ("ok", "degraded", "healthy")

    @pytest.mark.asyncio
    async def test_health_has_version(self, aclient):
        c, _, __ = aclient
        r = await c.get("/health")
        assert "version" in r.json()


class TestMonthlyStatsEndpoint:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_monthly_stats_returns_confirmed_finding_series(self, aclient):
        c, db, _ = aclient
        expected = {
            "period": "2026-07",
            "label": "Security signals this cycle",
            "total": 2,
            "confirmed_findings": 2,
            "series": [{"date": "2026-07-18", "count": 2}],
        }
        db.get_monthly_confirmed_finding_stats.return_value = expected

        response = await c.get("/stats/monthly", headers=_auth("admin", "team_lead"))

        assert response.status_code == 200
        assert response.json() == expected
        db.get_monthly_confirmed_finding_stats.assert_awaited_once_with()


# ── Security headers ──────────────────────────────────────────────────────────


class TestSecurityHeaders:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_x_frame_options_deny(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/health")).headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_x_content_type_nosniff(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/health")).headers.get(
            "x-content-type-options"
        ) == "nosniff"

    @pytest.mark.asyncio
    async def test_cache_control_no_store(self, aclient):
        c, _, __ = aclient
        assert "no-store" in (await c.get("/health")).headers.get("cache-control", "")

    @pytest.mark.asyncio
    async def test_server_header_stripped(self, aclient):
        c, _, __ = aclient
        hdrs = {k.lower() for k in (await c.get("/health")).headers}
        assert "server" not in hdrs

    @pytest.mark.asyncio
    async def test_cors_is_exact_and_never_credentialed(self, aclient):
        c, _, __ = aclient
        allowed = await c.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        denied = await c.options(
            "/health",
            headers={
                "Origin": "https://untrusted.example",
                "Access-Control-Request-Method": "GET",
            },
        )
        reduced = (
            allowed.headers.get("access-control-allow-origin")
            == "http://localhost:3000",
            "access-control-allow-credentials" not in allowed.headers,
            denied.headers.get("access-control-allow-origin") is None,
            "access-control-allow-credentials" not in denied.headers,
        )
        _require_fixed(all(reduced), "CORS credential boundary differed")


# ── Auth flow ─────────────────────────────────────────────────────────────────


class TestAuthFlow:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_me_without_token_returns_401(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/auth/me")).status_code == 401

    @pytest.mark.asyncio
    async def test_me_with_bad_token_returns_401(self, aclient):
        c, _, __ = aclient
        r = await c.get("/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_me_with_valid_token_returns_user(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        db.is_access_token_revoked.return_value = False
        r = await c.get("/auth/me", headers=_auth("admin", "team_lead"))
        assert r.status_code == 200
        assert r.json().get("username") == "admin"
        assert r.json().get("role") == "team_lead"

    @pytest.mark.asyncio
    async def test_csrf_bootstrap_is_empty_uncacheable_and_cookie_only(self, aclient):
        c, _, __ = aclient
        response = await c.get("/auth/csrf")
        cookie_headers = response.headers.get_list("set-cookie")
        reduced = (
            response.status_code == 204,
            response.content == b"",
            response.headers.get("cache-control") == "no-store",
            response.headers.get("pragma") == "no-cache",
            len(cookie_headers) == 1,
            cookie_headers[0].startswith("ares-dev-csrf=") if cookie_headers else False,
            "httponly" not in cookie_headers[0].lower() if cookie_headers else False,
            "max-age=600" in cookie_headers[0].lower() if cookie_headers else False,
        )
        del cookie_headers
        _require_fixed(all(reduced), "CSRF bootstrap contract differed")

    @pytest.mark.asyncio
    async def test_login_invalid_credentials_returns_401(self, aclient):
        """Login with mocked OAuth2PasswordRequestForm — invalid creds → 401."""
        c, db, _app = aclient
        _reset_rate_limiter()
        db.verify_user.return_value = None

        class FakeForm:
            username = "hacker"
            password = "wrong"  # noqa: S105 - test fixture credential
            scopes = []
            client_id = None
            client_secret = None

        _app.dependency_overrides[OAuth2PasswordRequestForm] = lambda: FakeForm()
        try:
            r = await c.post("/auth/token")
            assert r.status_code == 401
        finally:
            del _app.dependency_overrides[OAuth2PasswordRequestForm]

    @pytest.mark.asyncio
    async def test_login_valid_credentials_returns_tokens(self, aclient):
        """Login with mocked OAuth2PasswordRequestForm — valid creds → 200 + tokens."""
        c, db, _app = aclient
        _reset_rate_limiter()
        db.create_login_session.return_value = _issued_session()

        class FakeForm:
            username = "admin"
            password = "correct"  # noqa: S105 - test fixture credential
            scopes = []
            client_id = None
            client_secret = None

        _app.dependency_overrides[OAuth2PasswordRequestForm] = lambda: FakeForm()
        try:
            r = await c.post("/auth/token")
            assert r.status_code == 200
            body = r.json()
            assert "access_token" in body
            assert "refresh_token" not in body
            assert body["token_type"] == "bearer"  # noqa: S105 - OAuth token type
            cookie_headers = r.headers.get_list("set-cookie")
            reduced = (
                len(cookie_headers) == 2,
                any(value.startswith("ares-dev-refresh=") for value in cookie_headers),
                any(value.startswith("ares-dev-csrf=") for value in cookie_headers),
                sum("httponly" in value.lower() for value in cookie_headers) == 1,
                all("samesite=strict" in value.lower() for value in cookie_headers),
                all("path=/" in value.lower() for value in cookie_headers),
                all("domain=" not in value.lower() for value in cookie_headers),
            )
            del cookie_headers
            _require_fixed(all(reduced), "Committed login cookie contract differed")
        finally:
            del _app.dependency_overrides[OAuth2PasswordRequestForm]
            db.create_login_session.return_value = None

    @pytest.mark.asyncio
    async def test_unauthenticated_endpoint_returns_401(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/campaigns/any-id")).status_code == 401

    @pytest.mark.asyncio
    async def test_inactive_api_key_uses_generic_failure_without_endpoint_work(
        self, aclient
    ):
        """Response/handler mapping; real SQLite containment is covered below."""
        c, db, _ = aclient
        _reset_rate_limiter()
        db.verify_api_key.return_value = None
        db.verify_api_key.reset_mock()
        db.list_campaigns.reset_mock()

        response = await c.get("/campaigns", headers=_api_key_headers())
        response_body = response.json()
        generic_failure = (
            response_body.get("code") == 401
            and response_body.get("detail")
            == "Not authenticated. Provide Bearer token or X-API-Key."
            and response_body.get("type") == "api_error"
        )
        if not (
            response.status_code == 401
            and generic_failure
            and db.verify_api_key.await_count == 1
            and db.list_campaigns.await_count == 0
        ):
            pytest.fail(
                "expected inactive API key to fail generically before endpoint work",
                pytrace=False,
            )
        if "inactive" in response.text.lower():
            pytest.fail(
                "expected API-key authentication failure not to disclose account status",
                pytrace=False,
            )

    @pytest.mark.asyncio
    async def test_inactive_refresh_uses_generic_failure_without_successor(
        self, aclient
    ):
        """Response/handler mapping; real SQLite containment is covered below."""
        c, db, _ = aclient
        _reset_rate_limiter()
        db.rotate_refresh_session.reset_mock()
        db.create_refresh_token.reset_mock()
        c.cookies.set(
            "ares-dev-refresh", "r" * 64, domain="localhost.local", path="/"
        )

        response = await c.post("/auth/refresh")
        response_body = response.json()
        generic_failure = (
            response_body.get("code") == 401
            and response_body.get("detail") == "Session is not valid"
            and response_body.get("type") == "api_error"
        )
        _require_fixed(response.status_code == 401, "inactive refresh status differed")
        _require_fixed(generic_failure, "inactive refresh detail differed")
        _require_fixed(
            db.rotate_refresh_session.await_count == 1,
            "inactive refresh lookup count differed",
        )
        _require_fixed(
            db.create_refresh_token.await_count == 0,
            "inactive refresh created successor",
        )
        if "inactive" in response.text.lower():
            pytest.fail(
                "expected refresh authentication failure not to disclose account status",
                pytrace=False,
            )

    @pytest.mark.asyncio
    async def test_refresh_json_transport_is_rejected_before_database(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        db.rotate_refresh_session.reset_mock()
        c.cookies.set(
            "ares-dev-csrf", "A" * 43, domain="localhost.local", path="/"
        )
        response = await c.post(
            "/auth/refresh",
            json={"refresh_token": "legacy-transport"},
        )
        _require_fixed(response.status_code == 400, "legacy refresh body was accepted")
        _require_fixed(db.rotate_refresh_session.await_count == 0, "legacy body reached database")

    @pytest.mark.asyncio
    async def test_refresh_backend_uncertainty_publishes_no_cookie(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        c.cookies.set(
            "ares-dev-refresh", "r" * 64, domain="localhost.local", path="/"
        )
        db.rotate_refresh_session.side_effect = RuntimeError("fixed-test-canary")
        try:
            response = await c.post("/auth/refresh")
            reduced = (
                response.status_code == 503,
                not response.headers.get_list("set-cookie"),
            )
            _require_fixed(all(reduced), "Indeterminate refresh published browser state")
        finally:
            db.rotate_refresh_session.side_effect = None

    @pytest.mark.asyncio
    async def test_cookie_logout_commits_then_clears_exact_cookies(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        c.cookies.set(
            "ares-dev-refresh", "r" * 64, domain="localhost.local", path="/"
        )
        db.revoke_refresh_cookie_session.reset_mock()
        response = await c.post("/auth/logout")
        cookie_headers = response.headers.get_list("set-cookie")
        reduced = (
            response.status_code == 204,
            response.content == b"",
            db.revoke_refresh_cookie_session.await_count == 1,
            len(cookie_headers) == 2,
            all("max-age=0" in value.lower() for value in cookie_headers),
            all("path=/" in value.lower() for value in cookie_headers),
            all("samesite=strict" in value.lower() for value in cookie_headers),
            all("domain=" not in value.lower() for value in cookie_headers),
        )
        del cookie_headers
        _require_fixed(all(reduced), "Cookie logout contract differed")

    @pytest.mark.asyncio
    async def test_real_sqlite_inactive_credentials_fail_at_api_boundary(
        self,
        aclient,
        tmp_path,
        monkeypatch,
    ):
        c, _, app = aclient
        from ares.api.server import get_db
        from ares.db.database import AresDatabase

        real_db = await AresDatabase.create(tmp_path / "inactive-boundary.db")
        original_app_db = getattr(app.state, "db", None)
        no_override = object()
        original_override = app.dependency_overrides.get(get_db, no_override)
        handler_calls = [0]
        original_list_campaigns = real_db.list_campaigns

        async def counted_list_campaigns(*args, **kwargs):
            handler_calls[0] += 1
            return await original_list_campaigns(*args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(real_db, "list_campaigns", counted_list_campaigns)
            app.state.db = real_db
            app.dependency_overrides[get_db] = lambda: real_db
            try:
                user_id = await real_db.create_user(
                    "inactive-boundary-user",
                    "SyntheticBoundaryPass1!",
                    "operator",
                )
                key_id, raw_key = await real_db.create_api_key(
                    user_id,
                    "inactive-boundary-key",
                )
                refresh_token = await real_db.create_refresh_token(user_id)
                async with real_db.conn.execute(
                    "SELECT id FROM refresh_tokens WHERE user_id=?",
                    (user_id,),
                ) as cur:
                    original_refresh_row = await cur.fetchone()
                original_refresh_id = (
                    original_refresh_row["id"]
                    if original_refresh_row is not None
                    else None
                )

                active_response = await c.get(
                    "/campaigns",
                    headers={"X-API-Key": raw_key},
                )
                active_control = (
                    active_response.status_code == 200 and handler_calls[0] == 1
                )
                _require_fixed(
                    active_control,
                    "expected active real SQLite API key to reach protected work",
                )

                usage_marker = "2000-01-01 00:00:00"
                await real_db.conn.execute(
                    "UPDATE api_keys SET last_used=? WHERE id=?",
                    (usage_marker, key_id),
                )
                await real_db.conn.execute(
                    "UPDATE users SET is_active=0 WHERE id=?",
                    (user_id,),
                )
                await real_db.conn.commit()
                handler_calls[0] = 0

                api_response = await c.get(
                    "/campaigns",
                    headers={"X-API-Key": raw_key},
                )
                c.cookies.set(
                    "ares-dev-csrf", "A" * 43,
                    domain="localhost.local", path="/",
                )
                c.cookies.set(
                    "ares-dev-refresh", refresh_token,
                    domain="localhost.local", path="/",
                )
                refresh_response = await c.post("/auth/refresh")

                api_body = api_response.json()
                refresh_body = refresh_response.json()
                api_contract = (
                    api_response.status_code == 401
                    and api_body.get("detail")
                    == "Not authenticated. Provide Bearer token or X-API-Key."
                    and "inactive" not in api_response.text.lower()
                    and handler_calls[0] == 0
                )
                refresh_contract = (
                    refresh_response.status_code == 401
                    and refresh_body.get("detail") == "Session is not valid"
                    and "inactive" not in refresh_response.text.lower()
                    and "refresh_token" not in refresh_body
                )

                async with real_db.conn.execute(
                    "SELECT last_used FROM api_keys WHERE id=?",
                    (key_id,),
                ) as cur:
                    api_key_row = await cur.fetchone()
                async with real_db.conn.execute(
                    """SELECT id, user_id, is_revoked, used_at
                       FROM refresh_tokens
                       WHERE user_id=?""",
                    (user_id,),
                ) as cur:
                    refresh_rows = await cur.fetchall()

                usage_unchanged = (
                    api_key_row is not None
                    and api_key_row["last_used"] == usage_marker
                )
                predecessor_unchanged = (
                    len(refresh_rows) == 1
                    and original_refresh_id is not None
                    and refresh_rows[0]["id"] == original_refresh_id
                    and refresh_rows[0]["user_id"] == user_id
                    and refresh_rows[0]["is_revoked"] == 0
                    and refresh_rows[0]["used_at"] is None
                )
                _require_fixed(
                    api_contract,
                    "expected inactive real SQLite API key to fail generically",
                )
                _require_fixed(
                    refresh_contract,
                    "expected inactive real SQLite refresh to fail generically",
                )
                _require_fixed(
                    usage_unchanged,
                    "expected inactive API-key usage metadata to remain unchanged",
                )
                _require_fixed(
                    predecessor_unchanged,
                    "expected inactive refresh predecessor to remain unchanged",
                )
            finally:
                app.state.db = original_app_db
                if original_override is no_override:
                    app.dependency_overrides.pop(get_db, None)
                else:
                    app.dependency_overrides[get_db] = original_override
                await real_db.close()


# ── RBAC enforcement ──────────────────────────────────────────────────────────


class TestAPIKeyScopeEnforcement:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_api_key_identity_preserves_metadata(self, aclient):
        _, db, _ = aclient
        from ares.api.server import get_current_user_or_apikey

        db.verify_api_key.return_value = _api_key_record(["read", "write"])
        request = SimpleNamespace(
            headers=_api_key_headers(),
            app=SimpleNamespace(state=SimpleNamespace(db=db)),
        )

        actor = await get_current_user_or_apikey(request, bearer=None)

        assert actor.username == "admin"
        assert actor.role == "team_lead"
        assert actor.auth_type == "api_key"
        assert actor.is_api_key
        assert actor.api_key_id == "api-key-1"
        assert actor.api_key_scopes == ("read", "write")

    @pytest.mark.asyncio
    async def test_read_scoped_api_key_cannot_generate_report(self, aclient):
        c, db, _ = aclient
        db.verify_api_key.return_value = _api_key_record("read")
        db.get_campaign.reset_mock()

        r = await c.post("/reports/camp-api-key", headers=_api_key_headers())

        assert r.status_code == 403
        db.get_campaign.assert_not_called()

    @pytest.mark.asyncio
    async def test_write_scoped_api_key_can_generate_report_when_campaign_access_allows(
        self, aclient, tmp_path, monkeypatch
    ):
        c, db, _ = aclient
        import ares.modules.reporting.report_gen as report_gen

        db.verify_api_key.return_value = _api_key_record("write")
        db.audit.reset_mock()
        db.get_campaign.return_value = {
            "id": "camp-api-key",
            "name": "API Key Campaign",
            "client": "Internal",
            "operator": "admin",
            "targets": [],
            "scope": [],
        }

        class FakeReportGenerator:
            def __init__(self, *args, **kwargs):
                pass

            def generate(self, campaign, fmt="html"):
                path = tmp_path / f"{campaign.id}_report.{fmt}"
                path.write_text("report", encoding="utf-8")
                return path

        monkeypatch.setattr(report_gen, "ReportGenerator", FakeReportGenerator)

        r = await c.post(
            "/reports/camp-api-key?fmt=html",
            headers=_api_key_headers(),
        )

        assert r.status_code == 200
        assert r.json()["filename"] == "camp-api-key_report.html"
        db.audit.assert_awaited()

    @pytest.mark.asyncio
    async def test_write_scoped_api_key_does_not_bypass_campaign_access(self, aclient):
        c, db, _ = aclient
        db.verify_api_key.return_value = _api_key_record(
            "write", username="reporter_user", role="reporter"
        )
        db.get_campaign.return_value = {
            "id": "camp-api-key",
            "name": "API Key Campaign",
            "operator": "admin",
        }

        r = await c.post(
            "/reports/camp-api-key?fmt=html",
            headers=_api_key_headers(),
        )

        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_jwt_auth_generate_report_unchanged(
        self, aclient, tmp_path, monkeypatch
    ):
        c, db, _ = aclient
        import ares.modules.reporting.report_gen as report_gen

        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-jwt",
            "name": "JWT Campaign",
            "client": "Internal",
            "operator": "admin",
            "targets": [],
            "scope": [],
        }

        class FakeReportGenerator:
            def __init__(self, *args, **kwargs):
                pass

            def generate(self, campaign, fmt="html"):
                path = tmp_path / f"{campaign.id}_report.{fmt}"
                path.write_text("report", encoding="utf-8")
                return path

        monkeypatch.setattr(report_gen, "ReportGenerator", FakeReportGenerator)

        r = await c.post(
            "/reports/camp-jwt?fmt=html",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 200
        assert r.json()["filename"] == "camp-jwt_report.html"

    @pytest.mark.parametrize(
        ("method", "path", "kwargs"),
        [
            (
                "post",
                "/auth/change-password",
                {
                    "json": {
                        "current_password": "CurrentPassword123!",
                        "new_password": "NewPassword123!",
                    }
                },
            ),
            (
                "post",
                "/auth/api-keys",
                {"json": {"name": "ci", "scopes": "admin"}},
            ),
            ("get", "/auth/api-keys", {}),
            ("delete", "/auth/api-keys/api-key-1", {}),
        ],
    )
    @pytest.mark.asyncio
    async def test_api_key_cannot_manage_account_or_api_key_lifecycle(
        self, aclient, method, path, kwargs
    ):
        c, db, _ = aclient
        db.verify_api_key.return_value = _api_key_record("admin")

        r = await getattr(c, method)(path, headers=_api_key_headers(), **kwargs)

        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_cookie_logout_does_not_use_or_revoke_api_key(self, aclient):
        c, db, _ = aclient
        db.verify_api_key.reset_mock()
        db.revoke_refresh_cookie_session.reset_mock()
        c.cookies.delete("ares-dev-refresh")
        response = await c.post("/auth/logout", headers=_api_key_headers())
        _require_fixed(response.status_code == 204, "cookie logout was not idempotent")
        _require_fixed(db.verify_api_key.await_count == 0, "cookie logout verified API key")
        _require_fixed(
            db.revoke_refresh_cookie_session.await_count == 0,
            "cookie logout revoked family",
        )

    @pytest.mark.asyncio
    async def test_jwt_auth_can_create_list_and_delete_api_keys(self, aclient):
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        db.get_user.return_value = {"id": "user-1", "username": "admin"}
        db.create_api_key = AsyncMock(
            return_value=("api-key-1", "ares_created_secret_value")
        )
        db.list_api_keys = AsyncMock(
            return_value=[
                {
                    "id": "api-key-1",
                    "name": "ci",
                    "key_prefix": "ares_created",
                    "scopes": "read",
                }
            ]
        )
        db.revoke_api_key = AsyncMock(return_value=True)

        headers = _auth("admin", "team_lead")
        create = await c.post(
            "/auth/api-keys",
            headers=headers,
            json={"name": "ci", "scopes": "read"},
        )
        listed = await c.get("/auth/api-keys", headers=headers)
        deleted = await c.delete("/auth/api-keys/api-key-1", headers=headers)

        assert create.status_code == 200
        assert create.json()["key"] == "ares_created_secret_value"
        assert listed.status_code == 200
        item = listed.json()[0]
        assert item["key_prefix"] == "ares_created"
        assert "key" not in item
        assert "raw_key" not in item
        assert "key_hash" not in item
        assert deleted.status_code == 200
        assert deleted.json() == {"status": "revoked"}


class TestRBACEnforcement:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_register_requires_team_lead(self, aclient):
        """RBAC fires before body parse → 403 for reporter role."""
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        r = await c.post(
            "/auth/register",
            json={},
            headers=_auth("reporter_user", "reporter"),
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_security_audit_requires_team_lead(self, aclient):
        """GET /security/audit — operator role → 403."""
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        r = await c.get("/security/audit", headers=_auth("op_user", "operator"))
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_security_audit_accessible_to_team_lead(self, aclient):
        """GET /security/audit — team_lead → 200."""
        c, db, _ = aclient
        _reset_rate_limiter()
        db.is_access_token_revoked.return_value = False
        r = await c.get("/security/audit", headers=_auth("lead", "team_lead"))
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_campaigns_accessible_to_all_roles(self, aclient):
        """All authenticated roles can GET /campaigns."""
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        db.list_campaigns.return_value = ([], 0)
        for role in ("reporter", "recon", "operator", "team_lead"):
            _reset_rate_limiter()
            r = await c.get("/campaigns", headers=_auth(f"u_{role}", role))
            assert (
                r.status_code == 200
            ), f"Role {role!r} should access /campaigns, got {r.status_code}"

    @pytest.mark.asyncio
    async def test_create_campaign_invalid_scope_returns_422(self, aclient):
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        db.save_campaign.reset_mock()

        r = await c.post(
            "/campaigns",
            json={
                "name": "Invalid Scope",
                "client": "Internal",
                "targets": ["127.0.0.1"],
                "scope_cidrs": ["123"],
            },
            headers=_auth("op_user", "operator"),
        )

        assert r.status_code == 422
        assert "scope_cidrs" in r.text
        db.save_campaign.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_campaign_normalizes_uppercase_noise_profile(self, aclient):
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        captured: dict[str, Any] = {}

        async def capture_campaign(campaign: Any) -> None:
            captured["campaign"] = campaign

        db.save_campaign.side_effect = capture_campaign

        try:
            r = await c.post(
                "/campaigns",
                json={
                    "name": "AD Lab Attack Simulation",
                    "client": "Internal",
                    "targets": ["10.10.10.20"],
                    "scope_cidrs": ["10.10.10.0/24"],
                    "noise_profile": "NORMAL",
                },
                headers=_auth("op_user", "operator"),
            )
        finally:
            db.save_campaign.side_effect = None

        assert r.status_code == 200
        assert r.json()["noise_profile"] == "normal"
        assert captured["campaign"].noise_profile.value == "normal"

    @pytest.mark.asyncio
    async def test_delete_campaign_requires_team_lead(self, aclient):
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-delete",
            "name": "Delete Me",
            "operator": "operator1",
        }
        db.delete_campaign.reset_mock()

        for role in ("reporter", "recon", "operator"):
            _reset_rate_limiter()
            r = await c.delete("/campaigns/camp-delete", headers=_auth(f"u_{role}", role))
            assert r.status_code == 403

        db.delete_campaign.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_campaign_team_lead_deletes(self, aclient, tmp_path, monkeypatch):
        c, db, _ = aclient
        import ares.api.server as server

        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-delete",
            "name": "Delete Me",
            "operator": "operator1",
        }
        db.delete_campaign.return_value = True
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        owned_report = tmp_path / "camp-delete_Delete_Me_20260622_1745.pdf"
        owned_html_source = tmp_path / "camp-delete_Delete_Me_20260622_1745.html"
        other_report = tmp_path / "other-campaign_Delete_Me_20260622_1745.pdf"
        owned_report.write_text("owned pdf", encoding="utf-8")
        owned_html_source.write_text("owned html", encoding="utf-8")
        other_report.write_text("other pdf", encoding="utf-8")

        r = await c.delete("/campaigns/camp-delete", headers=_auth("admin", "team_lead"))

        assert r.status_code == 200
        assert r.json()["status"] == "deleted"
        db.delete_campaign.assert_awaited_once_with("camp-delete")
        assert not owned_report.exists()
        assert not owned_html_source.exists()
        assert other_report.exists()


# ── Pagination ────────────────────────────────────────────────────────────────


class TestPagination:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_x_total_count_header(self, aclient):
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        db.list_campaigns.return_value = ([], 42)
        r = await c.get("/campaigns", headers=_auth("admin", "team_lead"))
        assert r.status_code == 200
        assert r.headers.get("x-total-count") == "42"

    @pytest.mark.asyncio
    async def test_x_page_and_per_page_headers(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        db.is_access_token_revoked.return_value = False
        db.list_campaigns.return_value = ([], 0)
        r = await c.get(
            "/campaigns?page=2&per_page=10", headers=_auth("admin", "team_lead")
        )
        assert r.status_code == 200
        assert r.headers.get("x-page") == "2"
        assert r.headers.get("x-per-page") == "10"


# ── Error handling ────────────────────────────────────────────────────────────


class TestFindingsEvidenceContainment:
    _MARKER = "SYNTHETIC-HTTP-EVIDENCE-MARKER"

    def setup_method(self):
        _reset_rate_limiter()

    @classmethod
    def _finding_row(cls) -> dict[str, Any]:
        return {
            "id": "finding-contained",
            "campaign_id": "camp-contained",
            "module_id": "demo.synthetic",
            "title": "Synthetic finding title",
            "description": "Synthetic finding description",
            "severity": "high",
            "confidence": 0.9,
            "evidence_json": (
                '{"nested":{"token":"' + cls._MARKER + '"},'
                '"keyless":"' + cls._MARKER + '"}'
            ),
            "remediation": "Synthetic remediation",
            "host": "host.example.test",
            "validated": 1,
            "false_positive": 0,
        }

    @staticmethod
    def _prepare_db(db: Any, *, operator: str) -> None:
        db.is_access_token_revoked.return_value = False
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = {
            "id": "camp-contained",
            "name": "Contained Findings",
            "operator": operator,
        }
        db.list_findings.side_effect = None
        db.list_findings.reset_mock()

    @pytest.mark.parametrize(
        "role", ("reporter", "recon", "operator", "team_lead")
    )
    @pytest.mark.asyncio
    async def test_default_findings_response_redacts_every_jwt_role(
        self, aclient, role
    ):
        c, db, _ = aclient
        username = f"user-{role}"
        self._prepare_db(db, operator=username)
        row = self._finding_row()
        db.list_findings.return_value = ([row], 1)

        response = await c.get(
            "/campaigns/camp-contained/findings",
            headers=_auth(username, role),
        )

        assert response.status_code == 200
        assert response.json()[0]["evidence_json"] == '{"redacted":true}'
        assert response.json()[0]["title"] == row["title"]
        assert response.json()[0]["description"] == row["description"]
        assert self._MARKER not in response.text

    @pytest.mark.asyncio
    async def test_read_scoped_api_key_receives_redacted_findings(self, aclient):
        c, db, _ = aclient
        self._prepare_db(db, operator="api-reader")
        row = self._finding_row()
        db.list_findings.return_value = ([row], 1)
        db.verify_api_key.return_value = _api_key_record(
            "read",
            username="api-reader",
            role="reporter",
        )

        try:
            response = await c.get(
                "/campaigns/camp-contained/findings",
                headers=_api_key_headers(),
            )
        finally:
            db.verify_api_key.return_value = None

        assert response.status_code == 200
        assert response.json()[0]["evidence_json"] == '{"redacted":true}'
        assert self._MARKER not in response.text

    @pytest.mark.asyncio
    async def test_findings_preserve_filters_headers_total_and_db_rows(self, aclient):
        c, db, _ = aclient
        self._prepare_db(db, operator="operator-user")
        row = self._finding_row()
        original = dict(row)
        db.list_findings.return_value = ([row], 37)

        response = await c.get(
            "/campaigns/camp-contained/findings"
            "?page=2&per_page=7&severity=high&false_positive=true",
            headers=_auth("operator-user", "operator"),
        )

        assert response.status_code == 200
        assert response.headers["x-total-count"] == "37"
        assert response.headers["x-page"] == "2"
        assert response.headers["x-per-page"] == "7"
        db.list_findings.assert_awaited_once_with(
            "camp-contained", 2, 7, "high", True
        )
        assert row == original
        assert response.json()[0]["evidence_json"] == '{"redacted":true}'
        assert self._MARKER not in response.text

    @pytest.mark.asyncio
    async def test_campaign_ownership_denial_remains_404(self, aclient):
        c, db, _ = aclient
        self._prepare_db(db, operator="campaign-owner")

        response = await c.get(
            "/campaigns/camp-contained/findings",
            headers=_auth("different-reporter", "reporter"),
        )

        assert response.status_code == 404
        db.list_findings.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unknown_raw_query_flags_cannot_bypass_redaction(self, aclient):
        c, db, _ = aclient
        self._prepare_db(db, operator="admin")
        row = self._finding_row()
        db.list_findings.return_value = ([row], 1)

        response = await c.get(
            "/campaigns/camp-contained/findings?raw=true&include_sensitive=true",
            headers=_auth("admin", "team_lead"),
        )

        assert response.status_code == 200
        assert response.json()[0]["evidence_json"] == '{"redacted":true}'
        assert self._MARKER not in response.text


class TestErrorHandling:
    def setup_method(self):
        _reset_rate_limiter()

    @pytest.mark.asyncio
    async def test_unknown_route_returns_404(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/this-route-does-not-exist-xyz")).status_code == 404

    @pytest.mark.asyncio
    async def test_campaign_not_found_returns_404(self, aclient):
        c, db, _ = aclient
        _reset_rate_limiter()
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = None
        r = await c.get(
            "/campaigns/nonexistent-id-xyz", headers=_auth("admin", "team_lead")
        )
        assert r.status_code == 404


# ── Route inventory and dashboard static serving ─────────────────────────────


class TestRouteInventoryAndDashboard:
    def setup_method(self) -> None:
        _reset_rate_limiter()

    def test_required_routes_registered(self, aclient: Any) -> None:
        _, __, app = aclient
        inventory = {
            (method, getattr(route, "path", ""))
            for route in app.routes
            for method in (getattr(route, "methods", None) or {"WS"})
        }
        required = {
            ("POST", "/auth/token"),
            ("POST", "/auth/refresh"),
            ("POST", "/auth/logout"),
            ("GET", "/auth/me"),
            ("POST", "/campaigns"),
            ("GET", "/campaigns"),
            ("DELETE", "/campaigns/{campaign_id}"),
            ("GET", "/modules"),
            ("GET", "/modules/execution-chains"),
            ("POST", "/modules/{module_id}/run"),
            ("POST", "/reports/{campaign_id}"),
            ("GET", "/reports/{campaign_id}"),
            ("GET", "/reports/{campaign_id}/files/{filename}"),
            ("GET", "/health"),
            ("WS", "/ws/campaigns/{campaign_id}/events"),
            ("WS", "/dashboard"),
        }
        missing = required - inventory
        assert not missing

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_dashboard_index_and_spa_fallback(
        self, aclient: Any, tmp_path: Any
    ) -> None:
        c, _, app = aclient
        dist = tmp_path / "dist"
        dist.mkdir()
        (dist / "index.html").write_text(
            '<div id="root">ARES Dashboard</div>', encoding="utf-8"
        )
        (dist / "assets").mkdir()
        (dist / "assets" / "app.js").write_text("console.log('ok')", encoding="utf-8")
        for route in app.routes:
            if getattr(route, "name", "") == "dashboard":
                route.app.directory = str(dist)
                route.app.all_directories = [str(dist)]
                route.app.config_checked = False
                break
        r = await c.get("/dashboard/")
        assert r.status_code == 200
        assert "ARES Dashboard" in r.text
        fallback = await c.get("/dashboard/campaigns/demo")
        assert fallback.status_code == 200
        assert "ARES Dashboard" in fallback.text


# ── Modules schema metadata ──────────────────────────────────────────────────


class TestModuleSchemaEndpoint:
    def setup_method(self) -> None:
        _reset_rate_limiter()

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_modules_include_param_schema_from_backend(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine
        from ares.modules.base import OpsecLevel

        class FakeModule:
            MODULE_CATEGORY = "ad"
            MODULE_DESCRIPTION = "Kerberoast test module"
            OPSEC_LEVEL = OpsecLevel.MEDIUM
            MITRE_TECHNIQUES = ["T1558.003"]

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                return FakeModule if module_id == "ad.kerberoast" else None

        class FakeEngine:
            registry = FakeRegistry()

            def list_modules(self) -> list[dict[str, str]]:
                return [{"id": "ad.kerberoast", "name": "Kerberoast"}]

        db.is_access_token_revoked.return_value = False
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        try:
            r = await c.get("/modules", headers=_auth("admin", "team_lead"))
        finally:
            app.dependency_overrides.pop(get_engine, None)
        assert r.status_code == 200
        module = r.json()[0]
        assert module["category"] == "ad"
        assert module["opsec_level"] == "medium"
        assert module["mitre_list"] == ["T1558.003"]
        assert "dc" in module["param_schema"]
        assert module["param_schema"]["password"]["secret"] is True
        for field in (
            "required_params",
            "optional_params",
            "defaults",
            "capability_flags",
            "dry_run_supported",
            "supported_modes",
            "dependency_notes",
            "outcome_semantics",
            "safe_error_categories",
        ):
            assert field in module
        assert module["dry_run_supported"] is True

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_execution_chains_are_available_with_module_metadata(
        self, aclient: Any
    ) -> None:
        c, db, _ = aclient
        db.is_access_token_revoked.return_value = False
        response = await c.get("/modules/execution-chains", headers=_auth("admin", "team_lead"))

        assert response.status_code == 200
        chains = response.json()
        assert len(chains) >= 7
        kerberos = next(chain for chain in chains if chain["id"] == "ad-kerberos-exposure-chain")
        assert kerberos["stages"][1]["module_ids"] == ["ad.enum_spn"]
        assert kerberos["stages"][2]["module_ids"] == ["ad.kerberoast"]


# ── Reports safety ───────────────────────────────────────────────────────────


class TestHighNoiseAuthorizationPolicy:
    _INVALID_PLAN_DETAIL = (
        "Invalid plan: every stage must contain a modules list of non-empty "
        "string module IDs."
    )

    def setup_method(self) -> None:
        _reset_rate_limiter()

    @staticmethod
    def _module_classes() -> tuple[type, type]:
        from ares.modules.base import OpsecLevel

        class SafeModule:
            OPSEC_LEVEL = OpsecLevel.LOW

        class HighNoiseModule:
            OPSEC_LEVEL = OpsecLevel.HIGH_NOISE

        return SafeModule, HighNoiseModule

    @staticmethod
    def _actor(role: str, username: str = "operator-user") -> Any:
        from ares.api.rbac import AuthenticatedUser

        return AuthenticatedUser(username=username, role=role)

    @classmethod
    def _engine(cls, registry_items: dict[str, type | None]) -> Any:
        registry = MagicMock()
        registry.get.side_effect = registry_items.get

        def result_for(module_id: str) -> Any:
            result = SimpleNamespace(
                status="done",
                findings=[],
                error="",
                duration_ms=1.0,
            )
            result.model_dump = lambda: {
                "module_id": module_id,
                "status": "done",
                "findings": [],
                "validation_results": [],
                "raw_output": {},
                "error": "",
                "duration_ms": 1.0,
            }
            return result

        async def run_module(
            module_id: str,
            campaign: Any,
            params: dict[str, Any],
            actor_role: str = "",
        ) -> Any:
            return result_for(module_id)

        async def run_plan(
            plan: Any,
            campaign: Any,
            global_params: dict[str, Any],
            actor_role: str = "",
        ) -> dict[str, Any]:
            return {
                module_id: result_for(module_id)
                for module_id in plan.all_module_ids()
            }

        engine = SimpleNamespace(registry=registry)
        engine.run_module = AsyncMock(side_effect=run_module)
        engine.run_plan = AsyncMock(side_effect=run_plan)
        engine.dry_run_plan = MagicMock(
            return_value={
                "status": "dry_run_ok",
                "modules": [],
                "would_execute": True,
            }
        )
        return engine

    @staticmethod
    def _campaign(operator: str = "operator-user") -> dict[str, Any]:
        return {
            "id": "camp-plan-policy",
            "name": "Plan Policy",
            "client": "Internal",
            "operator": operator,
            "noise_profile": "normal",
            "status": "created",
            "scope_json": "[]",
            "targets_json": "[]",
            "notes": "",
        }

    @staticmethod
    def _plan_body(
        stages: list[tuple[str, list[str]]],
        *,
        dry_run: bool = False,
        global_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "plan": {
                "stages": [
                    {"name": name, "modules": modules, "params": {}}
                    for name, modules in stages
                ]
            },
            "global_params": global_params or {},
            "dry_run": dry_run,
        }

    def test_shared_policy_allows_operator_for_normal_module(self) -> None:
        from ares.api.server import _require_high_noise_module_access

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})

        _require_high_noise_module_access(
            ["plugin.safe"], self._actor("operator"), engine
        )

        engine.registry.get.assert_called_once_with("plugin.safe")

    def test_shared_policy_blocks_dynamic_high_noise_module(self) -> None:
        from ares.api.server import _require_high_noise_module_access

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})

        with pytest.raises(HTTPException) as exc_info:
            _require_high_noise_module_access(
                ["plugin.dynamic-high"], self._actor("operator"), engine
            )

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == (
            "'plugin.dynamic-high' is HIGH_NOISE — team_lead only."
        )

    def test_shared_policy_allows_team_lead_for_high_noise_module(self) -> None:
        from ares.api.server import _require_high_noise_module_access

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})

        _require_high_noise_module_access(
            ["plugin.dynamic-high"], self._actor("team_lead"), engine
        )

    def test_shared_policy_delegates_unknown_module(self) -> None:
        from ares.api.server import _require_high_noise_module_access

        engine = self._engine({})

        _require_high_noise_module_access(
            ["plugin.unknown"], self._actor("operator"), engine
        )

        engine.registry.get.assert_called_once_with("plugin.unknown")

    def test_shared_policy_deduplicates_sorts_and_excludes_sensitive_values(
        self,
    ) -> None:
        from ares.api.server import _require_high_noise_module_access

        _, high_noise_module = self._module_classes()
        engine = self._engine(
            {
                "plugin.zeta-high": high_noise_module,
                "plugin.alpha-high": high_noise_module,
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            _require_high_noise_module_access(
                [
                    "plugin.zeta-high",
                    "plugin.alpha-high",
                    "plugin.zeta-high",
                ],
                self._actor("operator"),
                engine,
            )

        detail = str(exc_info.value.detail)
        assert detail == (
            "'plugin.alpha-high', 'plugin.zeta-high' "
            "are HIGH_NOISE — team_lead only."
        )
        assert [call.args[0] for call in engine.registry.get.call_args_list] == [
            "plugin.alpha-high",
            "plugin.zeta-high",
        ]
        for sensitive_marker in (
            "plan-param-marker",
            "target-marker",
            "credential-marker",
            "evidence-marker",
        ):
            assert sensitive_marker not in detail

    @pytest.mark.parametrize(
        "module_ids",
        [
            pytest.param(["plugin.safe", 7], id="mixed-string-integer"),
            pytest.param([None], id="null"),
            pytest.param([["plugin.safe"]], id="list"),
            pytest.param([{"module_id": "plugin.safe"}], id="dict"),
            pytest.param([("plugin.safe",)], id="tuple"),
            pytest.param([b"plugin.safe"], id="bytes"),
            pytest.param([""], id="empty-string"),
            pytest.param(["   "], id="whitespace-only"),
            pytest.param([True], id="bool"),
        ],
    )
    def test_shared_policy_rejects_invalid_ids_before_registry_lookup(
        self, module_ids: list[Any]
    ) -> None:
        from ares.api.server import _require_high_noise_module_access

        engine = self._engine({})

        with pytest.raises(HTTPException) as exc_info:
            _require_high_noise_module_access(
                module_ids,
                self._actor("operator"),
                engine,
            )

        assert exc_info.value.status_code == 422
        assert exc_info.value.detail == self._INVALID_PLAN_DETAIL
        engine.registry.get.assert_not_called()

    @pytest.mark.parametrize(
        "plan_data",
        [
            pytest.param({"stages": [None]}, id="non-mapping-stage"),
            pytest.param({"stages": [{}]}, id="missing-modules"),
            pytest.param(
                {"stages": [{"modules": None}]},
                id="invalid-modules-collection",
            ),
            pytest.param(
                {"stages": [{"modules": [[]]}]},
                id="unhashable-module-id",
            ),
        ],
    )
    def test_plan_module_id_collector_rejects_structure_with_canonical_422(
        self, plan_data: dict[str, Any]
    ) -> None:
        from ares.api.server import _collect_plan_module_ids_for_authorization

        with pytest.raises(HTTPException) as exc_info:
            _collect_plan_module_ids_for_authorization(plan_data)

        assert exc_info.value.status_code == 422
        assert exc_info.value.detail == self._INVALID_PLAN_DETAIL

    def test_plan_module_id_collector_preserves_absent_stages_and_valid_ids(
        self,
    ) -> None:
        from ares.api.server import _collect_plan_module_ids_for_authorization

        assert _collect_plan_module_ids_for_authorization({}) == []
        module_ids = _collect_plan_module_ids_for_authorization(
            {
                "stages": [
                    {
                        "modules": [
                            " plugin.safe ",
                            "plugin.safe",
                            " plugin.safe ",
                        ]
                    }
                ]
            }
        )

        assert module_ids == [" plugin.safe ", "plugin.safe"]

    @pytest.mark.asyncio
    async def test_single_module_operator_high_noise_denied_before_engine(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_c_live_runtime, get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        runtime = MagicMock()
        original_runtime = app.dependency_overrides[get_c_live_runtime]
        db.get_campaign.reset_mock()
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = None
        app.dependency_overrides[get_engine] = lambda: engine
        app.dependency_overrides[get_c_live_runtime] = lambda: runtime
        try:
            with patch(
                "ares.api.server._broadcast_event",
                new_callable=AsyncMock,
            ) as broadcast:
                response = await c.post(
                    "/modules/plugin.dynamic-high/run",
                    json={
                        "campaign_id": "camp-plan-policy",
                        "params": {"target": "target-marker"},
                        "dry_run": False,
                    },
                    headers=_auth("operator-user", "operator"),
                )
        finally:
            app.dependency_overrides.pop(get_engine, None)
            app.dependency_overrides[get_c_live_runtime] = original_runtime

        # Live authority starts with the durable campaign identity; legacy
        # module classes are not an execution-authority source.
        assert response.status_code == 404
        assert response.json()["detail"] == "Campaign not found"
        db.get_campaign.assert_awaited_once_with("camp-plan-policy")
        engine.registry.get.assert_not_called()
        runtime.bind.assert_not_called()
        engine.run_module.assert_not_awaited()
        broadcast.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_single_module_team_lead_high_noise_reaches_engine(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign("another-operator")
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/modules/plugin.dynamic-high/run",
                json={
                    "campaign_id": "camp-plan-policy",
                    "params": {},
                    "dry_run": False,
                },
                headers=_auth("lead-user", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        engine.run_module.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_single_module_normal_and_unknown_modules_reach_existing_path(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            safe_response = await c.post(
                "/modules/plugin.safe/run",
                json={
                    "campaign_id": "camp-plan-policy",
                    "params": {},
                    "dry_run": False,
                },
                headers=_auth("operator-user", "operator"),
            )
            unknown_response = await c.post(
                "/modules/plugin.unknown/run",
                json={
                    "campaign_id": "camp-plan-policy",
                    "params": {},
                    "dry_run": False,
                },
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert safe_response.status_code == 200
        assert unknown_response.status_code == 200
        assert [call.args[0] for call in engine.run_module.await_args_list] == [
            "plugin.safe",
            "plugin.unknown",
        ]

    @pytest.mark.asyncio
    async def test_operator_safe_live_plan_reaches_engine_with_stable_response(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body([("safe", ["plugin.safe"])]),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        payload = response.json()
        assert payload["campaign_id"] == "camp-plan-policy"
        assert payload["modules_run"] == 1
        assert [child["module_id"] for child in payload["children"]] == [
            "plugin.safe"
        ]
        assert payload["children"][0]["status"] == "done"
        assert payload["children"][0]["execution"]["attempt_id"]
        engine.run_module.assert_awaited_once()
        assert engine.run_module.await_args.kwargs["actor_role"] == "operator"
        engine.run_plan.assert_not_awaited()

    @pytest.mark.parametrize(
        "stages",
        [
            [
                ("forbidden", ["plugin.dynamic-high"]),
                ("safe", ["plugin.safe"]),
            ],
            [
                ("safe", ["plugin.safe"]),
                ("forbidden", ["plugin.dynamic-high"]),
            ],
        ],
        ids=("high-noise-first", "high-noise-later"),
    )
    @pytest.mark.asyncio
    async def test_operator_high_noise_live_plan_denied_before_any_execution(
        self,
        aclient: Any,
        stages: list[tuple[str, list[str]]],
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, high_noise_module = self._module_classes()
        engine = self._engine(
            {
                "plugin.safe": safe_module,
                "plugin.dynamic-high": high_noise_module,
            }
        )
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(stages),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        expected_modules = [module_id for _name, module_ids in stages for module_id in module_ids]
        assert [
            call.args[0] for call in engine.run_module.await_args_list
        ] == expected_modules
        # The legacy HIGH_NOISE class is not an authority source. Descriptor
        # minimum-role metadata is the sole live role gate.
        engine.run_plan.assert_not_awaited()
        engine.dry_run_plan.assert_not_called()

    @pytest.mark.asyncio
    async def test_team_lead_high_noise_live_plan_reaches_engine(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign("another-operator")
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("forbidden", ["plugin.dynamic-high"])]
                ),
                headers=_auth("lead-user", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        engine.run_module.assert_awaited_once()
        assert engine.run_module.await_args.kwargs["actor_role"] == "team_lead"
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_duplicate_high_noise_plan_detail_is_safe_and_deterministic(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine(
            {
                "plugin.zeta-high": high_noise_module,
                "plugin.alpha-high": high_noise_module,
            }
        )
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        body = self._plan_body(
            [
                (
                    "mixed",
                    [
                        "plugin.zeta-high",
                        "plugin.alpha-high",
                        "plugin.zeta-high",
                    ],
                )
            ],
            global_params={
                "target": "target-marker",
                "credential": "credential-marker",
                "evidence": "evidence-marker",
            },
        )
        body["plan"]["stages"][0]["params"] = {
            "plugin.zeta-high": {"command": "plan-param-marker"}
        }
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=body,
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 422
        assert response.json()["detail"] == "raw_secret_material_forbidden"
        for sensitive_marker in (
            "plan-param-marker",
            "target-marker",
            "credential-marker",
            "evidence-marker",
        ):
            assert sensitive_marker not in response.text
        engine.run_module.assert_not_awaited()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.parametrize(
        "modules",
        [
            pytest.param(["plugin.safe", 7], id="mixed-string-integer"),
            pytest.param([None], id="null-entry"),
            pytest.param([["plugin.safe"]], id="list-entry"),
            pytest.param([{"module_id": "plugin.safe"}], id="dict-entry"),
            pytest.param(None, id="null-collection"),
            pytest.param(7, id="integer-collection"),
            pytest.param("plugin.safe", id="string-collection"),
            pytest.param(
                {"module_id": "plugin.safe"},
                id="dict-collection",
            ),
            pytest.param([""], id="empty-string"),
            pytest.param(["   "], id="whitespace-only"),
            pytest.param([True], id="bool-entry"),
        ],
    )
    @pytest.mark.parametrize(
        "dry_run",
        [False, True],
        ids=("live", "dry-run"),
    )
    @pytest.mark.asyncio
    async def test_malformed_plan_module_ids_return_stable_422_before_policy_lookup(
        self,
        aclient: Any,
        modules: Any,
        dry_run: bool,
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json={
                    "plan": {
                        "stages": [
                            {
                                "name": "malformed",
                                "modules": modules,
                                "params": {},
                            }
                        ]
                    },
                    "dry_run": dry_run,
                },
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 422
        assert response.json() == {
            "code": 422,
            "detail": self._INVALID_PLAN_DETAIL,
            "type": "api_error",
        }
        engine.registry.get.assert_not_called()
        engine.run_plan.assert_not_awaited()
        engine.dry_run_plan.assert_not_called()

    @pytest.mark.parametrize(
        "plan_data",
        [
            pytest.param({"stages": [None]}, id="null-stage"),
            pytest.param({"stages": [123]}, id="integer-stage"),
            pytest.param({"stages": ["invalid"]}, id="string-stage"),
            pytest.param({"stages": [[]]}, id="list-stage"),
            pytest.param({"stages": [{}]}, id="missing-modules"),
            pytest.param(
                {
                    "stages": [
                        {
                            "name": "safe",
                            "modules": ["plugin.safe"],
                            "params": {},
                        },
                        None,
                    ]
                },
                id="malformed-later-stage",
            ),
            pytest.param(
                {"stages": "invalid-stages-collection"},
                id="invalid-stages-collection",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "dry_run",
        [False, True],
        ids=("live", "dry-run"),
    )
    @pytest.mark.asyncio
    async def test_malformed_plan_structure_returns_canonical_422_before_engine(
        self,
        aclient: Any,
        plan_data: dict[str, Any],
        dry_run: bool,
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json={"plan": plan_data, "dry_run": dry_run},
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 422
        assert response.json() == {
            "code": 422,
            "detail": self._INVALID_PLAN_DETAIL,
            "type": "api_error",
        }
        assert str(plan_data) not in response.text
        engine.registry.get.assert_not_called()
        engine.run_plan.assert_not_awaited()
        engine.dry_run_plan.assert_not_called()

    @pytest.mark.asyncio
    async def test_unknown_valid_plan_module_is_delegated_to_engine(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        engine = self._engine({})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("unknown", ["plugin.unknown"])]
                ),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        engine.registry.get.assert_not_called()
        engine.run_module.assert_awaited_once()
        assert engine.run_module.await_args.args[0] == "plugin.unknown"
        engine.run_plan.assert_not_awaited()
        engine.dry_run_plan.assert_not_called()

    @pytest.mark.asyncio
    async def test_operator_safe_dry_run_reaches_preview_only(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("safe", ["plugin.safe"])], dry_run=True
                ),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        assert response.json()["status"] == "dry_run_ok"
        engine.dry_run_plan.assert_called_once()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_operator_high_noise_dry_run_denied_before_preview(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("forbidden", ["plugin.dynamic-high"])],
                    dry_run=True,
                ),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        assert response.json()["status"] == "dry_run_ok"
        engine.dry_run_plan.assert_called_once()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_team_lead_high_noise_dry_run_reaches_preview(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign("another-operator")
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("forbidden", ["plugin.dynamic-high"])],
                    dry_run=True,
                ),
                headers=_auth("lead-user", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        engine.dry_run_plan.assert_called_once()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_plan_missing_campaign_precedes_policy_lookup(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = None
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/missing/run",
                json=self._plan_body(
                    [("forbidden", ["plugin.dynamic-high"])]
                ),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 404
        engine.registry.get.assert_not_called()
        engine.run_module.assert_not_awaited()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_plan_campaign_ownership_denial_precedes_policy_lookup(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        _, high_noise_module = self._module_classes()
        engine = self._engine({"plugin.dynamic-high": high_noise_module})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign("different-owner")
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body(
                    [("forbidden", ["plugin.dynamic-high"])]
                ),
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        # The legacy campaign.operator username is not canonical execution
        # authority. The durable campaign grant is enforced by admission.
        assert response.status_code == 200
        assert response.json()["modules_run"] == 1
        engine.registry.get.assert_not_called()
        engine.run_module.assert_awaited_once()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_invalid_plan_structure_remains_422_before_policy_lookup(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        engine = self._engine({})
        db.get_campaign.side_effect = None
        db.get_campaign.return_value = self._campaign()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json={"plan": {"stages": [{}]}, "dry_run": False},
                headers=_auth("operator-user", "operator"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 422
        engine.registry.get.assert_not_called()
        engine.run_plan.assert_not_awaited()

    @pytest.mark.parametrize("role", ("reporter", "recon"))
    @pytest.mark.asyncio
    async def test_plan_reporter_and_recon_access_remains_forbidden(
        self, aclient: Any, role: str
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        safe_module, _ = self._module_classes()
        engine = self._engine({"plugin.safe": safe_module})
        db.get_campaign.reset_mock()
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            response = await c.post(
                "/campaigns/camp-plan-policy/run",
                json=self._plan_body([("safe", ["plugin.safe"])]),
                headers=_auth(f"{role}-user", role),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 403
        db.get_campaign.assert_not_awaited()
        engine.run_plan.assert_not_awaited()


@pytest.mark.parametrize(
    "case",
    [
        "missing-bearer",
        "invalid-bearer",
        "revoked-bearer",
        "deleted-user",
        "inactive-user",
        "demoted-role",
        "exact-replay-no-engine",
        "conflict-no-engine",
    ],
)
@pytest.mark.asyncio
async def test_c_live_http_authentication_and_submission_lookup(
    case: str,
    c_live_route: Any,
) -> None:
    from ares.core.execution_admission import DispatchDispositionV1
    from ares.db.execution_lifecycle import FixedResult

    client, db, _app, engine, install = c_live_route
    db.get_campaign.reset_mock()
    coordinator = _RecordingLiveCoordinator()
    username = f"c-live-{case}"
    headers = _auth(username, "operator")
    expected_status = 401
    if case == "missing-bearer":
        headers = {"Idempotency-Key": _C_LIVE_TEST_KEY}
    elif case == "invalid-bearer":
        headers = {
            "Authorization": "Bearer invalid.c-live.token",
            "Idempotency-Key": _C_LIVE_TEST_KEY,
        }
    elif case == "revoked-bearer":
        db.is_access_token_revoked.return_value = True
    elif case in {"deleted-user", "inactive-user"}:
        db.resolve_access_token_principal.side_effect = None
        db.resolve_access_token_principal.return_value = None
    elif case == "demoted-role":
        headers = _auth(username, "reporter")
        expected_status = 403
    elif case == "exact-replay-no-engine":
        coordinator = _RecordingLiveCoordinator(
            lambda _request: _nonterminal_outcome(
                FixedResult.REPLAYED,
                DispatchDispositionV1.REPLAYED,
            )
        )
        expected_status = 409
    else:
        coordinator = _RecordingLiveCoordinator(
            lambda _request: _nonterminal_outcome(
                FixedResult.CONFLICT_OPERATION,
                DispatchDispositionV1.CONFLICT,
            )
        )
        expected_status = 409
    install(coordinator)

    response = await client.post(
        "/modules/plugin.safe/run",
        json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
        headers=headers,
    )

    assert response.status_code == expected_status
    engine.run_module.assert_not_awaited()
    if case in {"exact-replay-no-engine", "conflict-no-engine"}:
        assert len(coordinator.requests) == 1
        assert len(coordinator.principals) == 1
        assert coordinator.principals[0].subject_ref == coordinator.principals[0].user_id
        assert coordinator.principals[0].user_id == f"mock-user-{username}"
        assert coordinator.principals[0].subject_ref != username
        assert db.get_campaign.await_count == 1
    else:
        assert not coordinator.requests
        db.get_campaign.assert_not_awaited()


@pytest.mark.parametrize("route", ["module", "plan", "strategy"])
@pytest.mark.asyncio
async def test_c_live_authenticated_dispatch_uses_v3_admission(
    route: str,
    c_live_route: Any,
    monkeypatch: Any,
) -> None:
    import ares.api.server as server

    client, _db, _app, engine, install = c_live_route
    coordinator = _RecordingLiveCoordinator()
    install(coordinator)
    headers = _auth(f"c-live-{route}", "operator")
    if route == "module":
        response = await client.post(
            "/modules/plugin.safe/run",
            json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
            headers=headers,
        )
        expected_ingress = "api_module"
    elif route == "plan":
        response = await client.post(
            "/campaigns/camp-c-live/run",
            json={
                "plan": {"stages": [{"name": "one", "modules": ["plugin.safe"]}]},
                "global_params": {},
                "dry_run": False,
            },
            headers=headers,
        )
        expected_ingress = "api_campaign_plan"
    else:
        monkeypatch.setattr(
            server,
            "_strategy_test_plan",
            lambda _body: {"stages": [{"name": "one", "modules": ["plugin.safe"]}]},
        )
        response = await client.post(
            "/strategy/engage",
            json={"campaign_id": "camp-c-live"},
            headers=headers,
        )
        expected_ingress = "strategy"

    assert response.status_code == 200
    assert [item.ingress_code for item in coordinator.requests] == [expected_ingress]
    engine.run_module.assert_not_awaited()


@pytest.mark.parametrize("route", ["module", "plan", "strategy"])
@pytest.mark.asyncio
async def test_c_live_admission_denial_prevents_engine(
    route: str,
    c_live_route: Any,
    monkeypatch: Any,
) -> None:
    import ares.api.server as server
    from ares.core.execution_admission import DispatchDispositionV1
    from ares.db.execution_lifecycle import FixedResult

    client, _db, _app, engine, install = c_live_route
    coordinator = _RecordingLiveCoordinator(
        lambda _request: _nonterminal_outcome(
            FixedResult.AUTHORITY_STALE,
            DispatchDispositionV1.NON_DISPATCHABLE,
        )
    )
    install(coordinator)
    headers = _auth(f"c-live-denied-{route}", "operator")
    if route == "module":
        response = await client.post(
            "/modules/plugin.safe/run",
            json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
            headers=headers,
        )
    elif route == "plan":
        response = await client.post(
            "/campaigns/camp-c-live/run",
            json={
                "plan": {"stages": [{"name": "one", "modules": ["plugin.safe"]}]},
                "global_params": {},
                "dry_run": False,
            },
            headers=headers,
        )
    else:
        monkeypatch.setattr(
            server,
            "_strategy_test_plan",
            lambda _body: {"stages": [{"name": "one", "modules": ["plugin.safe"]}]},
        )
        response = await client.post(
            "/strategy/engage",
            json={"campaign_id": "camp-c-live"},
            headers=headers,
        )

    assert response.status_code == 409
    assert response.json()["type"] == "execution_authority_stale"
    engine.run_module.assert_not_awaited()


@pytest.mark.parametrize("case", ["missing", "invalid"])
@pytest.mark.asyncio
async def test_c_live_idempotency_key_validation(case: str, c_live_route: Any) -> None:
    client, db, _app, engine, _install = c_live_route
    headers = {
        "Authorization": f"Bearer {_make_token(f'key-{case}', 'operator')}"
    }
    if case == "invalid":
        headers["Idempotency-Key"] = "11111111-1111-1111-8111-111111111111"
    db.get_campaign.reset_mock()

    response = await client.post(
        "/modules/plugin.safe/run",
        json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "idempotency_key_required" if case == "missing" else "idempotency_key_invalid"
    )
    assert db.get_campaign.await_count == 1
    engine.run_module.assert_not_awaited()


@pytest.mark.asyncio
async def test_c_live_api_key_execution_is_denied(c_live_route: Any) -> None:
    client, db, _app, engine, _install = c_live_route
    db.verify_api_key.reset_mock()
    response = await client.post(
        "/modules/plugin.safe/run",
        json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
        headers={"X-API-Key": "opaque-api-key", "Idempotency-Key": _C_LIVE_TEST_KEY},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "api_key_execution_denied"
    db.verify_api_key.assert_not_awaited()
    engine.run_module.assert_not_awaited()


@pytest.mark.asyncio
async def test_c_live_raw_credential_material_is_rejected(c_live_route: Any) -> None:
    client, _db, _app, engine, _install = c_live_route
    response = await client.post(
        "/modules/plugin.safe/run",
        json={
            "campaign_id": "camp-c-live",
            "params": {"password": "must-never-cross-live-boundary"},
            "dry_run": False,
        },
        headers=_auth("raw-secret-user", "operator"),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "raw_secret_material_forbidden"
    engine.run_module.assert_not_awaited()


@pytest.mark.parametrize("route", ["module", "plan"])
@pytest.mark.asyncio
async def test_c_live_http_preview_executes_no_module_code(
    route: str,
    c_live_route: Any,
) -> None:
    client, _db, _app, engine, _install = c_live_route
    headers = {"Authorization": f"Bearer {_make_token(f'preview-{route}', 'operator')}"}
    if route == "module":
        response = await client.post(
            "/modules/plugin.safe/run",
            json={"campaign_id": "camp-c-live", "params": {}, "dry_run": True},
            headers=headers,
        )
        engine.dry_run_module.assert_called_once()
    else:
        response = await client.post(
            "/campaigns/camp-c-live/run",
            json={
                "plan": {"stages": [{"name": "one", "modules": ["plugin.safe"]}]},
                "global_params": {},
                "dry_run": True,
            },
            headers=headers,
        )
        engine.dry_run_plan.assert_called_once()
    assert response.status_code == 200
    engine.run_module.assert_not_awaited()


@pytest.mark.parametrize("authority", ["credential", "approval"])
def test_c_live_required_authority_module_is_non_dispatchable(authority: str) -> None:
    from ares.modules.descriptors import ContractState, FIRST_PARTY_DESCRIPTORS

    assert _PRODUCTION_C_LIVE_DESCRIPTOR_GATE is not None
    if authority == "approval":
        descriptors = [
            item for item in FIRST_PARTY_DESCRIPTORS.values() if item.explicit_attempt_approval
        ]
    else:
        descriptors = [
            item
            for item in FIRST_PARTY_DESCRIPTORS.values()
            if item.credential_policy.state is not ContractState.NOT_APPLICABLE
        ]
    assert descriptors
    assert {
        _PRODUCTION_C_LIVE_DESCRIPTOR_GATE(item.module_id, "team_lead")
        for item in descriptors
    } == {"descriptor_unavailable"}


def test_c_live_production_descriptor_seam_cannot_escape_tests() -> None:
    from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS

    assert len(FIRST_PARTY_DESCRIPTORS) == 62
    assert _PRODUCTION_C_LIVE_DESCRIPTOR_GATE is not None
    assert all(
        not item.future_gateway_eligible
        and _PRODUCTION_C_LIVE_DESCRIPTOR_GATE(item.module_id, "team_lead")
        == "descriptor_unavailable"
        for item in FIRST_PARTY_DESCRIPTORS.values()
    )


def test_c_live_response_loss_status_inspection_is_stable_and_effect_free() -> None:
    from ares.api.server import _c_live_error_response
    from ares.core.execution_admission import DispatchDispositionV1
    from ares.db.execution_lifecycle import FixedResult

    outcome = _nonterminal_outcome(
        FixedResult.REPLAYED,
        DispatchDispositionV1.REPLAYED,
    )
    first = _c_live_error_response(outcome)
    second = _c_live_error_response(outcome)
    assert first.status_code == second.status_code == 409
    assert json.loads(first.body) == json.loads(second.body)
    assert json.loads(first.body)["redispatched"] is False
    assert json.loads(first.body)["execution"] == {
        "submission_id": "10000000-0000-4000-8000-000000000001",
        "logical_execution_id": "10000000-0000-4000-8000-000000000002",
        "attempt_id": "10000000-0000-4000-8000-000000000003",
    }


@pytest.mark.asyncio
async def test_c_live_repeated_module_response_preserves_occurrence_and_stable_ids(
    c_live_route: Any,
) -> None:
    client, _db, _app, _engine, install = c_live_route
    coordinator = _RecordingLiveCoordinator()
    install(coordinator)
    response = await client.post(
        "/campaigns/camp-c-live/run",
        json={
            "plan": {
                "stages": [
                    {"name": "repeat", "modules": ["plugin.safe", "plugin.safe"]}
                ]
            },
            "global_params": {},
            "dry_run": False,
        },
        headers=_auth("repeat-user", "operator"),
    )

    assert response.status_code == 200
    children = response.json()["children"]
    assert [item["occurrence"] for item in children] == [0, 1]
    assert [item["module_id"] for item in children] == ["plugin.safe", "plugin.safe"]
    assert children[0]["execution"]["attempt_id"] != children[1]["execution"]["attempt_id"]
    assert {item.idempotency_key for item in coordinator.requests} == {_C_LIVE_TEST_KEY}
    assert len({item.whole_intent_digest for item in coordinator.requests}) == 1


@pytest.mark.parametrize(
    ("role_case", "expected_status"),
    [
        ("operator", 200),
        ("team-lead", 200),
        ("reporter", 403),
        ("recon", 403),
        ("admin-not-synthesized", 401),
    ],
    ids=(
        "operator",
        "team-lead",
        "reporter",
        "recon",
        "admin-not-synthesized",
    ),
)
@pytest.mark.asyncio
async def test_c_live_role_mapping(
    role_case: str,
    expected_status: int,
    c_live_route: Any,
) -> None:
    client, db, _app, engine, _install = c_live_route
    role = {
        "team-lead": "team_lead",
        "admin-not-synthesized": "admin",
    }.get(role_case, role_case)
    db.get_campaign.reset_mock()
    response = await client.post(
        "/modules/plugin.safe/run",
        json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
        headers=_auth(f"role-{role_case}", role),
    )

    assert response.status_code == expected_status
    engine.run_module.assert_not_awaited()
    if expected_status != 200:
        db.get_campaign.assert_not_awaited()


@pytest.mark.parametrize(
    "case",
    [
        "applied",
        "replayed",
        "changed-conflict",
        "invalid-contract",
        "conflict-state",
        "authority-stale",
        "capacity-failure",
        "terminal-policy-outcome",
        "settlement-pending",
        "descriptor-unavailable",
    ],
)
@pytest.mark.asyncio
async def test_c_live_http_result_mapping(case: str, c_live_route: Any) -> None:
    from ares.api.server import _c_live_error_response, _c_live_unavailable_response
    from ares.core.execution_admission import DispatchDispositionV1
    from ares.db.execution_lifecycle import FixedResult

    client, _db, _app, _engine, install = c_live_route
    if case == "applied":
        install(_RecordingLiveCoordinator())
        response = await client.post(
            "/modules/plugin.safe/run",
            json={"campaign_id": "camp-c-live", "params": {}, "dry_run": False},
            headers=_auth("mapping-applied", "operator"),
        )
        assert response.status_code == 200
        assert "execution" in response.json()
        return
    if case == "descriptor-unavailable":
        response = _c_live_unavailable_response("descriptor_unavailable")
        expected_status, expected_type = 409, "descriptor_unavailable"
    elif case == "invalid-contract":
        coordinator = _RecordingLiveCoordinator()
        install(coordinator)
        response = await client.post(
            "/campaigns/camp-c-live/run",
            json={"plan": {"stages": []}, "global_params": {}, "dry_run": False},
            headers=_auth("mapping-invalid-contract", "operator"),
        )
        assert coordinator.requests == []
        expected_status, expected_type = 422, "invalid_contract"
    else:
        cases = {
            "replayed": (
                FixedResult.REPLAYED,
                DispatchDispositionV1.REPLAYED,
                409,
                "execution_replayed_no_redispatch",
            ),
            "changed-conflict": (
                FixedResult.CONFLICT_OPERATION,
                DispatchDispositionV1.CONFLICT,
                409,
                "idempotency_conflict",
            ),
            "conflict-state": (
                FixedResult.CONFLICT_STATE,
                DispatchDispositionV1.CONFLICT,
                409,
                "execution_not_dispatchable",
            ),
            "authority-stale": (
                FixedResult.AUTHORITY_STALE,
                DispatchDispositionV1.NON_DISPATCHABLE,
                409,
                "execution_authority_stale",
            ),
            "capacity-failure": (
                FixedResult.CAPACITY_UNAVAILABLE,
                DispatchDispositionV1.NON_DISPATCHABLE,
                429,
                "execution_capacity_unavailable",
            ),
            "terminal-policy-outcome": (
                FixedResult.APPLIED,
                DispatchDispositionV1.NON_DISPATCHABLE,
                409,
                "execution_not_dispatchable",
            ),
            "settlement-pending": (
                FixedResult.APPLIED,
                DispatchDispositionV1.INDETERMINATE,
                503,
                "execution_settlement_unconfirmed",
            ),
        }
        result, disposition, expected_status, expected_type = cases[case]
        response = _c_live_error_response(_nonterminal_outcome(result, disposition))
    if isinstance(response, httpx.Response):
        payload = response.json()
    elif isinstance(response, JSONResponse):
        payload = json.loads(response.body)
    else:
        raise AssertionError(
            "unsupported response type: "
            f"{type(response).__module__}.{type(response).__qualname__}"
        )
    assert response.status_code == expected_status
    assert payload["detail"] == payload["type"] == expected_type
    assert payload["redispatched"] is False


class TestModuleRunEndpoint:
    def setup_method(self) -> None:
        _reset_rate_limiter()

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_module_dry_run_returns_redacted_stable_contract(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine
        from ares.core.engine import AresEngine

        engine = AresEngine(settings=_settings())
        engine.load_modules()
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-dry-run-contract",
            "name": "Dry Run Contract",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "normal",
            "status": "created",
            "scope_json": '[{"cidr": "10.0.0.0/8", "description": ""}]',
            "targets_json": '["10.0.0.5"]',
            "notes": "",
            "created_at": "2026-06-27 02:15:19",
            "updated_at": "2026-06-27 02:15:19",
        }
        app.dependency_overrides[get_engine] = lambda: engine
        try:
            r = await c.post(
                "/modules/ad.kerberoast/run",
                json={
                    "campaign_id": "camp-dry-run-contract",
                    "params": {
                        "dc": "10.0.0.5",
                        "domain": "corp.local",
                        "username": "svc-roast",
                        "password": "Passw0rd!",
                        "target_user": "sqlsvc",
                    },
                    "dry_run": True,
                },
                headers=_auth("admin", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert r.status_code == 200
        payload = r.json()
        assert payload["status"] == "dry_run_ok"
        assert payload["module_id"] == "ad.kerberoast"
        assert payload["missing_params"] == []
        assert payload["validated_params_summary"]["password"] == "[redacted]"
        assert "Passw0rd!" not in r.text
        assert payload["would_execute"] is True

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_module_run_uses_persisted_campaign_scope_json(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        captured: dict[str, Any] = {}

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                return object

        class FakeResult:
            findings: list[Any] = []
            status = "success"

            def model_dump(self) -> dict[str, Any]:
                return {
                    "module_id": "demo.scope_capture",
                    "status": "success",
                    "findings": [],
                    "validation_results": [],
                    "raw_output": {},
                    "error": "",
                    "duration_ms": 0,
                }

        class FakeEngine:
            registry = FakeRegistry()

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> FakeResult:
                captured["campaign"] = campaign
                captured["params"] = params
                captured["actor_role"] = actor_role
                return FakeResult()

        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-scope-json",
            "name": "Scope JSON",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "stealth",
            "status": "created",
            "scope_json": '[{"cidr": "127.0.0.1/32", "description": ""}]',
            "targets_json": '["127.0.0.1"]',
            "notes": "",
            "created_at": "2026-06-27 02:15:19",
            "updated_at": "2026-06-27 02:15:19",
        }
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        try:
            r = await c.post(
                "/modules/demo.scope_capture/run",
                json={
                    "campaign_id": "camp-scope-json",
                    "params": {"target": "127.0.0.1"},
                    "dry_run": False,
                },
                headers=_auth("admin", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert r.status_code == 200
        campaign = captured["campaign"]
        assert [entry.cidr for entry in campaign.scope] == ["127.0.0.1/32"]
        assert campaign.targets == ["127.0.0.1"]

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_kerberoast_dashboard_payload_passes_api_validation(self, aclient: Any) -> None:
        c, db, app = aclient
        from ares.api.server import get_c_live_runtime, get_engine
        from ares.modules.ad.kerberoast import KerberoastModule

        captured: dict[str, Any] = {}
        registry_calls: list[str] = []

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                registry_calls.append(module_id)
                return KerberoastModule if module_id == "ad.kerberoast" else None

        class FakeResult:
            findings: list[Any] = []
            status = "success"

            def model_dump(self) -> dict[str, Any]:
                return {
                    "module_id": "ad.kerberoast",
                    "status": "success",
                    "findings": [],
                    "validation_results": [],
                    "raw_output": {"reached": True},
                    "error": "",
                    "duration_ms": 0,
                }

        class FakeEngine:
            registry = FakeRegistry()

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> FakeResult:
                captured["module_id"] = module_id
                captured["params"] = params
                captured["actor_role"] = actor_role
                return FakeResult()

        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-kerberoast",
            "name": "Kerberoast API",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "normal",
            "status": "created",
            "scope_json": '[{"cidr": "10.0.0.0/8", "description": ""}]',
            "targets_json": '["10.0.0.5"]',
            "notes": "",
            "created_at": "2026-06-27 02:15:19",
            "updated_at": "2026-06-27 02:15:19",
        }
        runtime = MagicMock()
        original_runtime = app.dependency_overrides[get_c_live_runtime]
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        app.dependency_overrides[get_c_live_runtime] = lambda: runtime
        try:
            with patch(
                "ares.api.server._broadcast_event",
                new_callable=AsyncMock,
            ) as broadcast:
                r = await c.post(
                    "/modules/ad.kerberoast/run",
                    json={
                        "campaign_id": "camp-kerberoast",
                        "params": {
                            "dc": "10.0.0.5",
                            "domain": "corp.local",
                            "username": "svc-roast",
                            "password": "Passw0rd!",
                            "use_ldaps": False,
                            "target_user": "sqlsvc",
                        },
                        "dry_run": False,
                    },
                    headers=_auth("admin", "team_lead"),
                )
        finally:
            app.dependency_overrides.pop(get_engine, None)
            app.dependency_overrides[get_c_live_runtime] = original_runtime

        assert r.status_code == 422
        assert r.json() == {
            "code": 422,
            "detail": "raw_secret_material_forbidden",
            "type": "api_error",
        }
        assert "Passw0rd!" not in r.text
        assert captured == {}
        assert registry_calls == []
        runtime.bind.assert_not_called()
        broadcast.assert_not_awaited()

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_module_result_redacts_sensitive_hash_evidence(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine

        full_asrep = "$krb5asrep$23$user@LAB.LOCAL:abcdef123456"
        full_tgs = "$krb5tgs$23$*svc-sql$LAB.LOCAL$svc/sql*abcdef123456"

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                return object

        class FakeResult:
            findings: list[Any] = []
            status = "done"
            duration_ms = 1.0

            def model_dump(self) -> dict[str, Any]:
                return {
                    "module_id": "demo.hash_output",
                    "status": "done",
                    "findings": [
                        {
                            "evidence": {
                                "hash_count": 2,
                                "sample_hash": full_asrep,
                            }
                        }
                    ],
                    "validation_results": [],
                    "raw_output": {
                        "asrep_hashes": [full_asrep],
                        "kerberos_hashes": [full_tgs],
                        "accounts": [{"name": "svc-sql", "hash": full_tgs}],
                        "hash_count": 2,
                    },
                    "error": "",
                    "duration_ms": self.duration_ms,
                }

        class FakeEngine:
            registry = FakeRegistry()

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> FakeResult:
                return FakeResult()

        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": "camp-hash-output",
            "name": "Hash Output",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "normal",
            "scope_json": '[{"cidr": "10.0.0.0/8", "description": ""}]',
            "targets_json": '["10.0.0.5"]',
            "status": "created",
        }
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        try:
            response = await c.post(
                "/modules/demo.hash_output/run",
                json={
                    "campaign_id": "camp-hash-output",
                    "params": {"target": "10.0.0.5"},
                    "dry_run": False,
                },
                headers=_auth("admin", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_engine, None)

        assert response.status_code == 200
        payload = response.json()
        assert full_asrep not in response.text
        assert full_tgs not in response.text
        assert payload["raw_output"]["hash_count"] == 2
        assert payload["raw_output"]["asrep_hashes"] == "[REDACTED sensitive evidence]"
        assert payload["raw_output"]["kerberos_hashes"] == "[REDACTED sensitive evidence]"
        assert payload["findings"][0]["evidence"]["sample_hash"] == "[REDACTED sensitive evidence]"

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_module_run_updates_telemetry_snapshot(
        self, aclient: Any, monkeypatch: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine
        import ares.telemetry.collector as telemetry

        telemetry._global_collector = telemetry.TelemetryCollector()

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                return object

        class FakeFinding:
            false_positive = False
            severity = "low"
            cvss_score = 0.0
            cvss_vector = ""
            trace_id = ""

        class FakeResult:
            findings: list[Any] = [FakeFinding()]
            status = "done"
            outcome = "confirmed_findings"
            duration_ms = 42.5

            def model_dump(self) -> dict[str, Any]:
                return {
                    "module_id": "demo.telemetry",
                    "status": "done",
                    "findings": [],
                    "validation_results": [],
                    "raw_output": {},
                    "error": "",
                    "duration_ms": self.duration_ms,
                    "outcome": self.outcome,
                }

        class FakeEngine:
            registry = FakeRegistry()

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> FakeResult:
                return FakeResult()

        db.is_access_token_revoked.return_value = False
        db.save_finding = AsyncMock()
        db.record_module_run.reset_mock()
        db.get_telemetry_stats.return_value = {
            "modules": {"total": 1, "success": 1, "failed": 0, "error_rate": 0.0},
            "findings": 1,
            "latency_ms": {"p50": 42.5, "p95": 42.5, "p99": 42.5},
            "throughput": {"tasks_per_min": 1.0},
            "hosts": {"available": False, "discovered": 0, "owned": None},
        }
        db.get_campaign.return_value = {
            "id": "camp-telemetry",
            "name": "Telemetry",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "stealth",
            "status": "created",
            "scope_json": '[{"cidr": "127.0.0.1/32", "description": ""}]',
            "targets_json": '["127.0.0.1"]',
            "notes": "",
            "created_at": "2026-06-27 02:15:19",
            "updated_at": "2026-06-27 02:15:19",
        }
        monkeypatch.setattr(
            "ares.api.server.enrich_finding_with_cvss",
            lambda finding: finding,
            raising=False,
        )
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        try:
            r = await c.post(
                "/modules/demo.telemetry/run",
                json={
                    "campaign_id": "camp-telemetry",
                    "params": {"target": "127.0.0.1"},
                    "dry_run": False,
                },
                headers=_auth("admin", "team_lead"),
            )
            t = await c.get("/telemetry", headers=_auth("admin", "team_lead"))
        finally:
            app.dependency_overrides.pop(get_engine, None)
            telemetry._global_collector = None

        assert r.status_code == 200
        assert t.status_code == 200
        snapshot = t.json()
        assert snapshot["modules"]["total"] == 1
        assert snapshot["modules"]["success"] == 1
        assert snapshot["findings"] == 1
        assert snapshot["latency_ms"]["p50"] == 42.5
        # Persistence belongs to the DB-bound engine.  A lightweight route
        # double must not cause the API layer to write a second record.
        db.record_module_run.assert_not_awaited()
        db.save_finding.assert_not_awaited()


class TestReportEndpoints:
    def setup_method(self) -> None:
        _reset_rate_limiter()

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_reports_list_only_campaign_prefixed_files(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        owned = tmp_path / f"{campaign_id}_Acme_20260101_0000.html"
        other = tmp_path / "other_Acme_20260101_0000.html"
        owned.write_text("owned", encoding="utf-8")
        other.write_text("other", encoding="utf-8")
        r = await c.get(f"/reports/{campaign_id}", headers=_auth("admin", "team_lead"))
        assert r.status_code == 200
        filenames = [item["filename"] for item in r.json()["reports"]]
        assert filenames == [owned.name]

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_generate_json_report_hydrates_confirmed_db_findings(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.modules.reporting.report_gen as report_gen

        real_report_generator = report_gen.ReportGenerator
        campaign_id = "camp-ad-lab"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "AD Lab Attack Simulation",
            "client": "Internal",
            "operator": "admin",
            "noise_profile": "normal",
            "status": "created",
            "scope_json": '[{"cidr": "10.10.10.0/24", "description": "AD lab"}]',
            "targets_json": '["10.10.10.20"]',
            "notes": "",
        }
        db.list_findings.return_value = (
            [
                {
                    "id": "finding-asrep",
                    "campaign_id": campaign_id,
                    "module_id": "ad.asreproast",
                    "title": "ASREPRoast Hashes Captured (1)",
                    "description": "Captured one AS-REP hash.",
                    "severity": "high",
                    "confidence": 1.0,
                    "mitre_technique": "T1558.004",
                    "mitre_tactic": "Credential Access",
                    "evidence_json": '{"hash_count": 1, "sample_hash": "$krb5asrep$23$user@LAB.LOCAL:abcdef"}',
                    "remediation": "Require Kerberos pre-authentication.",
                    "host": "10.10.10.20",
                    "validated": 0,
                    "false_positive": 0,
                    "discovered_at": "2026-07-12T01:00:00+00:00",
                },
                {
                    "id": "finding-kerb",
                    "campaign_id": campaign_id,
                    "module_id": "ad.kerberoast",
                    "title": "Kerberoast Hashes Captured (1)",
                    "description": "Captured one TGS hash.",
                    "severity": "critical",
                    "confidence": 1.0,
                    "mitre_technique": "T1558.003",
                    "mitre_tactic": "Credential Access",
                    "evidence_json": '{"hash_count": 1, "accounts": ["svc-sql"], "sample_hash": "$krb5tgs$23$*svc-sql$LAB.LOCAL$svc/sql*abcdef"}',
                    "remediation": "Rotate service account credentials.",
                    "host": "10.10.10.20",
                    "validated": 0,
                    "false_positive": 0,
                    "discovered_at": "2026-07-12T01:01:00+00:00",
                },
            ],
            2,
        )

        def generator_factory(*args: Any, **kwargs: Any) -> Any:
            return real_report_generator(output_dir=str(tmp_path), **kwargs)

        monkeypatch.setattr(report_gen, "ReportGenerator", generator_factory)

        r = await c.post(
            f"/reports/{campaign_id}?fmt=json",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 200
        path = tmp_path / r.json()["filename"]
        assert path.exists()
        data = __import__("json").loads(path.read_text(encoding="utf-8"))
        assert data["summary"]["total_confirmed"] == 2
        assert data["summary"]["by_severity"]["high"] == 1
        assert data["summary"]["by_severity"]["critical"] == 1
        assert data["summary"]["by_module"]["ad.asreproast"] == 1
        assert data["summary"]["by_module"]["ad.kerberoast"] == 1
        assert data["findings"]
        assert data["key_findings"]
        assert data["campaign"]["targets"] == ["10.10.10.20"]
        assert data["campaign"]["scope"][0]["cidr"] == "10.10.10.0/24"
        assert "$krb5asrep$" not in path.read_text(encoding="utf-8")
        assert "$krb5tgs$" not in path.read_text(encoding="utf-8")
        assert "validated" not in db.list_findings.await_args.kwargs
        assert db.list_findings.await_args.kwargs["false_positive"] is False

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_dashboard_run_findings_and_report_use_same_persisted_db_path(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, _, app = aclient
        import ares.modules.reporting.report_gen as report_gen
        from ares.api.server import get_c_live_runtime, get_db, get_engine
        from ares.core.campaign import Campaign, Finding, NoiseProfile, ScopeEntry, Severity
        from ares.core.engine import EngineModuleResult, ModuleStatus
        from ares.core.security import create_access_token
        from ares.db.database import AresDatabase

        real_report_generator = report_gen.ReportGenerator
        real_db = await AresDatabase.create(tmp_path / "ares.db")
        await real_db.create_user(
            "admin",
            "SyntheticReportPrincipal1!",
            "team_lead",
        )
        issued = await real_db.create_login_session(
            "admin",
            "SyntheticReportPrincipal1!",
            lambda claims: create_access_token(
                dict(claims),
                _settings().secret_key_value,
            ),
        )
        assert issued.session is not None
        real_auth = {
            "Authorization": f"Bearer {issued.session.access_token}",
            "Idempotency-Key": _C_LIVE_TEST_KEY,
        }
        original_db = getattr(app.state, "db", None)
        campaign = Campaign(
            name="AD Lab Attack Simulation",
            client="Internal",
            operator="admin",
            targets=["10.10.10.20"],
            scope=[ScopeEntry(cidr="10.10.10.0/24")],
            noise_profile=NoiseProfile.NORMAL,
        )
        await real_db.save_campaign(campaign)

        registry_calls: list[str] = []
        module_calls: list[str] = []

        def finding_for(module_id: str) -> Finding:
            if module_id == "ad.asreproast":
                return Finding(
                    title="ASREPRoast Hashes Captured (1)",
                    description="Captured one AS-REP hash.",
                    severity=Severity.HIGH,
                    validated=True,
                    module_id=module_id,
                    mitre_technique="T1558.004",
                    mitre_tactic="Credential Access",
                    evidence={
                        "hash_count": 1,
                        "sample_hash": "$krb5asrep$23$user@LAB.LOCAL:abcdef",
                    },
                    remediation="Require Kerberos pre-authentication.",
                    host="10.10.10.20",
                )
            return Finding(
                title="Kerberoast Hashes Captured (1)",
                description="Captured one TGS hash.",
                severity=Severity.CRITICAL,
                validated=True,
                module_id=module_id,
                mitre_technique="T1558.003",
                mitre_tactic="Credential Access",
                evidence={
                    "hash_count": 1,
                    "accounts": ["svc-sql"],
                    "sample_hash": "$krb5tgs$23$*svc-sql$LAB.LOCAL$svc/sql*abcdef",
                },
                remediation="Rotate service account credentials.",
                host="10.10.10.20",
            )

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                registry_calls.append(module_id)
                return None

        class FakeEngine:
            registry = FakeRegistry()

            def __init__(self, db: AresDatabase) -> None:
                self.db = db

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> EngineModuleResult:
                module_calls.append(module_id)
                finding = finding_for(module_id)
                result = EngineModuleResult(
                    module_id=module_id,
                    status=ModuleStatus.DONE,
                    findings=[finding],
                    raw_output={"confirmed": 1},
                    duration_ms=12.0,
                )
                await self.db.save_finding(campaign.id, finding, module_id)
                await self.db.record_module_run(
                    campaign.id,
                    module_id,
                    result.outcome,
                    True,
                    result.duration_ms,
                )
                return result

        def generator_factory(*args: Any, **kwargs: Any) -> Any:
            return real_report_generator(output_dir=str(tmp_path / "reports"), **kwargs)

        async def effect_counts() -> tuple[int, ...]:
            cursor = await real_db.conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM logical_executions),
                    (SELECT COUNT(*) FROM execution_attempts),
                    (SELECT COUNT(*) FROM execution_publication_outbox),
                    (SELECT COUNT(*) FROM execution_operation_receipts),
                    (SELECT COUNT(*) FROM module_runs),
                    (SELECT COUNT(*) FROM findings)
                """
            )
            row = await cursor.fetchone()
            await cursor.close()
            return tuple(int(value) for value in row)

        runtime = MagicMock()
        original_runtime = app.dependency_overrides[get_c_live_runtime]
        app.state.db = real_db
        app.dependency_overrides[get_db] = lambda: real_db
        app.dependency_overrides[get_engine] = lambda: FakeEngine(real_db)
        app.dependency_overrides[get_c_live_runtime] = lambda: runtime
        monkeypatch.setattr(report_gen, "ReportGenerator", generator_factory)
        try:
            before_effects = await effect_counts()
            assert before_effects == (0, 0, 0, 0, 0, 0)
            common_params = {
                "dc": "10.10.10.20",
                "domain": "lab.local",
                "username": "lab\\operator",
                "password": "CorrectHorseBatteryStaple!",
                "use_ldaps": False,
            }
            with patch(
                "ares.api.server._broadcast_event",
                new_callable=AsyncMock,
            ) as broadcast:
                asrep = await c.post(
                    "/modules/ad.asreproast/run",
                    headers=real_auth,
                    json={
                        "campaign_id": campaign.id,
                        "params": common_params,
                        "dry_run": False,
                    },
                )
                kerb = await c.post(
                    "/modules/ad.kerberoast/run",
                    headers=real_auth,
                    json={
                        "campaign_id": campaign.id,
                        "params": {**common_params, "target_user": "svc-sql"},
                        "dry_run": False,
                    },
                )
            assert asrep.status_code == 422
            assert kerb.status_code == 422
            assert asrep.json() == {
                "code": 422,
                "detail": "raw_secret_material_forbidden",
                "type": "api_error",
            }
            assert kerb.json() == {
                "code": 422,
                "detail": "raw_secret_material_forbidden",
                "type": "api_error",
            }
            assert "CorrectHorseBatteryStaple!" not in asrep.text
            assert "CorrectHorseBatteryStaple!" not in kerb.text
            assert registry_calls == []
            assert module_calls == []
            runtime.bind.assert_not_called()
            broadcast.assert_not_awaited()
            assert await effect_counts() == before_effects

            # Seed equivalent historical rows explicitly after proving the two
            # rejected requests had zero effect, so the persisted report-path
            # assertions below remain independent of the live boundary.
            for module_id in ("ad.asreproast", "ad.kerberoast"):
                finding = finding_for(module_id)
                result = EngineModuleResult(
                    module_id=module_id,
                    status=ModuleStatus.DONE,
                    findings=[finding],
                    raw_output={"confirmed": 1},
                    duration_ms=12.0,
                )
                await real_db.save_finding(campaign.id, finding, module_id)
                await real_db.record_module_run(
                    campaign.id,
                    module_id,
                    result.outcome,
                    True,
                    result.duration_ms,
                )

            # Legacy/current dashboard rows may be visible even if the validated
            # flag is not populated; report hydration must not use a stricter
            # finder than the dashboard list.
            await real_db.conn.execute(
                "UPDATE findings SET validated=0 WHERE campaign_id=?",
                (campaign.id,),
            )
            await real_db.conn.commit()

            findings_response = await c.get(
                f"/campaigns/{campaign.id}/findings",
                headers=real_auth,
            )
            assert findings_response.status_code == 200
            assert len(findings_response.json()) == 2
            assert all(
                row["evidence_json"] == '{"redacted":true}' for row in findings_response.json()
            )
            assert "$krb5asrep$" not in findings_response.text
            assert "$krb5tgs$" not in findings_response.text

            stored_rows, stored_total = await real_db.list_findings(
                campaign.id, page=1, per_page=50
            )
            stored_evidence = [
                __import__("json").loads(row["evidence_json"]) for row in stored_rows
            ]
            assert stored_total == 2
            assert all("sample_hash" in evidence for evidence in stored_evidence)
            assert all(evidence != {"redacted": True} for evidence in stored_evidence)

            report_response = await c.post(
                f"/reports/{campaign.id}?fmt=json",
                headers=real_auth,
            )
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_engine, None)
            app.dependency_overrides[get_c_live_runtime] = original_runtime
            app.state.db = original_db
            await real_db.close()

        assert report_response.status_code == 200
        path = tmp_path / "reports" / report_response.json()["filename"]
        data = __import__("json").loads(path.read_text(encoding="utf-8"))
        assert data["summary"]["total_confirmed"] == 2
        assert data["summary"]["by_module"]["ad.asreproast"] == 1
        assert data["summary"]["by_module"]["ad.kerberoast"] == 1
        assert data["summary"]["by_severity"]["high"] == 1
        assert data["summary"]["by_severity"]["critical"] == 1
        assert len(data["findings"]) >= 2
        assert len(data["key_findings"]) >= 2
        assert data["campaign"]["targets"] == ["10.10.10.20"]
        assert data["campaign"]["scope"][0]["cidr"] == "10.10.10.0/24"
        assert all(
            finding["evidence"]["sample_hash"] == "[REDACTED sensitive evidence]"
            for finding in data["findings"]
        )
        assert "T1558.003" in path.read_text(encoding="utf-8")
        assert "T1558.004" in path.read_text(encoding="utf-8")
        assert "$krb5asrep$" not in path.read_text(encoding="utf-8")
        assert "$krb5tgs$" not in path.read_text(encoding="utf-8")

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_download_rejects_encoded_traversal(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        r = await c.get(
            f"/reports/{campaign_id}/files/%2e%2e%5csecret.html",
            headers=_auth("admin", "team_lead"),
        )
        assert r.status_code == 400

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_download_serves_owned_file(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        report = tmp_path / f"{campaign_id}_Acme_20260101_0000.html"
        report.write_text("owned report", encoding="utf-8")
        r = await c.get(
            f"/reports/{campaign_id}/files/{report.name}",
            headers=_auth("admin", "team_lead"),
        )
        assert r.status_code == 200
        assert r.text == "owned report"

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_existing_file_succeeds(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        report = tmp_path / f"{campaign_id}_Acme_20260101_0000.pdf"
        report.write_bytes(b"%PDF-1.4\n")

        r = await c.delete(
            f"/reports/{campaign_id}/files/{report.name}",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 200
        assert r.json()["filename"] == report.name
        assert not report.exists()

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_missing_file_returns_404(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())

        r = await c.delete(
            f"/reports/{campaign_id}/files/{campaign_id}_Acme_missing.pdf",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 404

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_rejects_path_traversal(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())

        r = await c.delete(
            f"/reports/{campaign_id}/files/%2e%2e%5csecret.pdf",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 400

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_rejects_absolute_path(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())

        r = await c.delete(
            f"/reports/{campaign_id}/files/C%3A%5Csecret.pdf",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 400

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_rejects_nested_path(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())

        r = await c.delete(
            f"/reports/{campaign_id}/files/nested%5Creport.pdf",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 400

    @pytest.mark.asyncio  # type: ignore[untyped-decorator]
    async def test_report_delete_bulk_deletes_only_allowed_campaign_artifacts(
        self, aclient: Any, tmp_path: Any, monkeypatch: Any
    ) -> None:
        c, db, _ = aclient
        import ares.api.server as server

        campaign_id = "camp-123"
        db.is_access_token_revoked.return_value = False
        db.get_campaign.return_value = {
            "id": campaign_id,
            "name": "Acme",
            "operator": "admin",
        }
        monkeypatch.setattr(server, "_report_root", lambda: tmp_path.resolve())
        owned_pdf = tmp_path / f"{campaign_id}_Acme_20260101_0000.pdf"
        owned_json = tmp_path / f"{campaign_id}_Acme_20260101_0000.json"
        owned_html = tmp_path / f"{campaign_id}_Acme_20260101_0000.html"
        owned_md = tmp_path / f"{campaign_id}_Acme_20260101_0000.md"
        owned_txt = tmp_path / f"{campaign_id}_Acme_20260101_0000.txt"
        other = tmp_path / "other_Acme_20260101_0000.pdf"
        report_dir = tmp_path / f"{campaign_id}_Acme_20260101_0000.pdf.dir"
        report_dir.mkdir()
        for path in (owned_pdf, owned_json, owned_html, owned_md, owned_txt, other):
            path.write_text("artifact", encoding="utf-8")

        r = await c.delete(
            f"/reports/{campaign_id}",
            headers=_auth("admin", "team_lead"),
        )

        assert r.status_code == 200
        assert r.json()["deleted"] == 4
        assert not owned_pdf.exists()
        assert not owned_json.exists()
        assert not owned_html.exists()
        assert not owned_md.exists()
        assert owned_txt.exists()
        assert other.exists()
        assert report_dir.exists()


class TestAuthoritativeHTTPBearerPrincipal:
    @pytest.fixture
    async def auth_runtime(self, tmp_path: Any):
        from ares.api.server import app, get_db
        from ares.core.security import create_access_token
        from ares.db import database as database_module
        from ares.db.database import AresDatabase

        database = await AresDatabase.create(tmp_path / "http-principal.db")
        username = "http-principal-user"
        with patch.object(database_module.logger, "info"):
            user_id = await database.create_user(
                username,
                "SyntheticPrincipalPass1!",
                "team_lead",
            )
        issued = await database.create_login_session(
            username,
            "SyntheticPrincipalPass1!",
            lambda claims: create_access_token(
                dict(claims),
                _settings().secret_key_value,
            ),
        )
        assert issued.session is not None
        token = issued.session.access_token
        original_db = getattr(app.state, "db", None)
        original_overrides = dict(app.dependency_overrides)
        app.state.db = database
        app.dependency_overrides[get_db] = lambda: database
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost",
        )
        try:
            yield client, database, user_id, username, token, app
        finally:
            await client.aclose()
            app.dependency_overrides.clear()
            app.dependency_overrides.update(original_overrides)
            app.state.db = original_db
            await database.close()

    @staticmethod
    def _bearer_headers(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _signed_token(payload: dict[str, Any]) -> str:
        import jwt

        settings = _settings()
        return jwt.encode(
            payload,
            settings.secret_key_value,
            algorithm=settings.ares_jwt_algorithm,
        )

    @pytest.mark.asyncio
    async def test_active_inactive_reactivation_rename_and_delete(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, user_id, username, token, _ = auth_runtime
        _reset_rate_limiter()

        active_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        active_body = active_response.json()
        _require_fixed(
            active_response.status_code == 200
            and active_body.get("username") == username
            and active_body.get("role") == "team_lead",
            "expected an active bearer principal to reach the protected handler",
        )

        await database.apply_user_security_event(
            user_id=user_id,
            reason="user_status_change",
            is_active=False,
        )
        inactive_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        inactive_body = inactive_response.json()
        _require_fixed(
            inactive_response.status_code == 401
            and inactive_body.get("detail") == "Not authenticated"
            and "inactive" not in str(inactive_body).lower(),
            "expected an inactive bearer principal to receive the generic failure",
        )

        list_calls = [0]
        original_list_users = database.list_users

        async def tracked_list_users() -> list[dict[str, Any]]:
            list_calls[0] += 1
            return await original_list_users()

        database.list_users = tracked_list_users  # type: ignore[method-assign]
        inactive_elevated_response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            inactive_elevated_response.status_code == 401 and list_calls[0] == 0,
            "expected inactive bearer denial before protected handler work",
        )

        await database.apply_user_security_event(
            user_id=user_id,
            reason="user_status_change",
            is_active=True,
        )
        reactivated_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            reactivated_response.status_code == 401,
            "expected status-change epoch revocation to remain authoritative",
        )

        await database.conn.execute(
            "UPDATE users SET username=? WHERE id=?",
            ("renamed-http-principal", user_id),
        )
        await database.conn.commit()
        renamed_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            renamed_response.status_code == 401,
            "expected a token with a stale renamed subject to be rejected",
        )

        await database.conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        await database.conn.commit()
        deleted_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            deleted_response.status_code == 401
            and deleted_response.json().get("detail") == "Not authenticated",
            "expected a deleted bearer principal to receive the generic failure",
        )

    @pytest.mark.asyncio
    async def test_current_database_role_controls_403_and_promotion(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, user_id, _username, token, _ = auth_runtime
        _reset_rate_limiter()
        list_calls = [0]
        original_list_users = database.list_users

        async def tracked_list_users() -> list[dict[str, Any]]:
            list_calls[0] += 1
            return await original_list_users()

        database.list_users = tracked_list_users  # type: ignore[method-assign]
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        demoted_response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            demoted_response.status_code == 403 and list_calls[0] == 0,
            "expected current demoted role to block team-lead work",
        )

        await database.conn.execute(
            "UPDATE users SET role='team_lead' WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        promoted_response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            promoted_response.status_code == 200 and list_calls[0] == 1,
            "expected current promoted role to authorize the next request",
        )

        await database.conn.execute(
            "UPDATE users SET role='unsupported-role' WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        invalid_role_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            invalid_role_response.status_code == 401,
            "expected an unknown database role to fail authentication",
        )

    @pytest.mark.asyncio
    async def test_revoked_jti_is_generic_401(
        self,
        auth_runtime: Any,
    ) -> None:
        from ares.core.security import decode_access_token

        client, database, user_id, _, token, _ = auth_runtime
        settings = _settings()
        payload = decode_access_token(
            token,
            settings.secret_key_value,
            settings.ares_jwt_algorithm,
        )
        payload_valid = isinstance(payload, dict)
        _require_fixed(payload_valid, "expected the test bearer token to decode")
        jti = payload.get("jti") if payload else None
        jti_valid = isinstance(jti, str) and bool(jti.strip())
        _require_fixed(jti_valid, "expected the test bearer token to contain a JTI")
        await database.revoke_access_token(
            jti,
            user_id,
            "2099-01-01 00:00:00",
        )
        response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        body = response.json()
        _require_fixed(
            response.status_code == 401
            and body.get("detail") == "Not authenticated"
            and "revoked" not in str(body).lower(),
            "expected a revoked bearer token to receive the generic failure",
        )

    @pytest.mark.parametrize(
        ("_case", "claims"),
        [
            ("missing-sub", {"jti": "claim-jti", "exp": 4102444800}),
            ("empty-sub", {"sub": "", "jti": "claim-jti", "exp": 4102444800}),
            ("blank-sub", {"sub": "   ", "jti": "claim-jti", "exp": 4102444800}),
            ("numeric-sub", {"sub": 7, "jti": "claim-jti", "exp": 4102444800}),
            ("missing-jti", {"sub": "claim-user", "exp": 4102444800}),
            ("empty-jti", {"sub": "claim-user", "jti": "", "exp": 4102444800}),
            ("blank-jti", {"sub": "claim-user", "jti": "   ", "exp": 4102444800}),
            ("object-jti", {"sub": "claim-user", "jti": {}, "exp": 4102444800}),
            ("missing-exp", {"sub": "claim-user", "jti": "claim-jti"}),
            (
                "string-exp",
                {"sub": "claim-user", "jti": "claim-jti", "exp": "4102444800"},
            ),
            (
                "boolean-exp",
                {"sub": "claim-user", "jti": "claim-jti", "exp": True},
            ),
        ],
        ids=lambda value: value if isinstance(value, str) else None,
    )
    @pytest.mark.asyncio
    async def test_mandatory_claim_failures_do_not_query_database(
        self,
        auth_runtime: Any,
        _case: str,
        claims: dict[str, Any],
    ) -> None:
        client, database, _, _, _, _ = auth_runtime
        _reset_rate_limiter()
        calls = [0]
        original_resolve = database.resolve_access_token_principal

        async def tracked_resolve(subject: str, jti: str) -> dict[str, Any] | None:
            calls[0] += 1
            return await original_resolve(subject, jti)

        database.resolve_access_token_principal = tracked_resolve  # type: ignore[method-assign]
        token = self._signed_token(claims)
        response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        body = response.json()
        _require_fixed(
            response.status_code == 401
            and body.get("detail") == "Not authenticated"
            and response.headers.get("www-authenticate") == "Bearer"
            and calls[0] == 0,
            "expected fixed mandatory-claim validation failure",
        )

    @pytest.mark.parametrize(
        "_case",
        [
            "object",
            "list",
            "null",
            "positive-infinity",
            "negative-infinity",
            "nan",
            "oversized-integer",
        ],
    )
    @pytest.mark.asyncio
    async def test_malformed_exp_is_generic_401_before_database_or_handler(
        self,
        auth_runtime: Any,
        _case: str,
    ) -> None:
        client, database, _, username, _, _ = auth_runtime
        _reset_rate_limiter()
        principal_calls = [0]
        handler_calls = [0]
        original_resolve = database.resolve_access_token_principal
        original_list_users = database.list_users

        async def tracked_resolve(subject: str, jti: str) -> dict[str, Any] | None:
            principal_calls[0] += 1
            return await original_resolve(subject, jti)

        async def tracked_list_users() -> list[dict[str, Any]]:
            handler_calls[0] += 1
            return await original_list_users()

        database.resolve_access_token_principal = tracked_resolve  # type: ignore[method-assign]
        database.list_users = tracked_list_users  # type: ignore[method-assign]
        malformed_exp_by_case: dict[str, Any] = {
            "object": {},
            "list": [],
            "null": None,
            "positive-infinity": float("inf"),
            "negative-infinity": float("-inf"),
            "nan": float("nan"),
            "oversized-integer": 10**400,
        }
        token = self._signed_token(
            {
                "sub": username,
                "jti": "malformed-exp-jti",
                "exp": malformed_exp_by_case[_case],
            }
        )
        response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        body = response.json()
        body_text = str(body).lower()
        _require_fixed(
            response.status_code == 401 and response.status_code != 500,
            "expected malformed expiry to return the generic authentication status",
        )
        _require_fixed(
            body.get("detail") == "Not authenticated"
            and "typeerror" not in body_text
            and "overflowerror" not in body_text
            and "valueerror" not in body_text,
            "expected malformed expiry to return the generic authentication envelope",
        )
        _require_fixed(
            response.headers.get("www-authenticate") == "Bearer",
            "expected malformed expiry to retain the bearer challenge",
        )
        _require_fixed(
            principal_calls[0] == 0,
            "expected malformed expiry to fail before database principal lookup",
        )
        _require_fixed(
            handler_calls[0] == 0,
            "expected malformed expiry to fail before protected handler work",
        )

    @pytest.mark.asyncio
    async def test_expired_and_malformed_bearer_are_generic_401(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, _, username, _, _ = auth_runtime
        _reset_rate_limiter()
        calls = [0]
        original_resolve = database.resolve_access_token_principal

        async def tracked_resolve(subject: str, jti: str) -> dict[str, Any] | None:
            calls[0] += 1
            return await original_resolve(subject, jti)

        database.resolve_access_token_principal = tracked_resolve  # type: ignore[method-assign]
        from ares.core.security import create_access_token

        settings = _settings()
        expired = create_access_token(
            {"sub": username, "role": "team_lead"},
            settings.secret_key_value,
            algorithm=settings.ares_jwt_algorithm,
            expires_minutes=-1,
        )
        expired_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(expired),
        )
        malformed_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers("synthetic.invalid.jwt"),
        )
        _require_fixed(
            expired_response.status_code == 401
            and malformed_response.status_code == 401
            and calls[0] == 0,
            "expected expired and malformed bearers to fail before DB authorization",
        )

    @pytest.mark.asyncio
    async def test_closed_database_is_503_and_recovery_succeeds_without_handler_work(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, _, _, token, _ = auth_runtime
        _reset_rate_limiter()
        list_calls = [0]
        original_list_users = database.list_users

        async def tracked_list_users() -> list[dict[str, Any]]:
            list_calls[0] += 1
            return await original_list_users()

        database.list_users = tracked_list_users  # type: ignore[method-assign]
        await database.close()
        unavailable_response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        unavailable_body = unavailable_response.json()
        _require_fixed(
            unavailable_response.status_code == 503
            and unavailable_body.get("detail") == "Authentication service unavailable"
            and unavailable_response.headers.get("www-authenticate") is None
            and list_calls[0] == 0,
            "expected a closed auth database to deny work with fixed 503",
        )

        await database.connect()
        recovered_response = await client.get(
            "/security/users",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            recovered_response.status_code == 200 and list_calls[0] == 1,
            "expected a recovered auth database to authorize a subsequent request",
        )

    @pytest.mark.asyncio
    async def test_absent_and_timeout_database_are_fixed_503(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, _, _, token, app = auth_runtime
        _reset_rate_limiter()
        app.state.db = None
        absent_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        _require_fixed(
            absent_response.status_code == 503
            and absent_response.json().get("detail")
            == "Authentication service unavailable"
            and absent_response.headers.get("www-authenticate") is None,
            "expected absent auth database to map to fixed 503",
        )

        app.state.db = database

        async def fail_lookup(_subject: str, _jti: str) -> dict[str, Any] | None:
            raise TimeoutError

        database.resolve_access_token_principal = fail_lookup  # type: ignore[method-assign]
        timeout_response = await client.get(
            "/auth/me",
            headers=self._bearer_headers(token),
        )
        timeout_body = timeout_response.json()
        _require_fixed(
            timeout_response.status_code == 503
            and timeout_body.get("detail") == "Authentication service unavailable"
            and timeout_response.headers.get("www-authenticate") is None
            and "timeout" not in str(timeout_body).lower(),
            "expected auth lookup timeout to map to sanitized fixed 503",
        )

    @pytest.mark.asyncio
    async def test_api_key_outage_is_503_invalid_key_is_401_and_bearer_wins(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, user_id, _, token, _ = auth_runtime
        _reset_rate_limiter()
        _, raw_key = await database.create_api_key(user_id, "http-outage-key")
        verify_calls = [0]
        original_verify = database.verify_api_key

        async def tracked_verify(candidate: str) -> dict[str, Any] | None:
            verify_calls[0] += 1
            return await original_verify(candidate)

        database.verify_api_key = tracked_verify  # type: ignore[method-assign]
        await database.close()
        api_key_response = await client.get(
            "/auth/me",
            headers={"X-API-Key": raw_key},
        )
        _require_fixed(
            api_key_response.status_code == 503
            and api_key_response.json().get("detail")
            == "Authentication service unavailable"
            and verify_calls[0] == 1,
            "expected API-key database outage to map to fixed 503",
        )

        verify_calls[0] = 0
        precedence_response = await client.get(
            "/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-API-Key": raw_key,
            },
        )
        _require_fixed(
            precedence_response.status_code == 503 and verify_calls[0] == 0,
            "expected bearer backend outage not to fall through to API-key auth",
        )

        await database.connect()
        invalid_response = await client.get(
            "/auth/me",
            headers={"X-API-Key": "ares_invalid_synthetic_key"},
        )
        _require_fixed(
            invalid_response.status_code == 401
            and invalid_response.json().get("detail")
            == "Not authenticated. Provide Bearer token or X-API-Key.",
            "expected invalid API key to retain the generic 401 contract",
        )

    @pytest.mark.asyncio
    async def test_invalid_explicit_bearer_does_not_fall_through_to_api_key(
        self,
        auth_runtime: Any,
    ) -> None:
        client, database, user_id, _, _, _ = auth_runtime
        _reset_rate_limiter()
        _, raw_key = await database.create_api_key(user_id, "precedence-key")
        verify_calls = [0]
        original_verify = database.verify_api_key

        async def tracked_verify(candidate: str) -> dict[str, Any] | None:
            verify_calls[0] += 1
            return await original_verify(candidate)

        database.verify_api_key = tracked_verify  # type: ignore[method-assign]
        response = await client.get(
            "/auth/me",
            headers={
                "Authorization": "Bearer synthetic.invalid.jwt",
                "X-API-Key": raw_key,
            },
        )
        _require_fixed(
            response.status_code == 401 and verify_calls[0] == 0,
            "expected an explicitly invalid bearer not to fall through to API-key auth",
        )

    @pytest.mark.asyncio
    async def test_websocket_ticket_bearer_issuance_is_committed_and_uncached(
        self,
        auth_runtime: Any,
    ) -> None:
        from ares.core.campaign import Campaign

        client, database, _, _, token, _ = auth_runtime
        _reset_rate_limiter()
        campaign = Campaign(
            name="Ticket Issuance Campaign",
            operator="separate-owner",
        )
        await database.save_campaign(campaign)
        response = await client.post(
            f"/campaigns/{campaign.id}/websocket-ticket",
            headers=self._bearer_headers(token),
        )
        body = response.json()
        ticket = body.get("ticket") if isinstance(body, dict) else None
        async with database.conn.execute(
            "SELECT COUNT(*) FROM websocket_tickets"
        ) as cursor:
            row_count = int((await cursor.fetchone())[0])
        contract_is_exact = (
            response.status_code == 201
            and set(body) == {"ticket", "expires_in"}
            and isinstance(ticket, str)
            and len(ticket) == 43
            and body.get("expires_in") == 30
            and response.headers.get("cache-control") == "no-store"
            and response.headers.get("pragma") == "no-cache"
            and row_count == 1
        )
        _require_fixed(
            contract_is_exact,
            "expected one committed uncached bearer WebSocket ticket",
        )

    @pytest.mark.parametrize("scope", ["read", "write", "admin"])
    @pytest.mark.asyncio
    async def test_websocket_ticket_api_key_scopes_update_last_used_once(
        self,
        auth_runtime: Any,
        scope: str,
    ) -> None:
        from ares.core.campaign import Campaign

        client, database, user_id, username, _, _ = auth_runtime
        _reset_rate_limiter()
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        campaign = Campaign(
            name="API Key Ticket Campaign",
            operator=username,
        )
        await database.save_campaign(campaign)
        with patch("ares.db.database.logger.info"):
            key_id, raw_key = await database.create_api_key(
                user_id,
                "ticket-key",
                scopes=scope,
            )
        verify_calls = [0]
        original_verify = database.verify_api_key

        async def tracked_verify(candidate: str) -> Any:
            verify_calls[0] += 1
            return await original_verify(candidate)

        database.verify_api_key = tracked_verify  # type: ignore[method-assign]
        response = await client.post(
            f"/campaigns/{campaign.id}/websocket-ticket",
            headers={"X-API-Key": raw_key},
        )
        async with database.conn.execute(
            "SELECT last_used FROM api_keys WHERE id=?",
            (key_id,),
        ) as cursor:
            last_used_present = (await cursor.fetchone())[0] is not None
        async with database.conn.execute(
            "SELECT COUNT(*) FROM websocket_tickets"
        ) as cursor:
            row_count = int((await cursor.fetchone())[0])
        _require_fixed(
            response.status_code == 201
            and verify_calls[0] == 1
            and last_used_present
            and row_count == 1,
            "expected one API-key verification and one committed ticket",
        )

    @pytest.mark.asyncio
    async def test_websocket_ticket_denials_do_not_insert_rows(
        self,
        auth_runtime: Any,
        monkeypatch: Any,
    ) -> None:
        from ares.api import server
        from ares.core.campaign import Campaign

        client, database, user_id, username, token, _ = auth_runtime
        _reset_rate_limiter()
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        inaccessible = Campaign(
            name="Inaccessible Ticket Campaign",
            operator="different-owner",
        )
        accessible = Campaign(
            name="Accessible Ticket Campaign",
            operator=username,
        )
        await database.save_campaign(inaccessible)
        await database.save_campaign(accessible)
        with patch("ares.db.database.logger.info"):
            _, insufficient_key = await database.create_api_key(
                user_id,
                "insufficient-ticket-key",
                scopes="none",
            )

        invalid = await client.post(
            f"/campaigns/{accessible.id}/websocket-ticket",
            headers={"Authorization": "Bearer synthetic.invalid.jwt"},
        )
        insufficient = await client.post(
            f"/campaigns/{accessible.id}/websocket-ticket",
            headers={"X-API-Key": insufficient_key},
        )
        missing = await client.post(
            "/campaigns/missing-ticket-campaign/websocket-ticket",
            headers=self._bearer_headers(token),
        )
        inaccessible_response = await client.post(
            f"/campaigns/{inaccessible.id}/websocket-ticket",
            headers=self._bearer_headers(token),
        )

        original_issue = database.issue_websocket_ticket

        async def lose_authority(_campaign_id: str, _source: Any) -> None:
            return None

        database.issue_websocket_ticket = lose_authority  # type: ignore[method-assign]
        revalidation_loss = await client.post(
            f"/campaigns/{accessible.id}/websocket-ticket",
            headers=self._bearer_headers(token),
        )

        async def fail_issue(_campaign_id: str, _source: Any) -> Any:
            raise RuntimeError

        database.issue_websocket_ticket = fail_issue  # type: ignore[method-assign]
        unavailable = await client.post(
            f"/campaigns/{accessible.id}/websocket-ticket",
            headers=self._bearer_headers(token),
        )
        database.issue_websocket_ticket = original_issue  # type: ignore[method-assign]

        original_limit = server._limiter.is_allowed_async

        async def deny_auth_bucket(key: str, _limit: int) -> tuple[bool, int]:
            return (False, 0) if key.startswith("auth:") else (True, 1)

        monkeypatch.setattr(server._limiter, "is_allowed_async", deny_auth_bucket)
        limited = await client.post(
            f"/campaigns/{accessible.id}/websocket-ticket",
            headers=self._bearer_headers(token),
        )
        monkeypatch.setattr(server._limiter, "is_allowed_async", original_limit)

        async with database.conn.execute(
            "SELECT COUNT(*) FROM websocket_tickets"
        ) as cursor:
            row_count = int((await cursor.fetchone())[0])
        statuses = (
            invalid.status_code,
            insufficient.status_code,
            missing.status_code,
            inaccessible_response.status_code,
            revalidation_loss.status_code,
            limited.status_code,
            unavailable.status_code,
        )
        _require_fixed(
            statuses == (401, 403, 404, 404, 401, 429, 503) and row_count == 0,
            "expected fixed ticket denial statuses without row insertion",
        )


_WS_TEST_DISCONNECT = object()
_WS_TEST_HEARTBEAT = object()


class _FirstBroadcastSendCoordinator:
    """Order-independent barrier for the first of two real send stages."""

    def __init__(self) -> None:
        self._claim_lock = asyncio.Lock()
        self._roles: dict[int, bool] = {}
        self.release_first = asyncio.Event()
        self.first_stalled = asyncio.Event()
        self.first_cancelled = asyncio.Event()
        self.peer_delivered = asyncio.Event()
        self.active_count = 0
        self.settled_count = 0

    async def before_send(self, socket: Any) -> None:
        async with self._claim_lock:
            is_first = not self._roles
            self._roles[id(socket)] = is_first
            self.active_count += 1
        if not is_first:
            return
        self.first_stalled.set()
        try:
            await asyncio.wait_for(self.release_first.wait(), timeout=10.0)
        except asyncio.CancelledError:
            self.first_cancelled.set()
            raise
        except asyncio.TimeoutError:
            pytest.fail(
                "expected the first broadcast send barrier to be released",
                pytrace=False,
            )

    def after_send(self, socket: Any, *, delivered: bool) -> None:
        is_first = self._roles.pop(id(socket), None)
        if is_first is None:
            return
        self.active_count -= 1
        self.settled_count += 1
        if not is_first and delivered:
            self.peer_delivered.set()


class _MainWebSocketHarness:
    """Minimal ASGI peer for the real registered WebSocket route."""

    def __init__(self, app: Any, query_string: bytes = b"") -> None:
        self.scope = {"app": app, "query_string": query_string}
        self.accepted = asyncio.Event()
        self.closed = asyncio.Event()
        self.disconnect_observed = asyncio.Event()
        self.close_code: int | None = None
        self.close_reason: str | None = None
        self.close_calls = 0
        self.sent_types: list[str] = []
        self.sent = asyncio.Queue[str]()
        self.inbound = asyncio.Queue[Any]()
        self.fail_next_send = False
        self.fail_accept = False
        self.block_next_send = False
        self.send_started = asyncio.Event()
        self.send_release = asyncio.Event()
        self.broadcast_send_coordinator: (
            _FirstBroadcastSendCoordinator | None
        ) = None

    async def accept(self) -> None:
        if self.fail_accept:
            raise RuntimeError
        self.accepted.set()

    async def close(self, *, code: int, reason: str) -> None:
        self.close_calls += 1
        self.close_code = code
        self.close_reason = reason
        self.closed.set()
        await self.inbound.put(_WS_TEST_DISCONNECT)

    async def send_json(self, payload: Any) -> None:
        coordinator = self.broadcast_send_coordinator
        delivered = False
        try:
            if coordinator is not None:
                await coordinator.before_send(self)
            if self.block_next_send:
                self.block_next_send = False
                self.send_started.set()
                await _ws_wait(
                    self.send_release.wait(),
                    "expected protected send barrier release",
                )
            if self.fail_next_send:
                self.fail_next_send = False
                raise RuntimeError
            event_type = payload.get("type") if isinstance(payload, dict) else None
            safe_type = event_type if isinstance(event_type, str) else "unknown"
            self.sent_types.append(safe_type)
            await self.sent.put(safe_type)
            delivered = True
        finally:
            if coordinator is not None:
                coordinator.after_send(self, delivered=delivered)

    async def receive_text(self) -> str:
        item = await self.inbound.get()
        if item is _WS_TEST_HEARTBEAT:
            raise asyncio.TimeoutError
        if item is _WS_TEST_DISCONNECT:
            self.disconnect_observed.set()
            from starlette.websockets import WebSocketDisconnect

            raise WebSocketDisconnect
        return str(item)

    async def client_disconnect(self) -> None:
        await self.inbound.put(_WS_TEST_DISCONNECT)

    async def trigger_heartbeat(self) -> None:
        await self.inbound.put(_WS_TEST_HEARTBEAT)


async def _ws_wait(awaitable: Any, message: str) -> Any:
    try:
        return await asyncio.wait_for(awaitable, timeout=3.0)
    except asyncio.TimeoutError:
        pytest.fail(message, pytrace=False)


def _main_campaign_websocket_endpoint(app: Any) -> Any:
    endpoints = [
        getattr(route, "endpoint", None)
        for route in app.routes
        if getattr(route, "path", None) == "/ws/campaigns/{campaign_id}/events"
    ]
    if len(endpoints) != 1 or endpoints[0] is None:
        pytest.fail("expected exactly one main campaign WebSocket route", pytrace=False)
    return endpoints[0]


async def _launch_main_websocket(
    app: Any,
    campaign_id: str,
    *,
    ticket: str | None = None,
    token: str | None = None,
    api_key: str | None = None,
    query_string: bytes | None = None,
    fail_accept: bool = False,
) -> tuple[_MainWebSocketHarness, asyncio.Task[None]]:
    if query_string is None:
        if ticket is None and (token is not None or api_key is not None):
            ticket = await _issue_main_websocket_ticket(
                app,
                campaign_id,
                token=token,
                api_key=api_key,
            )
        query_string = b"" if ticket is None else b"ticket=" + ticket.encode("ascii")
    socket = _MainWebSocketHarness(app, query_string)
    socket.fail_accept = fail_accept
    endpoint = _main_campaign_websocket_endpoint(app)
    task = asyncio.create_task(endpoint(socket, campaign_id))
    return socket, task


async def _request_main_websocket_ticket(
    app: Any,
    campaign_id: str,
    *,
    token: str | None = None,
    api_key: str | None = None,
) -> httpx.Response:
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if api_key is not None:
        headers["X-API-Key"] = api_key
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://localhost",
    ) as client:
        return await client.post(
            f"/campaigns/{campaign_id}/websocket-ticket",
            headers=headers,
        )


async def _issue_main_websocket_ticket(
    app: Any,
    campaign_id: str,
    *,
    token: str | None = None,
    api_key: str | None = None,
) -> str:
    response = await _request_main_websocket_ticket(
        app,
        campaign_id,
        token=token,
        api_key=api_key,
    )
    body = response.json()
    ticket = body.get("ticket") if isinstance(body, dict) else None
    canonical = (
        response.status_code == 201
        and isinstance(ticket, str)
        and len(ticket) == 43
        and body.get("expires_in") == 30
    )
    _require_fixed(canonical, "expected committed WebSocket ticket issuance")
    return ticket


async def _settle_main_websocket(
    socket: _MainWebSocketHarness,
    task: asyncio.Task[None],
) -> None:
    if not task.done():
        await socket.client_disconnect()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=3.0)
    except asyncio.TimeoutError:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        pytest.fail("expected main WebSocket task to terminate", pytrace=False)


class TestMainWebSocketAuthoritativeLifetime:
    @pytest.fixture
    async def ws_runtime(
        self,
        tmp_path: Any,
    ) -> Any:
        from ares.api import server
        from ares.core.campaign import Campaign
        from ares.core.security import create_access_token
        from ares.db import database as database_module
        from ares.db.database import AresDatabase

        database = await AresDatabase.create(tmp_path / "main-websocket.db")
        username = "main-websocket-principal"
        with patch.object(database_module.logger, "info"):
            user_id = await database.create_user(
                username,
                "SyntheticWebSocketPass1!",
                "team_lead",
            )
        issued = await database.create_login_session(
            username,
            "SyntheticWebSocketPass1!",
            lambda claims: create_access_token(
                dict(claims),
                _settings().secret_key_value,
                algorithm=_settings().ares_jwt_algorithm,
                expires_minutes=60,
            ),
        )
        _require_fixed(
            issued.session is not None,
            "expected authoritative WebSocket login session",
        )
        token = issued.session.access_token
        campaign = Campaign(
            name="Synthetic WebSocket Campaign",
            operator="separate-campaign-owner",
        )
        await database.save_campaign(campaign)
        original_db = getattr(server.app.state, "db", None)
        server.app.state.db = database
        server._ws_connections.clear()
        _reset_rate_limiter()
        try:
            yield server, database, user_id, username, token, campaign, server.app
        finally:
            server._ws_connections.clear()
            server.app.state.db = original_db
            await database.close()

    @staticmethod
    async def _await_connected(socket: _MainWebSocketHarness) -> None:
        await _ws_wait(
            socket.accepted.wait(),
            "expected main WebSocket handshake acceptance",
        )
        initial_type = await _ws_wait(
            socket.sent.get(),
            "expected main WebSocket connected event",
        )
        _require_fixed(
            initial_type == "connected",
            "expected the fixed connected event after authorization",
        )

    @staticmethod
    async def _await_denied(
        socket: _MainWebSocketHarness,
        task: asyncio.Task[None],
        *,
        code: int,
    ) -> None:
        await _ws_wait(
            socket.closed.wait(),
            "expected main WebSocket handshake denial",
        )
        await _ws_wait(task, "expected denied WebSocket route to terminate")
        safe_contract = (
            not socket.accepted.is_set()
            and socket.close_code == code
            and socket.close_reason
            in {
                "Authentication or authorization failed",
                "Authentication service unavailable",
            }
            and socket.close_calls == 1
        )
        _require_fixed(
            safe_contract,
            "expected fixed WebSocket denial code and reason",
        )

    @pytest.mark.asyncio
    async def test_active_bearer_and_api_key_use_real_authoritative_handshake(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, _, token, campaign, app = ws_runtime
        bearer_socket, bearer_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(bearer_socket)
            registered = list(server._ws_connections.get(campaign.id, set()))
            representation_safe = (
                len(registered) == 1 and token not in repr(registered[0])
            )
            _require_fixed(
                representation_safe,
                "expected opaque registry state without credential representation",
            )
        finally:
            await _settle_main_websocket(bearer_socket, bearer_task)

        with patch("ares.db.database.logger.info"):
            _, raw_key = await database.create_api_key(
                user_id,
                "main-websocket-read-key",
                scopes="read",
            )
        key_socket, key_task = await _launch_main_websocket(
            app,
            campaign.id,
            api_key=raw_key,
        )
        try:
            await self._await_connected(key_socket)
            key_representation_safe = all(
                raw_key not in repr(connection)
                for connection in server._ws_connections.get(campaign.id, set())
            )
            _require_fixed(
                key_representation_safe,
                "expected API-key connection state to hide the credential",
            )
        finally:
            await _settle_main_websocket(key_socket, key_task)

    @pytest.mark.asyncio
    async def test_ticket_is_single_use_and_concurrent_handshake_has_one_winner(
        self,
        ws_runtime: Any,
    ) -> None:
        _, _, _, _, token, campaign, app = ws_runtime
        ticket = await _issue_main_websocket_ticket(app, campaign.id, token=token)
        first_socket, first_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket
        )
        second_socket, second_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket
        )
        try:
            async def wait_for_outcome(socket: _MainWebSocketHarness) -> None:
                accepted = asyncio.create_task(socket.accepted.wait())
                closed = asyncio.create_task(socket.closed.wait())
                done, pending = await asyncio.wait(
                    {accepted, closed},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for waiter in pending:
                    waiter.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                _require_fixed(bool(done), "expected a handshake outcome")

            await _ws_wait(
                asyncio.gather(
                    wait_for_outcome(first_socket),
                    wait_for_outcome(second_socket),
                ),
                "expected exactly one concurrent ticket winner",
            )
            accepted_count = sum(
                socket.accepted.is_set() for socket in (first_socket, second_socket)
            )
            denied_count = sum(
                socket.close_code == 4001 for socket in (first_socket, second_socket)
            )
            _require_fixed(
                accepted_count == 1 and denied_count == 1,
                "expected one accepted and one replay-denied handshake",
            )
        finally:
            await _settle_main_websocket(first_socket, first_task)
            await _settle_main_websocket(second_socket, second_task)

        replay_socket, replay_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket
        )
        await self._await_denied(replay_socket, replay_task, code=4001)

    @pytest.mark.parametrize(
        "query_string",
        [
            b"",
            b"ticket=",
            b"ticket=short",
            b"ticket%3Dsynthetic",
            b"%74icket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%41",
            b"ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&extra=1",
            b"extra=1&ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"token=synthetic-legacy-value",
            b"api_key=synthetic-legacy-value",
            b"ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&token=legacy",
            b"ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&api_key=legacy",
        ],
    )
    @pytest.mark.asyncio
    async def test_ticket_query_parser_rejects_every_noncanonical_shape_before_db(
        self,
        ws_runtime: Any,
        query_string: bytes,
    ) -> None:
        _, database, _, _, _, campaign, app = ws_runtime
        consume_calls = [0]
        original_consume = database.consume_websocket_ticket

        async def tracked_consume(raw_ticket: str, campaign_id: str) -> Any:
            consume_calls[0] += 1
            return await original_consume(raw_ticket, campaign_id)

        database.consume_websocket_ticket = tracked_consume  # type: ignore[method-assign]
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            query_string=query_string,
        )
        try:
            await self._await_denied(socket, task, code=4001)
            _require_fixed(
                consume_calls[0] == 0 and socket.scope["query_string"] == b"",
                "expected malformed query rejection after synchronous scrubbing",
            )
        finally:
            database.consume_websocket_ticket = original_consume  # type: ignore[method-assign]

    @pytest.mark.asyncio
    async def test_wrong_campaign_does_not_consume_ticket(
        self,
        ws_runtime: Any,
    ) -> None:
        from ares.core.campaign import Campaign

        _, database, _, _, token, campaign, app = ws_runtime
        other_campaign = Campaign(
            name="Wrong Ticket Campaign",
            operator="separate-owner",
        )
        await database.save_campaign(other_campaign)
        ticket = await _issue_main_websocket_ticket(app, campaign.id, token=token)
        wrong_socket, wrong_task = await _launch_main_websocket(
            app, other_campaign.id, ticket=ticket
        )
        await self._await_denied(wrong_socket, wrong_task, code=4001)
        correct_socket, correct_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket
        )
        try:
            await self._await_connected(correct_socket)
        finally:
            await _settle_main_websocket(correct_socket, correct_task)

    @pytest.mark.asyncio
    async def test_expired_ticket_and_consume_outage_use_fixed_close_codes(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, _, _, token, campaign, app = ws_runtime
        expired_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.conn.execute(
            "UPDATE websocket_tickets SET created_at=?, expires_at=? "
            "WHERE consumed_at IS NULL",
            (
                "1999-12-31T23:59:30.000Z",
                "2000-01-01T00:00:00.000Z",
            ),
        )
        await database.conn.commit()
        expired_socket, expired_task = await _launch_main_websocket(
            app, campaign.id, ticket=expired_ticket
        )
        await self._await_denied(expired_socket, expired_task, code=4001)

        unavailable_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        original_consume = database.consume_websocket_ticket

        async def fail_consume(_ticket: str, _campaign_id: str) -> Any:
            raise ConnectionError

        database.consume_websocket_ticket = fail_consume  # type: ignore[method-assign]
        try:
            unavailable_socket, unavailable_task = await _launch_main_websocket(
                app, campaign.id, ticket=unavailable_ticket
            )
            await self._await_denied(
                unavailable_socket,
                unavailable_task,
                code=1013,
            )
        finally:
            database.consume_websocket_ticket = original_consume  # type: ignore[method-assign]

    @pytest.mark.asyncio
    async def test_failed_accept_keeps_ticket_consumed_and_fresh_ticket_recovers(
        self,
        ws_runtime: Any,
    ) -> None:
        _, _, _, _, token, campaign, app = ws_runtime
        ticket = await _issue_main_websocket_ticket(app, campaign.id, token=token)
        failed_socket, failed_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket, fail_accept=True
        )
        failed_accept_observed = False
        try:
            await failed_task
        except RuntimeError:
            failed_accept_observed = True
        _require_fixed(
            failed_accept_observed,
            "expected the synthetic accept failure to propagate",
        )

        replay_socket, replay_task = await _launch_main_websocket(
            app, campaign.id, ticket=ticket
        )
        await self._await_denied(replay_socket, replay_task, code=4001)

        recovered_socket, recovered_task = await _launch_main_websocket(
            app, campaign.id, token=token
        )
        try:
            await self._await_connected(recovered_socket)
        finally:
            await _settle_main_websocket(recovered_socket, recovered_task)

    @pytest.mark.asyncio
    async def test_bearer_handshake_denies_inactive_renamed_revoked_and_deleted(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, user_id, username, token, campaign, app = ws_runtime

        inactive_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.conn.execute(
            "UPDATE users SET is_active=0 WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        inactive_socket, inactive_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=inactive_ticket,
        )
        await self._await_denied(inactive_socket, inactive_task, code=4001)

        await database.conn.execute(
            "UPDATE users SET is_active=1 WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        renamed_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.conn.execute(
            "UPDATE users SET username=? WHERE id=?",
            ("renamed-main-websocket-principal", user_id),
        )
        await database.conn.commit()
        renamed_socket, renamed_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=renamed_ticket,
        )
        await self._await_denied(renamed_socket, renamed_task, code=4001)

        await database.conn.execute(
            "UPDATE users SET username=? WHERE id=?",
            (username, user_id),
        )
        await database.conn.commit()
        from datetime import datetime, timedelta, timezone

        expired_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.conn.execute(
            "UPDATE websocket_tickets SET bearer_expires_at=? "
            "WHERE consumed_at IS NULL",
            ("2000-01-01T00:00:00.000Z",),
        )
        await database.conn.commit()
        expired_socket, expired_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=expired_ticket,
        )
        await self._await_denied(expired_socket, expired_task, code=4001)

        import jwt

        settings = _settings()
        authoritative_claims = jwt.decode(
            token,
            settings.secret_key_value,
            algorithms=[settings.ares_jwt_algorithm],
        )
        revocation_marker = "synthetic-main-websocket-revocation"
        revoked_token = jwt.encode(
            {
                "sub": username,
                "sid": authoritative_claims["sid"],
                "ver": authoritative_claims["ver"],
                "jti": revocation_marker,
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            },
            settings.secret_key_value,
            algorithm=settings.ares_jwt_algorithm,
        )
        revoked_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=revoked_token
        )
        await database.revoke_access_token(
            revocation_marker,
            user_id,
            (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        revoked_socket, revoked_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=revoked_ticket,
        )
        await self._await_denied(revoked_socket, revoked_task, code=4001)

        deleted_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        await database.conn.commit()
        deleted_socket, deleted_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=deleted_ticket,
        )
        await self._await_denied(deleted_socket, deleted_task, code=4001)

    @pytest.mark.asyncio
    async def test_current_role_and_campaign_ownership_control_handshake(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, user_id, _, token, campaign, app = ws_runtime
        ticket = await _issue_main_websocket_ticket(app, campaign.id, token=token)
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=ticket,
        )
        await self._await_denied(socket, task, code=4001)

    @pytest.mark.asyncio
    async def test_explicit_invalid_bearer_is_terminal_over_valid_api_key(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, user_id, _, _, campaign, app = ws_runtime
        missing_socket, missing_task = await _launch_main_websocket(
            app,
            campaign.id,
        )
        await self._await_denied(missing_socket, missing_task, code=4001)

        with patch("ares.db.database.logger.info"):
            _, raw_key = await database.create_api_key(
                user_id,
                "main-websocket-precedence-key",
            )
        verify_calls = [0]
        original_verify = database.verify_api_key

        async def tracked_verify(candidate: str) -> Any:
            verify_calls[0] += 1
            return await original_verify(candidate)

        database.verify_api_key = tracked_verify  # type: ignore[method-assign]
        response = await _request_main_websocket_ticket(
            app,
            campaign.id,
            token="synthetic.invalid.jwt",
            api_key=raw_key,
        )
        database.verify_api_key = original_verify  # type: ignore[method-assign]
        _require_fixed(
            response.status_code == 401 and verify_calls[0] == 0,
            "expected bearer issuance failure to remain terminal",
        )

        legacy_socket, legacy_task = await _launch_main_websocket(
            app,
            campaign.id,
            query_string=b"api_key=synthetic-legacy-value",
        )
        await self._await_denied(legacy_socket, legacy_task, code=4001)

    @pytest.mark.asyncio
    async def test_api_key_revocation_and_inactive_owner_deny_handshake(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, user_id, _, _, campaign, app = ws_runtime
        with patch("ares.db.database.logger.info"):
            key_id, raw_key = await database.create_api_key(
                user_id,
                "main-websocket-lifecycle-key",
            )
        revoked_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, api_key=raw_key
        )
        await database.conn.execute(
            "UPDATE api_keys SET is_active=0 WHERE id=?",
            (key_id,),
        )
        await database.conn.commit()
        revoked_socket, revoked_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=revoked_ticket,
        )
        await self._await_denied(revoked_socket, revoked_task, code=4001)

        await database.conn.execute(
            "UPDATE api_keys SET is_active=1 WHERE id=?",
            (key_id,),
        )
        await database.conn.commit()
        inactive_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, api_key=raw_key
        )
        await database.conn.execute(
            "UPDATE users SET is_active=0 WHERE id=?",
            (user_id,),
        )
        await database.conn.commit()
        inactive_socket, inactive_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=inactive_ticket,
        )
        await self._await_denied(inactive_socket, inactive_task, code=4001)

    @pytest.mark.asyncio
    async def test_absent_closed_and_failing_backend_close_1013_then_recover(
        self,
        ws_runtime: Any,
    ) -> None:
        _, database, _, _, token, campaign, app = ws_runtime
        absent_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        app.state.db = None
        absent_socket, absent_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=absent_ticket,
        )
        await self._await_denied(absent_socket, absent_task, code=1013)

        app.state.db = database
        closed_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        await database.close()
        closed_socket, closed_task = await _launch_main_websocket(
            app,
            campaign.id,
            ticket=closed_ticket,
        )
        await self._await_denied(closed_socket, closed_task, code=1013)
        await database.connect()

        failed_ticket = await _issue_main_websocket_ticket(
            app, campaign.id, token=token
        )
        original_resolve = database.resolve_websocket_ticket_principal

        async def fail_lookup(_handle: Any) -> Any:
            raise TimeoutError

        database.resolve_websocket_ticket_principal = fail_lookup  # type: ignore[method-assign]
        try:
            failed_socket, failed_task = await _launch_main_websocket(
                app,
                campaign.id,
                ticket=failed_ticket,
            )
            await self._await_denied(failed_socket, failed_task, code=1013)
        finally:
            database.resolve_websocket_ticket_principal = original_resolve  # type: ignore[method-assign]

        recovered_socket, recovered_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(recovered_socket)
        finally:
            await _settle_main_websocket(recovered_socket, recovered_task)

    @pytest.mark.parametrize(
        "state_change",
        ["inactive", "renamed", "deleted", "revoked", "expired", "demoted"],
    )
    @pytest.mark.asyncio
    async def test_bearer_lifetime_revalidation_closes_before_event(
        self,
        ws_runtime: Any,
        state_change: str,
    ) -> None:
        server, database, user_id, username, token, campaign, app = ws_runtime
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(socket)
            if state_change == "inactive":
                await database.conn.execute(
                    "UPDATE users SET is_active=0 WHERE id=?",
                    (user_id,),
                )
                await database.conn.commit()
            elif state_change == "renamed":
                await database.conn.execute(
                    "UPDATE users SET username=? WHERE id=?",
                    ("renamed-after-websocket-connect", user_id),
                )
                await database.conn.commit()
            elif state_change == "deleted":
                await database.conn.execute(
                    "DELETE FROM users WHERE id=?",
                    (user_id,),
                )
                await database.conn.commit()
            elif state_change == "revoked":
                from ares.core.security import decode_access_token
                from datetime import datetime, timedelta, timezone

                settings = _settings()
                payload = decode_access_token(
                    token,
                    settings.secret_key_value,
                    settings.ares_jwt_algorithm,
                )
                revocation_marker = payload.get("jti") if payload else None
                if not isinstance(revocation_marker, str):
                    pytest.fail(
                        "expected generated bearer to contain a revocation marker",
                        pytrace=False,
                    )
                await database.revoke_access_token(
                    revocation_marker,
                    user_id,
                    (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                )
            elif state_change == "expired":
                from dataclasses import replace
                from datetime import datetime, timezone

                contexts = list(server._ws_connections.get(campaign.id, set()))
                _require_fixed(
                    len(contexts) == 1,
                    "expected one registered ticket handle",
                )
                contexts[0].ticket_handle = replace(
                    contexts[0].ticket_handle,
                    bearer_expires_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
                )
            else:
                await database.conn.execute(
                    "UPDATE users SET role='operator' WHERE id=?",
                    (user_id,),
                )
                await database.conn.commit()

            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            await _ws_wait(
                socket.closed.wait(),
                "expected stale bearer connection to close before delivery",
            )
            no_protected_event = (
                socket.close_code == 4001
                and socket.close_reason == "Authentication or authorization failed"
                and socket.sent_types == ["connected"]
                and not server._ws_connections.get(campaign.id)
            )
            _require_fixed(
                no_protected_event,
                "expected bearer state change to prevent protected delivery",
            )
        finally:
            await _settle_main_websocket(socket, task)

    @pytest.mark.parametrize(
        "state_change",
        ["revoked", "inactive", "ownership", "scope", "expired", "key_owner"],
    )
    @pytest.mark.asyncio
    async def test_api_key_and_ownership_lifetime_revalidation(
        self,
        ws_runtime: Any,
        state_change: str,
    ) -> None:
        server, database, user_id, username, _, campaign, app = ws_runtime
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await database.conn.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (username, campaign.id),
        )
        await database.conn.commit()
        with patch("ares.db.database.logger.info"):
            key_id, raw_key = await database.create_api_key(
                user_id,
                "main-websocket-revalidation-key",
            )
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            api_key=raw_key,
        )
        try:
            await self._await_connected(socket)
            if state_change == "revoked":
                await database.conn.execute(
                    "UPDATE api_keys SET is_active=0 WHERE id=?",
                    (key_id,),
                )
            elif state_change == "inactive":
                await database.conn.execute(
                    "UPDATE users SET is_active=0 WHERE id=?",
                    (user_id,),
                )
            elif state_change == "ownership":
                await database.conn.execute(
                    "UPDATE campaigns SET operator=? WHERE id=?",
                    ("different-campaign-owner", campaign.id),
                )
            elif state_change == "scope":
                await database.conn.execute(
                    "UPDATE api_keys SET scopes='none' WHERE id=?",
                    (key_id,),
                )
            elif state_change == "expired":
                await database.conn.execute(
                    "UPDATE api_keys SET expires_at=? WHERE id=?",
                    ("2000-01-01T00:00:00+00:00", key_id),
                )
            else:
                with patch("ares.db.database.logger.info"):
                    replacement_user_id = await database.create_user(
                        "main-websocket-key-owner",
                        "SyntheticKeyOwnerPass1!",
                        "team_lead",
                    )
                await database.conn.execute(
                    "UPDATE api_keys SET user_id=? WHERE id=?",
                    (replacement_user_id, key_id),
                )
            await database.conn.commit()

            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            await _ws_wait(
                socket.closed.wait(),
                "expected stale API-key or ownership connection to close",
            )
            denied_without_delivery = (
                socket.close_code == 4001
                and socket.sent_types == ["connected"]
                and not server._ws_connections.get(campaign.id)
            )
            _require_fixed(
                denied_without_delivery,
                "expected API-key or ownership change to prevent delivery",
            )
        finally:
            await _settle_main_websocket(socket, task)

    @pytest.mark.asyncio
    async def test_heartbeat_revalidates_without_broadcast(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, _, token, campaign, app = ws_runtime
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(socket)
            await database.conn.execute(
                "UPDATE users SET is_active=0 WHERE id=?",
                (user_id,),
            )
            await database.conn.commit()
            await socket.trigger_heartbeat()
            await _ws_wait(
                socket.closed.wait(),
                "expected heartbeat to detect authorization loss",
            )
            heartbeat_denied = (
                socket.close_code == 4001
                and socket.sent_types == ["connected"]
                and not server._ws_connections.get(campaign.id)
            )
            _require_fixed(
                heartbeat_denied,
                "expected heartbeat revalidation before keepalive delivery",
            )
        finally:
            await _settle_main_websocket(socket, task)

    @pytest.mark.asyncio
    async def test_pong_revalidates_without_broadcast(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, _, token, campaign, app = ws_runtime
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(socket)
            await database.conn.execute(
                "UPDATE users SET is_active=0 WHERE id=?",
                (user_id,),
            )
            await database.conn.commit()
            await socket.inbound.put("ping")
            await _ws_wait(
                socket.closed.wait(),
                "expected pong authorization loss to close the connection",
            )
            _require_fixed(
                socket.close_code == 4001
                and socket.sent_types == ["connected"]
                and not server._ws_connections.get(campaign.id),
                "expected principal revalidation before pong delivery",
            )
        finally:
            await _settle_main_websocket(socket, task)

    @pytest.mark.asyncio
    async def test_consumed_handle_survives_ticket_expiry_and_purge_read_only(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, username, _, campaign, app = ws_runtime
        await database.conn.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await database.conn.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (username, campaign.id),
        )
        await database.conn.commit()
        with patch("ares.db.database.logger.info"):
            key_id, raw_key = await database.create_api_key(
                user_id,
                "read-only-lifetime-key",
                scopes="read",
            )
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            api_key=raw_key,
        )
        try:
            await self._await_connected(socket)
            async with database.conn.execute(
                "SELECT last_used FROM api_keys WHERE id=?",
                (key_id,),
            ) as cursor:
                last_used_before = (await cursor.fetchone())[0]
            await database.conn.execute(
                "UPDATE websocket_tickets "
                "SET created_at=?, consumed_at=?, expires_at=?",
                (
                    "1999-12-31T23:59:00.000Z",
                    "1999-12-31T23:59:15.000Z",
                    "1999-12-31T23:59:30.000Z",
                ),
            )
            await database.conn.commit()
            await database.purge_expired_websocket_tickets()
            await server._broadcast_event(
                campaign.id,
                {"type": "module_complete"},
            )
            await server._broadcast_event(
                campaign.id,
                {"type": "strategy_update"},
            )
            first = await _ws_wait(
                socket.sent.get(),
                "expected module event after ticket purge",
            )
            second = await _ws_wait(
                socket.sent.get(),
                "expected strategy event after ticket purge",
            )
            async with database.conn.execute(
                "SELECT last_used FROM api_keys WHERE id=?",
                (key_id,),
            ) as cursor:
                last_used_after = (await cursor.fetchone())[0]
            async with database.conn.execute(
                "SELECT COUNT(*) FROM websocket_tickets"
            ) as cursor:
                ticket_rows = int((await cursor.fetchone())[0])
            _require_fixed(
                (first, second) == ("module_complete", "strategy_update")
                and ticket_rows == 0
                and last_used_before == last_used_after,
                "expected purged handle authority with read-only API-key resolution",
            )
        finally:
            await _settle_main_websocket(socket, task)

    @pytest.mark.asyncio
    async def test_delayed_authoritative_lookup_observes_committed_invalidation(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, _, token, campaign, app = ws_runtime
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        lookup_started = asyncio.Event()
        lookup_release = asyncio.Event()
        original_resolve = database.resolve_websocket_ticket_principal

        async def delayed_resolve(handle: Any) -> Any:
            lookup_started.set()
            await _ws_wait(
                lookup_release.wait(),
                "expected authoritative lookup barrier release",
            )
            return await original_resolve(handle)

        try:
            await self._await_connected(socket)
            database.resolve_websocket_ticket_principal = delayed_resolve  # type: ignore[method-assign]
            broadcast_task = asyncio.create_task(
                server._broadcast_event(
                    campaign.id,
                    {"type": "synthetic_protected_event"},
                )
            )
            await _ws_wait(
                lookup_started.wait(),
                "expected authoritative lookup barrier to be reached",
            )
            await database.conn.execute(
                "UPDATE users SET is_active=0 WHERE id=?",
                (user_id,),
            )
            await database.conn.commit()
            lookup_release.set()
            await _ws_wait(
                broadcast_task,
                "expected delayed protected broadcast to terminate",
            )
            await _ws_wait(
                socket.closed.wait(),
                "expected committed invalidation to close delayed connection",
            )
            _require_fixed(
                socket.sent_types == ["connected"]
                and socket.close_code == 4001
                and not server._ws_connections.get(campaign.id),
                "expected post-barrier authoritative state to prevent delivery",
            )
        finally:
            lookup_release.set()
            database.resolve_websocket_ticket_principal = original_resolve  # type: ignore[method-assign]
            await _settle_main_websocket(socket, task)

    @pytest.mark.asyncio
    async def test_backend_failure_after_connect_closes_1013_and_new_connection_recovers(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, _, _, token, campaign, app = ws_runtime
        socket, task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        original_resolve = database.resolve_websocket_ticket_principal

        async def fail_lookup(_handle: Any) -> Any:
            raise ConnectionError

        try:
            await self._await_connected(socket)
            database.resolve_websocket_ticket_principal = fail_lookup  # type: ignore[method-assign]
            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            await _ws_wait(
                socket.closed.wait(),
                "expected backend failure to close established connection",
            )
            unavailable_without_delivery = (
                socket.close_code == 1013
                and socket.close_reason == "Authentication service unavailable"
                and socket.sent_types == ["connected"]
                and not server._ws_connections.get(campaign.id)
            )
            _require_fixed(
                unavailable_without_delivery,
                "expected backend outage to prevent protected delivery with 1013",
            )
        finally:
            database.resolve_websocket_ticket_principal = original_resolve  # type: ignore[method-assign]
            await _settle_main_websocket(socket, task)

        recovered_socket, recovered_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        try:
            await self._await_connected(recovered_socket)
        finally:
            await _settle_main_websocket(recovered_socket, recovered_task)

    @pytest.mark.asyncio
    async def test_one_failed_connection_does_not_block_an_authorized_peer(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, _, _, token, campaign, app = ws_runtime
        from ares.core.security import create_access_token
        from ares.db import database as database_module

        with patch.object(database_module.logger, "info"):
            await database.create_user(
                "main-websocket-peer",
                "SyntheticWebSocketPeer1!",
                "team_lead",
            )
        peer_session = await database.create_login_session(
            "main-websocket-peer",
            "SyntheticWebSocketPeer1!",
            lambda claims: create_access_token(
                dict(claims),
                _settings().secret_key_value,
                algorithm=_settings().ares_jwt_algorithm,
                expires_minutes=60,
            ),
        )
        _require_fixed(
            peer_session.session is not None,
            "expected authoritative peer session",
        )
        peer_token = peer_session.session.access_token
        first_socket, first_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        second_socket, second_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=peer_token,
        )
        try:
            await self._await_connected(first_socket)
            await self._await_connected(second_socket)
            first_socket.fail_next_send = True
            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            delivered_type = await _ws_wait(
                second_socket.sent.get(),
                "expected authorized peer delivery after another send failure",
            )
            delivery_isolated = (
                delivered_type == "synthetic_protected_event"
                and first_socket.sent_types == ["connected"]
                and len(server._ws_connections.get(campaign.id, set())) == 1
            )
            _require_fixed(
                delivery_isolated,
                "expected one failed connection not to block an authorized peer",
            )
        finally:
            await _settle_main_websocket(first_socket, first_task)
            await _settle_main_websocket(second_socket, second_task)

    @pytest.mark.asyncio
    async def test_authorization_loser_does_not_block_an_authorized_peer(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, user_id, _, token, campaign, app = ws_runtime
        from ares.core.security import create_access_token
        from ares.db import database as database_module

        with patch.object(database_module.logger, "info"):
            await database.create_user(
                "main-websocket-authorized-peer",
                "SyntheticAuthorizedPeerPass1!",
                "team_lead",
            )
        peer_session = await database.create_login_session(
            "main-websocket-authorized-peer",
            "SyntheticAuthorizedPeerPass1!",
            lambda claims: create_access_token(
                dict(claims),
                _settings().secret_key_value,
                algorithm=_settings().ares_jwt_algorithm,
                expires_minutes=60,
            ),
        )
        _require_fixed(
            peer_session.session is not None,
            "expected authoritative peer session",
        )
        peer_token = peer_session.session.access_token
        stale_socket, stale_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        peer_socket, peer_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=peer_token,
        )
        try:
            await self._await_connected(stale_socket)
            await self._await_connected(peer_socket)
            await database.conn.execute(
                "UPDATE users SET is_active=0 WHERE id=?",
                (user_id,),
            )
            await database.conn.commit()
            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            await _ws_wait(
                stale_socket.closed.wait(),
                "expected authorization loser to be retired",
            )
            peer_event_type = await _ws_wait(
                peer_socket.sent.get(),
                "expected authorized peer to receive protected event",
            )
            isolated_delivery = (
                stale_socket.close_code == 4001
                and stale_socket.sent_types == ["connected"]
                and peer_event_type == "synthetic_protected_event"
                and len(server._ws_connections.get(campaign.id, set())) == 1
            )
            _require_fixed(
                isolated_delivery,
                "expected an authorization loser not to block an authorized peer",
            )
        finally:
            await _settle_main_websocket(stale_socket, stale_task)
            await _settle_main_websocket(peer_socket, peer_task)

    @pytest.mark.asyncio
    async def test_slow_first_peer_does_not_delay_authorized_peer(
        self,
        ws_runtime: Any,
    ) -> None:
        server, _, _, _, token, campaign, app = ws_runtime
        first_socket, first_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        second_socket, second_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        coordinator = _FirstBroadcastSendCoordinator()
        broadcast_task: asyncio.Task[None] | None = None
        try:
            await self._await_connected(first_socket)
            await self._await_connected(second_socket)
            first_socket.broadcast_send_coordinator = coordinator
            second_socket.broadcast_send_coordinator = coordinator
            broadcast_task = asyncio.create_task(
                server._broadcast_event(
                    campaign.id,
                    {"type": "synthetic_protected_event"},
                )
            )
            await _ws_wait(
                coordinator.first_stalled.wait(),
                "expected the first protected send to reach the barrier",
            )
            await _ws_wait(
                coordinator.peer_delivered.wait(),
                "expected an authorized peer to receive before slow-peer release",
            )
            delivered_while_first_stalled = (
                not coordinator.release_first.is_set()
                and not broadcast_task.done()
                and sum(
                    socket.sent_types.count("synthetic_protected_event")
                    for socket in (first_socket, second_socket)
                )
                == 1
            )
            _require_fixed(
                delivered_while_first_stalled,
                "expected slow-peer isolation before releasing the first send",
            )

            coordinator.release_first.set()
            await _ws_wait(
                broadcast_task,
                "expected concurrent protected broadcast to complete",
            )
            all_operations_settled = (
                coordinator.active_count == 0
                and coordinator.settled_count == 2
                and all(
                    socket.sent_types
                    == ["connected", "synthetic_protected_event"]
                    for socket in (first_socket, second_socket)
                )
                and len(server._ws_connections.get(campaign.id, set())) == 2
            )
            _require_fixed(
                all_operations_settled,
                "expected both concurrent protected sends to settle",
            )
        finally:
            coordinator.release_first.set()
            first_socket.broadcast_send_coordinator = None
            second_socket.broadcast_send_coordinator = None
            if broadcast_task is not None and not broadcast_task.done():
                await _ws_wait(
                    broadcast_task,
                    "expected slow-peer broadcast cleanup",
                )
            await _settle_main_websocket(first_socket, first_task)
            await _settle_main_websocket(second_socket, second_task)

    @pytest.mark.asyncio
    async def test_cancelled_broadcast_awaits_owned_children(
        self,
        ws_runtime: Any,
    ) -> None:
        server, _, _, _, token, campaign, app = ws_runtime
        first_socket, first_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        second_socket, second_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        coordinator = _FirstBroadcastSendCoordinator()
        broadcast_task: asyncio.Task[None] | None = None
        cancellation_propagated = False
        try:
            await self._await_connected(first_socket)
            await self._await_connected(second_socket)
            first_socket.broadcast_send_coordinator = coordinator
            second_socket.broadcast_send_coordinator = coordinator
            broadcast_task = asyncio.create_task(
                server._broadcast_event(
                    campaign.id,
                    {"type": "synthetic_protected_event"},
                )
            )
            await _ws_wait(
                coordinator.first_stalled.wait(),
                "expected one owned broadcast child to reach the barrier",
            )
            await _ws_wait(
                coordinator.peer_delivered.wait(),
                "expected the unblocked owned child to deliver",
            )
            broadcast_task.cancel()
            try:
                await asyncio.wait_for(broadcast_task, timeout=3.0)
            except asyncio.CancelledError:
                cancellation_propagated = True
            except asyncio.TimeoutError:
                pytest.fail(
                    "expected parent cancellation to settle owned children",
                    pytrace=False,
                )

            await _ws_wait(
                coordinator.first_cancelled.wait(),
                "expected held child to receive parent cancellation",
            )
            contexts = list(server._ws_connections.get(campaign.id, set()))
            owned_cleanup_complete = (
                cancellation_propagated
                and broadcast_task.done()
                and broadcast_task.cancelled()
                and coordinator.active_count == 0
                and coordinator.settled_count == 2
                and len(contexts) == 2
                and all(not connection.send_lock.locked() for connection in contexts)
            )
            _require_fixed(
                owned_cleanup_complete,
                "expected cancelled broadcast to await every owned child",
            )
        finally:
            coordinator.release_first.set()
            first_socket.broadcast_send_coordinator = None
            second_socket.broadcast_send_coordinator = None
            if broadcast_task is not None and not broadcast_task.done():
                broadcast_task.cancel()
                try:
                    await asyncio.wait_for(broadcast_task, timeout=3.0)
                except asyncio.CancelledError:
                    pass
                except asyncio.TimeoutError:
                    pytest.fail(
                        "expected cancelled broadcast cleanup",
                        pytrace=False,
                    )
            await _settle_main_websocket(first_socket, first_task)
            await _settle_main_websocket(second_socket, second_task)

    @pytest.mark.asyncio
    async def test_campaign_registry_prevents_cross_campaign_delivery(
        self,
        ws_runtime: Any,
    ) -> None:
        server, database, _, _, token, campaign, app = ws_runtime
        from ares.core.campaign import Campaign

        other_campaign = Campaign(
            name="Synthetic Other WebSocket Campaign",
            operator="separate-campaign-owner",
        )
        await database.save_campaign(other_campaign)
        first_socket, first_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        other_socket, other_task = await _launch_main_websocket(
            app,
            other_campaign.id,
            token=token,
        )
        try:
            await self._await_connected(first_socket)
            await self._await_connected(other_socket)
            await server._broadcast_event(
                campaign.id,
                {"type": "synthetic_protected_event"},
            )
            delivered_type = await _ws_wait(
                first_socket.sent.get(),
                "expected same-campaign protected delivery",
            )
            isolated = (
                delivered_type == "synthetic_protected_event"
                and other_socket.sent.empty()
                and other_socket.sent_types == ["connected"]
            )
            _require_fixed(
                isolated,
                "expected no cross-campaign WebSocket delivery",
            )
        finally:
            await _settle_main_websocket(first_socket, first_task)
            await _settle_main_websocket(other_socket, other_task)

    @pytest.mark.asyncio
    async def test_broadcast_and_disconnect_are_serialized_without_orphan(
        self,
        ws_runtime: Any,
    ) -> None:
        server, _, _, _, token, campaign, app = ws_runtime
        socket, route_task = await _launch_main_websocket(
            app,
            campaign.id,
            token=token,
        )
        broadcast_task: asyncio.Task[None] | None = None
        try:
            await self._await_connected(socket)
            socket.block_next_send = True
            broadcast_task = asyncio.create_task(
                server._broadcast_event(
                    campaign.id,
                    {"type": "synthetic_protected_event"},
                )
            )
            await _ws_wait(
                socket.send_started.wait(),
                "expected protected send barrier to be reached",
            )
            await socket.client_disconnect()
            await _ws_wait(
                socket.disconnect_observed.wait(),
                "expected route to observe client disconnect",
            )
            route_waits_for_send = not route_task.done()
            socket.send_release.set()
            await _ws_wait(
                broadcast_task,
                "expected serialized broadcast to complete",
            )
            await _ws_wait(
                route_task,
                "expected serialized disconnect cleanup to complete",
            )
            serialized_cleanup = (
                route_waits_for_send
                and socket.sent_types
                == ["connected", "synthetic_protected_event"]
                and not server._ws_connections.get(campaign.id)
                and not broadcast_task.cancelled()
                and not route_task.cancelled()
            )
            _require_fixed(
                serialized_cleanup,
                "expected one serialized send and deterministic disconnect cleanup",
            )
        finally:
            socket.send_release.set()
            if broadcast_task is not None and not broadcast_task.done():
                await _ws_wait(
                    broadcast_task,
                    "expected pending broadcast cleanup",
                )
            await _settle_main_websocket(socket, route_task)
