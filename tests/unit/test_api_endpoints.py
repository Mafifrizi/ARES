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
import os
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.security import OAuth2PasswordRequestForm

# ── env bootstrap (before any ares import) ────────────────────────────────────
os.environ.setdefault("ARES_SECRET_KEY", "test-api-secret-key-min32-chars!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY", "test-enc-key-min32-chars-xxxxxxx")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestApiPass1!")


# ── helpers ───────────────────────────────────────────────────────────────────


def _settings():
    from ares.core.config import AresSettings

    return AresSettings()


def _make_token(username: str, role: str) -> str:
    from ares.core.security import create_access_token

    s = _settings()
    return create_access_token(
        data={"sub": username, "role": role},
        secret_key=s.secret_key_value,
        expires_minutes=60,
    )


def _auth(username: str, role: str) -> dict:
    return {"Authorization": f"Bearer {_make_token(username, role)}"}


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
    return db


def _reset_rate_limiter() -> None:
    """Clear global in-process rate limiter to prevent cross-test bleed."""
    from ares.api.rbac import _limiter

    _limiter._windows.clear()


def _run(coro):
    """Run a coroutine in a new event loop (for sync pytest methods)."""
    return asyncio.get_event_loop().run_until_complete(coro)


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
    # Clear lru_cache so unit tests always use UNIT env vars,
    # not a cached instance from a previous integration test run.
    from ares.core.config import get_settings as _get_settings_fn

    _get_settings_fn.cache_clear()

    from ares.api.server import app as _app
    from ares.api.server import get_db, get_settings
    from ares.core.config import AresSettings

    mock_db = _make_mock_db()
    fake_settings = AresSettings()

    # Set app.state.db for endpoints that read it directly (e.g. /health)
    _app.state.db = mock_db

    _app.dependency_overrides[get_db] = lambda: mock_db
    _app.dependency_overrides[get_settings] = lambda: fake_settings

    yield _app, mock_db

    _app.dependency_overrides.clear()
    # Clear cache again so the next test module starts fresh
    _get_settings_fn.cache_clear()


@pytest.fixture(scope="module")
def aclient(_app_mock_db):
    """Async httpx client with ASGITransport. base_url=localhost passes TrustedHostMiddleware."""
    _app, mock_db = _app_mock_db
    transport = httpx.ASGITransport(app=_app)
    client = httpx.AsyncClient(transport=transport, base_url="http://localhost")
    yield client, mock_db, _app
    asyncio.run(client.aclose())


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
        db.verify_user.return_value = {
            "id": "u1",
            "username": "admin",
            "role": "team_lead",
        }

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
            assert "refresh_token" in body
            assert body["token_type"] == "bearer"  # noqa: S105 - OAuth token type
        finally:
            del _app.dependency_overrides[OAuth2PasswordRequestForm]
            db.verify_user.return_value = None

    @pytest.mark.asyncio
    async def test_unauthenticated_endpoint_returns_401(self, aclient):
        c, _, __ = aclient
        assert (await c.get("/campaigns/any-id")).status_code == 401


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
            ("post", "/auth/logout", {}),
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
    async def test_kerberoast_dashboard_payload_passes_api_validation(
        self, aclient: Any
    ) -> None:
        c, db, app = aclient
        from ares.api.server import get_engine
        from ares.modules.ad.kerberoast import KerberoastModule

        captured: dict[str, Any] = {}

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
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
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        try:
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

        assert r.status_code == 200
        assert captured["module_id"] == "ad.kerberoast"
        assert captured["actor_role"] == "team_lead"
        assert captured["params"] == {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "use_ldaps": False,
            "target_user": "sqlsvc",
        }

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
        db.record_module_run.assert_awaited_once()
        assert db.record_module_run.await_args.kwargs["outcome"] == "confirmed_findings"
        assert db.record_module_run.await_args.kwargs["success"] is True


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
        from ares.api.server import get_db, get_engine
        from ares.core.campaign import Campaign, Finding, NoiseProfile, ScopeEntry, Severity
        from ares.core.engine import EngineModuleResult, ModuleStatus
        from ares.db.database import AresDatabase

        real_report_generator = report_gen.ReportGenerator
        real_db = await AresDatabase.create(tmp_path / "ares.db")
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

        class FakeRegistry:
            def get(self, module_id: str) -> Any:
                return None

        class FakeEngine:
            registry = FakeRegistry()

            async def run_module(
                self,
                module_id: str,
                campaign: Any,
                params: dict[str, Any],
                actor_role: str = "",
            ) -> EngineModuleResult:
                if module_id == "ad.asreproast":
                    finding = Finding(
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
                else:
                    finding = Finding(
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
                return EngineModuleResult(
                    module_id=module_id,
                    status=ModuleStatus.DONE,
                    findings=[finding],
                    raw_output={"confirmed": 1},
                    duration_ms=12.0,
                )

        def generator_factory(*args: Any, **kwargs: Any) -> Any:
            return real_report_generator(output_dir=str(tmp_path / "reports"), **kwargs)

        app.state.db = real_db
        app.dependency_overrides[get_db] = lambda: real_db
        app.dependency_overrides[get_engine] = lambda: FakeEngine()
        monkeypatch.setattr(report_gen, "ReportGenerator", generator_factory)
        try:
            common_params = {
                "dc": "10.10.10.20",
                "domain": "lab.local",
                "username": "lab\\operator",
                "password": "CorrectHorseBatteryStaple!",
                "use_ldaps": False,
            }
            asrep = await c.post(
                f"/modules/ad.asreproast/run",
                headers=_auth("admin", "team_lead"),
                json={
                    "campaign_id": campaign.id,
                    "params": common_params,
                    "dry_run": False,
                },
            )
            kerb = await c.post(
                f"/modules/ad.kerberoast/run",
                headers=_auth("admin", "team_lead"),
                json={
                    "campaign_id": campaign.id,
                    "params": {**common_params, "target_user": "svc-sql"},
                    "dry_run": False,
                },
            )
            assert asrep.status_code == 200
            assert kerb.status_code == 200

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
                headers=_auth("admin", "team_lead"),
            )
            assert findings_response.status_code == 200
            assert len(findings_response.json()) == 2

            report_response = await c.post(
                f"/reports/{campaign.id}?fmt=json",
                headers=_auth("admin", "team_lead"),
            )
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides.pop(get_engine, None)
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
