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


# ── Reports safety ───────────────────────────────────────────────────────────


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
