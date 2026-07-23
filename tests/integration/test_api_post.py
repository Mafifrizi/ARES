"""
ARES API Integration Tests — POST body endpoints.

Uses full FastAPI lifespan with an in-memory SQLite database.
Tests JSON body parsing, business logic, and DB persistence end-to-end
without any mocks.

Each test class creates its own TestClient to avoid lru_cache(get_settings)
cross-contamination when run in the same process as unit tests.

Coverage:
  POST /auth/token (form)          — login, get tokens
  POST /auth/refresh               — refresh token rotation
  POST /auth/register              — register new user
  POST /auth/change-password       — password change
  POST /campaigns                  — create campaign + DB persist
  POST /campaigns/{id}/run (body)  — run plan (dry_run=True)
  GET  /campaigns/{id}             — verify persist after POST
  GET  /campaigns/{id}/findings    — findings list
  Security headers on POST responses

Run: pytest tests/integration/test_api_post.py -v --timeout=30
"""
from __future__ import annotations

import os

# ── env must be set BEFORE any ares import ────────────────────────────────────
_SECRET = "integration-post-test-secret-32ab"
_ENCKEY = "integration-enc-key-min32-chars!!"
_ADMIN  = "IntegrationAdmin1!"
_DBURL  = "sqlite+aiosqlite:///file:int_post_test?mode=memory&cache=shared&uri=true"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module", autouse=True)
def isolated_api_post_environment():
    """Keep this integration database URL from leaking into the full suite."""
    updates = {
        "ARES_SECRET_KEY": _SECRET,
        "ARES_ENCRYPTION_KEY": _ENCKEY,
        "ARES_DEFAULT_ADMIN_PASSWORD": _ADMIN,
        "ARES_DATABASE_URL": _DBURL,
    }
    original = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    from ares.core.config import get_settings

    get_settings.cache_clear()
    yield
    for key, value in original.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()


def _fresh_client() -> TestClient:
    """
    Return a TestClient with a fresh settings cache.
    Called once per test class so lru_cache doesn't bleed from unit tests.
    """
    from ares.core.config import get_settings
    get_settings.cache_clear()   # clear lru_cache — force re-read from env
    from ares.api.server import app
    return TestClient(app, base_url="http://localhost", raise_server_exceptions=False)


def _login(client: TestClient, password: str = _ADMIN) -> str:
    r = client.post("/auth/token",
                    data={"username": "admin", "password": password})
    assert r.status_code == 200, f"Login failed ({r.status_code}): {r.text}"
    return r.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Auth flow ─────────────────────────────────────────────────────────────────

class TestAuthPostEndpoints:

    @pytest.fixture(scope="class")
    def c(self):
        with _fresh_client() as client:
            yield client

    @pytest.fixture(scope="class")
    def token(self, c):
        return _login(c)

    def test_login_valid_returns_tokens(self, c):
        r = c.post("/auth/token", data={"username": "admin", "password": _ADMIN})
        assert r.status_code == 200
        body = r.json()
        assert "access_token"  in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"
        assert body["role"]       == "team_lead"

    def test_login_wrong_password_returns_401(self, c):
        r = c.post("/auth/token", data={"username": "admin", "password": "WrongPass!"})
        assert r.status_code == 401

    def test_login_unknown_user_returns_401(self, c):
        r = c.post("/auth/token", data={"username": "nobody", "password": "anything"})
        assert r.status_code == 401

    def test_refresh_invalid_token_returns_401(self, c):
        r = c.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})
        assert r.status_code == 401

    def test_refresh_valid_rotates_token(self, c):
        r = c.post("/auth/token", data={"username": "admin", "password": _ADMIN})
        assert r.status_code == 200
        old_refresh = r.json()["refresh_token"]

        r2 = c.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert r2.status_code == 200
        assert "access_token"  in r2.json()
        assert "refresh_token" in r2.json()

        # Old refresh token must now be revoked
        r3 = c.post("/auth/refresh", json={"refresh_token": old_refresh})
        assert r3.status_code == 401

    def test_register_new_operator(self, c, token):
        r = c.post(
            "/auth/register",
            json={"username": "op_post_test", "password": "OpPass1!Test99",
                  "role": "operator"},
            headers=_auth(token),
        )
        assert r.status_code in (200, 201)
        assert r.json().get("username") == "op_post_test"
        assert r.json().get("role")     == "operator"

    def test_register_duplicate_username_returns_409(self, c, token):
        r = c.post(
            "/auth/register",
            json={"username": "op_post_test", "password": "AnotherPass1!",
                  "role": "reporter"},
            headers=_auth(token),
        )
        assert r.status_code == 409

    def test_register_forbidden_for_non_team_lead(self, c, token):
        # Log in as the new operator
        login = c.post("/auth/token",
                       data={"username": "op_post_test", "password": "OpPass1!Test99"})
        assert login.status_code == 200
        op_token = login.json()["access_token"]

        r = c.post(
            "/auth/register",
            json={"username": "newuser99", "password": "NewUser1!Pass",
                  "role": "reporter"},
            headers=_auth(op_token),
        )
        assert r.status_code == 403

    def test_change_password_valid(self, c, token):
        r = c.post(
            "/auth/change-password",
            json={"current_password": _ADMIN, "new_password": _ADMIN + "New"},
            headers=_auth(token),
        )
        assert r.status_code == 200
        # Change it back
        login2 = c.post("/auth/token",
                        data={"username": "admin", "password": _ADMIN + "New"})
        new_tok = login2.json()["access_token"]
        c.post(
            "/auth/change-password",
            json={"current_password": _ADMIN + "New", "new_password": _ADMIN},
            headers=_auth(new_tok),
        )

    def test_change_password_wrong_current_returns_401(self, c, token):
        r = c.post(
            "/auth/change-password",
            json={"current_password": "WrongCurrent!", "new_password": "NewPass1!"},
            headers=_auth(token),
        )
        assert r.status_code == 401


# ── Campaign CRUD ─────────────────────────────────────────────────────────────

class TestCampaignPostEndpoints:

    @pytest.fixture(scope="class")
    def c(self):
        with _fresh_client() as client:
            yield client

    @pytest.fixture(scope="class")
    def token(self, c):
        return _login(c)

    @pytest.fixture(scope="class")
    def campaign_id(self, c, token):
        r = c.post(
            "/campaigns",
            json={"name": "Integration POST Campaign",
                  "client": "ACME Corp",
                  "targets": ["10.0.0.1"],
                  "scope_cidrs": ["10.0.0.0/24"]},
            headers=_auth(token),
        )
        assert r.status_code == 200, f"Campaign create failed: {r.text}"
        return r.json()["id"]

    def test_create_campaign_returns_200(self, c, token):
        r = c.post(
            "/campaigns",
            json={"name": "Test Campaign Alpha",
                  "client": "Corp A",
                  "targets": [],
                  "scope_cidrs": ["192.168.1.0/24"]},
            headers=_auth(token),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["name"]   == "Test Campaign Alpha"
        assert body["client"] == "Corp A"
        assert "id" in body

    def test_create_campaign_persists_to_db(self, c, token, campaign_id):
        r = c.get(f"/campaigns/{campaign_id}", headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["id"]     == campaign_id
        assert body["name"]   == "Integration POST Campaign"
        assert body["client"] == "ACME Corp"

    def test_create_campaign_missing_name_returns_422(self, c, token):
        r = c.post(
            "/campaigns",
            json={"client": "Corp B"},
            headers=_auth(token),
        )
        assert r.status_code == 422

    def test_campaign_appears_in_list(self, c, token, campaign_id):
        r = c.get("/campaigns", headers=_auth(token))
        assert r.status_code == 200
        ids = [camp["id"] for camp in r.json()]
        assert campaign_id in ids

    def test_findings_empty_initially(self, c, token, campaign_id):
        r = c.get(f"/campaigns/{campaign_id}/findings", headers=_auth(token))
        assert r.status_code == 200
        assert r.json() == []

    def test_x_total_count_header(self, c, token):
        r = c.get("/campaigns", headers=_auth(token))
        assert r.status_code == 200
        assert "x-total-count" in r.headers

    def test_run_plan_dry_run(self, c, token, campaign_id):
        r = c.post(
            f"/campaigns/{campaign_id}/run",
            json={
                "plan": {
                    "stages": [{
                        "name": "recon",
                        "modules": ["ad.enum_users"],
                        "params": {"ad.enum_users": {
                            "dc": "10.0.0.1", "username": "test",
                            "password": "pass", "domain": "CORP"
                        }}
                    }]
                },
                "dry_run": True,
            },
            headers=_auth(token),
        )
        assert r.status_code in (200, 202), f"run plan: {r.text}"

    def test_campaign_not_found_returns_404(self, c, token):
        r = c.get("/campaigns/nonexistent-xyz-id", headers=_auth(token))
        assert r.status_code == 404

    def test_unauthenticated_create_returns_401(self, c):
        r = c.post("/campaigns",
                   json={"name": "Test", "client": "C", "targets": []})
        assert r.status_code == 401


# ── Security headers on POST ──────────────────────────────────────────────────

class TestSecurityHeadersOnPOST:

    @pytest.fixture(scope="class")
    def c(self):
        with _fresh_client() as client:
            yield client

    @pytest.fixture(scope="class")
    def token(self, c):
        return _login(c)

    def test_post_response_has_x_frame_options(self, c, token):
        r = c.post("/campaigns",
                   json={"name": "Hdr Test", "client": "X", "targets": []},
                   headers=_auth(token))
        assert r.status_code == 200
        assert r.headers.get("x-frame-options") == "DENY"

    def test_post_response_has_nosniff(self, c, token):
        r = c.post("/campaigns",
                   json={"name": "Hdr Test 2", "client": "X", "targets": []},
                   headers=_auth(token))
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_post_response_has_cache_control(self, c, token):
        r = c.post("/campaigns",
                   json={"name": "Hdr Test 3", "client": "X", "targets": []},
                   headers=_auth(token))
        assert "no-store" in r.headers.get("cache-control", "")
