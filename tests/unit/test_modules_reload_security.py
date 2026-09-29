"""
Security test for AUD-001: Verification of authentication enforcement on POST /modules/reload.
Ensures zero loopback bypass and strict operator RBAC.
"""

import sys
from starlette.testclient import TestClient

from ares.api.server import app
from ares.api.rbac import AuthenticatedUser, get_current_user


def test_modules_reload_unauthenticated_rejected_401():
    """Request tanpa token ke /modules/reload -> 401 Unauthorized."""
    with TestClient(app, base_url="http://127.0.0.1") as client:
        resp = client.post("/modules/reload")
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"


def test_modules_reload_loopback_unauthenticated_rejected_401():
    """Request dari 127.0.0.1 / localhost tanpa token -> 401 (bukan 200)."""
    # 1. base_url 127.0.0.1
    with TestClient(app, base_url="http://127.0.0.1") as client_ip:
        resp = client_ip.post("/modules/reload")
        assert resp.status_code == 401

    # 2. base_url localhost
    with TestClient(app, base_url="http://localhost") as client_host:
        resp = client_host.post("/modules/reload")
        assert resp.status_code == 401

    # 3. With X-Forwarded-For 127.0.0.1
    with TestClient(app, base_url="http://127.0.0.1") as client_fwd:
        resp = client_fwd.post("/modules/reload", headers={"X-Forwarded-For": "127.0.0.1"})
        assert resp.status_code == 401


def test_modules_reload_operator_authenticated_succeeds_200():
    """Request dengan token valid operator -> 200 OK."""
    saved_modules = dict(sys.modules)
    try:
        app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
            username="ops_lead", role="operator"
        )
        with TestClient(app, base_url="http://127.0.0.1") as client:
            resp = client.post("/modules/reload")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["reloaded"] is True
            assert "module_count" in data
            assert data["module_count"] >= 1
    finally:
        app.dependency_overrides.clear()
        sys.modules.clear()
        sys.modules.update(saved_modules)


def test_modules_reload_insufficient_role_rejected_403():
    """Request dengan role non-operator (recon/reporter) -> 403 Forbidden."""
    try:
        app.dependency_overrides[get_current_user] = lambda: AuthenticatedUser(
            username="recon_agent", role="recon"
        )
        with TestClient(app, base_url="http://127.0.0.1") as client:
            resp = client.post("/modules/reload")
            assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()
