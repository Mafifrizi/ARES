"""Security Audit Remediation Regression Tests.

Validates fixes for:
- ARES-SEC-01: MCP SSE Transport network access control and ephemeral auth on external binds.
- ARES-SEC-02: Strict campaign authorization on execution and feasibility endpoints.
- ARES-SEC-03: Prevention of API key scope escalation based on caller role.
"""
from __future__ import annotations

import base64
import hashlib
import os
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

# Ensure test environment variables
os.environ.setdefault("ARES_SECRET_KEY", "test-sec-secret-key-min32-chars!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY", "test-enc-key-min32-chars-xxxxxxx")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestApiPass1!")
os.environ.setdefault("ARES_DEBUG", "true")
os.environ.setdefault("ARES_BROWSER_ORIGIN", "http://localhost:5173")


# ── Helpers for Auth and Principals ──────────────────────────────────────────

_MOCK_ROLES: dict[str, str] = {}


def _make_token(username: str, role: str) -> str:
    from ares.core.config import AresSettings
    from ares.core.security import create_access_token

    _MOCK_ROLES[username] = role
    s = AresSettings()
    family_id = base64.urlsafe_b64encode(
        hashlib.sha256(username.encode("utf-8")).digest()
    ).rstrip(b"=").decode("ascii")
    return create_access_token(
        data={"sub": username, "sid": family_id, "ver": 1},
        secret_key=s.secret_key_value,
        expires_minutes=60,
    )


def _auth_headers(username: str, role: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_make_token(username, role)}",
        "Idempotency-Key": "22222222-2222-4222-8222-222222222222",
    }


# ── 1. ARES-SEC-01: MCP SSE Transport Access Control Tests ───────────────────

class MockMcpServer:
    async def handle_message(self, body: dict) -> dict | None:
        return {"jsonrpc": "2.0", "id": body.get("id"), "result": "pong"}


@pytest.mark.asyncio
async def test_mcp_sse_loopback_allowed_without_api_key():
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        # Loopback client: auth passes, proceeds to session validation (400 Bad Request)
        res = await client.post("/messages?session_id=fake_sess", json={"jsonrpc": "2.0"})
        assert res.status_code == 400
        assert "Invalid or expired session_id" in res.json().get("error", "")


@pytest.mark.asyncio
async def test_mcp_sse_non_loopback_rejected_without_api_key():
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    # External IP client trying to access open MCP server without key
    transport = httpx.ASGITransport(app=app, client=("192.168.1.105", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://192.168.1.1") as client:
        res = await client.get("/sse")
        # Non-loopback client without API key must be 401 Unauthorized
        assert res.status_code == 401
        assert "Unauthorized" in res.json().get("error", "")

        res_msg = await client.post("/messages?session_id=fake_sess", json={"jsonrpc": "2.0"})
        assert res_msg.status_code == 401


@pytest.mark.asyncio
async def test_mcp_sse_drive_by_cross_origin_rejected_without_api_key():
    """Operator browser visits malicious site which attempts to CSRF/drive-by local MCP server."""
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    # Client IP is loopback (from operator's local browser), BUT Origin is malicious website
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        # Cross-origin drive-by attempt from attacker.com
        res = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Origin": "https://malicious-attacker.com"},
        )
        assert res.status_code == 401
        assert "Unauthorized" in res.json().get("error", "")

        # GET /sse drive-by stream hijack attempt
        res_sse = await client.get("/sse", headers={"Origin": "https://malicious-attacker.com"})
        assert res_sse.status_code == 401


@pytest.mark.asyncio
async def test_mcp_sse_dns_rebinding_rejected_without_api_key():
    """Attacker uses DNS rebinding (evil.com -> 127.0.0.1) against local MCP server."""
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    # Client IP is loopback, but Host header contains attacker-controlled domain
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        res = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Host": "rebind.attacker-domain.xyz:8765"},
        )
        assert res.status_code == 401
        assert "Unauthorized" in res.json().get("error", "")


@pytest.mark.asyncio
async def test_mcp_sse_cross_site_fetch_rejected():
    """Browser sends Sec-Fetch-Site: cross-site indicator."""
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        res = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_mcp_sse_loopback_valid_origin_allowed():
    """Legitimate local frontend (e.g. Vite on localhost:5173) connects to local MCP server."""
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key=None)

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        res = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Origin": "http://localhost:5173"},
        )
        # Auth succeeds; proceeds to MCP session check (400)
        assert res.status_code == 400
        assert "Invalid or expired session_id" in res.json().get("error", "")


@pytest.mark.asyncio
async def test_mcp_sse_non_loopback_allowed_with_valid_bearer_token():
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key="secret-token-xyz-12345")

    transport = httpx.ASGITransport(app=app, client=("192.168.1.105", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://192.168.1.1") as client:
        # Without token -> 401
        res_no_auth = await client.get("/sse")
        assert res_no_auth.status_code == 401

        # With Bearer token -> auth passes, proceeds to session validation (400)
        res_auth = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Authorization": "Bearer secret-token-xyz-12345"},
        )
        assert res_auth.status_code == 400


@pytest.mark.asyncio
async def test_mcp_sse_non_loopback_allowed_with_header_or_query_key():
    from ares.mcp.transport.sse import create_sse_app

    server = MockMcpServer()
    app = create_sse_app(server, api_key="network-key-999")

    transport = httpx.ASGITransport(app=app, client=("10.0.0.42", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://10.0.0.1") as client:
        # X-ARES-API-Key header -> auth passes (400)
        res_hdr = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"X-ARES-API-Key": "network-key-999"},
        )
        assert res_hdr.status_code == 400

        # Query param -> auth passes (400)
        res_query = await client.post(
            "/messages?session_id=fake_sess&api_key=network-key-999",
            json={"jsonrpc": "2.0"},
        )
        assert res_query.status_code == 400

        # Wrong token -> 401
        res_bad = await client.get("/sse", headers={"Authorization": "Bearer wrong-token"})
        assert res_bad.status_code == 401
        res_bad_msg = await client.post(
            "/messages?session_id=fake_sess",
            json={"jsonrpc": "2.0"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert res_bad_msg.status_code == 401


# ── 2. ARES-SEC-02: Campaign Authorization on Execution / Feasibility ───────

@pytest.fixture
def api_test_setup():
    from ares.api.server import app, get_c_live_runtime, get_db, get_engine

    db = MagicMock()
    db.is_access_token_revoked = AsyncMock(return_value=False)
    db.get_user = AsyncMock(return_value={"id": "usr-1", "username": "alice", "role": "operator"})

    async def resolve_principal(subject, _jti, _family_id, auth_epoch):
        role = _MOCK_ROLES.get(subject, "operator")
        return {"id": f"uid-{subject}", "username": subject, "role": role, "auth_epoch": auth_epoch}

    db.resolve_access_token_principal = AsyncMock(side_effect=resolve_principal)

    campaigns = {
        "camp-alice": {
            "id": "camp-alice",
            "name": "Alice Campaign",
            "client": "Internal",
            "operator": "alice",
            "noise_profile": "normal",
            "status": "created",
            "scope_json": "[]",
            "targets_json": '["10.0.0.1"]',
            "notes": "",
        }
    }

    async def get_campaign(cid):
        return campaigns.get(cid)

    db.get_campaign = AsyncMock(side_effect=get_campaign)
    db.save_finding = AsyncMock()
    db.save_loot = AsyncMock()
    db.upsert_host = AsyncMock()
    db.update_campaign_status = AsyncMock()
    db.audit = AsyncMock()
    db.create_api_key = AsyncMock(return_value=("key-123", "ares_key_mock_secret_abcdef123456"))

    engine = MagicMock()
    engine.bind_database = MagicMock()
    fake_report = MagicMock()
    fake_report.to_dict.return_value = {"feasibility": "high", "risk_score": 10}
    engine.assess_module_feasibility = AsyncMock(return_value=fake_report)
    fake_result = SimpleNamespace(
        module_id="plugin.safe",
        status="success",
        findings=[],
        raw_output={},
        duration_ms=5.0,
    )
    fake_result.model_dump = lambda: {"module_id": "plugin.safe", "status": "success", "findings": []}
    engine.run_module = AsyncMock(return_value=fake_result)
    engine.dry_run_module = MagicMock(return_value={"status": "dry_run_ok"})
    engine.dry_run_plan = MagicMock(return_value={"status": "dry_run_ok", "modules": []})

    orig_state_db = getattr(app.state, "db", None)
    orig_state_engine = getattr(app.state, "engine", None)
    app.state.db = db
    app.state.engine = engine

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_engine] = lambda: engine

    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://localhost")

    yield client, db, engine, app

    app.state.db = orig_state_db
    app.state.engine = orig_state_engine
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_engine, None)


@pytest.mark.asyncio
async def test_feasibility_cross_operator_rejected_with_404(api_test_setup):
    client, db, engine, app = api_test_setup

    # Bob (operator) tries to assess feasibility for Alice's campaign -> 404
    bob_headers = _auth_headers("bob", "operator")
    res = await client.post(
        "/modules/plugin.safe/feasibility",
        json={"campaign_id": "camp-alice", "target": "10.0.0.1", "params": {}},
        headers=bob_headers,
    )
    assert res.status_code == 404
    assert "Campaign not found" in res.json().get("detail", "")
    engine.assess_module_feasibility.assert_not_awaited()


@pytest.mark.asyncio
async def test_feasibility_owner_operator_allowed(api_test_setup):
    client, db, engine, app = api_test_setup

    # Alice (the owner operator) assesses feasibility for her own campaign -> 200
    alice_headers = _auth_headers("alice", "operator")
    res = await client.post(
        "/modules/plugin.safe/feasibility",
        json={"campaign_id": "camp-alice", "target": "10.0.0.1", "params": {}},
        headers=alice_headers,
    )
    assert res.status_code == 200
    assert res.json()["campaign_id"] == "camp-alice"


@pytest.mark.asyncio
async def test_feasibility_team_lead_allowed(api_test_setup):
    client, db, engine, app = api_test_setup

    # Charlie (team_lead) assesses feasibility for Alice's campaign -> 200
    lead_headers = _auth_headers("charlie", "team_lead")
    res = await client.post(
        "/modules/plugin.safe/feasibility",
        json={"campaign_id": "camp-alice", "target": "10.0.0.1", "params": {}},
        headers=lead_headers,
    )
    assert res.status_code == 200


# ── 3. ARES-SEC-03: API Key Scope Privilege Escalation Defense ───────────────

@pytest.mark.asyncio
async def test_api_key_reporter_cannot_mint_write_or_admin(api_test_setup):
    client, db, engine, app = api_test_setup

    async def get_user(username):
        return {"id": "uid-rep", "username": username, "role": "reporter"}

    db.get_user = AsyncMock(side_effect=get_user)
    rep_headers = _auth_headers("reporter_user", "reporter")

    # Reporter requesting admin -> 403
    res_admin = await client.post(
        "/auth/api-keys",
        json={"name": "test-admin-key", "scopes": "admin"},
        headers=rep_headers,
    )
    assert res_admin.status_code == 403
    assert "not authorized" in res_admin.json().get("detail", "")

    # Reporter requesting write -> 403
    res_write = await client.post(
        "/auth/api-keys",
        json={"name": "test-write-key", "scopes": "write"},
        headers=rep_headers,
    )
    assert res_write.status_code == 403

    # Reporter requesting read -> 200
    res_read = await client.post(
        "/auth/api-keys",
        json={"name": "test-read-key", "scopes": "read"},
        headers=rep_headers,
    )
    assert res_read.status_code == 200
    assert "key" in res_read.json()


@pytest.mark.asyncio
async def test_api_key_operator_cannot_mint_admin(api_test_setup):
    client, db, engine, app = api_test_setup

    async def get_user(username):
        return {"id": "uid-op", "username": username, "role": "operator"}

    db.get_user = AsyncMock(side_effect=get_user)
    op_headers = _auth_headers("op_user", "operator")

    # Operator requesting admin -> 403
    res_admin = await client.post(
        "/auth/api-keys",
        json={"name": "op-admin-key", "scopes": "admin"},
        headers=op_headers,
    )
    assert res_admin.status_code == 403
    assert "not authorized" in res_admin.json().get("detail", "")

    # Operator requesting write -> 200
    res_write = await client.post(
        "/auth/api-keys",
        json={"name": "op-write-key", "scopes": "write"},
        headers=op_headers,
    )
    assert res_write.status_code == 200

    # Operator requesting read -> 200
    res_read = await client.post(
        "/auth/api-keys",
        json={"name": "op-read-key", "scopes": "read"},
        headers=op_headers,
    )
    assert res_read.status_code == 200


@pytest.mark.asyncio
async def test_api_key_team_lead_can_mint_admin(api_test_setup):
    client, db, engine, app = api_test_setup

    async def get_user(username):
        return {"id": "uid-lead", "username": username, "role": "team_lead"}

    db.get_user = AsyncMock(side_effect=get_user)
    lead_headers = _auth_headers("lead_user", "team_lead")

    # Team Lead requesting admin -> 200
    res_admin = await client.post(
        "/auth/api-keys",
        json={"name": "lead-admin-key", "scopes": "admin"},
        headers=lead_headers,
    )
    assert res_admin.status_code == 200
    assert "key" in res_admin.json()


# ── 4. Deep Hardening: MCP Scope Invariance & Secret Masking Tests ────────────

@pytest.mark.asyncio
async def test_mcp_database_scope_strict_enforcement():
    """Verify that real DB scope_json is strictly parsed and blocks out-of-scope targets."""
    from ares.mcp.security import ConfirmationTokenManager, McpSecurityViolation
    from ares.mcp.tools import McpToolRegistry

    mock_db = MagicMock()
    # Campaign configured strictly for 192.168.50.0/24 (no 10.0.0.0/8 allowed!)
    mock_db.get_campaign = AsyncMock(return_value={
        "id": "camp-strict-50",
        "name": "Strict Scope Engagement",
        "scope_json": '["192.168.50.0/24"]',
        "targets_json": '["192.168.50.5"]',
    })

    token_mgr = ConfirmationTokenManager()
    registry = McpToolRegistry(token_manager=token_mgr, db=mock_db)

    # 1. Target in scope (192.168.50.5:445) -> succeeds
    res_in = await registry.call_tool("ares_verify_target_scope", {
        "campaign_id": "camp-strict-50",
        "target": "192.168.50.5:445",
    })
    assert not res_in.isError
    assert "APPROVED_FOR_TESTING" in res_in.content[0].text

    # 2. Target OUT of scope (10.0.0.1: previously allowed by broad fallback!) -> must be REJECTED
    res_out = await registry.call_tool("ares_verify_target_scope", {
        "campaign_id": "camp-strict-50",
        "target": "10.0.0.1",
    })
    assert not res_out.isError
    assert "REJECTED_OUT_OF_SCOPE" in res_out.content[0].text

    # 3. Dry-run execution on out-of-scope target must raise McpSecurityViolation
    res_dry = await registry.call_tool("ares_dry_run_module", {
        "campaign_id": "camp-strict-50",
        "module_id": "ad.kerberoast",
        "target": "10.0.0.1",
    })
    assert res_dry.isError
    assert "SECURITY VIOLATION" in res_dry.content[0].text
    assert "SCOPE VIOLATION [BLOCKED]" in res_dry.content[0].text


@pytest.mark.asyncio
async def test_mcp_nonexistent_campaign_rejected():
    """Verify that querying a non-existent campaign ID in MCP fails closed."""
    from ares.mcp.security import ConfirmationTokenManager
    from ares.mcp.tools import McpToolRegistry

    mock_db = MagicMock()
    mock_db.get_campaign = AsyncMock(return_value=None)  # Campaign does not exist!

    token_mgr = ConfirmationTokenManager()
    registry = McpToolRegistry(token_manager=token_mgr, db=mock_db)

    res = await registry.call_tool("ares_verify_target_scope", {
        "campaign_id": "camp-ghost-999",
        "target": "10.0.0.1",
    })
    assert res.isError
    assert "Campaign 'camp-ghost-999' not found in database" in res.content[0].text


def test_mcp_scope_gate_port_and_naked_domain():
    """Verify McpScopeGate handles port notation and naked domain rules."""
    from ares.mcp.security import McpScopeGate

    rules = ["10.0.0.0/24", "corp.local", "192.168.1.1"]

    # IP with port matching CIDR
    assert McpScopeGate.is_in_scope("10.0.0.5:445", rules) is True
    # Hostname with port matching naked domain
    assert McpScopeGate.is_in_scope("dc01.corp.local:88", rules) is True
    # Exact host matching naked domain
    assert McpScopeGate.is_in_scope("corp.local", rules) is True
    # IP with port matching exact IP
    assert McpScopeGate.is_in_scope("192.168.1.1:8080", rules) is True
    # Out of scope
    assert McpScopeGate.is_in_scope("10.0.1.5:445", rules) is False
    assert McpScopeGate.is_in_scope("other.com", rules) is False


def test_mcp_secret_masker_pem_block():
    """Verify SecretMasker scrubs raw PEM private key blocks in strings."""
    from ares.mcp.security import SecretMasker

    fake_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0YpW3H...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    raw_output = f"Connecting to target... Found SSH key:\n{fake_pem}\nDone."
    masked = SecretMasker.mask(raw_output)

    assert "-----BEGIN RSA PRIVATE KEY-----" not in masked
    assert "[REDACTED_PRIVATE_KEY_BLOCK]" in masked

