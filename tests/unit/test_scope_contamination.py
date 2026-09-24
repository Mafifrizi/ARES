import pytest
from httpx import ASGITransport, AsyncClient

from ares.api.server import app, get_db, get_engine
from ares.core.campaign import Campaign, ScopeEntry
from ares.core.config import get_settings
from ares.core.engine import AresEngine
from ares.core.security import create_access_token
from ares.db.database import AresDatabase


@pytest.mark.asyncio
async def test_engine_persist_runtime_hosts_blocks_out_of_scope(tmp_path):
    """
    NEW-03 Reproduction:
    Verify that AresEngine._persist_runtime_hosts does NOT persist
    out-of-scope hosts into the campaign's database inventory.
    """
    db_file = tmp_path / "test_scope_engine.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    try:
        engine = AresEngine(db=db)
        campaign = Campaign(
            name="Strict Scope Campaign",
            scope=[ScopeEntry(cidr="10.0.0.0/24")],
            targets=["10.0.0.10"],
            operator="admin",
        )
        await db.save_campaign(campaign)

        runtime_state = await engine.ensure_campaign_runtime(campaign)
        # Add one valid in-scope host and two out-of-scope hosts
        runtime_state.session.add_host("10.0.0.10", hostname="internal-srv.local")
        runtime_state.session.add_host("8.8.8.8", hostname="external-dns.google")
        runtime_state.session.add_host("192.168.1.100", hostname="unrelated-lan.local")

        # Persist runtime hosts
        await engine._persist_runtime_hosts(campaign, runtime_state)

        persisted = await db.get_hosts(campaign.id)
        persisted_ips = [h.get("ip_address") for h in persisted]

        # In-scope host must be persisted
        assert "10.0.0.10" in persisted_ips
        # Out-of-scope hosts MUST NOT be persisted into database inventory
        assert "8.8.8.8" not in persisted_ips
        assert "192.168.1.100" not in persisted_ips
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_server_auto_upsert_host_blocks_out_of_scope(tmp_path):
    """
    NEW-03 Reproduction:
    Verify that when a module runs via server.py and reports an out-of-scope
    target IP in raw_output, server.py does NOT upsert it into the campaign
    hosts table.
    """
    db_file = tmp_path / "test_scope_server.db"
    db = AresDatabase(str(db_file))
    await db.connect()

    class FakeRegistry:
        def get(self, module_id: str):
            return object

    class FakeResult:
        status = "success"
        findings = []
        duration_ms = 1.0

        def model_dump(self):
            return {
                "module_id": "recon.mock",
                "status": "success",
                "findings": [],
                "validation_results": [],
                "raw_output": {
                    "target": "8.8.8.8",
                    "open_ports": [53],
                    "hostname": "dns.google",
                },
                "error": "",
                "duration_ms": 1.0,
            }

    class FakeEngine:
        registry = FakeRegistry()

        async def run_module(self, module_id, campaign, params, actor_role=""):
            return FakeResult()

    try:
        app.state.db = db
        settings = get_settings()
        await db.create_user("admin", "TestAdminPass1!", "team_lead")

        def token_factory(claims):
            return create_access_token(
                data=dict(claims),
                secret_key=settings.secret_key_value,
                algorithm=settings.ares_jwt_algorithm,
                expires_minutes=60,
            )

        session_res = await db.create_login_session("admin", "TestAdminPass1!", token_factory)
        token = session_res.session.access_token

        campaign = Campaign(
            name="Server Scope Campaign",
            scope=[ScopeEntry(cidr="10.0.0.0/24")],
            targets=["10.0.0.10"],
            operator="admin",
        )
        await db.save_campaign(campaign)

        class DummyCLive:
            def bind(self, *a, **k):
                return (None, None)

        app.state.c_live_runtime = DummyCLive()
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_engine] = lambda: FakeEngine()

        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "550e8400-e29b-41d4-a716-446655440000",
        }

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://localhost"
        ) as client:
            resp = await client.post(
                "/modules/recon.mock/run",
                json={
                    "campaign_id": campaign.id,
                    "params": {"target": "8.8.8.8"},
                    "dry_run": False,
                },
                headers=headers,
            )
            assert resp.status_code == 200

        hosts = await db.get_hosts(campaign.id)
        host_ips = [h.get("ip_address") for h in hosts]

        # 8.8.8.8 is out of scope (scope is 10.0.0.0/24), so it must NOT be in the hosts inventory!
        assert "8.8.8.8" not in host_ips

        # Now verify an in-scope host (10.0.0.50) IS successfully upserted
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://localhost"
        ) as client:
            resp_in_scope = await client.post(
                "/modules/recon.mock/run",
                json={
                    "campaign_id": campaign.id,
                    "params": {"target": "10.0.0.50"},
                    "dry_run": False,
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": "550e8400-e29b-41d4-a716-446655440001",
                },
            )
            assert resp_in_scope.status_code == 200

        hosts_after = await db.get_hosts(campaign.id)
        host_ips_after = [h.get("ip_address") for h in hosts_after]
        assert "10.0.0.50" in host_ips_after
    finally:
        app.dependency_overrides.clear()
        await db.close()
