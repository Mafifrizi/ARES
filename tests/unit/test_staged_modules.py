"""
Tests for staged next-gen offensive modules:
  - cloud.phantom_token (Hybrid Entra ID PRT Hijack)
  - ad.ghost_forge (ADCS Cryptographic Identity & PKINIT Takeover)
"""
from __future__ import annotations

import asyncio
import os
import pytest

from tests.unit.modules.test_modules import _make_module
from tests.unit.test_roadmap_modules import _mock_ctx, _run
from ares.modules.cloud.phantom_token import PhantomTokenModule
from ares.modules.ad.ghost_forge import GhostForgeModule


class TestPhantomTokenModule:
    def test_module_attributes(self):
        assert PhantomTokenModule.MODULE_ID == "cloud.phantom_token"
        assert "T1528" in PhantomTokenModule.MITRE_TECHNIQUES
        assert "T1606" in PhantomTokenModule.MITRE_TECHNIQUES

    def test_dry_run_execution(self):
        mod, _ = _make_module(PhantomTokenModule)
        ctx = _mock_ctx(params={"tenant_id": "corp.onmicrosoft.com"})
        ctx.dry_run = True
        res = _run(mod.execute(ctx))
        assert res.status == "dry_run"
        assert res.module_id == "cloud.phantom_token"
        assert res.raw.get("tenant_id") == "corp.onmicrosoft.com"

    def test_live_execution_findings(self):
        mod, _ = _make_module(PhantomTokenModule)
        ctx = _mock_ctx(params={"tenant_id": "corp.onmicrosoft.com", "evaluate_cap_bypass": True})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert len(res.findings) >= 1
        assert res.findings[0].mitre_technique == "T1528"
        assert res.raw.get("prt_valid") is True


class TestGhostForgeModule:
    def test_module_attributes(self):
        assert GhostForgeModule.MODULE_ID == "ad.ghost_forge"
        assert "T1649" in GhostForgeModule.MITRE_TECHNIQUES
        assert "T1558" in GhostForgeModule.MITRE_TECHNIQUES

    def test_dry_run_execution(self):
        mod, _ = _make_module(GhostForgeModule)
        ctx = _mock_ctx(params={
            "dc": "10.10.10.1",
            "domain": "CORP.LOCAL",
            "ca_server": "ca.corp.local",
            "ca_name": "CORP-CA",
            "username": "audit_operator",
            "password": "SecretPassword123!",
        })
        ctx.dry_run = True
        res = _run(mod.execute(ctx))
        assert res.status == "dry_run"
        assert res.module_id == "ad.ghost_forge"
        assert res.raw.get("dc") == "10.10.10.1"

    def test_live_execution_findings(self):
        mod, _ = _make_module(GhostForgeModule)
        ctx = _mock_ctx(params={
            "dc": "10.10.10.1",
            "domain": "CORP.LOCAL",
            "ca_server": "ca.corp.local",
            "ca_name": "CORP-CA",
            "impersonate_user": "Administrator",
            "username": "audit_operator",
            "password": "SecretPassword123!",
            "perform_pkinit": True,
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert len(res.findings) >= 1
        assert res.findings[0].mitre_technique == "T1649"
        assert res.raw.get("pkinit_success") is True

    @pytest.mark.asyncio
    async def test_engine_persists_loot_from_module_output(self, tmp_path):
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.engine import AresEngine
        from ares.db.database import AresDatabase
        db_path = str(tmp_path / "loot_test.db")
        db = AresDatabase(db_path)
        await db.connect()
        campaign = Campaign(name="Loot Test", client="Client", scope=[ScopeEntry(cidr="10.10.10.0/24")], operator="operator")
        await db.save_campaign(campaign)

        from ares.core.execution_admission import _mint_test_dispatch_context, mark_terminal_committed

        engine = AresEngine(db=db)
        mod, _ = _make_module(GhostForgeModule)
        engine.registry.register(mod)

        dispatch_ctx = _mint_test_dispatch_context(engine, campaign.id, "ad.ghost_forge")
        result = await engine.run_module(
            "ad.ghost_forge",
            campaign,
            {
                "dc": "10.10.10.1",
                "domain": "CORP.LOCAL",
                "ca_server": "ca.corp.local",
                "ca_name": "CORP-CA",
                "username": "audit_operator",
                "password": "SecretPassword123!",
            },
            dispatch_context=dispatch_ctx,
        )
        assert str(result.status) in ("success", "done", "ModuleStatus.DONE")
        mark_terminal_committed(dispatch_ctx)
        await engine._finalize_committed_module_result(campaign, "ad.ghost_forge", result, dispatch_ctx)
        loots = await db.get_loot(campaign.id)
        assert len(loots) >= 1
        assert any("TGT" in l["name"] for l in loots)
        await db.close()

