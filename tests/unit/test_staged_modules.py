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
