"""
Tests for disabled Batch 4 modules:
  - windows.dpapi (MOD-029)
  - windows.token_impersonation (MOD-030)
Verifies:
  - Module does not appear in active module lists (all, by_category, list_metadata)
  - Module cannot produce findings
  - Module cannot contaminate the vault
  - Calling run(), execute(), or validate() raises explicit ModuleError / ModuleValidationError
"""
from __future__ import annotations

import asyncio
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleError, ModuleValidationError
from ares.core.noise import NoiseController
from ares.core.plugin.loader import PluginLoader
from ares.modules.windows.dpapi import DPAPIModule
from ares.modules.windows.token_impersonation import TokenImpersonationModule


def _run(coro):
    return asyncio.run(coro)


def _make_module(cls):
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test-Disabled-Batch4",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise), campaign


class TestDPAPIDisabled:
    def test_dpapi_attributes(self):
        assert DPAPIModule.MODULE_ID == "windows.dpapi"
        assert DPAPIModule.ENABLED is False
        assert "MOD-029" in DPAPIModule.DISABLED_REASON

    def test_dpapi_registry_exclusion(self):
        loader = PluginLoader()
        loader._load_builtin()
        reg = loader.registry

        assert "windows.dpapi" not in [m["id"] for m in reg.list_metadata()]
        assert "windows.dpapi" not in [cls.MODULE_ID for cls in reg.all()]
        assert "windows.dpapi" not in [cls.MODULE_ID for cls in reg.by_category("windows")]
        assert reg.is_disabled("windows.dpapi") is True
        assert "MOD-029" in (reg.get_disabled_reason("windows.dpapi") or "")
        assert "windows.dpapi" not in reg

    def test_dpapi_direct_run_raises_explicit_exception(self):
        mod, _ = _make_module(DPAPIModule)
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.run(target="10.0.0.5", username="target_user", password="secret"))
        assert "module disabled: DPAPI decryption not implemented, stub only - false credential injection risk (MOD-029)" in str(exc_info.value)
        assert len(mod._findings) == 0

    def test_dpapi_execute_raises_explicit_exception(self):
        mod, campaign = _make_module(DPAPIModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.dpapi",
            params={"target": "10.0.0.5", "username": "target_user", "password": "secret"},
        )
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.execute(ctx))
        assert "module disabled: DPAPI decryption not implemented, stub only - false credential injection risk (MOD-029)" in str(exc_info.value)
        assert len(mod._findings) == 0

    def test_dpapi_validate_raises_explicit_exception(self):
        mod, campaign = _make_module(DPAPIModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.dpapi",
            params={"target": "10.0.0.5", "username": "target_user"},
        )
        with pytest.raises(ModuleValidationError) as exc_info:
            _run(mod.validate(ctx))
        assert "module disabled: DPAPI decryption not implemented, stub only - false credential injection risk (MOD-029)" in str(exc_info.value)

    def test_dpapi_assess_feasibility_reports_disabled(self):
        mod, campaign = _make_module(DPAPIModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.dpapi",
            params={"target": "10.0.0.5", "username": "target_user"},
        )
        report = _run(mod.assess_feasibility(ctx))
        assert report.feasible is False
        assert any("MOD-029" in b for b in report.blockers)


class TestTokenImpersonationDisabled:
    def test_token_impersonation_attributes(self):
        assert TokenImpersonationModule.MODULE_ID == "windows.token_impersonation"
        assert TokenImpersonationModule.ENABLED is False
        assert "MOD-030" in TokenImpersonationModule.DISABLED_REASON

    def test_token_impersonation_registry_exclusion(self):
        loader = PluginLoader()
        loader._load_builtin()
        reg = loader.registry

        assert "windows.token_impersonation" not in [m["id"] for m in reg.list_metadata()]
        assert "windows.token_impersonation" not in [cls.MODULE_ID for cls in reg.all()]
        assert "windows.token_impersonation" not in [cls.MODULE_ID for cls in reg.by_category("windows")]
        assert reg.is_disabled("windows.token_impersonation") is True
        assert "MOD-030" in (reg.get_disabled_reason("windows.token_impersonation") or "")
        assert "windows.token_impersonation" not in reg

    def test_token_impersonation_direct_run_raises_explicit_exception(self):
        mod, _ = _make_module(TokenImpersonationModule)
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.run(target="10.0.0.5", username="target_user", password="secret"))
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)
        assert len(mod._findings) == 0

    def test_token_impersonation_execute_raises_explicit_exception(self):
        mod, campaign = _make_module(TokenImpersonationModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.token_impersonation",
            params={"target": "10.0.0.5", "username": "target_user", "password": "secret"},
        )
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.execute(ctx))
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)
        assert len(mod._findings) == 0

    def test_token_impersonation_validate_raises_explicit_exception(self):
        mod, campaign = _make_module(TokenImpersonationModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.token_impersonation",
            params={"target": "10.0.0.5", "username": "target_user"},
        )
        with pytest.raises(ModuleValidationError) as exc_info:
            _run(mod.validate(ctx))
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)

    def test_token_impersonation_assess_feasibility_reports_disabled(self):
        mod, campaign = _make_module(TokenImpersonationModule)
        ctx = ExecutionContext.build(
            campaign=campaign,
            target="10.0.0.5",
            module_id="windows.token_impersonation",
            params={"target": "10.0.0.5", "username": "target_user"},
        )
        report = _run(mod.assess_feasibility(ctx))
        assert report.feasible is False
        assert any("MOD-030" in b for b in report.blockers)

