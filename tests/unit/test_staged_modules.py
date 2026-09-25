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

    def test_direct_run_method(self):
        mod, _ = _make_module(PhantomTokenModule)
        findings, raw = _run(mod.run(
            tenant_id="corp.onmicrosoft.com",
            evaluate_cap_bypass=True,
            dry_run=False,
        ))
        assert len(findings) == 1
        assert findings[0].mitre_technique == "T1528"
        assert raw.get("prt_valid") is True
        assert raw.get("tenant_id") == "corp.onmicrosoft.com"


class TestGhostForgeModule:
    def test_module_attributes(self):
        assert GhostForgeModule.MODULE_ID == "ad.ghost_forge"
        assert GhostForgeModule.ENABLED is False
        assert GhostForgeModule.DISABLED_REASON == "module disabled: implementation incomplete, see MOD-005"
        assert "T1649" in GhostForgeModule.MITRE_TECHNIQUES
        assert "T1558" in GhostForgeModule.MITRE_TECHNIQUES

    def test_direct_run_raises_disabled_error(self):
        from ares.core.errors import ModuleError
        mod, _ = _make_module(GhostForgeModule)
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.run(
                dc="10.10.10.1",
                domain="CORP.LOCAL",
                ca_server="ca.corp.local",
                ca_name="CORP-CA",
                impersonate_user="Administrator",
                username="audit_operator",
                password="SecretPassword123!",
            ))
        assert "module disabled: implementation incomplete, see MOD-005" in str(exc_info.value)

    def test_execute_raises_disabled_error(self):
        from ares.core.errors import ModuleError
        mod, _ = _make_module(GhostForgeModule)
        ctx = _mock_ctx(params={
            "dc": "10.10.10.1",
            "domain": "CORP.LOCAL",
            "ca_server": "ca.corp.local",
            "ca_name": "CORP-CA",
            "username": "audit_operator",
            "password": "SecretPassword123!",
        })
        with pytest.raises(ModuleError) as exc_info:
            _run(mod.execute(ctx))
        assert "module disabled: implementation incomplete, see MOD-005" in str(exc_info.value)

    def test_validate_raises_disabled_error(self):
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(GhostForgeModule)
        ctx = _mock_ctx(params={
            "dc": "10.10.10.1",
            "domain": "CORP.LOCAL",
            "ca_server": "ca.corp.local",
            "ca_name": "CORP-CA",
            "username": "audit_operator",
            "password": "SecretPassword123!",
        })
        with pytest.raises(ModuleValidationError) as exc_info:
            _run(mod.validate(ctx))
        assert "module disabled: implementation incomplete, see MOD-005" in str(exc_info.value)

    def test_assess_feasibility_reports_disabled(self):
        mod, _ = _make_module(GhostForgeModule)
        ctx = _mock_ctx(params={"dc": "10.10.10.1"})
        report = _run(mod.assess_feasibility(ctx))
        assert report.feasible is False
        assert any("MOD-005" in b for b in report.blockers)

    @pytest.mark.asyncio
    async def test_engine_run_module_fails_with_disabled_error(self, tmp_path):
        from ares.core.campaign import Campaign, ScopeEntry
        from ares.core.engine import AresEngine
        from ares.db.database import AresDatabase
        db_path = str(tmp_path / "loot_test.db")
        db = AresDatabase(db_path)
        await db.connect()
        campaign = Campaign(name="Loot Test", client="Client", scope=[ScopeEntry(cidr="10.10.10.0/24")], operator="operator")
        await db.save_campaign(campaign)

        from ares.core.execution_admission import _mint_test_dispatch_context

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
        assert str(result.status) in ("failed", "ModuleStatus.FAILED")
        assert "module disabled: implementation incomplete, see MOD-005" in (result.error or "")
        loots = await db.get_loot(campaign.id)
        assert len(loots) == 0
        await db.close()

    def test_registry_excludes_ghost_forge_from_listings(self):
        from ares.core.plugin.loader import PluginLoader
        loader = PluginLoader()
        loader._load_builtin()
        assert "ad.ghost_forge" not in [m["id"] for m in loader.registry.list_metadata()]
        assert "ad.ghost_forge" not in [cls.MODULE_ID for cls in loader.registry.all()]
        assert "ad.ghost_forge" not in [cls.MODULE_ID for cls in loader.registry.by_category("ad")]
        assert loader.registry.is_disabled("ad.ghost_forge") is True
        assert loader.registry.get_disabled_reason("ad.ghost_forge") == "module disabled: implementation incomplete, see MOD-005"
        assert "ad.ghost_forge" not in loader.registry

    def test_phantom_token_workload_identity_and_detection(self):
        mod, _ = _make_module(PhantomTokenModule)
        ctx = _mock_ctx(params={
            "tenant_id": "corp.onmicrosoft.com",
            "assessment_mode": "workload_identity",
            "federation_issuer": "https://token.actions.githubusercontent.com",
            "dpop_enforced": True,
            "generate_detection_rules": True,
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert len(res.findings) >= 1
        assert "Workload Identity Federation" in res.findings[0].title
        assert res.raw.get("assessment_mode_applied") == "workload_identity"
        assert res.raw.get("dpop_status") == "enforced"
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_kerberoast_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.ad.kerberoast import KerberoastModule
        mod, _ = _make_module(KerberoastModule)
        async def fake_run(*args, **kwargs):
            return [], {
                "kerberos_hashes": ["$krb5tgs$23$*svc-sql$LAB.LOCAL$MSSQLSvc/sql01.lab.local*..."],
                "accounts": [{"name": "svc-sql", "spn": "MSSQLSvc/sql01.lab.local:1433", "hash": "$krb5tgs$23$..."}],
                "loot": [],
            }
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "LAB.LOCAL", "username": "operator",
            "password": "Password123!", "target_user": "svc-sql",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert res.raw.get("kb5008380_pac_validation_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_asreproast_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.ad.asreproast import ASREPRoastModule
        mod, _ = _make_module(ASREPRoastModule)
        async def fake_run(*args, **kwargs):
            return [], {"asrep_hashes": ["$krb5asrep$23$user@DOMAIN:..."], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "LAB.LOCAL", "username": "operator",
            "password": "Password123!", "usernames": ["svc-backup"],
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert res.raw.get("preauth_policy_assessed") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_adcs_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.ad.adcs import ADCSModule
        mod, _ = _make_module(ADCSModule)
        async def fake_run(*args, **kwargs):
            return [], {"adcs_findings": ["ESC1"], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "LAB.LOCAL", "username": "operator",
            "password": "Password123!", "target_user": "Administrator",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert res.raw.get("kb5014754_strong_mapping_assessed") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_dcsync_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.ad.dcsync import DCSyncModule
        mod, _ = _make_module(DCSyncModule)
        async def fake_run(*args, **kwargs):
            return [], {"ntlm_hashes": {"krbtgt": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "LAB.LOCAL", "username": "da_user",
            "password": "Password123!", "target_user": "krbtgt",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert res.raw.get("replication_extended_rights_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_laps_enum_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.ad.laps_enum import LAPSEnumModule
        mod, _ = _make_module(LAPSEnumModule)
        async def fake_run(*args, **kwargs):
            return [], {"found": 1, "entries": [{"computer": "WS01", "version": "v2"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "LAB.LOCAL", "username": "operator",
            "password": "Password123!",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status == "success"
        assert res.raw.get("laps_v2_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_golden_ticket_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.credential.golden_ticket import GoldenTicketModule
        mod, _ = _make_module(GoldenTicketModule)
        async def fake_run(*args, **kwargs):
            return [], {
                "domain": "CORP.LOCAL",
                "forged_as": "Administrator",
                "success": True,
                "ticket_path": "/tmp/test.ccache",
                "loot": [],
            }
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "domain": "CORP.LOCAL",
            "domain_sid": "S-1-5-21-1234567890-1234567890-1234567890",
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "username": "Administrator",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("diamond_ticket_audited") is True
        assert res.raw.get("aes256_pac_validation_audited") is True
        assert res.raw.get("event_4768_anomaly_monitored") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_pass_the_hash_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.credential.pass_the_hash import PassTheHashModule
        mod, _ = _make_module(PassTheHashModule)
        async def fake_run(*args, **kwargs):
            return [], {
                "target": "10.0.0.5",
                "username": "CORP\\Administrator",
                "success": True,
                "output": "Authenticated",
                "privilege": "local_admin",
                "loot": [],
            }
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "target": "10.0.0.5",
            "username": "Administrator",
            "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain": "CORP",
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("restricted_admin_evaluated") is True
        assert res.raw.get("credential_guard_isolated") is True
        assert res.raw.get("ntlm_deprecation_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_pass_spray_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.credential.pass_spray import PassSprayModule
        mod, _ = _make_module(PassSprayModule)
        async def fake_run(*args, **kwargs):
            return [], {
                "target": "10.0.0.1",
                "domain": "CORP.LOCAL",
                "protocol": "ldap",
                "attempts": 5,
                "valid_credentials": [],
                "locked_accounts": [],
                "lockout_detected": False,
                "loot": [],
            }
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={
            "target": "10.0.0.1",
            "domain": "CORP.LOCAL",
            "users": ["alice", "bob"],
            "passwords": ["Winter2024!"],
        })
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("fgpp_observation_window_evaluated") is True
        assert res.raw.get("smart_lockout_defended") is True
        assert res.raw.get("closed_loop_telemetry_generated") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_dcom_lateral_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.lateral.dcom import DCOMLateral
        mod, _ = _make_module(DCOMLateral)
        async def fake_run(*args, **kwargs):
            return [], {"target": "10.0.0.1", "username": "Admin", "success": True, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.1", "username": "Admin", "password": "SecretPassword123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("credential_guard_evaluated") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_smb_relay_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.lateral.smb_relay import SMBRelayAuditModule
        mod, _ = _make_module(SMBRelayAuditModule)
        async def fake_run(*args, **kwargs):
            return [], {"signing_disabled": ["10.0.0.2"], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"targets": ["10.0.0.2"]})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("smb_signing_enforcement_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_ntlm_relay_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.lateral.ntlm_relay import NTLMRelayModule
        mod, _ = _make_module(NTLMRelayModule)
        async def fake_run(*args, **kwargs):
            return [], {"relay_targets": [{"host": "10.0.0.3"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"dc": "10.0.0.1", "domain": "CORP.LOCAL", "username": "op", "password": "pw"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("ldap_signing_and_channel_binding_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_mssql_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.lateral.mssql import MSSQLModule
        mod, _ = _make_module(MSSQLModule)
        async def fake_run(*args, **kwargs):
            return [], {"target": "10.0.0.4", "success": True, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.4", "username": "sa", "password": "pw"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("clr_assembly_and_xp_cmdshell_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_lsass_dump_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.lsass_dump import LsassDumpModule
        mod, _ = _make_module(LsassDumpModule)
        async def fake_run(*args, **kwargs):
            return [], {"hashes": [{"username": "Admin", "nt": "31d6cfe0d16ae931b73c59d7e0c089c0"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("runasppl_protection_assessed") is True
        assert res.raw.get("credential_guard_vbs_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_lsa_secrets_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.lsa_secrets import LSASecretsModule
        mod, _ = _make_module(LSASecretsModule)
        async def fake_run(*args, **kwargs):
            return [], {"secrets": [{"name": "dpapi_system"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("dpapi_machine_key_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_token_impersonation_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.token_impersonation import TokenImpersonationModule
        mod, _ = _make_module(TokenImpersonationModule)
        async def fake_run(*args, **kwargs):
            return [], {"success": True, "tokens": ["NT AUTHORITY\\SYSTEM"], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("se_impersonate_privilege_evaluated") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_uac_bypass_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.uac_bypass import UACBypassModule
        mod, _ = _make_module(UACBypassModule)
        async def fake_run(*args, **kwargs):
            return [], {"uac_config": {"EnableLUA": 1}, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("consent_prompt_behavior_admin_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_dpapi_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.dpapi import DPAPIModule
        mod, _ = _make_module(DPAPIModule)
        async def fake_run(*args, **kwargs):
            return [], {"masterkeys": [{"guid": "abc-123"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("domain_backup_key_evaluated") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_scheduled_task_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.persistence.scheduled_task import ScheduledTaskPersistence
        mod, _ = _make_module(ScheduledTaskPersistence)
        async def fake_run(*args, **kwargs):
            return [], {"task_name": "AresUpdater", "persistence_established": True, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("event_4698_task_creation_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_wmi_subscription_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.persistence.wmi_subscription import WMISubscriptionModule
        mod, _ = _make_module(WMISubscriptionModule)
        async def fake_run(*args, **kwargs):
            return [], {"subscription_name": "WindowsUpdate", "persistence_established": True, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("sysmon_wmi_events_19_20_21_audited") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_bypass_adaptive_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        async def fake_run(*args, **kwargs):
            return [], {"edr_vendor": "crowdstrike", "viable_techniques": [{"technique_id": "indirect_syscalls"}], "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike", "target": "10.0.0.5"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("indirect_syscalls_and_unhooking_evaluated") is True
        assert res.raw.get("call_stack_spoofing_audited") is True
        assert res.raw.get("hardware_breakpoint_veh_evaluated") is True
        assert res.raw.get("etwti_kernel_telemetry_assessed") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_applocker_bypass_closed_loop_telemetry(self, monkeypatch):
        from ares.modules.windows.applocker_bypass import AppLockerBypassModule
        mod, _ = _make_module(AppLockerBypassModule)
        async def fake_run(*args, **kwargs):
            return [], {"configured": True, "collections": {"Exe": {"enforcement": 2}}, "loot": []}
        monkeypatch.setattr(mod, "run", fake_run)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "Admin", "password": "Password123!"})
        ctx.dry_run = False
        res = _run(mod.execute(ctx))
        assert res.status in ("partial", "success")
        assert res.raw.get("wdac_citool_policy_audited") is True
        assert res.raw.get("smart_app_control_evaluated") is True
        assert res.raw.get("trusted_path_bypass_identified") is True
        assert any(l["loot_type"] == "detection_rule_kql" for l in res.raw["loot"])
        assert any(l["loot_type"] == "detection_rule_sigma" for l in res.raw["loot"])

    def test_bypass_adaptive_modern_techniques(self):
        from ares.modules.edr.bypass_adaptive import _BYPASS_TECHNIQUES, _EDR_BLIND_SPOTS
        tech_ids = {t.technique_id for t in _BYPASS_TECHNIQUES}
        assert "evasion-indirect-syscalls" in tech_ids
        assert "evasion-stack-spoofing" in tech_ids
        assert "evasion-hardware-breakpoints" in tech_ids
        assert "evasion-etwti-tamper-check" in tech_ids
        assert len(_EDR_BLIND_SPOTS["crowdstrike"]) >= 2
        assert len(_EDR_BLIND_SPOTS["sentinelone"]) >= 2
        assert len(_EDR_BLIND_SPOTS["defender_atp"]) >= 2




