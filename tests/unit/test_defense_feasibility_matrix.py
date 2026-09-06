"""
Pre-Flight Defense Feasibility Matrix Unit Tests
Validates intelligent evasion and defense assessment for Windows, Lateral, and Planner modules:
  - windows.lsass_dump (Credential Guard, RunAsPPL, Sysmon ID 10 / EDR hooks)
  - windows.dpapi (Credential Guard bypass, backup key, offline derivation)
  - windows.lsa_secrets (SAM/LSA registry auditing, DC role recommendation)
  - windows.token_impersonation (Potato privilege escalation defense tuning)
  - lateral.psexec, lateral.dcom, lateral.winrm, lateral.rdp (EDR service monitoring, stealth alternatives)
  - AttackPlanner (Automated intelligent evasion routing based on target host defense profile)
  - AresEngine.assess_module_feasibility (Engine orchestration interface)
"""
from __future__ import annotations

import pytest

from ares.core.campaign import Campaign, NoiseProfile
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.state.target_state import HostState, OperatorSession
from ares.modules.windows.lsass_dump import LsassDumpModule
from ares.modules.windows.dpapi import DPAPIModule
from ares.modules.windows.lsa_secrets import LSASecretsModule
from ares.modules.windows.token_impersonation import TokenImpersonationModule
from ares.modules.lateral.modules import PsExecLateral, WmiExecLateral, WinRMLateral, RDPLateral
from ares.modules.lateral.dcom import DCOMLateral
from ares.modules.credential.golden_ticket import GoldenTicketModule
from ares.modules.credential.pass_spray import PassSprayModule
from ares.modules.credential.pass_the_hash import PassTheHashModule
from ares.modules.persistence.scheduled_task import ScheduledTaskPersistence
from ares.modules.persistence.wmi_subscription import WMISubscriptionModule


@pytest.fixture
def dummy_settings():
    return AresSettings(jwt_secret_key="test-secret-that-is-at-least-32-bytes-long!")


@pytest.fixture
def test_campaign():
    return Campaign(
        name="Enterprise Engagement",
        operator="lead_operator",
        noise_profile=NoiseProfile.NORMAL,
    )


@pytest.fixture
def stealth_campaign():
    return Campaign(
        name="Stealth Red Team",
        operator="covert_operator",
        noise_profile=NoiseProfile.STEALTH,
    )


@pytest.fixture
def test_noise(test_campaign):
    return NoiseController(test_campaign)


@pytest.fixture
def stealth_noise(stealth_campaign):
    return NoiseController(stealth_campaign)


class TestLsassDumpFeasibility:
    @pytest.mark.asyncio
    async def test_baseline_feasibility(self, dummy_settings, test_campaign, test_noise):
        mod = LsassDumpModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.lsass_dump",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.8
        assert report.risk_level == "high_noise"
        assert len(report.blockers) == 0

    @pytest.mark.asyncio
    async def test_blocked_by_credential_guard(self, dummy_settings, test_campaign, test_noise):
        mod = LsassDumpModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50", hostname="WORKSTATION-01")
        host.update_defense_profile(controls={"credential_guard": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.lsass_dump",
            params={"username": "Administrator", "password": "Password123!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.score <= 0.1
        assert report.risk_level == "critical_alarm"
        assert any("Credential Guard" in b for b in report.blockers)
        assert "windows.dpapi" in report.recommended_alternatives
        assert "windows.token_impersonation" in report.recommended_alternatives
        assert "ad.kerberoast" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_blocked_by_lsa_protection_ppl(self, dummy_settings, test_campaign, test_noise):
        mod = LsassDumpModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"ppl": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.lsass_dump",
            params={"username": "Administrator", "password": "Password123!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.score <= 0.2
        assert any("RunAsPPL" in b or "LSA Protection" in b for b in report.blockers)
        assert "windows.dpapi" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_blocked_in_stealth_noise_profile(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = LsassDumpModule(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.50",
            module_id="windows.lsass_dump",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.risk_level == "critical_alarm"
        assert any("STEALTH" in b for b in report.blockers)
        assert "windows.dpapi" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_edr_detected_tunes_to_comsvcs(self, dummy_settings, test_campaign, test_noise):
        mod = LsassDumpModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(edr="CrowdStrike Falcon")

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.lsass_dump",
            params={"username": "Administrator", "password": "Password123!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.opsec_tuning.get("recommended_technique") == "comsvcs"
        assert "windows.dpapi" in report.recommended_alternatives


class TestDPAPIFeasibility:
    @pytest.mark.asyncio
    async def test_baseline_feasibility(self, dummy_settings, test_campaign, test_noise):
        mod = DPAPIModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.dpapi",
            params={"username": "jdoe", "password": "UserPass123"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.8
        assert report.risk_level == "medium"

    @pytest.mark.asyncio
    async def test_credential_guard_evasion_advantage(self, dummy_settings, test_campaign, test_noise):
        mod = DPAPIModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"credential_guard": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.dpapi",
            params={"username": "jdoe", "password": "UserPass123"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score == 1.0
        assert "evasion_advantage" in report.opsec_tuning
        assert "Credential Guard" in report.opsec_tuning["evasion_advantage"]

    @pytest.mark.asyncio
    async def test_backup_mode_without_key_blocks(self, dummy_settings, test_campaign, test_noise):
        mod = DPAPIModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.dpapi",
            params={"username": "jdoe", "mode": "backup"},
        )
        report = await mod.assess_feasibility(ctx)
        assert any("Backup key" in b for b in report.blockers)
        assert "windows.lsa_secrets" in report.recommended_alternatives


class TestLSASecretsFeasibility:
    @pytest.mark.asyncio
    async def test_blocked_in_stealth(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = LSASecretsModule(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.50",
            module_id="windows.lsa_secrets",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("STEALTH" in b for b in report.blockers)
        assert "windows.dpapi" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_recommends_dcsync_for_domain_controller(self, dummy_settings, test_campaign, test_noise):
        mod = LSASecretsModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.5", is_dc=True)

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.5",
            module_id="windows.lsa_secrets",
            params={"username": "Administrator", "password": "Password123!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert "ad.dcsync" in report.recommended_alternatives


class TestTokenImpersonationFeasibility:
    @pytest.mark.asyncio
    async def test_edr_tuning_for_potatoes(self, dummy_settings, test_campaign, test_noise):
        mod = TokenImpersonationModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"edr": "SentinelOne"})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="windows.token_impersonation",
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert "GodPotato" in report.opsec_tuning.get("suggested_variant", "")


class TestLateralMovementFeasibility:
    @pytest.mark.asyncio
    async def test_psexec_blocked_in_stealth(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = PsExecLateral(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.50",
            module_id="lateral.psexec",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.risk_level == "critical_alarm"
        assert any("STEALTH" in b for b in report.blockers)
        assert "lateral.dcom" in report.recommended_alternatives
        assert "lateral.winrm" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_psexec_blocked_by_edr(self, dummy_settings, test_campaign, test_noise):
        mod = PsExecLateral(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(edr="Microsoft Defender for Endpoint")

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="lateral.psexec",
            params={"username": "Administrator", "password": "Password123!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.score <= 0.15
        assert any("Event ID 7045" in b for b in report.blockers)
        assert "lateral.dcom" in report.recommended_alternatives
        assert "lateral.winrm" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_dcom_stealthier_alternative(self, dummy_settings, test_campaign, test_noise):
        mod = DCOMLateral(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="lateral.dcom",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.risk_level == "medium"
        assert report.opsec_tuning.get("object_preference") == "MMC20.Application"

    @pytest.mark.asyncio
    async def test_winrm_optimal_admin_protocol(self, dummy_settings, test_campaign, test_noise):
        mod = WinRMLateral(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="lateral.winrm",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.risk_level == "low"
        assert "5985" in report.opsec_tuning.get("preferred_protocol", "")

    @pytest.mark.asyncio
    async def test_rdp_blocked_in_stealth(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = RDPLateral(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.50",
            module_id="lateral.rdp",
            params={"username": "Administrator", "password": "Password123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("STEALTH" in b for b in report.blockers)
        assert "lateral.winrm" in report.recommended_alternatives


class TestAttackPlannerDefenseEvasion:
    def test_planner_prefers_dpapi_over_lsass_dump_when_credential_guard_active(self):
        from ares.goal.planner import AttackPlanner, PlannerContext
        from ares.goal.engine import Goal
        from ares.core.plugin.loader import ModuleRegistry

        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"credential_guard": True})

        registry = ModuleRegistry()
        registry.register(LsassDumpModule)
        registry.register(DPAPIModule)

        planner = AttackPlanner(registry=registry, session=session)
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.10.10.50"],
            opsec_profile="normal",
            session=session,
        )
        suggestions = planner.suggest(ctx, limit=5)

        # DPAPI should rank higher than LSASS dump due to Credential Guard penalty
        suggested_ids = [s.module_id for s in suggestions]
        assert "windows.dpapi" in suggested_ids
        dpapi_score = next((s.score for s in suggestions if s.module_id == "windows.dpapi"), None)
        lsass_score = next((s.score for s in suggestions if s.module_id == "windows.lsass_dump"), 0.0)
        assert dpapi_score is not None
        assert dpapi_score > lsass_score

    def test_planner_penalizes_psexec_when_edr_monitors_services(self):
        from ares.goal.planner import AttackPlanner, PlannerContext
        from ares.goal.engine import Goal
        from ares.core.plugin.loader import ModuleRegistry

        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"service_creation_monitoring": True, "edr": "Falcon"})

        registry = ModuleRegistry()
        registry.register(PsExecLateral)
        registry.register(DCOMLateral)
        registry.register(WinRMLateral)

        planner = AttackPlanner(registry=registry, session=session)
        ctx = PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.10.10.50"],
            opsec_profile="normal",
            session=session,
        )
        suggestions = planner.suggest(ctx, limit=5)

        dcom_score = next((s.score for s in suggestions if s.module_id == "lateral.dcom"), 0.0)
        psexec_score = next((s.score for s in suggestions if s.module_id == "lateral.psexec"), 0.0)
        assert dcom_score > psexec_score


class TestEngineFeasibilityAPI:
    @pytest.mark.asyncio
    async def test_engine_assess_module_feasibility(self, test_campaign):
        from ares.core.engine import AresEngine
        engine = AresEngine()
        engine.load_modules()

        report = await engine.assess_module_feasibility(
            module_id="windows.lsass_dump",
            campaign=test_campaign,
            params={"target": "10.10.10.50", "username": "admin", "password": "Password123!"},
        )
        assert report.feasible is True
        assert report.risk_level == "high_noise"

    @pytest.mark.asyncio
    async def test_engine_assess_nonexistent_module(self, test_campaign):
        from ares.core.engine import AresEngine
        engine = AresEngine()
        report = await engine.assess_module_feasibility(
            module_id="nonexistent.module",
            campaign=test_campaign,
            params={"target": "10.10.10.50"},
        )
        assert report.feasible is False
        assert any("not found" in b for b in report.blockers)


class TestGoldenTicketFeasibility:
    @pytest.mark.asyncio
    async def test_missing_credentials_blockers(self, dummy_settings, test_campaign, test_noise):
        mod = GoldenTicketModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.1",
            module_id="credential.golden_ticket",
            params={},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("domain_sid" in b.lower() for b in report.blockers)
        assert any("krbtgt" in b.lower() for b in report.blockers)

    @pytest.mark.asyncio
    async def test_baseline_feasible(self, dummy_settings, test_campaign, test_noise):
        mod = GoldenTicketModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.1",
            module_id="credential.golden_ticket",
            params={
                "domain": "corp.local",
                "domain_sid": "S-1-5-21-123456789-123456789-123456789",
                "krbtgt_key": "aad3b435b51404eeaad3b435b51404ee",
            },
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.8

    @pytest.mark.asyncio
    async def test_mdi_pac_validation_risk(self, dummy_settings, test_campaign, test_noise):
        mod = GoldenTicketModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.1", is_dc=True)
        host.update_defense_profile(controls={"mdi": True, "pac_validation": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.1",
            module_id="credential.golden_ticket",
            params={"domain": "corp.local", "domain_sid": "S-1-5-21-123", "krbtgt_key": "abcdef"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.risk_level == "critical_alarm"
        assert report.score <= 0.1
        assert "ad.dcsync" in report.recommended_alternatives


class TestPassSprayFeasibility:
    @pytest.mark.asyncio
    async def test_missing_user_list(self, dummy_settings, test_campaign, test_noise):
        mod = PassSprayModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.1",
            module_id="credential.pass_spray",
            params={},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("user_list" in b.lower() for b in report.blockers)

    @pytest.mark.asyncio
    async def test_stealth_noise_blocked(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = PassSprayModule(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.1",
            module_id="credential.pass_spray",
            params={"user_list": ["user1", "user2"], "password": "Password1!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("4625" in b for b in report.blockers)
        assert "ad.asreproast" in report.recommended_alternatives
        assert "ad.kerberoast" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_strict_lockout_blocked(self, dummy_settings, test_campaign, test_noise):
        mod = PassSprayModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.1", is_dc=True)
        host.update_defense_profile(controls={"lockout_threshold": 3})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.1",
            module_id="credential.pass_spray",
            params={"user_list": ["user1", "user2"], "password": "Password1!"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("lockout" in b.lower() for b in report.blockers)


class TestPassTheHashFeasibility:
    @pytest.mark.asyncio
    async def test_missing_hash(self, dummy_settings, test_campaign, test_noise):
        mod = PassTheHashModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="credential.pass_the_hash",
            params={"username": "Administrator"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("ntlm hash is required" in b.lower() for b in report.blockers)

    @pytest.mark.asyncio
    async def test_ntlm_disabled_blocked(self, dummy_settings, test_campaign, test_noise):
        mod = PassTheHashModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"ntlm_disabled": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="credential.pass_the_hash",
            params={"username": "Administrator", "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("kerberos-only" in b.lower() or "ntlm disabled" in b.lower() for b in report.blockers)
        assert "credential.golden_ticket" in report.recommended_alternatives


class TestScheduledTaskFeasibility:
    @pytest.mark.asyncio
    async def test_missing_target(self, dummy_settings, test_campaign, test_noise):
        mod = ScheduledTaskPersistence(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="",
            module_id="persistence.scheduled_task",
            params={},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("No target host specified" in b for b in report.blockers)

    @pytest.mark.asyncio
    async def test_stealth_noise_blocked(self, dummy_settings, stealth_campaign, stealth_noise):
        mod = ScheduledTaskPersistence(dummy_settings, stealth_campaign, stealth_noise)
        ctx = ExecutionContext.build(
            campaign=stealth_campaign,
            target="10.10.10.50",
            module_id="persistence.scheduled_task",
            params={"username": "admin"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert any("4698" in b for b in report.blockers)
        assert "persistence.wmi_subscription" in report.recommended_alternatives


class TestWMISubscriptionFeasibility:
    @pytest.mark.asyncio
    async def test_baseline_feasible(self, dummy_settings, test_campaign, test_noise):
        mod = WMISubscriptionModule(dummy_settings, test_campaign, test_noise)
        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="persistence.wmi_subscription",
            params={"username": "admin"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.8

    @pytest.mark.asyncio
    async def test_sysmon_telemetry_detected(self, dummy_settings, test_campaign, test_noise):
        mod = WMISubscriptionModule(dummy_settings, test_campaign, test_noise)
        session = OperatorSession(campaign_id="test-camp")
        host = session.add_host("10.10.10.50")
        host.update_defense_profile(controls={"sysmon_id19": True})

        ctx = ExecutionContext.build(
            campaign=test_campaign,
            target="10.10.10.50",
            module_id="persistence.wmi_subscription",
            params={"username": "admin"},
            session=session,
        )
        report = await mod.assess_feasibility(ctx)
        assert "Sysmon 19/20/21" in report.opsec_tuning.get("note", "")


class TestModuleFeasibilityEndpoint:
    def test_feasibility_endpoint_success(self, test_campaign):
        from unittest.mock import AsyncMock, MagicMock
        from fastapi.testclient import TestClient
        from ares.api.server import app, get_engine, get_db, get_current_user
        from ares.core.engine import AresEngine
        from ares.api.rbac import AuthenticatedUser
        from ares.modules.base import FeasibilityReport

        mock_user = AuthenticatedUser(username="operator1", role="operator")
        mock_db = MagicMock()
        mock_db.get_campaign = AsyncMock(return_value=test_campaign)
        mock_engine = MagicMock(spec=AresEngine)
        mock_report = FeasibilityReport(
            feasible=True,
            score=0.85,
            risk_level="low",
            blockers=[],
            recommended_alternatives=[],
            opsec_tuning={"test": "tuning"},
        )
        mock_engine.assess_module_feasibility = AsyncMock(return_value=mock_report)
        mock_engine.bind_database = MagicMock()

        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: mock_db
        app.dependency_overrides[get_engine] = lambda: mock_engine

        try:
            client = TestClient(app, base_url="http://localhost:8000")
            resp = client.post(
                "/modules/credential.pass_the_hash/feasibility",
                json={
                    "campaign_id": test_campaign.id,
                    "target": "10.10.10.50",
                    "params": {"nthash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"},
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["module_id"] == "credential.pass_the_hash"
            assert data["campaign_id"] == test_campaign.id
            assert data["report"]["feasible"] is True
            assert data["report"]["score"] == 0.85
        finally:
            app.dependency_overrides.clear()

