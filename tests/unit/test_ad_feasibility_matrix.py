"""
Unit tests for the ARES Pre-Flight Defense Feasibility Matrix.
Tests feasibility evaluation across Active Directory modules:
- ad.adcs
- ad.kerberoast
- ad.asreproast
- ad.dcsync
And HostState defense profiling integration.
"""
from __future__ import annotations

import pytest

from ares.core.campaign import Campaign, NoiseProfile
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.modules.base import BaseModule, FeasibilityReport, OpsecLevel
from ares.state.target_state import HostState, OperatorSession
from ares.modules.ad.adcs import ADCSModule
from ares.modules.ad.kerberoast import KerberoastModule
from ares.modules.ad.asreproast import ASREPRoastModule
from ares.modules.ad.dcsync import DCSyncModule
from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule


@pytest.fixture
def dummy_settings():
    return AresSettings(jwt_secret_key="test-secret-that-is-at-least-32-bytes-long!")


@pytest.fixture
def dummy_campaign():
    return Campaign(name="test-feasibility-campaign", operator="test_operator", noise_profile=NoiseProfile.NORMAL)


@pytest.fixture
def dummy_noise(dummy_campaign):
    return NoiseController(dummy_campaign)


class TestHostStateDefenseProfile:
    def test_host_state_defense_profile_defaults(self):
        host = HostState(ip_address="10.0.0.10", hostname="dc01.corp.local")
        assert host.defense_profile == {}
        assert host.security_controls == {}
        assert host.has_defense("crowdstrike") is False

    def test_host_state_update_and_has_defense(self):
        host = HostState(ip_address="10.0.0.10", hostname="dc01.corp.local")
        host.update_defense_profile({
            "edr_vendor": "CrowdStrike",
            "crowdstrike": True,
            "credential_guard": True,
            "ldap_signing_enforced": True,
        })
        assert host.has_defense("crowdstrike") is True
        assert host.has_defense("CrowdStrike") is True
        assert host.has_defense("credential_guard") is True
        assert host.has_defense("sentinelone") is False

    def test_host_state_serialization_round_trip(self):
        sess = OperatorSession(campaign_id="test-camp")
        host = sess.add_host("10.0.0.20", hostname="srv01.corp.local")
        host.update_defense_profile({"mde_identity": True, "edr_vendor": "defender_atp"})
        snapshot = sess.snapshot()

        restored = OperatorSession.from_snapshot(snapshot)
        restored_host = restored.get_host("10.0.0.20")
        assert restored_host is not None
        assert restored_host.has_defense("mde_identity") is True
        assert restored_host.defense_profile.get("edr_vendor") == "defender_atp"


class TestBaseModuleFeasibility:
    @pytest.mark.asyncio
    async def test_default_base_module_feasibility_normal(self, dummy_settings, dummy_campaign, dummy_noise):
        class DummyMod(BaseModule):
            MODULE_ID = "test.dummy"
            OPSEC_LEVEL = OpsecLevel.LOW

        mod = DummyMod(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(campaign=dummy_campaign, target="10.0.0.1", module_id=mod.MODULE_ID)
        report = await mod.assess_feasibility(ctx)
        assert isinstance(report, FeasibilityReport)
        assert report.feasible is True
        assert report.score == 1.0
        assert report.risk_level == "low"
        assert report.blockers == []

    @pytest.mark.asyncio
    async def test_default_base_module_stealth_blocks_high_noise(self, dummy_settings, dummy_campaign, dummy_noise):
        class NoisyMod(BaseModule):
            MODULE_ID = "test.noisy"
            OPSEC_LEVEL = OpsecLevel.HIGH_NOISE

        mod = NoisyMod(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign, target="10.0.0.1", module_id=mod.MODULE_ID, opsec_profile="stealth"
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.score < 0.5
        assert report.risk_level == "high_noise"
        assert len(report.blockers) > 0


class TestADCSFeasibility:
    @pytest.mark.asyncio
    async def test_adcs_feasibility_ready(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ADCSModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.9
        assert report.risk_level == "low"
        assert report.blockers == []

    @pytest.mark.asyncio
    async def test_adcs_feasibility_missing_dc(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ADCSModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="",
            module_id=mod.MODULE_ID,
            params={"username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert "No Domain Controller (dc) or target IP specified" in report.blockers

    @pytest.mark.asyncio
    async def test_adcs_feasibility_recommends_asreproast_when_unauthenticated(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ADCSModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert "ad.asreproast" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_adcs_feasibility_detects_target_edr(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ADCSModule(dummy_settings, dummy_campaign, dummy_noise)
        session = OperatorSession(campaign_id="test-camp")
        dc_host = session.add_host("10.0.0.10")
        dc_host.update_defense_profile({"crowdstrike": True, "edr_active": True})

        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            session=session,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.risk_level == "medium"
        assert "ad.shadow_credentials" in report.recommended_alternatives


class TestKerberoastFeasibility:
    @pytest.mark.asyncio
    async def test_kerberoast_feasibility_normal_profile(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = KerberoastModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.risk_level == "medium"
        assert "preferred_cipher" in report.opsec_tuning

    @pytest.mark.asyncio
    async def test_kerberoast_feasibility_stealth_profile_recommends_adcs(self, dummy_settings):
        stealth_camp = Campaign(name="stealth-camp", noise_profile=NoiseProfile.STEALTH)
        mod = KerberoastModule(dummy_settings, stealth_camp, NoiseController(stealth_camp))
        ctx = ExecutionContext.build(
            campaign=stealth_camp,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.risk_level == "high_noise"
        assert any("STEALTH" in b for b in report.blockers)
        assert "ad.adcs" in report.recommended_alternatives
        assert "ad.enum_spn" in report.recommended_alternatives


class TestASREPRoastFeasibility:
    @pytest.mark.asyncio
    async def test_asreproast_feasibility_with_creds(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ASREPRoastModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "alice", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.score >= 0.9

    @pytest.mark.asyncio
    async def test_asreproast_feasibility_with_user_list(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ASREPRoastModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "usernames": ["svc_backup", "svc_sql"]},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.details.get("auth_mode") == "unauthenticated_list"

    @pytest.mark.asyncio
    async def test_asreproast_feasibility_without_any_users(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = ASREPRoastModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert "ad.enum_users" in report.recommended_alternatives


class TestDCSyncFeasibility:
    @pytest.mark.asyncio
    async def test_dcsync_feasibility_normal_profile(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = DCSyncModule(dummy_settings, dummy_campaign, dummy_noise)
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "Administrator", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is True
        assert report.risk_level == "high_noise"

    @pytest.mark.asyncio
    async def test_dcsync_feasibility_stealth_blocks_and_recommends_adcs(self, dummy_settings):
        stealth_camp = Campaign(name="stealth-camp", noise_profile=NoiseProfile.STEALTH)
        mod = DCSyncModule(dummy_settings, stealth_camp, NoiseController(stealth_camp))
        ctx = ExecutionContext.build(
            campaign=stealth_camp,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "Administrator", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.feasible is False
        assert report.risk_level == "critical_alarm"
        assert "ad.adcs" in report.recommended_alternatives
        assert "ad.shadow_credentials" in report.recommended_alternatives

    @pytest.mark.asyncio
    async def test_dcsync_feasibility_target_with_drsuapi_monitoring(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = DCSyncModule(dummy_settings, dummy_campaign, dummy_noise)
        session = OperatorSession(campaign_id="test-camp")
        dc_host = session.add_host("10.0.0.10")
        dc_host.update_defense_profile({"mde_identity": True, "drsuapi_monitoring": True})

        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            session=session,
            params={"dc": "10.0.0.10", "domain": "corp.local", "username": "Administrator", "password": "Secret123!"},
        )
        report = await mod.assess_feasibility(ctx)
        assert report.risk_level == "critical_alarm"
        assert "ad.adcs" in report.recommended_alternatives


class TestEDRBridgeIntegration:
    @pytest.mark.asyncio
    async def test_edr_execution_populates_host_defense_profile(self, dummy_settings, dummy_campaign, dummy_noise):
        mod = EDRAdaptiveBypassModule(dummy_settings, dummy_campaign, dummy_noise)
        session = OperatorSession(campaign_id="test-camp")
        ctx = ExecutionContext.build(
            campaign=dummy_campaign,
            target="10.0.0.10",
            module_id=mod.MODULE_ID,
            session=session,
            params={"edr_vendor": "crowdstrike", "target": "10.0.0.10"},
        )
        res = await mod.execute(ctx)
        assert res.status in ("success", "partial")

        host = session.get_host("10.0.0.10")
        assert host is not None
        assert host.has_defense("crowdstrike") is True
        assert host.has_defense("edr_active") is True
