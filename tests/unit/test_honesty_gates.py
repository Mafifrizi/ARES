"""
Tests for Gate 3 (Engine Validator Enforcement) and Gate 5 (Goal Indicator Verifier).
Verifies fail-closed enforcement preventing phantom exploits, fake findings, and premature goal achievement.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock

from ares.core.config import AresSettings
from ares.core.campaign import Campaign, Finding, Severity, ScopeEntry
from ares.core.engine import AresEngine, EngineModuleResult, ModuleStatus
from ares.core.validator import (
    FindingValidator,
    ValidationCheck,
    ValidationStage,
    ValidationResult,
    build_default_validator,
)
from ares.strategy.engine import StrategyEngine
from ares.credential.vault import CredentialVault, Credential, CredentialType, PrivilegeLevel


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Fixtures & Factories
# ═══════════════════════════════════════════════════════════════════════════════

from ares.core.campaign import Campaign, Finding, Severity, ScopeEntry, NoiseProfile

def _make_campaign() -> Campaign:
    return Campaign(
        name="honesty-gate-test",
        client="test-client",
        operator="test-operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        targets=["10.0.0.5"],
        noise_profile=NoiseProfile.NORMAL,
    )

def _make_settings() -> AresSettings:
    return AresSettings(
        environment="test",
        encryption_master_key="0" * 64,
        jwt_secret_key="0" * 32,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# GATE 3: Engine Validator Fail-Closed Enforcement Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGate3ValidatorEnforcement:
    """Verifies that AresEngine enforces validator results fail-closed."""

    @pytest.mark.asyncio
    async def test_high_confidence_finding_confirmed(self):
        """Valid finding with high confidence (>= 0.4) is confirmed."""
        validator = FindingValidator()
        validator.register("test.valid", [
            ValidationCheck(
                stage=ValidationStage.EXPLOITABLE,
                name="pass_check",
                check=AsyncMock(return_value=(True, 0.9, "verified")),
            )
        ])
        engine = AresEngine(settings=_make_settings(), validator=validator)
        campaign = _make_campaign()

        finding = Finding(
            title="Verified Vulnerability",
            description="High confidence evidence",
            severity=Severity.HIGH,
            module_id="test.valid",
        )

        val_res = await validator.validate(finding, {})
        assert val_res.should_report is True
        assert val_res.confidence >= 0.4
        assert finding.validated is True
        assert finding.false_positive is False

    @pytest.mark.asyncio
    async def test_low_confidence_finding_rejected_by_validator(self):
        """Finding with confidence < 0.4 is rejected and marked as false positive."""
        validator = FindingValidator()
        validator.register("test.fake", [
            ValidationCheck(
                stage=ValidationStage.EXPLOITABLE,
                name="fail_check",
                check=AsyncMock(return_value=(False, 0.2, "insufficient evidence")),
            )
        ])
        engine = AresEngine(settings=_make_settings(), validator=validator)

        finding = Finding(
            title="Phantom Exploit Finding",
            description="No real evidence behind this",
            severity=Severity.CRITICAL,
            module_id="test.fake",
        )

        val_res = await validator.validate(finding, {})
        assert val_res.should_report is False
        assert val_res.confidence < 0.4
        assert finding.false_positive is True
        assert finding.validated is False

    @pytest.mark.asyncio
    async def test_unregistered_module_finding_passes_with_default_confidence(self):
        """Finding from an unregistered module passes with default 0.6 confidence (0.6 >= 0.4)."""
        validator = FindingValidator()  # empty registry
        engine = AresEngine(settings=_make_settings(), validator=validator)

        finding = Finding(
            title="Unregistered Module Finding",
            description="Module not in registry yet",
            severity=Severity.MEDIUM,
            module_id="community.new_scanner",
        )

        val_res = await validator.validate(finding, {})
        assert val_res.confidence == 0.6
        assert val_res.should_report is True
        assert finding.validated is True
        assert finding.false_positive is False

    @pytest.mark.asyncio
    async def test_lateral_evidence_target_only_rejected(self):
        """Lateral movement finding with only target host (MOD-021 pattern) scores 0.2 and is rejected."""
        validator = build_default_validator()

        rdp_finding = Finding(
            title="Lateral Movement: RDP -> 10.0.0.5",
            description="Port 3389 was open, claiming lateral movement",
            severity=Severity.HIGH,
            module_id="lateral.rdp",
            host="10.0.0.5",
            evidence={"target": "10.0.0.5"},  # target only! No command output, no session
        )

        val_res = await validator.validate(rdp_finding, {})
        assert val_res.confidence == 0.2
        assert val_res.passed is False
        assert val_res.should_report is False
        assert rdp_finding.false_positive is True
        assert rdp_finding.validated is False

    @pytest.mark.asyncio
    async def test_lateral_evidence_target_plus_execution_confirmed(self):
        """Lateral movement finding with target + command output scores 0.8 and is confirmed."""
        validator = build_default_validator()

        psexec_finding = Finding(
            title="Lateral Movement: lateral.psexec -> 10.0.0.5",
            description="Moved laterally and executed whoami",
            severity=Severity.CRITICAL,
            module_id="lateral.psexec",
            host="10.0.0.5",
            evidence={
                "target": "10.0.0.5",
                "command_output": "nt authority\\system",
                "technique": "psexec",
            },
        )

        val_res = await validator.validate(psexec_finding, {})
        assert val_res.confidence == 0.8
        assert val_res.passed is True
        assert val_res.should_report is True
        assert psexec_finding.validated is True
        assert psexec_finding.false_positive is False

    @pytest.mark.asyncio
    async def test_engine_execution_filters_unvalidated_findings(self):
        """Engine execution loop rejects findings where validator returned confidence < 0.4."""
        from ares.modules.base import ModuleResult
        from unittest.mock import patch

        validator = FindingValidator()
        validator.register("test.mixed", [
            ValidationCheck(
                stage=ValidationStage.EXPLOITABLE,
                name="selective_check",
                check=lambda finding, context: (
                    AsyncMock(return_value=(True, 0.9, "good"))()
                    if "Valid" in finding.title
                    else AsyncMock(return_value=(False, 0.1, "bad"))()
                ),
            )
        ])
        engine = AresEngine(settings=_make_settings(), validator=validator)
        campaign = _make_campaign()

        f_good = Finding(title="Valid Finding", description="Passes", severity=Severity.HIGH, module_id="test.mixed")
        f_bad = Finding(title="Fake Finding", description="Fails", severity=Severity.CRITICAL, module_id="test.mixed")

        # Mock the dispatch and execution to reach the engine validation loop directly
        from ares.core.execution_admission import _mint_test_dispatch_context
        from ares.modules.ad.kerberoast import KerberoastModule

        engine.load_modules()
        # Register a mock module that produces both findings
        async def fake_exec(self_unused, ctx):
            return ModuleResult(
                status="success",
                findings=[f_good, f_bad],
                raw={"test": True},
                module_id="test.mixed",
            )

        with patch.object(KerberoastModule, "execute", fake_exec):
            # Temporarily register test.mixed validator on kerberoast
            validator.register("ad.kerberoast", validator._registry["test.mixed"])
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                {"dc": "10.0.0.5", "domain": "corp.local", "username": "u", "password": "p", "target_user": "t"},
                actor_role="team_lead",
                dispatch_context=_mint_test_dispatch_context(engine, campaign.id, "ad.kerberoast"),
            )

        # Gate 3 enforcement: only f_good is confirmed, f_bad is rejected
        assert result.status == ModuleStatus.DONE
        assert len(result.findings) == 1
        assert result.findings[0].title == "Valid Finding"
        assert result.findings[0].validated is True
        assert f_bad.false_positive is True
        assert f_bad.validated is False


# ═══════════════════════════════════════════════════════════════════════════════
# GATE 5: Goal Indicator Verifier Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGate5GoalVerifier:
    """Verifies that StrategyEngine._check_goal_achieved requires confirmed findings and vault evidence."""

    def _make_strategy_engine(self):
        return StrategyEngine(ares_engine=MagicMock(), settings=MagicMock())

    def test_goal_not_achieved_if_finding_not_confirmed(self):
        """Title matches 'DCSync' but finding is unvalidated or marked false positive -> goal fails."""
        engine = self._make_strategy_engine()
        campaign = _make_campaign()

        # Finding with matching title, but false_positive=True, validated=False
        f = Finding(
            title="DCSync Attack Successful",
            description="Fake DCSync",
            severity=Severity.CRITICAL,
        )
        f.false_positive = True
        f.validated = False
        campaign.findings = [f]

        # Even with vault credentials present, unvalidated finding must block goal
        mock_vault = MagicMock()
        mock_vault.all.return_value = [
            MagicMock(cred_type="ntlm", privilege="domain_admin", username="krbtgt")
        ]
        object.__setattr__(campaign, "_vault", mock_vault)

        assert engine._check_goal_achieved(campaign, "domain_admin") is False

    def test_goal_not_achieved_if_confirmed_finding_but_vault_empty(self):
        """Finding is confirmed, but vault has no credentials -> privilege goal fails."""
        engine = self._make_strategy_engine()
        campaign = _make_campaign()

        # Finding passed Gate 3
        f = Finding(
            title="DCSync Attack - krbtgt hash obtained",
            description="Real DCSync finding",
            severity=Severity.CRITICAL,
        )
        f.validated = True
        f.false_positive = False
        campaign.findings = [f]

        # Vault is empty
        mock_vault = MagicMock()
        mock_vault.all.return_value = []
        mock_vault.domain_admins.return_value = []
        object.__setattr__(campaign, "_vault", mock_vault)

        assert engine._check_goal_achieved(campaign, "domain_admin") is False

    def test_goal_achieved_when_confirmed_finding_and_vault_creds_exist(self):
        """Finding is confirmed AND vault has supporting credentials -> goal succeeds."""
        engine = self._make_strategy_engine()
        campaign = _make_campaign()

        f = Finding(
            title="DCSync Attack - krbtgt hash obtained",
            description="Real DCSync finding",
            severity=Severity.CRITICAL,
        )
        f.validated = True
        f.false_positive = False
        campaign.findings = [f]

        # Real CredentialVault with a stored Domain Admin credential
        vault = CredentialVault(encryption_key="test-key-32-chars-long-secret!!")
        cred = Credential(
            username="krbtgt",
            domain="CORP",
            cred_type=CredentialType.NTLM,
            privilege=PrivilegeLevel.DOMAIN_ADMIN,
        )
        vault.store(cred, "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        object.__setattr__(campaign, "_vault", vault)

        assert engine._check_goal_achieved(campaign, "domain_admin") is True

    def test_non_privilege_goal_does_not_require_vault_credentials(self):
        """Non-privilege goals like data_exfil only require confirmed findings, not vault credentials."""
        engine = self._make_strategy_engine()
        campaign = _make_campaign()

        f = Finding(
            title="Sensitive File Exfiltrated: financials.xlsx",
            description="Data exfil confirmed",
            severity=Severity.HIGH,
        )
        f.validated = True
        f.false_positive = False
        campaign.findings = [f]
        # No vault attached at all
        assert engine._check_goal_achieved(campaign, "data_exfil") is True


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION: MOD-005 and MOD-021 Simulation Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGate3And5IntegrationSimulations:
    """End-to-end integration scenarios verifying defense against MOD-005 and MOD-021 failure modes."""

    @pytest.mark.asyncio
    async def test_mod_005_ghost_forge_simulation(self):
        """
        Simulation of MOD-005 (ghost_forge):
        Module produces CRITICAL 'DCSync Success' finding without network I/O or valid evidence.
        1. Gate 3 rejects the finding (confidence too low / no execution evidence).
        2. Finding is excluded from confirmed and marked false positive.
        3. Gate 5 verifies that domain_admin goal is NOT achieved.
        """
        validator = build_default_validator()
        strategy_engine = StrategyEngine(ares_engine=MagicMock(), settings=MagicMock())
        campaign = _make_campaign()

        # Simulated ghost_forge finding with empty evidence (no captured hashes, no I/O)
        fake_finding = Finding(
            title="DCSync Attack - krbtgt hash obtained",
            description="Claimed DCSync without real network execution",
            severity=Severity.CRITICAL,
            module_id="ad.kerberoast",  # registered AD validator
            evidence={"hash_count": 0},  # 0 hashes captured!
        )

        # Gate 3: validate
        val_res = await validator.validate(fake_finding, {})
        assert val_res.confidence < 0.4
        assert val_res.should_report is False
        assert fake_finding.false_positive is True
        assert fake_finding.validated is False

        # Attempt to achieve goal with this rejected finding
        campaign.findings = [fake_finding]
        assert strategy_engine._check_goal_achieved(campaign, "domain_admin") is False

    @pytest.mark.asyncio
    async def test_mod_021_rdp_port_open_simulation(self):
        """
        Simulation of MOD-021 (RDP port open false lateral movement):
        Module produces finding 'Lateral Movement via RDP' simply because port 3389 was open.
        1. Gate 3 blocks finding (target only = 0.2 < 0.4).
        2. Gate 5 rejects goal achievement because finding is unvalidated and vault has no creds.
        """
        validator = build_default_validator()
        strategy_engine = StrategyEngine(ares_engine=MagicMock(), settings=MagicMock())
        campaign = _make_campaign()

        fake_lateral_finding = Finding(
            title="Lateral Movement via RDP: 10.0.0.5",
            description="Port 3389 open - no session established",
            severity=Severity.HIGH,
            module_id="lateral.rdp",
            host="10.0.0.5",
            evidence={"target": "10.0.0.5", "port": 3389},
        )

        # Gate 3: validate
        val_res = await validator.validate(fake_lateral_finding, {})
        assert val_res.confidence == 0.2
        assert val_res.should_report is False
        assert fake_lateral_finding.false_positive is True
        assert fake_lateral_finding.validated is False

        # Gate 5: goal not achieved
        campaign.findings = [fake_lateral_finding]
        assert strategy_engine._check_goal_achieved(campaign, "domain_admin") is False


# ═══════════════════════════════════════════════════════════════════════════════
# GATE 6: Vault Write Guard (MOD-045, MOD-049 Integrity Protection)
# ═══════════════════════════════════════════════════════════════════════════════

class TestGate6VaultWriteGuard:
    """
    Gate 6 verifies that:
      1. Empty or synthetic secrets (PRT_ESTSAUTH_, TGT_PKINIT_, SIMULATED_, FAKE_, TEST_) are blocked.
      2. Incoherent credential types (e.g. Linux crypt hash declared as CLEARTEXT) are blocked.
      3. Secrets are only stored when genuine I/O evidence exists in the execution context.
      4. Synthetic token injection attacks like cloud.phantom_token are blocked before vault poisoning.
    """

    def test_empty_secret_blocked(self, caplog, capsys):
        vault = CredentialVault(encryption_key=None)
        # Empty string via add()
        res = vault.add(username="testuser", secret="", cred_type="cleartext")
        assert res is False
        captured = caplog.text + capsys.readouterr().out + capsys.readouterr().err
        assert "vault_write_blocked_invalid_secret" in captured

    def test_synthetic_prefixes_blocked(self, caplog, capsys):
        vault = CredentialVault(encryption_key=None)
        synthetic_secrets = [
            "PRT_ESTSAUTH_dev-123456789abc",
            "TGT_PKINIT_base64payloadhere",
            "SIMULATED_TOKEN_XYZ",
            "FAKE_PASSWORD_123",
            "TEST_SECRET_DO_NOT_USE",
        ]
        for syn in synthetic_secrets:
            res = vault.add(username="user1", secret=syn, cred_type="cleartext")
            assert res is False
        captured = caplog.text + capsys.readouterr().out + capsys.readouterr().err
        assert "vault_write_blocked_invalid_secret" in captured

    def test_hash_declared_as_cleartext_blocked(self, caplog, capsys):
        vault = CredentialVault(encryption_key=None)
        linux_sha512 = "$6$rounds=5000$saltsalt$xyz123abc456"
        # Declared as CLEARTEXT (MOD-045 bug pattern) -> must be blocked
        res = vault.add(username="root", secret=linux_sha512, cred_type=CredentialType.CLEARTEXT)
        assert res is False
        captured = caplog.text + capsys.readouterr().out + capsys.readouterr().err
        assert "vault_write_blocked_type_mismatch" in captured

    def test_hash_declared_as_hash_allowed(self):
        vault = CredentialVault(encryption_key=None)
        linux_sha512 = "$6$rounds=5000$saltsalt$xyz123abc456"
        # Correctly declared as HASH
        res = vault.add(username="root", secret=linux_sha512, cred_type=CredentialType.HASH)
        assert res is not False
        assert len(vault.all()) == 1

    def test_credential_valid_with_io_evidence_allowed(self):
        from ares.core.context import ExecutionContext
        vault = CredentialVault(encryption_key=None)
        ctx = ExecutionContext(
            target="10.0.0.1",
            module_id="linux.sssd_harvest",
            vault=vault,
        )
        ctx.mark_network_io_occurred(True)
        res = ctx.record_credential(
            username="ad_admin",
            secret="CorrectPassword2026!",
            cred_type="cleartext",
        )
        assert res is not None
        assert res is not False
        assert len(vault.all()) == 1

    def test_phantom_token_synthetic_simulation_completely_blocked(self, caplog, capsys):
        from ares.core.context import ExecutionContext
        vault = CredentialVault(encryption_key=None)
        ctx = ExecutionContext(
            target="corp.onmicrosoft.com",
            module_id="cloud.phantom_token",
            vault=vault,
        )
        # Case A: No I/O occurred -> blocked by Condition 2
        res = ctx.record_credential(
            username="corp.onmicrosoft.com_prt_session",
            secret="PRT_ESTSAUTH_dev-0123456789ab",
            cred_type="token",
        )
        assert res is False
        captured = caplog.text + capsys.readouterr().out + capsys.readouterr().err
        assert "vault_write_blocked_zero_io" in captured

        # Case B: Even if someone marked I/O occurred, blocked by Condition 1 (synthetic prefix)
        ctx.mark_network_io_occurred(True)
        res2 = ctx.record_credential(
            username="corp.onmicrosoft.com_prt_session",
            secret="PRT_ESTSAUTH_dev-0123456789ab",
            cred_type="token",
        )
        assert res2 is False or res2 is None
        assert len(vault.all()) == 0
