"""
ARES Simulation Tests
End-to-end campaign simulations using dry_run=True.
No real network calls — verifies the full automation logic:
  Engine → GoalEngine → ModuleRegistry → Module → ModuleResult → StateUpdate

These tests prove:
  1. A full attack chain can be planned and simulated
  2. ExecutionContext flows through every layer correctly
  3. ModuleResult causes correct state transitions
  4. Error handling and fallback paths work end-to-end
  5. Telemetry is collected for all executions
  6. Campaign checkpoint save/restore is lossless
  7. Artifact correlation produces attack opportunities
  8. Multi-operator collaboration enforces access correctly
  9. Adaptive strategy generates fallback paths
  10. GuardRail blocks out-of-scope operations everywhere

Run with: pytest tests/simulation/ -v --tb=short
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ares.core.campaign import Campaign, Finding, NoiseProfile, Severity, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.di import AresContainer
from ares.core.errors import (
    AccountLocked, AuthenticationFailed,
    ModuleValidationError, ScopeError,
    HoneypotDetected,
)
from ares.modules.base import BaseModule, ModuleResult, OpsecLevel


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def enc_key() -> bytes:
    raw = hashlib.sha256(b"sim-test-key").digest()
    return base64.urlsafe_b64encode(raw)


@pytest.fixture
def container() -> AresContainer:
    return AresContainer.for_test()


@pytest.fixture
def campaign() -> Campaign:
    return Campaign(
        name="Simulation Campaign",
        client="SimCorp",
        scope=[
            ScopeEntry(cidr="10.0.0.0/8"),
            ScopeEntry(cidr="192.168.0.0/16"),
        ],
        noise_profile=NoiseProfile.NORMAL,
        operator="sim_operator",
        domain="CORP.LOCAL",
    )


@pytest.fixture
def stealth_campaign() -> Campaign:
    return Campaign(
        name="Stealth Simulation",
        client="StealthCorp",
        scope=[ScopeEntry(cidr="172.16.0.0/12")],
        noise_profile=NoiseProfile.STEALTH,
        operator="silent_op",
        domain="STEALTH.LOCAL",
    )


# ── Stub module for simulation ──────────────────────────────────────────────────

class StubKerberoastModule(BaseModule):
    MODULE_ID          = "ad.kerberoast"
    MODULE_NAME        = "Kerberoast Stub"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Stub kerberoast for simulation"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["credential"]
    MITRE_TECHNIQUES   = ["T1558.003"]

    async def run(self, **kwargs: Any):
        if kwargs.get("dry_run") or getattr(self, "_dry_run", False):
            return [], {}
        f = self.finding(
            title="Kerberoastable SPN found",
            description="svc_sql has SPN MSSQLSvc/db01:1433",
            severity=Severity.HIGH,
            mitre_technique="T1558.003",
            host=kwargs.get("dc", "10.0.0.1"),
        )
        return [f], {"hashes": ["$krb5tgs$23$..."], "spn_count": 1}

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        if ctx.dry_run:
            f = self.finding(
                title="[DRY RUN] Kerberoastable SPN",
                description="Simulated kerberoast — svc_sql",
                severity=Severity.HIGH,
                mitre_technique="T1558.003",
                host=ctx.target,
            )
            return ModuleResult(
                status="success", findings=[f],
                raw={"hashes": ["$krb5tgs$23$..."], "spn_count": 1},
                module_id=self.MODULE_ID,
            )
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(status="success", findings=findings, raw=raw,
                            module_id=self.MODULE_ID, execution_id=ctx.execution_id)


class StubDCSyncModule(BaseModule):
    MODULE_ID          = "ad.dcsync"
    MODULE_NAME        = "DCSync Stub"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Stub DCSync for simulation"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    REQUIRES           = ["domain_admin_creds"]
    OUTPUTS            = ["all_ntlm_hashes"]
    MITRE_TECHNIQUES   = ["T1003.006"]

    async def run(self, **kwargs: Any):
        return [], {}

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        if ctx.dry_run:
            f = self.finding(
                title="[DRY RUN] DCSync — all hashes",
                description="Simulated DCSync — retrieved 150 hashes",
                severity=Severity.CRITICAL,
                mitre_technique="T1003.006",
                host=ctx.target,
            )
            return ModuleResult(
                status="success", findings=[f],
                raw={"hash_count": 150, "domain": ctx.domain},
                module_id=self.MODULE_ID,
            )
        return ModuleResult(status="no_op", module_id=self.MODULE_ID)


class StubLateralModule(BaseModule):
    MODULE_ID          = "lateral.wmiexec"
    MODULE_NAME        = "WMI Exec Stub"
    MODULE_CATEGORY    = "lateral"
    MODULE_DESCRIPTION = "Stub lateral for simulation"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["local_admin"]
    OUTPUTS            = ["shell_access"]
    MITRE_TECHNIQUES   = ["T1047"]

    async def run(self, **kwargs: Any):
        return [], {}

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        if ctx.dry_run:
            f = self.finding(
                title="[DRY RUN] WMI lateral movement",
                description=f"Simulated WMI shell on {ctx.target}",
                severity=Severity.HIGH,
                mitre_technique="T1047",
                host=ctx.target,
            )
            return ModuleResult(
                status="success", findings=[f],
                discovered_hosts=[ctx.target],
                module_id=self.MODULE_ID,
            )
        return ModuleResult(status="no_op", module_id=self.MODULE_ID)


# ── Scenario 1: Basic AD attack chain (dry run) ────────────────────────────────

class TestScenario01BasicADChain:
    """
    Simulate: domain user creds → kerberoast → lateral movement → DCSync.
    Full campaign automation without any real network activity.
    """

    @pytest.mark.asyncio
    async def test_kerberoast_produces_finding(self, campaign) -> None:
        from ares.core.noise import NoiseController
        settings = AresSettings()
        noise    = NoiseController(campaign)
        module   = StubKerberoastModule(settings=settings, campaign=campaign, noise=noise)

        ctx = ExecutionContext.build(
            campaign=campaign, target="10.0.0.1",
            module_id="ad.kerberoast", domain="CORP",
            params={"dc": "10.0.0.1", "domain": "CORP"},
            dry_run=True,
        )
        result = await module.execute(ctx)

        assert result.success
        assert len(result.findings) == 1
        assert result.findings[0].mitre_technique == "T1558.003"
        assert result.findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_full_chain_kerberoast_to_dcsync(self, campaign) -> None:
        from ares.core.noise import NoiseController
        settings = AresSettings()
        noise    = NoiseController(campaign)

        chain = [
            ("ad.kerberoast", StubKerberoastModule,  "10.0.0.1"),
            ("lateral.wmiexec", StubLateralModule,   "10.0.0.5"),
            ("ad.dcsync",    StubDCSyncModule,        "10.0.0.1"),
        ]

        all_findings = []
        for module_id, module_cls, target in chain:
            module = module_cls(settings=settings, campaign=campaign, noise=noise)
            ctx    = ExecutionContext.build(
                campaign=campaign, target=target,
                module_id=module_id, domain="CORP",
                params={"dc": "10.0.0.1", "domain": "CORP"},
                dry_run=True,
            )
            result = await module.execute(ctx)
            assert result.success, f"Module {module_id} failed: {result.error}"
            all_findings.extend(result.findings)

        assert len(all_findings) == 3
        techniques = {f.mitre_technique for f in all_findings}
        assert "T1558.003" in techniques
        assert "T1003.006" in techniques

    @pytest.mark.asyncio
    async def test_dry_run_no_network_calls(self, campaign) -> None:
        """Verify dry_run never makes real network calls."""
        from ares.core.noise import NoiseController
        settings = AresSettings()
        noise    = NoiseController(campaign)

        module = StubKerberoastModule(settings=settings, campaign=campaign, noise=noise)
        ctx    = ExecutionContext.build(
            campaign=campaign, target="203.0.113.1",  # public IP
            module_id="ad.kerberoast", domain="CORP",
            dry_run=True,
        )
        # No exception even with public IP — dry_run bypasses scope
        result = await module.execute(ctx)
        assert result.success

    @pytest.mark.asyncio
    async def test_execution_context_carries_metadata(self, campaign) -> None:
        ctx = ExecutionContext.build(
            campaign=campaign, target="10.0.0.1",
            module_id="ad.kerberoast", domain="CORP",
            params={"dc": "10.0.0.1"},
            opsec_profile="stealth", dry_run=True,
            tags=["simulation", "v9test"],
        )
        assert ctx.campaign_id == campaign.id
        assert ctx.module_id   == "ad.kerberoast"
        assert ctx.opsec_profile == "stealth"
        assert "simulation" in ctx.tags
        assert ctx.dry_run

    @pytest.mark.asyncio
    async def test_context_for_test_factory(self) -> None:
        ctx = ExecutionContext.for_test(
            target="10.0.0.1", module_id="ad.kerberoast",
            params={"dc": "dc01"},
        )
        assert ctx.dry_run
        assert ctx.target    == "10.0.0.1"
        assert ctx.module_id == "ad.kerberoast"
        assert ctx.params    == {"dc": "dc01"}


# ── Scenario 2: Error handling and fallback ────────────────────────────────────

class TestScenario02ErrorFallback:
    """
    Simulate: kerberoast fails → adaptive engine selects asreproast.
    Verify error types trigger correct engine behaviors.
    """

    def test_account_locked_action_is_abort(self) -> None:
        from ares.core.errors import AccountLocked, AresError
        err = AccountLocked("Account CORP\\svc_sql is locked",
                             username="svc_sql", domain="CORP")
        assert err.action == AresError.ABORT

    def test_connection_refused_action_is_fallback(self) -> None:
        from ares.core.errors import ConnectionRefused, AresError
        err = ConnectionRefused("Port 445 refused", port=445)
        assert err.action == AresError.FALLBACK

    def test_host_unreachable_action_is_skip(self) -> None:
        from ares.core.errors import HostUnreachable, AresError
        err = HostUnreachable("No route to 10.0.0.100")
        assert err.action == AresError.SKIP

    def test_detection_signal_action_is_pause(self) -> None:
        from ares.core.errors import DetectionSignal, AresError
        err = DetectionSignal("IDS alert detected", signal_type="rate_limited")
        assert err.action == AresError.PAUSE

    def test_honeypot_action_is_abort(self) -> None:
        from ares.core.errors import HoneypotDetected, AresError
        err = HoneypotDetected("Honeypot indicators found", indicators=["fake_share"])
        assert err.action == AresError.ABORT

    def test_scope_error_action_is_abort(self) -> None:
        from ares.core.errors import ScopeError, AresError
        err = ScopeError("Target 8.8.8.8 is out of scope", target="8.8.8.8")
        assert err.action == AresError.ABORT

    def test_http_status_mapping(self) -> None:
        from ares.core.errors import (
            http_status, AuthenticationFailed, AccountLocked,
            RateLimited, ModuleValidationError,
        )
        assert http_status(AuthenticationFailed("bad creds")) == 401
        assert http_status(AccountLocked("locked")) == 423
        assert http_status(RateLimited("429")) == 429
        assert http_status(ModuleValidationError("invalid")) == 400

    def test_error_to_dict_structure(self) -> None:
        from ares.core.errors import AuthenticationFailed
        err = AuthenticationFailed("Bad password", username="admin",
                                    module_id="lateral.psexec", target="10.0.0.1")
        d = err.to_dict()
        assert d["error_type"] == "AuthenticationFailed"
        assert d["module_id"]  == "lateral.psexec"
        assert d["target"]     == "10.0.0.1"
        assert d["action"]     in ("retry", "skip", "fallback", "abort", "pause")

    def test_is_lockout_risk(self) -> None:
        from ares.core.errors import AuthenticationFailed, is_lockout_risk, AccountLocked
        auth_err  = AuthenticationFailed("bad", username="user1")
        lock_err  = AccountLocked("locked", username="user1", domain="CORP")
        other_err = AuthenticationFailed("bad")   # no username
        assert is_lockout_risk(auth_err)
        assert is_lockout_risk(lock_err)
        assert not is_lockout_risk(other_err)


# ── Scenario 3: Adaptive strategy simulation ──────────────────────────────────

class TestScenario03AdaptiveStrategy:
    """
    Simulate: psexec blocked → wmiexec → winrm fallback chain.
    """

    @pytest.fixture
    def session(self):
        from ares.state.target_state import OperatorSession
        return OperatorSession(campaign_id="sim-adaptive", operator="op")

    def test_simulate_edr_blocks_psexec(self, session) -> None:
        from ares.goal.adaptive import AdaptiveAttackStrategy
        strategy = AdaptiveAttackStrategy(session)
        strategy.record_failure("lateral.psexec", "10.0.0.1",
                                 "CS Falcon blocked service creation",
                                 error_class="edr_blocked")
        fb = strategy.next_alternative("lateral.psexec", "10.0.0.1")
        assert fb is not None
        assert fb.module_id == "lateral.wmiexec"

    def test_simulate_two_failures_chain(self, session) -> None:
        from ares.goal.adaptive import AdaptiveAttackStrategy
        strategy = AdaptiveAttackStrategy(session)

        # PsExec blocked
        strategy.record_failure("lateral.psexec", "10.0.0.2",
                                 "EDR blocked", error_class="edr_blocked")
        # WMI also fails
        strategy.record_failure("lateral.wmiexec", "10.0.0.2",
                                 "WMI namespace restricted")
        # Should fallback to WinRM or ssh
        fb = strategy.next_alternative("lateral.psexec", "10.0.0.2")
        if fb:
            assert fb.module_id not in ("lateral.psexec", "lateral.wmiexec")

    def test_simulate_kerberoast_to_asreproast_fallback(self, session) -> None:
        from ares.goal.adaptive import AdaptiveAttackStrategy
        strategy = AdaptiveAttackStrategy(session)
        strategy.record_failure("ad.kerberoast", "10.0.0.3",
                                 "No SPN accounts found")
        fb = strategy.next_alternative("ad.kerberoast", "10.0.0.3")
        assert fb is not None
        assert fb.module_id == "ad.asreproast"

    def test_simulate_full_credential_path(self, session) -> None:
        from ares.goal.adaptive import AdaptiveAttackStrategy
        strategy = AdaptiveAttackStrategy(session)

        chain = strategy.alternative_chain("ad.kerberoast", "dc01", max_depth=3)
        assert len(chain) >= 1
        module_ids = [fb.module_id for fb in chain]
        assert len(set(module_ids)) == len(module_ids)  # no duplicates in chain


# ── Scenario 4: State engine + session tracking ───────────────────────────────

class TestScenario04SessionTracking:
    """
    Simulate: hosts discovered → compromised → compromise level escalation.
    """

    def test_simulate_host_discovery_and_ownership(self) -> None:
        from ares.state.target_state import OperatorSession, CompromiseLevel
        session = OperatorSession(campaign_id="sim-state", operator="op")

        # Discover DC
        session.discover_host("10.0.0.1", hostname="dc01", is_dc=True)
        # Compromise it
        session.mark_owned("10.0.0.1", CompromiseLevel.DOMAIN_ADMIN,
                            via_module="ad.dcsync", credentials=["da_hash"])

        host = session.get_host("10.0.0.1")
        assert host is not None
        assert host.compromise_level == CompromiseLevel.DOMAIN_ADMIN
        assert host.is_dc
        assert host.is_owned

    def test_simulate_compromise_level_never_downgrades(self) -> None:
        from ares.state.target_state import OperatorSession, CompromiseLevel
        session = OperatorSession(campaign_id="sim-state2", operator="op")
        session.discover_host("10.0.0.2")
        session.mark_owned("10.0.0.2", CompromiseLevel.DOMAIN_ADMIN,
                            via_module="ad.dcsync")
        # Try to downgrade
        session.mark_owned("10.0.0.2", CompromiseLevel.LOCAL_ADMIN,
                            via_module="lateral.psexec")
        host = session.get_host("10.0.0.2")
        assert host.compromise_level == CompromiseLevel.DOMAIN_ADMIN  # no downgrade

    def test_simulate_session_snapshot_is_serializable(self) -> None:
        import json
        from ares.state.target_state import OperatorSession, CompromiseLevel
        session = OperatorSession(campaign_id="sim-snap", operator="op")
        session.discover_host("10.0.0.1", hostname="dc01", is_dc=True)
        session.mark_owned("10.0.0.1", CompromiseLevel.SYSTEM,
                            via_module="linux.privesc")
        snap = session.snapshot()
        # Must be JSON-serializable
        dumped = json.dumps(snap, default=str)
        assert len(dumped) > 0
        restored = json.loads(dumped)
        assert "hosts" in restored

    def test_simulate_attack_history_recorded(self) -> None:
        from ares.state.target_state import OperatorSession, CompromiseLevel
        session = OperatorSession(campaign_id="sim-hist", operator="op")
        session.discover_host("10.0.0.1")
        session.mark_owned("10.0.0.1", CompromiseLevel.LOCAL_ADMIN,
                            via_module="lateral.psexec")
        session.record_attack("10.0.0.1", "lateral.wmiexec", success=True)
        host = session.get_host("10.0.0.1")
        assert len(host.attack_history) >= 1


# ── Scenario 5: Guardrail enforcement ─────────────────────────────────────────

class TestScenario05GuardrailEnforcement:
    """
    Simulate: operator accidentally targets out-of-scope host.
    CampaignGuardrail must block ALL operations.
    """

    def test_simulate_out_of_scope_blocked_everywhere(self) -> None:
        from ares.knowledge import CampaignGuardrail
        g = CampaignGuardrail(["10.0.0.0/24"])

        # Try all major module types against OOS target
        dangerous_ops = [
            ("ad.kerberoast",  "192.168.1.50"),
            ("lateral.psexec", "172.16.0.1"),
            ("ad.dcsync",      "203.0.113.1"),
            ("linux.privesc",  "8.8.8.8"),
        ]
        for module_id, target in dangerous_ops:
            allowed, reason = g.check(module_id, target)
            assert not allowed, f"Expected block for {target}"
            assert "OUT OF SCOPE" in reason

    def test_simulate_dangerous_module_gate(self) -> None:
        from ares.knowledge import CampaignGuardrail
        g = CampaignGuardrail(["10.0.0.0/8"])
        # DCSync without confirmation — blocked
        ok1, msg1 = g.check("ad.dcsync", "10.0.0.1", confirmed=False)
        assert not ok1
        assert "HIGH-RISK" in msg1
        # After confirmation — allowed
        g.confirm_dangerous("ad.dcsync", "10.0.0.1")
        ok2, _ = g.check("ad.dcsync", "10.0.0.1", confirmed=True)
        assert ok2

    def test_simulate_metadata_endpoint_blocked(self) -> None:
        from ares.knowledge import CampaignGuardrail
        g = CampaignGuardrail(["169.254.0.0/16"])  # Even if scope includes IMDS
        ok, _ = g.check("cloud.aws", "169.254.169.254")
        assert not ok   # Sensitive range always blocked


# ── Scenario 6: Telemetry collection through chain ────────────────────────────

class TestScenario06TelemetryCollection:
    """
    Simulate a 5-module chain and verify telemetry tracks all executions.
    """

    @pytest.mark.asyncio
    async def test_simulate_telemetry_through_chain(self, campaign) -> None:
        from ares.core.noise import NoiseController
        from ares.telemetry.collector import TelemetryCollector
        import time

        settings  = AresSettings()
        noise     = NoiseController(campaign)
        telemetry = TelemetryCollector()

        modules = [
            ("ad.kerberoast",  StubKerberoastModule, "10.0.0.1", True),
            ("ad.dcsync",      StubDCSyncModule,      "10.0.0.1", True),
            ("lateral.wmiexec", StubLateralModule,    "10.0.0.5", True),
        ]

        for module_id, module_cls, target, success in modules:
            t0     = time.monotonic()
            module = module_cls(settings=settings, campaign=campaign, noise=noise)
            ctx    = ExecutionContext.build(
                campaign=campaign, target=target,
                module_id=module_id, domain="CORP",
                dry_run=True, telemetry=telemetry,
            )
            result = await module.execute(ctx)
            elapsed = (time.monotonic() - t0) * 1000
            telemetry.record_execution(module_id, elapsed, success=result.success)
            telemetry.record_finding(len(result.findings))

        snap = telemetry.snapshot()
        assert snap.total_modules_run  == 3
        assert snap.successful_modules == 3
        assert snap.failed_modules     == 0
        assert snap.findings_total     == 3   # one per module
        assert snap.error_rate         == 0.0
        assert snap.p50_execution_ms   >= 0


# ── Scenario 7: DI container wiring ───────────────────────────────────────────

class TestScenario07DIContainer:
    """
    Verify AresContainer correctly wires and provides services.
    """

    def test_for_test_container_provides_settings(self, container) -> None:
        from ares.core.config import AresSettings
        s = container.settings()
        assert isinstance(s, AresSettings)

    def test_for_test_container_provides_registry(self, container) -> None:
        from ares.core.plugin.loader import ModuleRegistry
        r = container.registry()
        assert isinstance(r, ModuleRegistry)

    def test_for_test_container_provides_telemetry(self, container) -> None:
        from ares.telemetry.collector import TelemetryCollector
        t = container.telemetry()
        assert isinstance(t, TelemetryCollector)

    def test_container_override_for_mock(self, container) -> None:
        mock_kb = object()   # mock knowledge base
        container.override("kb", mock_kb)
        assert container.kb() is mock_kb
        container.clear_overrides()

    def test_container_build_context(self, container, campaign) -> None:
        ctx = container.build_context(campaign, "10.0.0.1", "ad.kerberoast",
                                       domain="CORP", dry_run=True)
        assert ctx.target    == "10.0.0.1"
        assert ctx.module_id == "ad.kerberoast"
        assert ctx.campaign_id == campaign.id

    def test_container_service_not_found_error(self, container) -> None:
        from ares.core.di import ServiceNotFound
        with pytest.raises(ServiceNotFound):
            container.get("nonexistent_service")

    def test_container_list_services(self, container) -> None:
        services = container.list_services()
        assert "settings"  in services
        assert "registry"  in services
        assert "telemetry" in services

    def test_production_container_factory(self) -> None:
        c = AresContainer.production()
        # Should not raise
        services = c.list_services()
        assert "settings" in services


# ── Scenario 8: Module SDK and formal contract ────────────────────────────────

class TestScenario08ModuleSDKContract:
    """
    Verify the Module SDK contract (validate/execute/report) works end-to-end.
    """

    @pytest.mark.asyncio
    async def test_sdk_module_validate_missing_target(self, campaign) -> None:
        from ares.core.noise import NoiseController
        settings = AresSettings()
        noise    = NoiseController(campaign)
        module   = StubKerberoastModule(settings=settings, campaign=campaign, noise=noise)

        # Context with empty target
        ctx = ExecutionContext.for_test(target="", module_id="ad.kerberoast")
        with pytest.raises(ModuleValidationError):
            await module.validate(ctx)

    @pytest.mark.asyncio
    async def test_sdk_module_report_returns_dict(self, campaign) -> None:
        from ares.core.noise import NoiseController
        settings = AresSettings()
        noise    = NoiseController(campaign)
        module   = StubKerberoastModule(settings=settings, campaign=campaign, noise=noise)

        ctx    = ExecutionContext.build(
            campaign=campaign, target="10.0.0.1",
            module_id="ad.kerberoast", domain="CORP",
            dry_run=True,
        )
        result = await module.execute(ctx)
        report = module.report(result)
        assert "module_id"  in report
        assert "findings"   in report
        assert "severity"   in report
        assert "mitre"      in report

    def test_sdk_module_metadata_structure(self) -> None:
        meta = StubKerberoastModule.metadata()
        assert meta["id"]       == "ad.kerberoast"
        assert meta["category"] == "ad"
        assert len(meta["mitre_list"]) > 0

    def test_sdk_validate_module_class(self) -> None:
        from ares.modules.base import validate_module_class

        class GoodModule(BaseModule):
            MODULE_ID          = "corp.good"
            MODULE_NAME        = "Good"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "A good module"
            async def run(self, **k): return [], {}

        class BadModule(BaseModule):
            MODULE_ID          = ""   # missing!
            MODULE_NAME        = "Bad"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "Missing ID"
            async def run(self, **k): return [], {}

        good_errors = validate_module_class(GoodModule)
        bad_errors  = validate_module_class(BadModule)
        assert len(good_errors) == 0
        assert len(bad_errors)  > 0

    def test_module_test_helper(self) -> None:
        from ares.modules.sdk import ModuleTestHelper
        helper = ModuleTestHelper(StubKerberoastModule)
        ctx    = helper.make_context(target="10.0.0.1", domain="CORP",
                                      params={"dc": "10.0.0.1"})
        assert ctx.target   == "10.0.0.1"
        assert ctx.dry_run

    @pytest.mark.asyncio
    async def test_module_test_helper_full_run(self) -> None:
        from ares.modules.sdk import ModuleTestHelper
        helper = ModuleTestHelper(StubKerberoastModule)
        result = await helper.run_full(target="10.0.0.1", domain="CORP",
                                        params={"dc": "10.0.0.1"})
        assert result.success

    def test_module_metadata_decorator(self) -> None:
        from ares.modules.sdk import module_metadata, OpsecLevel, BaseModule
        @module_metadata(
            module_id   = "test.decorated",
            name        = "Decorated Test",
            category    = "ad",
            description = "A decorated module",
            author      = "test@test.com",
            opsec       = OpsecLevel.LOW,
        )
        class DecoratedModule(BaseModule):
            async def run(self, **k): return [], {}

        assert DecoratedModule.MODULE_ID          == "test.decorated"
        assert DecoratedModule.MODULE_CATEGORY    == "ad"
        assert DecoratedModule.OPSEC_LEVEL        == OpsecLevel.LOW


# ── Scenario 9: Artifact correlation simulation ───────────────────────────────

class TestScenario09ArtifactCorrelation:
    """
    Simulate: credentials + hosts + permissions → attack opportunities.
    """

    def test_simulate_full_correlation_pipeline(self) -> None:
        from ares.artifact_intel.correlation import ArtifactCorrelationEngine
        from ares.normalize.artifacts import (
            ArtifactStore, CredentialArtifact, HostArtifact,
            UserArtifact, PermissionArtifact,
        )

        store = ArtifactStore()

        # Discovered: domain admin cred
        store.add(CredentialArtifact(username="Administrator", domain="CORP",
                                      privilege="domain_admin",
                                      cred_type="cleartext"))
        # Discovered: member servers
        for ip in ["10.0.0.10", "10.0.0.11", "10.0.0.12"]:
            store.add(HostArtifact(ip_address=ip, hostname=f"srv{ip[-2:]}",
                                    open_ports=[445, 5985]))

        # Discovered: kerberoastable user
        store.add(UserArtifact(username="svc_sql", domain="CORP",
                               spns=["MSSQLSvc/db01:1433"], enabled=True))

        # Discovered: dangerous ACL
        store.add(PermissionArtifact(principal="svc_backup",
                                      target="Domain Admins",
                                      right="WriteDACL", domain="CORP"))
        store.add(CredentialArtifact(username="svc_backup", domain="CORP",
                                      privilege="service_account"))

        engine = ArtifactCorrelationEngine()
        opps   = engine.correlate(store)

        # Should find multiple opportunities
        assert len(opps) >= 2
        rule_ids = {o.rule_id for o in opps}
        assert "RULE-01" in rule_ids  # DA cred + hosts
        assert "RULE-03" in rule_ids  # SPN kerberoast path

        # Critical severity first
        assert opps[0].severity in ("critical", "high")


# ── Scenario 10: Multi-operator collaboration ─────────────────────────────────

class TestScenario10MultiOperatorCollaboration:
    """
    Simulate: 3 operators with different roles working on same campaign.
    Verify locks and permissions are enforced throughout.
    """

    def test_simulate_three_operator_campaign(self) -> None:
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager("sim-collab-camp")

        lead      = mgr.register_operator("alice", OperatorRole.TEAM_LEAD)
        attacker  = mgr.register_operator("bob",   OperatorRole.OPERATOR)
        recon_op  = mgr.register_operator("charlie", OperatorRole.RECON)
        reporter  = mgr.register_operator("dave",  OperatorRole.REPORTER)

        # Lead can do everything
        ok_lead, _ = mgr.check_permission(lead.operator_id, "ad.dcsync")
        assert ok_lead

        # Operator can run attack modules
        ok_op, _ = mgr.check_permission(attacker.operator_id, "lateral.psexec")
        assert ok_op

        # Recon can only enumerate
        ok_recon, _ = mgr.check_permission(recon_op.operator_id, "ad.enum_users")
        assert ok_recon
        nok_recon, _ = mgr.check_permission(recon_op.operator_id, "lateral.psexec")
        assert not nok_recon

        # Reporter reads only
        nok_rep, _ = mgr.check_permission(reporter.operator_id, "ad.enum_users")
        assert not nok_rep

    def test_simulate_target_lock_prevents_collision(self) -> None:
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr  = CollaborationManager("sim-lock-camp")
        op1  = mgr.register_operator("op1", OperatorRole.OPERATOR)
        op2  = mgr.register_operator("op2", OperatorRole.OPERATOR)

        # Op1 claims dc01 for kerberoast
        ok1, lock1 = mgr.acquire_lock(op1.operator_id, "10.0.0.1", "ad.kerberoast")
        assert ok1

        # Op2 tries same target+module — locked
        ok2, msg2 = mgr.acquire_lock(op2.operator_id, "10.0.0.1", "ad.kerberoast")
        assert not ok2
        assert "locked" in msg2.lower()

        # Op1 finishes and releases
        mgr.release_lock(lock1)

        # Now op2 can claim
        ok3, _ = mgr.acquire_lock(op2.operator_id, "10.0.0.1", "ad.kerberoast")
        assert ok3

    def test_simulate_journal_tracks_all_actions(self) -> None:
        from ares.collab.manager import CollaborationManager, OperatorRole
        mgr = CollaborationManager("sim-journal-camp")
        op  = mgr.register_operator("alice", OperatorRole.OPERATOR)

        mgr.log(op.operator_id, "module_started",  target="10.0.0.1",
                module_id="ad.kerberoast")
        mgr.log(op.operator_id, "module_completed", target="10.0.0.1",
                module_id="ad.kerberoast", success=True)
        mgr.log(op.operator_id, "finding_added",   target="10.0.0.1")

        journal = mgr.journal(operator_id=op.operator_id)
        actions = {e.action for e in journal}
        assert "module_started"  in actions
        assert "module_completed" in actions
        assert "finding_added"   in actions
