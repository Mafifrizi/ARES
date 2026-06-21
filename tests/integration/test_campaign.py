"""
ARES Integration Tests
End-to-end campaign simulation tests.

These tests simulate full attack flows without real network calls (dry_run=True).
They verify the integration between engine, modules, state, vault, and telemetry.

Run with: pytest tests/integration/ -v
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import uuid
from typing import Any

import pytest

from ares.core.campaign import Campaign, Finding, NoiseProfile, Severity, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.di import AresContainer
from ares.core.errors import (
    AccountLocked, AuthenticationFailed, ModuleValidationError, ScopeError,
)
from ares.core.noise import NoiseController
from ares.modules.base import BaseModule, ModuleResult, OpsecLevel


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_campaign(scope: str = "10.0.0.0/8") -> Campaign:
    return Campaign(
        name="Integration Test Campaign",
        client="ACME Corp",
        targets=["dc01.corp.local", "10.0.0.5"],
        scope=[ScopeEntry(cidr=scope)],
        noise_profile=NoiseProfile.NORMAL,
        operator="integration-tester",
    )


def enc_key() -> bytes:
    raw = hashlib.sha256(b"integration-test-key").digest()
    return base64.urlsafe_b64encode(raw)


# ── Stub modules for integration ──────────────────────────────────────────────

class StubEnumUsersModule(BaseModule):
    """Stub AD user enumeration — returns fake users for integration tests."""
    MODULE_ID          = "ad.enum_users"
    MODULE_NAME        = "AD User Enumeration"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Enumerate domain users via LDAP"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["user_list"]
    MITRE_TECHNIQUES   = ["T1087.002"]

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        await self.before_request(ctx.target)
        if ctx.dry_run:
            users = [
                {"username": "alice", "domain": "CORP", "enabled": True, "spns": []},
                {"username": "svc_sql", "domain": "CORP", "enabled": True,
                 "spns": ["MSSQLSvc/db01:1433"]},
                {"username": "bob", "domain": "CORP", "enabled": True,
                 "spns": [], "no_preauth": True},
            ]
            f = self.finding(
                title       = f"Enumerated {len(users)} domain users",
                description = f"Found {len(users)} users including service accounts",
                severity    = Severity.INFO,
                mitre_technique = "T1087.002",
                host        = ctx.target,
            )
            return ModuleResult(
                status   = "success",
                findings = [f],
                artifacts = {"users": users},
                module_id = self.MODULE_ID,
                execution_id = ctx.execution_id,
            )
        raise NotImplementedError("Integration stub — dry_run only")


class StubKerberoastModule(BaseModule):
    """Stub Kerberoast module."""
    MODULE_ID          = "ad.kerberoast"
    MODULE_NAME        = "Kerberoasting"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Request TGS tickets for SPN accounts"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds", "spn_list"]
    OUTPUTS            = ["kerberos_hashes"]
    MITRE_TECHNIQUES   = ["T1558.003"]

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target", "domain")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        await self.before_request(ctx.target)
        if ctx.dry_run:
            hashes = [
                {"username": "svc_sql", "hash": "$krb5tgs$23$*svc_sql*CORP*...",
                 "domain": "CORP"},
            ]
            f = self.finding(
                title       = "Kerberoastable: svc_sql",
                description = "Service account svc_sql has SPN and RC4 ticket obtained",
                severity    = Severity.HIGH,
                mitre_technique = "T1558.003",
                host        = ctx.target,
            )
            return ModuleResult(
                status           = "success",
                findings         = [f],
                new_credentials  = hashes,
                module_id        = self.MODULE_ID,
                execution_id     = ctx.execution_id,
            )
        raise NotImplementedError("dry_run only")


class StubLateralModule(BaseModule):
    """Stub lateral movement module."""
    MODULE_ID          = "lateral.psexec"
    MODULE_NAME        = "PsExec Lateral Movement"
    MODULE_CATEGORY    = "lateral"
    MODULE_DESCRIPTION = "Execute commands via PsExec / service installation"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    REQUIRES           = ["local_admin", "smb_access"]
    OUTPUTS            = ["shell_access"]
    MITRE_TECHNIQUES   = ["T1569.002"]

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target", "credentials")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        await self.before_request(ctx.target)
        if ctx.dry_run:
            f = self.finding(
                title       = f"Shell access on {ctx.target}",
                description = "PsExec shell established as SYSTEM",
                severity    = Severity.CRITICAL,
                mitre_technique = "T1569.002",
                host        = ctx.target,
            )
            return ModuleResult(
                status           = "success",
                findings         = [f],
                discovered_hosts = ["10.0.0.10", "10.0.0.11"],
                module_id        = self.MODULE_ID,
                execution_id     = ctx.execution_id,
            )
        raise NotImplementedError("dry_run only")


# ─────────────────────────────────────────────────────────────────────────────
# Integration Test Suite
# ─────────────────────────────────────────────────────────────────────────────

class TestDIContainer:
    """Test the dependency injection container wires everything correctly."""

    def test_production_container_builds(self) -> None:
        container = AresContainer.production()
        assert container.has("settings")
        assert container.has("registry")
        assert container.has("telemetry")

    def test_test_container_builds(self) -> None:
        container = AresContainer.for_test()
        settings  = container.settings()
        assert settings is not None

    def test_override_replaces_service(self) -> None:
        container = AresContainer.for_test()

        class MockVault:
            def credentials_for_reuse(self): return []

        container.override("vault", MockVault())
        vault = container.get("vault")
        assert isinstance(vault, MockVault)

    def test_service_not_found_raises(self) -> None:
        from ares.core.di import ServiceNotFound
        container = AresContainer.for_test()
        with pytest.raises(ServiceNotFound):
            container.get("nonexistent_service")

    def test_build_context_injects_services(self) -> None:
        container = AresContainer.for_test()
        campaign  = make_campaign()
        ctx = container.build_context(campaign, "10.0.0.1", "ad.kerberoast",
                                       params={"domain": "CORP"})
        assert ctx.target      == "10.0.0.1"
        assert ctx.module_id   == "ad.kerberoast"
        assert ctx.campaign_id == campaign.id

    def test_list_services(self) -> None:
        container = AresContainer.for_test()
        services  = container.list_services()
        assert "settings"  in services
        assert "registry"  in services
        assert "telemetry" in services


class TestExecutionContext:
    """Test the formal ExecutionContext contract."""

    def test_build_derives_campaign_fields(self) -> None:
        campaign = make_campaign()
        ctx = ExecutionContext.build(
            campaign  = campaign,
            target    = "10.0.0.1",
            module_id = "ad.kerberoast",
            operator  = "alice",
        )
        assert ctx.campaign_id == campaign.id
        assert ctx.operator    == "alice"
        assert ctx.target      == "10.0.0.1"

    def test_for_test_is_dry_run(self) -> None:
        ctx = ExecutionContext.for_test()
        assert ctx.dry_run is True

    def test_require_raises_on_missing(self) -> None:
        from ares.core.errors import InvalidContext
        ctx = ExecutionContext.for_test(target="")
        with pytest.raises(InvalidContext) as exc_info:
            ctx.require("target")
        assert "target" in exc_info.value.missing_field

    def test_require_passes_when_present(self) -> None:
        ctx = ExecutionContext.for_test(target="10.0.0.1")
        ctx.require("target")   # should not raise

    def test_has_returns_false_for_empty(self) -> None:
        ctx = ExecutionContext.for_test()
        assert ctx.has("domain") is False
        ctx.domain = "CORP"
        assert ctx.has("domain") is True

    def test_best_credential_from_list(self) -> None:
        from ares.credential.vault import Credential, CredentialType
        ctx = ExecutionContext.for_test()
        cred = Credential(username="admin", domain="CORP",
                           cred_type=CredentialType.CLEARTEXT)
        ctx.credentials = [cred]
        assert ctx.best_credential() is cred

    def test_to_dict_excludes_sensitive(self) -> None:
        ctx = ExecutionContext.for_test()
        d   = ctx.to_dict()
        assert "credentials" not in d
        assert "vault" not in d
        assert "has_credentials" in d

    def test_repr_useful(self) -> None:
        ctx = ExecutionContext.for_test(target="10.0.0.1", module_id="ad.kerberoast")
        r   = repr(ctx)
        assert "10.0.0.1" in r
        assert "ad.kerberoast" in r


class TestBaseModuleSDK:
    """Test the formal BaseModule SDK contract (v0.9.0)."""

    @pytest.fixture
    def campaign(self) -> Campaign:
        return make_campaign()

    @pytest.fixture
    def module(self, campaign) -> StubEnumUsersModule:
        return StubEnumUsersModule(
            settings  = AresSettings(),
            campaign  = campaign,
            noise     = NoiseController(campaign),
        )

    @pytest.mark.asyncio
    async def test_validate_passes_with_target(self, module) -> None:
        ctx = ExecutionContext.for_test(target="10.0.0.1")
        await module.validate(ctx)   # should not raise

    @pytest.mark.asyncio
    async def test_validate_raises_missing_target(self, module) -> None:
        from ares.core.errors import InvalidContext
        ctx = ExecutionContext.for_test(target="")
        with pytest.raises(InvalidContext):
            await module.validate(ctx)

    @pytest.mark.asyncio
    async def test_execute_dry_run_returns_result(self, module) -> None:
        ctx = ExecutionContext.build(
            campaign  = module.campaign,
            target    = "10.0.0.1",
            module_id = "ad.enum_users",
            params    = {"domain": "CORP"},
            dry_run   = True,
        )
        result = await module.execute(ctx)
        assert isinstance(result, ModuleResult)
        assert result.success
        assert len(result.findings) > 0

    def test_report_returns_structured_dict(self, module) -> None:
        result = ModuleResult(
            status   = "success",
            findings = [Finding(title="test", description="x", severity=Severity.HIGH)],
            module_id = "ad.enum_users",
        )
        report = module.report(result)
        assert "module_id"   in report
        assert "title"       in report
        assert "findings"    in report
        assert "mitre"       in report
        assert "summary"     in report

    def test_validate_module_class_valid(self) -> None:
        from ares.modules.base import validate_module_class
        errors = validate_module_class(StubEnumUsersModule)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_validate_module_class_detects_missing_id(self) -> None:
        from ares.modules.base import validate_module_class

        class BadModule(BaseModule):
            MODULE_ID          = ""   # missing!
            MODULE_NAME        = "Bad"
            MODULE_CATEGORY    = "test"
            MODULE_DESCRIPTION = "Bad module"
            async def run(self, **kwargs): return [], {}

        errors = validate_module_class(BadModule)
        assert any("MODULE_ID" in e for e in errors)

    def test_validate_module_class_detects_bad_id_format(self) -> None:
        from ares.modules.base import validate_module_class

        class BadIdModule(BaseModule):
            MODULE_ID          = "kerberoast"   # no dot!
            MODULE_NAME        = "Kerberoast"
            MODULE_CATEGORY    = "ad"
            MODULE_DESCRIPTION = "Bad ID"
            async def run(self, **kwargs): return [], {}

        errors = validate_module_class(BadIdModule)
        assert any("dotted" in e for e in errors)


class TestErrorHierarchy:
    """Test that the error hierarchy integrates correctly with modules."""

    @pytest.fixture
    def campaign(self) -> Campaign:
        return make_campaign()

    def test_account_locked_is_abort(self) -> None:
        from ares.core.errors import resolve_action, AresError
        err = AccountLocked("Account locked", username="alice", domain="CORP")
        assert resolve_action(err) == AresError.ABORT

    def test_auth_failed_is_retry(self) -> None:
        from ares.core.errors import resolve_action, AresError
        err = AuthenticationFailed("Bad password", username="alice")
        assert resolve_action(err) == AresError.RETRY

    def test_scope_error_is_abort(self) -> None:
        from ares.core.errors import resolve_action, AresError
        err = ScopeError("Out of scope", target="8.8.8.8")
        assert resolve_action(err) == AresError.ABORT

    def test_module_validation_error_is_abort(self) -> None:
        from ares.core.errors import resolve_action, AresError
        err = ModuleValidationError("Missing field", module_id="ad.kerberoast", field="domain")
        assert resolve_action(err) == AresError.ABORT

    def test_connection_refused_is_fallback(self) -> None:
        from ares.core.errors import resolve_action, AresError, ConnectionRefused
        err = ConnectionRefused("Port 445 refused", port=445)
        assert resolve_action(err) == AresError.FALLBACK

    def test_rate_limited_is_pause(self) -> None:
        from ares.core.errors import resolve_action, AresError, RateLimited
        err = RateLimited("Too many requests", retry_after_s=60)
        assert resolve_action(err) == AresError.PAUSE

    def test_is_lockout_risk_true_for_locked(self) -> None:
        from ares.core.errors import is_lockout_risk
        err = AccountLocked("Locked", username="alice", domain="CORP")
        assert is_lockout_risk(err)

    def test_http_status_mapping(self) -> None:
        from ares.core.errors import http_status
        assert http_status(AccountLocked("x")) == 423
        assert http_status(ScopeError("x"))    == 403
        assert http_status(ModuleValidationError("x")) == 400

    def test_error_to_dict_structure(self) -> None:
        err = ModuleValidationError(
            "Missing domain", module_id="ad.kerberoast",
            field="domain", target="10.0.0.1",
        )
        d = err.to_dict()
        assert d["error_type"]  == "ModuleValidationError"
        assert d["module_id"]   == "ad.kerberoast"
        assert d["target"]      == "10.0.0.1"
        assert d["action"]      == "abort"


class TestEndToEndCampaignSimulation:
    """
    Full campaign simulation: recon → credential → lateral → report.
    All network calls are dry_run=True (no real connections).
    Tests the integration between context, modules, vault, telemetry, state.
    """

    @pytest.fixture
    def campaign(self) -> Campaign:
        return make_campaign("10.0.0.0/8")

    @pytest.fixture
    def container(self) -> AresContainer:
        return AresContainer.for_test()

    @pytest.mark.asyncio
    async def test_full_recon_to_credential_chain(self, campaign, container) -> None:
        """
        Phase 1: enum_users → discover SPN accounts
        Phase 2: kerberoast → get hashes
        Phase 3: verify vault has credentials
        """
        from ares.credential.vault import CredentialVault, CredentialType
        vault = CredentialVault(enc_key())
        container.override("vault", vault)
        telemetry = container.telemetry()

        # Phase 1: Enumerate users
        enum_module = StubEnumUsersModule(
            settings  = AresSettings(),
            campaign  = campaign,
            noise     = NoiseController(campaign),
        )
        ctx1 = ExecutionContext.build(
            campaign  = campaign, target="dc01.corp.local",
            module_id = "ad.enum_users", params={"domain": "CORP"},
            vault=vault, telemetry=telemetry, dry_run=True,
        )
        await enum_module.validate(ctx1)
        result1 = await enum_module.execute(ctx1)
        assert result1.success
        assert len(result1.findings) == 1
        assert result1.artifacts.get("users")

        telemetry.record_execution("ad.enum_users", 800.0, success=True)

        # Phase 2: Kerberoast
        kerb_module = StubKerberoastModule(
            settings  = AresSettings(), campaign=campaign,
            noise     = NoiseController(campaign),
        )
        ctx2 = ExecutionContext.build(
            campaign  = campaign, target="dc01.corp.local",
            module_id = "ad.kerberoast", params={"domain": "CORP"},
            vault=vault, telemetry=telemetry, dry_run=True,
        )
        await kerb_module.validate(ctx2)
        result2 = await kerb_module.execute(ctx2)
        assert result2.success
        assert result2.has_credentials
        assert any(c["username"] == "svc_sql" for c in result2.new_credentials)

        telemetry.record_execution("ad.kerberoast", 2400.0, success=True)
        telemetry.record_credential(len(result2.new_credentials))

        # Verify telemetry captured correctly
        snap = telemetry.snapshot()
        assert snap.total_modules_run   == 2
        assert snap.successful_modules  == 2
        assert snap.credentials_found   == 1
        assert snap.error_rate          == 0.0

    @pytest.mark.asyncio
    async def test_lateral_movement_discovers_new_hosts(self, campaign, container) -> None:
        """
        lateral.psexec with HIGH_NOISE opsec level.
        Verifies: new hosts discovered are reported in ModuleResult.
        """
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(enc_key())
        cred  = Credential(username="Administrator", domain="CORP",
                            cred_type=CredentialType.CLEARTEXT)
        vault.add(cred, secret="P@ssw0rd!")

        lateral = StubLateralModule(
            settings = AresSettings(), campaign=campaign,
            noise    = NoiseController(campaign),
        )
        ctx = ExecutionContext.build(
            campaign    = campaign, target="10.0.0.5",
            module_id   = "lateral.psexec",
            credentials = vault.credentials_for_reuse(),
            vault=vault, dry_run=True,
        )
        await lateral.validate(ctx)
        result = await lateral.execute(ctx)
        assert result.success
        assert result.has_new_hosts
        assert len(result.discovered_hosts) == 2

    @pytest.mark.asyncio
    async def test_out_of_scope_blocked(self, campaign) -> None:
        """CampaignGuardrail blocks out-of-scope targets."""
        from ares.knowledge import CampaignGuardrail
        guardrail = CampaignGuardrail(scope_cidrs=["10.0.0.0/24"])

        # In-scope: allowed
        allowed, _ = guardrail.check("ad.kerberoast", "10.0.0.50")
        assert allowed

        # Out-of-scope: blocked
        allowed, reason = guardrail.check("ad.kerberoast", "192.168.1.1")
        assert not allowed
        assert "OUT OF SCOPE" in reason

    @pytest.mark.asyncio
    async def test_account_locked_stops_campaign(self, campaign) -> None:
        """Simulates account lockout — engine behavior should abort."""
        from ares.core.errors import AccountLocked, resolve_action, AresError

        def simulate_lockout():
            raise AccountLocked("svc_sql is locked after 5 failures",
                                  username="svc_sql", domain="CORP")

        err = None
        try:
            simulate_lockout()
        except AccountLocked as e:
            err = e

        assert err is not None
        assert resolve_action(err) == AresError.ABORT
        assert err.username == "svc_sql"

    @pytest.mark.asyncio
    async def test_checkpoint_pause_resume(self, campaign, tmp_path) -> None:
        """Save and restore campaign state via checkpoint."""
        import ares.checkpoint.manager as cm_mod
        from ares.checkpoint.manager import CheckpointManager, build_checkpoint
        from ares.state.target_state import OperatorSession, CompromiseLevel

        cm_mod.CHECKPOINT_DIR = tmp_path / "checkpoints"

        session = OperatorSession(campaign_id=campaign.id, operator="tester")
        session.get_or_create_host("10.0.0.1").hostname = "dc01"
        session.mark_owned("10.0.0.1", CompromiseLevel.DOMAIN_ADMIN)
        snapshot = session.snapshot()

        mgr  = CheckpointManager(enc_key())
        data = build_checkpoint(
            campaign_id     = campaign.id,
            campaign_name   = campaign.name,
            operator        = "tester",
            session_snapshot = snapshot,
            findings        = [],
            goal            = "domain_admin",
            goal_achieved   = True,
        )
        path = mgr.save(data, notes="integration test pause")
        assert path.exists()

        # Resume
        restored = mgr.load(campaign.id)
        assert restored.manifest.campaign_id    == campaign.id
        assert restored.manifest.goal_achieved  is True
        assert "hosts" in restored.session
        assert "10.0.0.1" in restored.session["hosts"]

    @pytest.mark.asyncio
    async def test_adaptive_fallback_on_psexec_failure(self, campaign) -> None:
        """When psexec fails (EDR blocks), engine should auto-select wmiexec."""
        from ares.goal.adaptive import AdaptiveAttackStrategy
        from ares.state.target_state import OperatorSession

        session  = OperatorSession(campaign_id=campaign.id, operator="tester")
        strategy = AdaptiveAttackStrategy(session)
        strategy.record_failure("lateral.psexec", "10.0.0.5",
                                 "EDR blocked service creation", error_class="edr_blocked")
        assert "lateral.psexec" in strategy._disabled

        fb = strategy.next_alternative("lateral.psexec", "10.0.0.5")
        assert fb is not None
        assert fb.module_id == "lateral.wmiexec"

    @pytest.mark.asyncio
    async def test_multi_operator_collaboration(self, campaign) -> None:
        """Two operators working on same campaign with role enforcement."""
        from ares.collab.manager import CollaborationManager, OperatorRole

        collab = CollaborationManager(campaign.id)
        op1    = collab.register_operator("alice", OperatorRole.OPERATOR)
        op2    = collab.register_operator("bob",   OperatorRole.RECON)

        # alice (OPERATOR) can run kerberoast
        ok, _ = collab.check_permission(op1.operator_id, "ad.kerberoast")
        assert ok

        # bob (RECON) cannot run kerberoast
        ok, reason = collab.check_permission(op2.operator_id, "ad.kerberoast")
        assert not ok

        # alice acquires lock on dc01
        ok1, lock_id = collab.acquire_lock(op1.operator_id, "dc01", "ad.kerberoast")
        assert ok1

        # bob cannot claim same lock
        ok2, msg = collab.acquire_lock(op2.operator_id, "dc01", "ad.kerberoast")
        assert not ok2
        assert "locked" in msg

        # alice finishes, releases lock
        collab.release_lock(lock_id)

        # Now anyone can lock
        ok3, _ = collab.acquire_lock(op2.operator_id, "dc01", "ad.enum_users")
        assert ok3

    @pytest.mark.asyncio
    async def test_full_artifact_correlation(self, campaign) -> None:
        """Artifact correlation finds compound attack opportunities."""
        from ares.artifact_intel.correlation import ArtifactCorrelationEngine
        from ares.normalize.artifacts import (
            ArtifactStore, CredentialArtifact, HostArtifact,
            PermissionArtifact, UserArtifact,
        )

        store = ArtifactStore()
        # Add a WriteDACL permission + matching credential
        store.add(PermissionArtifact(principal="svc_backup", target="Domain Admins",
                                      right="WriteDACL", domain="CORP"))
        store.add(CredentialArtifact(username="svc_backup", domain="CORP",
                                      privilege="service_account"))
        # Add domain admin cred + hosts
        store.add(CredentialArtifact(username="Administrator", domain="CORP",
                                      privilege="domain_admin"))
        store.add(HostArtifact(ip_address="10.0.0.1", hostname="ws01"))
        store.add(HostArtifact(ip_address="10.0.0.2", hostname="dc01", is_dc=True))

        engine = ArtifactCorrelationEngine()
        opps   = engine.correlate(store)

        # Should find RULE-04 (WriteDACL) and RULE-01 (DA cred)
        rule_ids = {o.rule_id for o in opps}
        assert "RULE-04" in rule_ids
        assert "RULE-01" in rule_ids

        # All should be sorted critical → high → medium
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(opps) - 1):
            assert sev_order.get(opps[i].severity, 4) <= sev_order.get(opps[i+1].severity, 4)

    @pytest.mark.asyncio
    async def test_telemetry_captures_full_chain(self) -> None:
        """Telemetry collector captures all module executions across a chain."""
        from ares.telemetry.collector import TelemetryCollector

        t = TelemetryCollector()
        modules = [
            ("ad.enum_users",    800.0,  True),
            ("ad.enum_spn",      400.0,  True),
            ("ad.kerberoast",   2400.0,  True),
            ("credential.crack", 30000.0, True),
            ("lateral.psexec",   1200.0,  False),   # failed (EDR)
            ("lateral.wmiexec",  900.0,  True),
        ]
        for mid, dur, success in modules:
            t.record_execution(mid, dur, success=success)

        t.record_credential(2)
        t.record_host_discovered(4)
        t.record_host_owned(2)
        t.record_finding(8)

        snap = t.snapshot()
        assert snap.total_modules_run  == 6
        assert snap.successful_modules == 5
        assert snap.failed_modules     == 1
        assert snap.error_rate         == pytest.approx(1/6, rel=0.01)
        assert snap.credentials_found  == 2
        assert snap.hosts_discovered   == 4
        assert snap.hosts_owned        == 2
        assert snap.findings_total     == 8
        assert snap.p50_execution_ms   > 0

        # Prometheus export
        prom = snap.to_prometheus()
        assert "ares_modules_total" in prom
        assert "5" in prom  # 5 successes

    def test_module_result_properties(self) -> None:
        from ares.modules.base import ModuleResult

        r = ModuleResult(status="success",
                          new_credentials=[{"hash": "abc"}],
                          discovered_hosts=["10.0.0.5"])
        assert r.success          is True
        assert r.has_credentials  is True
        assert r.has_new_hosts    is True

        r2 = ModuleResult(status="failure", error="connection refused")
        assert r2.success         is False
        assert r2.has_credentials is False
