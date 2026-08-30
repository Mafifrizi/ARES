"""
Tests for ARES AresEngine — execution, timeout, retry, concurrency.

Modules used in engine tests are mocked to return instantly.
This tests ENGINE behavior (planning, parallelism, semaphore, timeout, retry)
not individual module behavior (which is tested in test_modules.py).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch, AsyncMock

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.execution_admission import (
    DispatchDispositionV1,
    DispatchOutcomeV1,
    DispatchRequestV1,
    ExecutionAdmissionCoordinatorV1,
    RevalidatedPrincipalV1,
    _mint_test_dispatch_context,
    _mint_test_plan_context,
    canonical_intent_digest,
)
from ares.core.notifier import build_notifier_from_settings
from ares.db.execution_lifecycle import FixedResult, OperationResult, TrustedPrincipal


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="test-secret-key-min32-chars-xxxxxx",
        ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
        ares_default_admin_password="TestEnginePass1!",
    )


@pytest.fixture
def campaign() -> Campaign:
    return Campaign(
        name="Engine Test Campaign",
        client="ACME",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
        operator="tester",
    )


def _fast_run(**kwargs: Any):
    """Instant async mock run — returns no findings, no raw data."""

    async def _inner(**kw: Any):
        return [], {}

    return _inner(**kwargs)


def _admitted(engine: AresEngine, campaign: Campaign, module_id: str, ordinal: int = 0):
    return _mint_test_dispatch_context(engine, campaign.id, module_id, ordinal=ordinal)


def _admitted_plan(engine: AresEngine, campaign: Campaign, plan: ExecutionPlan):
    return _mint_test_plan_context(engine, campaign.id, tuple(plan.all_module_ids()))


# ── Engine Tests ──────────────────────────────────────────────────────────────


class TestAsyncEngine:
    def test_blank_webhook_url_disables_notifier(self, settings: AresSettings) -> None:
        """Blank/whitespace webhook config is disabled, not validated as a URL."""
        settings.ares_webhook_url = "  "
        assert build_notifier_from_settings(settings) is None

    def test_http_webhook_url_still_rejected(self, settings: AresSettings) -> None:
        """SSRF protection remains strict for configured non-HTTPS webhooks."""
        settings.ares_webhook_url = "http://example.com/webhook"
        with pytest.raises(ValueError, match="must use https"):
            build_notifier_from_settings(settings)

    @pytest.mark.asyncio
    async def test_run_module_not_found(self, settings: AresSettings, campaign: Campaign) -> None:
        engine = AresEngine(settings=settings)
        engine.load_modules()
        result = await engine.run_module(
            "nonexistent.module",
            campaign,
            {},
            dispatch_context=_admitted(engine, campaign, "nonexistent.module"),
        )
        assert result.status == ModuleStatus.FAILED
        assert "not found" in (result.error or "")

    @pytest.mark.asyncio
    async def test_kerberoast_flat_dashboard_params_reach_execution(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Flat dashboard fields must satisfy Kerberoast's credential contract."""
        from ares.modules.ad.kerberoast import KerberoastModule
        from ares.modules.base import ModuleResult

        engine = AresEngine(settings=settings)
        engine.load_modules()
        captured: dict[str, Any] = {}

        async def fake_execute(self_unused: Any, ctx: Any) -> ModuleResult:
            captured["params"] = dict(ctx.params)
            return ModuleResult(
                status="success",
                raw={"reached": True},
                module_id="ad.kerberoast",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "use_ldaps": False,
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", fake_execute):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
                dispatch_context=_admitted(engine, campaign, "ad.kerberoast"),
            )

        assert result.status == ModuleStatus.DONE
        assert captured["params"] == params

    @pytest.mark.asyncio
    async def test_kerberoast_still_blocks_stealth_profile(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.campaign import NoiseProfile
        from ares.modules.ad.kerberoast import KerberoastModule

        campaign.noise_profile = NoiseProfile.STEALTH
        engine = AresEngine(settings=settings)
        engine.load_modules()

        async def unexpected_execute(self_unused: Any, ctx: Any) -> Any:
            raise AssertionError("stealth profile must block before execution")

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "use_ldaps": False,
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", unexpected_execute):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
                dispatch_context=_admitted(engine, campaign, "ad.kerberoast"),
            )

        assert result.status == ModuleStatus.FAILED
        assert "blocked in STEALTH profile" in (result.error or "")

    @pytest.mark.asyncio
    async def test_kerberoast_classified_tgs_timeout_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberoast_tgs_timeout,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def classified_timeout(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                format_kerberoast_tgs_timeout(2),
                module_id="ad.kerberoast",
                field="kerberos_tgs",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with (
            patch.object(KerberoastModule, "execute", classified_timeout),
            patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep,
        ):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
                dispatch_context=_admitted(engine, campaign, "ad.kerberoast"),
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "network_error"
        assert "found 2 Kerberoastable candidate account(s)" in result.outcome_message
        assert "Kerberos TGS request timed out" in result.outcome_message
        assert "port 88" in result.operator_next_steps[0]
        assert "clock synchronization" in result.operator_next_steps[0]
        assert "Kerberos service health" in result.operator_next_steps[0]
        assert "account/SPN validity" in result.operator_next_steps[0]

    @pytest.mark.asyncio
    async def test_asreproast_operator_outcome_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.modules.ad.asreproast import ASREPRoastModule
        from ares.modules.base import ModuleResult

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def candidate_failure(self_unused: Any, ctx: Any) -> ModuleResult:
            nonlocal calls
            calls += 1
            return ModuleResult(
                status="success",
                raw={
                    "outcome_category": "operator_error",
                    "outcome_message": (
                        "LDAP found 1 ASREPRoast candidate account(s), but Kerberos "
                        "did not return AS-REP material. Last Kerberos error: "
                        "KRB_AP_ERR_SKEW: Kerberos clock skew too great."
                    ),
                },
                module_id="ad.asreproast",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
        }
        with (
            patch.object(ASREPRoastModule, "execute", candidate_failure),
            patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep,
        ):
            result = await engine.run_module(
                "ad.asreproast",
                campaign,
                params,
                dispatch_context=_admitted(engine, campaign, "ad.asreproast"),
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert "ASREPRoast candidate" in result.outcome_message

    @pytest.mark.asyncio
    async def test_enum_users_nonretryable_bind_failure_does_not_retry(
        self, settings: AresSettings, campaign: Campaign, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.core.noise import JitterEngine
        from ares.modules.ad.enum_users import ADEnumUsersModule

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        def classified_bind_failure(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                "ad.enum_users LDAP bind failed: invalid LDAP credentials.",
                module_id="ad.enum_users",
                field="username",
            )

        monkeypatch.setattr(ADEnumUsersModule, "_ldap_query_sync", classified_bind_failure)

        async def no_noise_sleep(*args: Any, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(JitterEngine, "sleep", no_noise_sleep)
        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
            "use_ldaps": False,
        }
        with patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module(
                "ad.enum_users",
                campaign,
                params,
                dispatch_context=_admitted(engine, campaign, "ad.enum_users"),
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert result.findings == []
        assert "invalid LDAP credentials" in result.outcome_message
        assert "Passw0rd!" not in result.outcome_message

    @pytest.mark.asyncio
    async def test_kerberoast_clock_skew_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberos_clock_skew,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def classified_clock_skew(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                format_kerberos_clock_skew(),
                module_id="ad.kerberoast",
                field="time",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with (
            patch.object(KerberoastModule, "execute", classified_clock_skew),
            patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep,
        ):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                dispatch_context=_admitted(engine, campaign, "ad.kerberoast"),
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert "clock skew too great" in result.outcome_message
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_retry_stops_when_retry_attempt_classifies_tgs_timeout(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError, NetworkError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberoast_tgs_timeout,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def transient_then_classified(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise NetworkError("temporary KDC reachability failure")
            raise ModuleValidationError(
                format_kerberoast_tgs_timeout(2),
                module_id="ad.kerberoast",
                field="kerberos_tgs",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with (
            patch.object(KerberoastModule, "execute", transient_then_classified),
            patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep,
        ):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
                dispatch_context=_admitted(engine, campaign, "ad.kerberoast"),
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "network_error"
        assert "temporary KDC reachability failure" in result.outcome_message

        generic_engine = AresEngine(settings=settings)
        generic_engine.load_modules()
        generic_calls = 0

        async def generic_opaque_failure(self_unused: Any, ctx: Any) -> Any:
            nonlocal generic_calls
            generic_calls += 1
            raise RuntimeError("temporary KDC reachability failure")

        with (
            patch.object(KerberoastModule, "execute", generic_opaque_failure),
            patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as generic_sleep,
        ):
            generic_result = await generic_engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
                dispatch_context=_admitted(
                    generic_engine,
                    campaign,
                    "ad.kerberoast",
                ),
            )

        assert generic_calls == 1
        assert generic_sleep.await_count == 0
        assert generic_result.status is ModuleStatus.FAILED
        assert generic_result.outcome == "module_error"
        assert "temporary KDC reachability failure" in generic_result.outcome_message

    @pytest.mark.asyncio
    async def test_run_module_timeout(self, settings: AresSettings, campaign: Campaign) -> None:
        engine = AresEngine(settings=settings)
        engine.load_modules()

        # Patch BOTH execute() and run():
        #   - engine calls instance.execute(ctx) on first attempt
        #   - retry path calls module2.run(**params) directly (bypasses execute)
        # Both must sleep forever so all attempts time out → status=TIMEOUT.
        async def slow_execute(self_unused, ctx):
            await asyncio.sleep(999)
            from ares.modules.base import ModuleResult

            return ModuleResult(status="success", module_id="linux.container")

        async def slow_run(self_unused, **kwargs):
            await asyncio.sleep(999)
            return [], {}

        mid = "linux.container"
        if mid in engine.registry:
            cls = engine.registry.get(mid)
            with patch.object(cls, "execute", slow_execute), patch.object(cls, "run", slow_run):
                result = await engine.run_module(
                    mid,
                    campaign,
                    {"target": "10.0.0.5"},
                    timeout_seconds=1,
                    dispatch_context=_admitted(engine, campaign, mid),
                )
            assert result.status == ModuleStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_execution_plan_parallel(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """All modules in a stage are attempted — mocked to return instantly."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        # Mock both modules so test runs in ms, not 20+ seconds on real filesystem
        fast = AsyncMock(return_value=([], {}))
        privesc_cls = engine.registry.get("linux.privesc")
        container_cls = engine.registry.get("linux.container")

        patches = []
        if privesc_cls:
            patches.append(patch.object(privesc_cls, "run", fast))
        if container_cls:
            patches.append(patch.object(container_cls, "run", fast))

        with patches[0] if patches else _noop_ctx():
            ctx = patches[1] if len(patches) > 1 else _noop_ctx()
            with ctx:
                plan = ExecutionPlan().add_stage("recon", ["linux.privesc", "linux.container"])
                results = await engine.run_plan(
                    plan,
                    campaign,
                    timeout_per_module=5,
                    dispatch_context=_admitted_plan(engine, campaign, plan),
                )

        assert "linux.privesc" in results
        assert "linux.container" in results

    @pytest.mark.asyncio
    async def test_plan_progress_callback(self, settings: AresSettings, campaign: Campaign) -> None:
        """Progress callback should be called for each module."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        fast = AsyncMock(return_value=([], {}))
        container_cls = engine.registry.get("linux.container")

        events: list[Any] = []

        async def on_progress(event: Any) -> None:
            events.append(event)

        ctx = patch.object(container_cls, "run", fast) if container_cls else _noop_ctx()
        with ctx:
            plan = ExecutionPlan().add_stage("test", ["linux.container"])
            await engine.run_plan(
                plan,
                campaign,
                on_progress=on_progress,
                timeout_per_module=5,
                dispatch_context=_admitted_plan(engine, campaign, plan),
            )
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Engine respects max_parallel — mocked to avoid filesystem scans."""
        engine = AresEngine(settings=settings, max_parallel=2)
        engine.load_modules()

        fast = AsyncMock(return_value=([], {}))
        privesc_cls = engine.registry.get("linux.privesc")
        container_cls = engine.registry.get("linux.container")

        patches = []
        if privesc_cls:
            patches.append(patch.object(privesc_cls, "run", fast))
        if container_cls:
            patches.append(patch.object(container_cls, "run", fast))

        with patches[0] if patches else _noop_ctx():
            ctx = patches[1] if len(patches) > 1 else _noop_ctx()
            with ctx:
                plan = ExecutionPlan().add_stage("test", ["linux.privesc", "linux.container"])
                results = await engine.run_plan(
                    plan,
                    campaign,
                    timeout_per_module=5,
                    dispatch_context=_admitted_plan(engine, campaign, plan),
                )
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_c_live_public_run_module_rejects_unsealed_dispatch(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        engine = AresEngine(settings=settings)
        result = await engine.run_module("test.never", campaign, {})
        assert result.status is ModuleStatus.FAILED
        assert "sealed admission context" in (result.error or "")
        assert engine._registry is None

    @pytest.mark.asyncio
    async def test_c_live_public_run_plan_rejects_unsealed_dispatch(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        engine = AresEngine(settings=settings)
        plan = ExecutionPlan().add_stage("blocked", ["test.never"])
        results = await engine.run_plan(plan, campaign)
        assert results["test.never"].status is ModuleStatus.FAILED
        assert "sealed plan context" in (results["test.never"].error or "")
        assert engine._registry is None

    @pytest.mark.parametrize(
        "case",
        [
            "fabricated",
            "stale-revision",
            "reused",
            "cross-module",
            "cross-attempt",
            "cross-campaign",
            "cross-submission",
            "cross-store",
        ],
    )
    @pytest.mark.asyncio
    async def test_c_live_sealed_dispatch_context_rejection(
        self,
        case: str,
        settings: AresSettings,
        campaign: Campaign,
    ) -> None:
        engine = AresEngine(settings=settings)
        store_a = SimpleNamespace(
            lifecycle_mutations=[],
            attempt_mutations=[],
            terminal_mutations=[],
            outbox_mutations=[],
            broadcasts=[],
        )
        sealed_module = "ad.c_live_reuse_probe" if case == "reused" else "test.never"
        context = _mint_test_dispatch_context(
            engine,
            campaign.id,
            sealed_module,
            store=store_a,
        )
        if case == "cross-store":
            with pytest.raises(PermissionError, match="different admission store"):
                _mint_test_dispatch_context(
                    engine,
                    campaign.id,
                    "test.never",
                    store=object(),
                    ordinal=1,
                )
            assert engine._registry is None
            return
        if case == "fabricated":
            candidate: Any = object()
        else:
            candidate = context
            if case == "stale-revision":
                candidate.attempt_revision = 2
            elif case == "cross-attempt":
                candidate.attempt_id = "77777777-7777-4777-8777-777777777777"
            elif case == "cross-submission":
                candidate.submission_id = "88888888-8888-4888-8888-888888888888"

        target_campaign = campaign
        target_module = sealed_module
        if case == "cross-module":
            target_module = "test.other"
        elif case == "cross-campaign":
            target_campaign = Campaign(
                name="other",
                client="ACME",
                scope=[ScopeEntry(cidr="10.0.0.0/8")],
                noise_profile=NoiseProfile.NORMAL,
            )

        if case == "reused":
            from ares.core.plugin.loader import ModuleRegistry
            from ares.modules.base import BaseModule, ModuleResult

            effects: list[str] = []

            class CountingRegistry(ModuleRegistry):
                def __init__(self) -> None:
                    super().__init__()
                    self.lookups: list[tuple[str, str]] = []

                def __contains__(self, module_id: str) -> bool:
                    self.lookups.append(("contains", module_id))
                    return super().__contains__(module_id)

                def get(self, module_id: str):
                    self.lookups.append(("get", module_id))
                    return super().get(module_id)

            class ReuseProbeModule(BaseModule):
                MODULE_ID = "ad.c_live_reuse_probe"
                MODULE_NAME = "C-LIVE reuse probe"
                MODULE_CATEGORY = "ad"
                MODULE_DESCRIPTION = "No-network sealed-context reuse probe"

                async def validate(self, ctx: Any) -> None:
                    return None

                async def execute(self, ctx: Any) -> ModuleResult:
                    effects.append(context.attempt_id)
                    return ModuleResult(status="success", module_id=self.MODULE_ID, raw={})

            registry = CountingRegistry()
            registry.register(ReuseProbeModule)
            engine._registry = registry
            engine.notifier = SimpleNamespace(
                should_notify=lambda _severity: True,
                notify_finding=AsyncMock(),
            )
            first = await engine.run_module(
                target_module,
                target_campaign,
                {},
                dispatch_context=candidate,
            )
            assert first.status is ModuleStatus.DONE
            assert effects == [context.attempt_id]
            assert engine._registry is registry
            registry_identity = id(engine._registry)

            def observable_snapshot() -> tuple[Any, ...]:
                runtime_states = engine._runtime_states._states
                return (
                    id(engine._registry),
                    len(engine._registry),
                    engine._registry._registry.get(target_module) is ReuseProbeModule,
                    tuple(registry.lookups),
                    tuple(effects),
                    tuple(sorted(engine._admitted_dispatch_contexts)),
                    engine._admission_store_id,
                    tuple(sorted(runtime_states)),
                    tuple((key, id(value)) for key, value in sorted(runtime_states.items())),
                    tuple(store_a.lifecycle_mutations),
                    tuple(store_a.attempt_mutations),
                    tuple(store_a.terminal_mutations),
                    tuple(store_a.outbox_mutations),
                    tuple(store_a.broadcasts),
                    engine.notifier.notify_finding.await_count,
                    tuple(campaign.findings),
                    context._consumed,
                    context._effect_started,
                    context._terminal_committed,
                    context._finalized,
                )

            before_reuse = observable_snapshot()
            rejected = await engine.run_module(
                target_module,
                target_campaign,
                {},
                dispatch_context=candidate,
            )
            assert rejected.status is ModuleStatus.FAILED
            assert (
                rejected.error
                == "dispatch context is stale, transferred, fabricated, or already used"
            )
            assert observable_snapshot() == before_reuse
            assert id(engine._registry) == registry_identity
            assert effects == [context.attempt_id]
            assert context._consumed is True
            assert context._effect_started is True
            return
        rejected = await engine.run_module(
            target_module,
            target_campaign,
            {},
            dispatch_context=candidate,
        )
        assert rejected.status is ModuleStatus.FAILED
        assert engine._registry is None
        if case != "fabricated":
            burned = await engine.run_module(
                "test.never",
                campaign,
                {},
                dispatch_context=context,
            )
            assert "already used" in (burned.error or "") or "fabricated" in (burned.error or "")

    @pytest.mark.asyncio
    async def test_c_live_retry_creates_v3_child_before_redispatch(
        self, settings: AresSettings, campaign: Campaign, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = TrustedPrincipal(
            "99999999-9999-4999-8999-999999999999",
            "99999999-9999-4999-8999-999999999999",
        )
        store = SimpleNamespace(
            create_retry_attempt_v3=AsyncMock(
                return_value=OperationResult(FixedResult.APPLIED, 0)
            )
        )
        engine = AresEngine(settings=settings)

        async def revalidate(*_args: Any):
            return RevalidatedPrincipalV1(principal, 0, "team_lead")

        coordinator = ExecutionAdmissionCoordinatorV1(store, engine, revalidate)
        expected = DispatchOutcomeV1(
            DispatchDispositionV1.TERMINAL,
            None,
            FixedResult.APPLIED,
            4,
            terminal_committed=True,
        )
        advance = AsyncMock(return_value=expected)
        monkeypatch.setattr(coordinator, "_advance_and_execute", advance)
        request = DispatchRequestV1(
            campaign_id=campaign.id,
            module_id="test.retry",
            ingress_code="api_module",
            idempotency_key="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            raw_parameters={},
            whole_intent_digest=canonical_intent_digest({"module": "test.retry"}),
        )
        result = await coordinator.retry_module(
            principal,
            request,
            campaign,
            logical_execution_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            parent_attempt_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            expected_parent_revision=4,
        )
        assert result is expected
        store.create_retry_attempt_v3.assert_awaited_once()
        advance.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_c_live_retry_non_applied_child_never_redispatches(
        self, settings: AresSettings, campaign: Campaign, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        principal = TrustedPrincipal(
            "99999999-9999-4999-8999-999999999999",
            "99999999-9999-4999-8999-999999999999",
        )
        store = SimpleNamespace(
            create_retry_attempt_v3=AsyncMock(
                return_value=OperationResult(FixedResult.REPLAYED_BOUND_CHILD, 0)
            )
        )
        engine = AresEngine(settings=settings)

        async def revalidate(*_args: Any):
            return RevalidatedPrincipalV1(principal, 0, "team_lead")

        coordinator = ExecutionAdmissionCoordinatorV1(store, engine, revalidate)
        advance = AsyncMock()
        monkeypatch.setattr(coordinator, "_advance_and_execute", advance)
        request = DispatchRequestV1(
            campaign_id=campaign.id,
            module_id="test.retry",
            ingress_code="api_module",
            idempotency_key="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            raw_parameters={},
            whole_intent_digest=canonical_intent_digest({"module": "test.retry"}),
        )
        result = await coordinator.retry_module(
            principal,
            request,
            campaign,
            logical_execution_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            parent_attempt_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            expected_parent_revision=4,
        )
        assert result.disposition is DispatchDispositionV1.REPLAYED
        advance.assert_not_awaited()


# ── Helpers ───────────────────────────────────────────────────────────────────

from contextlib import contextmanager


@contextmanager
def _noop_ctx():
    """No-op context manager for optional patches."""
    yield
