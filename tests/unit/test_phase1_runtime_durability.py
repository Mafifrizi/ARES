"""Phase 1 regressions for the durable API -> engine -> DB -> graph path."""

from __future__ import annotations

import asyncio
import json
from dataclasses import fields, replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ares.api import server
from ares.core.campaign import Campaign, Finding, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.execution_admission import (
    C_LIVE_PLAN_CHILD_DOMAIN,
    C_LIVE_RETRY_CHILD_DOMAIN,
    C_LIVE_STRATEGY_CHILD_DOMAIN,
    DispatchDispositionV1,
    DispatchRequestV1,
    ExecutionAdmissionCoordinatorV1,
    RevalidatedPrincipalV1,
    _identity,
    _mark_test_settlement_proof,
    _mint_test_dispatch_context,
    _mint_test_plan_context,
    canonical_intent_digest,
    derive_attempt_id,
    derive_child_submission_id,
    derive_logical_execution_id,
    derive_operation_id,
    derive_submission_id,
    mark_terminal_committed,
)
from ares.core.plugin.loader import ModuleRegistry
from ares.credential.vault import Credential, CredentialType, CredentialVault
from ares.db.database import AresDatabase, DBCredential, Host
from ares.db.execution_lifecycle import (
    AttemptState,
    CampaignActorGrantMutation,
    FixedResult,
    OperationResult,
    OutcomeCode,
    TrustedPrincipal,
)
from ares.modules.base import BaseModule, ModuleResult
from ares.strategy.engine import StrategyEngine


class PhaseOneProbeModule(BaseModule):
    """A no-network module used only to exercise engine persistence."""

    MODULE_ID = "ad.phase1_probe"
    MODULE_NAME = "Phase 1 probe"
    MODULE_CATEGORY = "ad"
    MODULE_DESCRIPTION = "Test-only durable runtime probe"
    contexts: list[Any] = []

    async def validate(self, ctx: Any) -> None:
        return None

    async def execute(self, ctx: Any) -> ModuleResult:
        type(self).contexts.append(ctx)
        ctx.session.add_host("10.10.10.5", hostname="dc01", is_dc=True)
        finding = Finding(
            title="Persisted probe finding",
            description="A safe test finding created without contacting a target.",
            severity=Severity.HIGH,
            host="10.10.10.5",
            module_id=self.MODULE_ID,
        )
        return ModuleResult(
            status="success",
            module_id=self.MODULE_ID,
            findings=[finding],
            raw={"source": "phase1-test"},
        )


class SQLiteLifecycleProbeModule(BaseModule):
    """Descriptor-backed no-network probe for real SQLite lifecycle wiring."""

    MODULE_ID = "ad.phase1_sqlite_probe"
    MODULE_NAME = "SQLite lifecycle probe"
    MODULE_CATEGORY = "ad"
    MODULE_DESCRIPTION = "Test-only real-store lifecycle probe"
    contexts: list[Any] = []

    async def validate(self, ctx: Any) -> None:
        return None

    async def execute(self, ctx: Any) -> ModuleResult:
        type(self).contexts.append(ctx)
        return ModuleResult(
            status="success",
            module_id=self.MODULE_ID,
            raw={"source": "sqlite-lifecycle-probe"},
        )


def _settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="phase1-test-secret-key-min-32-chars!!",
        ares_encryption_key="phase1-test-encryption-key-min-32chars!!",
        ares_default_admin_password="Phase1TestPassword!",
    )


def _campaign(campaign_id: str = "phase1-campaign") -> Campaign:
    return Campaign(
        id=campaign_id,
        name="Phase 1 durable test",
        client="ARES",
        operator="owner",
        scope=[ScopeEntry(cidr="10.10.10.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )


def _engine(settings: AresSettings, db: AresDatabase) -> AresEngine:
    engine = AresEngine(settings=settings, db=db)
    registry = ModuleRegistry()
    registry.register(PhaseOneProbeModule)
    engine._registry = registry
    return engine


async def _run_committed(
    engine: AresEngine,
    campaign: Campaign,
    module_id: str,
    params: dict[str, Any],
):
    context = _mint_test_dispatch_context(engine, campaign.id, module_id)
    result = await engine.run_module(
        module_id,
        campaign,
        params,
        actor_role="team_lead",
        dispatch_context=context,
    )
    mark_terminal_committed(context)
    return await engine._finalize_committed_module_result(campaign, module_id, result, context)


class _LifecycleStoreStub:
    def __init__(self) -> None:
        self.initial = OperationResult(FixedResult.APPLIED, 0)
        self.replay_after_first = False
        self.admission_calls = 0
        self.transition_failure_target = None
        self.terminal: OperationResult | None = None
        self.terminal_exception: BaseException | None = None
        self.transitions: list[Any] = []
        self.terminal_intents: list[Any] = []
        self.settlement_requests: list[Any] = []

    async def create_initial_execution_v3(self, principal: Any, intent: Any):
        self.admission_calls += 1
        self.principal = principal
        self.admission_intent = intent
        if self.replay_after_first and self.admission_calls > 1:
            return OperationResult(FixedResult.REPLAYED, 0)
        return self.initial

    async def create_retry_attempt_v3(self, principal: Any, intent: Any):
        self.principal = principal
        self.retry_intent = intent
        return self.initial

    async def transition_attempt(self, request: Any):
        self.transitions.append(request)
        if request.target_state is self.transition_failure_target:
            return OperationResult(FixedResult.CONFLICT_STATE, request.expected_revision)
        return OperationResult(FixedResult.APPLIED, request.expected_revision + 1)

    async def commit_terminal_attempt_v3(self, intent: Any):
        self.terminal_intents.append(intent)
        if self.terminal_exception is not None:
            raise self.terminal_exception
        return self.terminal or OperationResult(
            FixedResult.APPLIED, intent.expected_attempt_revision + 1
        )

    async def enter_settlement_pending(self, request: Any):
        self.settlement_requests.append(request)
        return OperationResult(FixedResult.APPLIED, request.expected_revision + 1)


class _RecordingLifecycleStore:
    """Transparent recorder around a real lifecycle store used by C-LIVE tests."""

    def __init__(self, store: Any) -> None:
        self._store = store
        self.transitions: list[Any] = []
        self.terminal_intents: list[Any] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    async def transition_attempt(self, request: Any):
        self.transitions.append(request)
        return await self._store.transition_attempt(request)

    async def commit_terminal_attempt_v3(self, intent: Any):
        self.terminal_intents.append(intent)
        return await self._store.commit_terminal_attempt_v3(intent)


def _live_fixture():
    campaign = _campaign("11111111-1111-4111-8111-111111111111")
    engine = AresEngine(settings=_settings())
    registry = ModuleRegistry()
    registry.register(PhaseOneProbeModule)
    engine._registry = registry
    store = _LifecycleStoreStub()
    principal = TrustedPrincipal(
        "33333333-3333-4333-8333-333333333333",
        "33333333-3333-4333-8333-333333333333",
    )

    async def revalidate(candidate: Any, campaign_id: str, module_id: str):
        assert candidate.subject_ref == principal.subject_ref
        assert campaign_id == campaign.id
        assert module_id == PhaseOneProbeModule.MODULE_ID
        return RevalidatedPrincipalV1(principal, 0, "team_lead")

    coordinator = ExecutionAdmissionCoordinatorV1(store, engine, revalidate)
    request = DispatchRequestV1(
        campaign_id=campaign.id,
        module_id=PhaseOneProbeModule.MODULE_ID,
        ingress_code="api_module",
        idempotency_key="22222222-2222-4222-8222-222222222222",
        raw_parameters={"target": "10.10.10.5"},
        whole_intent_digest=canonical_intent_digest(
            {"module_id": PhaseOneProbeModule.MODULE_ID, "target": "10.10.10.5"}
        ),
    )
    return campaign, engine, store, principal, coordinator, request


async def _sqlite_live_fixture(tmp_path: Any, monkeypatch: pytest.MonkeyPatch):
    """Build one descriptor-authorized C-LIVE coordinator on the real SQLite store."""
    from tests.unit.test_execution_lifecycle_persistence import (
        _p1c_eligible_descriptor,
        _p1c_enable_acceptance,
        _p1c_sqlite_authority_store,
    )

    from ares.modules import descriptors as descriptor_module
    from ares.modules.descriptors import ModuleCategory, ModuleDescriptor

    source = _p1c_eligible_descriptor(monkeypatch)
    descriptor_values = {
        field.name: getattr(source, field.name)
        for field in fields(ModuleDescriptor)
        if field.init
    }
    descriptor_values.update(
        module_id=SQLiteLifecycleProbeModule.MODULE_ID,
        category=ModuleCategory.AD,
    )
    descriptor = ModuleDescriptor(**descriptor_values)
    descriptors = dict(descriptor_module.FIRST_PARTY_DESCRIPTORS)
    descriptors[descriptor.module_id] = descriptor
    monkeypatch.setattr(descriptor_module, "FIRST_PARTY_DESCRIPTORS", descriptors)
    database, _setup_store, admin, actor_id, campaign_id, _credential_id = (
        await _p1c_sqlite_authority_store(tmp_path)
    )
    actual_store = database.execution_lifecycle_store()
    principal = TrustedPrincipal(actor_id, actor_id)
    grant = await actual_store.put_campaign_actor_grant(
        admin,
        CampaignActorGrantMutation(
            "77777777-7777-4777-8777-777777777777",
            campaign_id,
            principal.user_id,
            None,
        ),
    )
    assert grant.result is FixedResult.APPLIED
    await _p1c_enable_acceptance(actual_store, admin, campaign_id)
    store = _RecordingLifecycleStore(actual_store)

    campaign = _campaign(campaign_id)
    engine = AresEngine(settings=_settings())
    registry = ModuleRegistry()
    registry.register(SQLiteLifecycleProbeModule)
    engine._registry = registry

    async def revalidate(candidate: Any, candidate_campaign: str, module_id: str):
        assert candidate == principal
        assert candidate_campaign == campaign_id
        assert module_id == SQLiteLifecycleProbeModule.MODULE_ID
        return RevalidatedPrincipalV1(principal, 0, "operator")

    coordinator = ExecutionAdmissionCoordinatorV1(store, engine, revalidate)
    request = DispatchRequestV1(
        campaign_id=campaign_id,
        module_id=SQLiteLifecycleProbeModule.MODULE_ID,
        ingress_code="api_module",
        idempotency_key="88888888-8888-4888-8888-888888888888",
        raw_parameters={"noise_profile": "stealth"},
        whole_intent_digest=canonical_intent_digest(
            {
                "module_id": SQLiteLifecycleProbeModule.MODULE_ID,
                "noise_profile": "stealth",
            }
        ),
    )
    return database, campaign, engine, store, principal, coordinator, request


def _assert_c_live_typed_length_uuid_vectors_are_literal() -> None:
    campaign_id = "11111111-1111-4111-8111-111111111111"
    key = "22222222-2222-4222-8222-222222222222"
    submission = derive_submission_id(campaign_id, "api_module", key)
    logical = derive_logical_execution_id(campaign_id, submission)
    attempt = derive_attempt_id(logical, "test.safe_probe")
    assert submission == "b6dc6c66-d862-4e37-83b7-88060726d0f5"
    assert logical == "90f8daee-8ac7-48d0-8e3a-4293580cf2bf"
    assert attempt == "f8c45915-a12d-409e-8552-8a0d25586a9f"
    assert (
        derive_operation_id(attempt, "admission")
        == "cca963e4-fd56-4246-8cbb-c775f68e715b"
    )
    assert derive_operation_id(attempt, "queue") == "5a190d69-5318-4f30-8213-8881319448da"
    assert (
        derive_child_submission_id(
            submission,
            "test.safe_probe",
            occurrence=1,
            stage_ordinal=2,
            decision_ordinal=0,
            module_ordinal=3,
            domain=C_LIVE_PLAN_CHILD_DOMAIN,
        )
        == "f506c525-b0db-492c-8133-e4d280b00e49"
    )
    assert (
        derive_child_submission_id(
            submission,
            "test.safe_probe",
            occurrence=1,
            stage_ordinal=2,
            decision_ordinal=4,
            module_ordinal=3,
            domain=C_LIVE_STRATEGY_CHILD_DOMAIN,
        )
        == "92dd04fa-f59f-4439-86a4-50fab7529867"
    )
    assert (
        derive_child_submission_id(
            submission,
            "test.safe_probe",
            occurrence=1,
            stage_ordinal=0,
            decision_ordinal=0,
            module_ordinal=0,
            domain=C_LIVE_RETRY_CHILD_DOMAIN,
        )
        == "cd8b9bfd-6e95-4149-8a23-89edf120e1d2"
    )


@pytest.mark.asyncio
async def test_c_live_concurrent_duplicate_dispatches_exactly_once(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _assert_c_live_typed_length_uuid_vectors_are_literal()
    database, campaign, _engine_value, store, principal, coordinator, request = (
        await _sqlite_live_fixture(tmp_path, monkeypatch)
    )
    peer_database = AresDatabase(tmp_path / "p1c-authority.db")
    await peer_database.connect()
    peer_store = _RecordingLifecycleStore(peer_database.execution_lifecycle_store())
    peer_engine = AresEngine(settings=_settings())
    peer_registry = ModuleRegistry()
    peer_registry.register(SQLiteLifecycleProbeModule)
    peer_engine._registry = peer_registry

    async def peer_revalidate(candidate: Any, campaign_id: str, module_id: str):
        assert candidate == principal
        assert campaign_id == campaign.id
        assert module_id == SQLiteLifecycleProbeModule.MODULE_ID
        return RevalidatedPrincipalV1(principal, 0, "operator")

    peer = ExecutionAdmissionCoordinatorV1(peer_store, peer_engine, peer_revalidate)
    SQLiteLifecycleProbeModule.contexts.clear()
    try:
        results = await asyncio.gather(
            coordinator.execute_module(principal, request, campaign),
            peer.execute_module(principal, request, campaign),
        )
        assert {result.disposition for result in results} == {
            DispatchDispositionV1.TERMINAL,
            DispatchDispositionV1.REPLAYED,
        }
        assert sum(result.terminal_committed for result in results) == 1
        assert len(SQLiteLifecycleProbeModule.contexts) == 1
        transitions = store.transitions + peer_store.transitions
        assert [item.target_state for item in transitions] == [
            AttemptState.QUEUED,
            AttemptState.DISPATCHING,
            AttemptState.RUNNING,
        ]
        assert [item.expected_revision for item in transitions] == [0, 1, 2]
        terminal_intents = store.terminal_intents + peer_store.terminal_intents
        assert len(terminal_intents) == 1
        assert terminal_intents[0].expected_attempt_revision == 3
        assert terminal_intents[0].concurrency_actual == 0
        attempt = await (
            await database.conn.execute(
                "SELECT state,revision FROM execution_attempts WHERE id=?",
                (results[0].identity.attempt_id,),
            )
        ).fetchone()
        assert tuple(attempt) == ("succeeded", 4)
    finally:
        await peer_database.close()
        await database.close()


@pytest.mark.asyncio
async def test_c_live_terminal_commit_then_response_loss_replays_stable_ids_without_effect() -> None:
    campaign, _engine_value, store, principal, coordinator, request = _live_fixture()
    PhaseOneProbeModule.contexts.clear()
    applied = await coordinator.execute_module(principal, request, campaign)
    store.initial = OperationResult(FixedResult.REPLAYED, 0)
    transition_count = len(store.transitions)
    terminal_count = len(store.terminal_intents)
    replay = await coordinator.execute_module(principal, request, campaign)
    assert applied.disposition is DispatchDispositionV1.TERMINAL
    assert replay.disposition is DispatchDispositionV1.REPLAYED
    assert replay.identity == applied.identity
    assert len(PhaseOneProbeModule.contexts) == 1
    assert len(store.transitions) == transition_count
    assert len(store.terminal_intents) == terminal_count


@pytest.mark.parametrize(
    "failed_target",
    [AttemptState.QUEUED, AttemptState.DISPATCHING, AttemptState.RUNNING],
    ids=["queued", "dispatching", "running"],
)
@pytest.mark.asyncio
async def test_c_live_failed_pre_effect_state_cas_has_zero_effect(
    failed_target: AttemptState,
) -> None:
    campaign, _engine_value, store, principal, coordinator, request = _live_fixture()
    store.transition_failure_target = failed_target
    PhaseOneProbeModule.contexts.clear()
    result = await coordinator.execute_module(principal, request, campaign)
    assert result.lifecycle_result is FixedResult.CONFLICT_STATE
    assert result.effect_started is False
    assert PhaseOneProbeModule.contexts == []
    assert store.terminal_intents == []


@pytest.mark.asyncio
async def test_c_live_uncertainty_after_running_is_settlement_pending_without_retry(
    monkeypatch: Any,
) -> None:
    campaign, _engine_value, store, principal, coordinator, request = _live_fixture()

    async def timeout_execute(self: Any, ctx: Any):
        raise TimeoutError("executor quiescence is not proven")

    monkeypatch.setattr(PhaseOneProbeModule, "execute", timeout_execute)
    result = await coordinator.execute_module(principal, request, campaign)
    assert result.disposition is DispatchDispositionV1.INDETERMINATE
    assert result.terminal_committed is False
    assert store.terminal_intents == []
    assert len(store.settlement_requests) == 1
    assert store.settlement_requests[0].target_state is AttemptState.SETTLEMENT_PENDING

    # External task cancellation is process control, not an HTTP outcome.  The
    # coordinator must shield one bounded safety write and then re-raise it.
    campaign, _engine_value, cancelled_store, principal, coordinator, request = (
        _live_fixture()
    )
    entered_effect = asyncio.Event()

    async def cancelled_execute(self: Any, ctx: Any):
        entered_effect.set()
        await asyncio.Future()

    monkeypatch.setattr(PhaseOneProbeModule, "execute", cancelled_execute)
    task = asyncio.create_task(coordinator.execute_module(principal, request, campaign))
    await entered_effect.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(cancelled_store.settlement_requests) == 1
    assert cancelled_store.settlement_requests[0].target_state is AttemptState.SETTLEMENT_PENDING


@pytest.mark.asyncio
async def test_c_live_terminal_persistence_failure_has_no_success_response_or_broadcast() -> None:
    campaign, _engine_value, store, principal, coordinator, request = _live_fixture()
    store.terminal_exception = RuntimeError("injected terminal persistence failure")
    PhaseOneProbeModule.contexts.clear()
    result = await coordinator.execute_module(principal, request, campaign)
    assert result.disposition is DispatchDispositionV1.INDETERMINATE
    assert result.lifecycle_result is FixedResult.APPLIED
    assert result.terminal_committed is False
    assert len(store.settlement_requests) == 1
    assert campaign.findings == []

    campaign, _engine_value, cancelled_store, principal, coordinator, request = (
        _live_fixture()
    )
    cancelled_store.terminal_exception = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await coordinator.execute_module(principal, request, campaign)
    assert len(cancelled_store.settlement_requests) == 1
    assert campaign.findings == []

    campaign, _engine_value, wrong_revision_store, principal, coordinator, request = (
        _live_fixture()
    )
    wrong_revision_store.terminal = OperationResult(FixedResult.APPLIED, 99)
    result = await coordinator.execute_module(principal, request, campaign)
    assert result.disposition is DispatchDispositionV1.INDETERMINATE
    assert result.lifecycle_result is FixedResult.INVARIANT_FAILURE
    assert result.terminal_committed is False
    assert campaign.findings == []


@pytest.mark.asyncio
async def test_c_live_crash_after_admission_before_queue_is_stranded_without_effect() -> None:
    campaign, engine, store, principal, _coordinator, request = _live_fixture()

    async def unavailable_revalidation(*_args: Any):
        return None

    coordinator = ExecutionAdmissionCoordinatorV1(store, engine, unavailable_revalidation)
    PhaseOneProbeModule.contexts.clear()
    result = await coordinator.execute_module(principal, request, campaign)
    assert result.lifecycle_result is FixedResult.AUTHORITY_STALE
    assert result.revision == 0
    assert store.transitions == []
    assert PhaseOneProbeModule.contexts == []


@pytest.mark.parametrize(
    ("created_result", "expected_effects"),
    [
        pytest.param(OperationResult(FixedResult.APPLIED, 0), 1, id="applied-child-dispatches"),
        pytest.param(
            OperationResult(FixedResult.REPLAYED_BOUND_CHILD, 0),
            0,
            id="replayed-child-does-not-dispatch",
        ),
    ],
)
@pytest.mark.asyncio
async def test_c_live_retry_dispatch_ownership(
    created_result: OperationResult,
    expected_effects: int,
) -> None:
    campaign, _engine_value, store, principal, coordinator, request = _live_fixture()
    store.initial = created_result
    PhaseOneProbeModule.contexts.clear()
    result = await coordinator.retry_module(
        principal,
        request,
        campaign,
        logical_execution_id="44444444-4444-4444-8444-444444444444",
        parent_attempt_id="55555555-5555-4555-8555-555555555555",
        expected_parent_revision=4,
    )
    assert len(PhaseOneProbeModule.contexts) == expected_effects
    assert result.effect_started is bool(expected_effects)


def test_c_live_repeated_plan_modules_have_deterministic_child_identities() -> None:
    _assert_c_live_typed_length_uuid_vectors_are_literal()
    campaign, _engine_value, _store, _principal, _coordinator, base = _live_fixture()
    digest = canonical_intent_digest(["ad.phase1_probe", "ad.phase1_probe"])
    first_request = replace(
        base,
        ingress_code="api_campaign_plan",
        whole_intent_digest=digest,
        module_ordinal=0,
    )
    second_request = replace(
        base,
        ingress_code="api_campaign_plan",
        whole_intent_digest=digest,
        module_ordinal=1,
    )
    first = _identity(first_request)
    second = _identity(second_request)
    assert first == _identity(first_request)
    assert second == _identity(second_request)
    assert first.submission_id != second.submission_id
    assert first.logical_execution_id != second.logical_execution_id
    assert first.attempt_id != second.attempt_id
    assert campaign.id == base.campaign_id


@pytest.mark.asyncio
async def test_c_live_changed_whole_plan_conflicts_before_child_redispatch(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, campaign, _engine_value, store, principal, coordinator, base = (
        await _sqlite_live_fixture(tmp_path, monkeypatch)
    )
    original = replace(
        base,
        ingress_code="api_campaign_plan",
        module_ordinal=0,
        whole_intent_digest=canonical_intent_digest(["ad.phase1_probe"]),
    )
    changed = replace(
        base,
        ingress_code="api_campaign_plan",
        module_ordinal=0,
        whole_intent_digest=canonical_intent_digest(
            ["ad.phase1_probe", "ad.phase1_probe"]
        ),
    )
    first_identity = _identity(original)
    changed_identity = _identity(changed)
    assert first_identity.submission_id == changed_identity.submission_id
    assert first_identity.logical_execution_id != changed_identity.logical_execution_id
    SQLiteLifecycleProbeModule.contexts.clear()
    try:
        applied = await coordinator.execute_module(principal, original, campaign)
        conflict = await coordinator.execute_module(principal, changed, campaign)
        assert applied.terminal_committed is True
        assert conflict.lifecycle_result is FixedResult.CONFLICT_OPERATION
        assert len(SQLiteLifecycleProbeModule.contexts) == 1
        attempts = await (
            await database.conn.execute(
                "SELECT state,revision FROM execution_attempts ORDER BY id"
            )
        ).fetchall()
        assert [tuple(row) for row in attempts] == [("succeeded", 4)]
    finally:
        await database.close()


@pytest.mark.parametrize(
    ("case", "expected_outcome"),
    [
        pytest.param("success", OutcomeCode.CONFIRMED_SUCCESS, id="confirmed-success"),
        pytest.param("failure", OutcomeCode.CONFIRMED_FAILURE, id="confirmed-failure"),
        pytest.param(
            "cancelled",
            OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
            id="confirmed-cancelled-no-result",
        ),
        pytest.param(
            "timeout",
            OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
            id="confirmed-timeout-terminated",
        ),
    ],
)
@pytest.mark.asyncio
async def test_c_live_known_settled_outcome_commits_before_result(
    case: str,
    expected_outcome: OutcomeCode,
    monkeypatch: Any,
) -> None:
    campaign, engine, store, principal, coordinator, request = _live_fixture()
    if case == "failure":
        async def failed_execute(self: Any, ctx: Any):
            raise RuntimeError("known settled failure")

        monkeypatch.setattr(PhaseOneProbeModule, "execute", failed_execute)
    elif case in {"cancelled", "timeout"}:
        original_run = engine.run_module

        async def settled_run(*args: Any, **kwargs: Any):
            result = await original_run(*args, **kwargs)
            context = kwargs["dispatch_context"]
            proof = (
                "cancellation_no_result_ack"
                if case == "cancelled"
                else "timeout_termination_ack"
            )
            _mark_test_settlement_proof(context, proof)
            result.status = (
                ModuleStatus.CANCELLED if case == "cancelled" else ModuleStatus.TIMEOUT
            )
            result.findings = []
            result.raw_output = {}
            return result

        monkeypatch.setattr(engine, "run_module", settled_run)

    result = await coordinator.execute_module(principal, request, campaign)
    assert result.terminal_committed is True
    assert store.terminal_intents[-1].outcome_code is expected_outcome
    if case == "success":
        assert campaign.findings, "result publication must occur after terminal commit"
    if case in {"cancelled", "timeout"}:
        assert store.terminal_intents[-1].execution_result_digest is None


@pytest.mark.parametrize(
    "case",
    [
        "principal-and-mutable-input-not-in-namespace",
        "changed-principal-conflicts",
        "changed-immutable-intent-conflicts",
    ],
)
@pytest.mark.asyncio
async def test_c_live_submission_namespace_and_binding(
    case: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, _engine_value, _store, principal, _coordinator, request = _live_fixture()
    changed = replace(request, raw_parameters={"target": "10.10.10.6"})
    assert _identity(request).submission_id == _identity(changed).submission_id
    if case == "principal-and-mutable-input-not-in-namespace":
        assert derive_submission_id(
            campaign.id, request.ingress_code, request.idempotency_key
        ) == _identity(request).submission_id
        return

    database, campaign, _engine_value, _store, principal, coordinator, request = (
        await _sqlite_live_fixture(tmp_path, monkeypatch)
    )
    changed = replace(request, raw_parameters={"noise_profile": "normal"})
    candidate = principal
    if case == "changed-principal-conflicts":
        candidate = TrustedPrincipal(
            "66666666-6666-4666-8666-666666666666",
            "66666666-6666-4666-8666-666666666666",
        )
    SQLiteLifecycleProbeModule.contexts.clear()
    try:
        applied = await coordinator.execute_module(principal, request, campaign)
        result = await coordinator.execute_module(
            candidate,
            changed if case == "changed-immutable-intent-conflicts" else request,
            campaign,
        )
        assert applied.terminal_committed is True
        assert result.lifecycle_result is FixedResult.CONFLICT_OPERATION
        assert len(SQLiteLifecycleProbeModule.contexts) == 1
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_db_bound_engine_persists_each_execution_once(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1.db", settings.encryption_key_value)
    campaign = _campaign()
    await db.save_campaign(campaign)
    engine = _engine(settings, db)
    PhaseOneProbeModule.contexts.clear()
    try:
        result = await _run_committed(
            engine,
            campaign,
            PhaseOneProbeModule.MODULE_ID,
            {"target": "10.10.10.5"},
        )
        findings, total = await db.list_findings(campaign.id, per_page=20)
        async with db.conn.execute(
            "SELECT COUNT(*) AS n FROM module_runs WHERE campaign_id=?", (campaign.id,)
        ) as cursor:
            module_runs = int((await cursor.fetchone())["n"])

        assert result.status is ModuleStatus.DONE
        assert total == len(findings) == 1
        assert module_runs == 1
        assert (
            PhaseOneProbeModule.contexts[-1].artifact_store
            is campaign._runtime_state.artifact_store
        )
        assert PhaseOneProbeModule.contexts[-1].vault is campaign._runtime_state.vault
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_restored_vault_is_reused_by_the_next_campaign_run(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-vault.db", settings.encryption_key_value)
    campaign = _campaign("phase1-vault")
    await db.save_campaign(campaign)
    source_vault = CredentialVault(settings.encryption_key_value)
    credential = Credential(
        campaign_id=campaign.id,
        username="svc_phase1",
        domain="LAB.LOCAL",
        cred_type=CredentialType.CLEARTEXT,
    )
    source_vault.store(credential, "never-return-this-secret")
    await db.save_credential_preencrypted(
        DBCredential(
            id=credential.id,
            campaign_id=campaign.id,
            username=credential.username,
            cred_type=credential.cred_type.value,
            secret=credential.secret_enc.decode(),
            domain=credential.domain,
            source_module="phase1.fixture",
        )
    )
    engine = _engine(settings, db)
    PhaseOneProbeModule.contexts.clear()
    try:
        restored = await engine.restore_campaign_vault(campaign)
        result = await _run_committed(
            engine,
            campaign,
            PhaseOneProbeModule.MODULE_ID,
            {"target": "10.10.10.5"},
        )

        assert restored == 1
        assert result.status is ModuleStatus.DONE
        assert PhaseOneProbeModule.contexts[-1].vault is campaign._runtime_state.vault
        assert campaign._runtime_state.vault.get(credential.id) is not None
        assert "never-return-this-secret" not in json.dumps(result.model_dump(mode="json"))
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_plan_and_strategy_rehydrate_durable_state_and_done_is_success(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-plan.db", settings.encryption_key_value)
    campaign = _campaign("phase1-plan")
    await db.save_campaign(campaign)
    engine = _engine(settings, db)
    try:
        plan = ExecutionPlan().add_stage(
            "probe",
            [PhaseOneProbeModule.MODULE_ID],
            {PhaseOneProbeModule.MODULE_ID: {"target": "10.10.10.5"}},
        )
        plan_context = _mint_test_plan_context(engine, campaign.id, tuple(plan.all_module_ids()))
        plan_results = await engine.run_plan(
            plan,
            campaign,
            actor_role="team_lead",
            dispatch_context=plan_context,
        )
        for child_context in plan_context.children:
            module_result = plan_results[child_context.module_id]
            mark_terminal_committed(child_context)
            await engine._finalize_committed_module_result(
                campaign,
                child_context.module_id,
                module_result,
                child_context,
            )
        assert plan_results[PhaseOneProbeModule.MODULE_ID].status is ModuleStatus.DONE

        strategy = StrategyEngine(ares_engine=engine, settings=settings)
        strategy._run_coverage_predictor = AsyncMock(
            return_value={
                "detection_score": 0.0,
                "wait_recommendation": {"hours": 0},
            }
        )
        strategy._get_edr_context = AsyncMock(
            return_value={
                "edr_vendor": "test",
                "viable_techniques": [],
                "recommended_approach": None,
            }
        )
        strategy._run_ai_planner = AsyncMock(
            return_value={
                "confidence_score": 1.0,
                "execution_plan": [
                    {
                        "name": "probe",
                        "modules": [PhaseOneProbeModule.MODULE_ID],
                        "params": {PhaseOneProbeModule.MODULE_ID: {"target": "10.10.10.5"}},
                    }
                ],
                "warnings": [],
            }
        )
        strategy_result = await strategy.run_autonomous_engagement(
            campaign=campaign,
            max_rounds=1,
            llm_backend="local",
            actor_role="team_lead",
        )
        assert PhaseOneProbeModule.MODULE_ID not in strategy_result.modules_succeeded
        strategy._run_coverage_predictor.assert_not_awaited()
        strategy._get_edr_context.assert_not_awaited()
        strategy._run_ai_planner.assert_not_awaited()

        engine.discard_campaign_runtime(campaign.id)
        rehydrated_campaign = _campaign(campaign.id)
        restarted_engine = _engine(settings, db)
        restarted_state = await restarted_engine.ensure_campaign_runtime(rehydrated_campaign)
        findings, total = await db.list_findings(campaign.id, per_page=20)

        assert total == len(findings) == 1
        assert restarted_state.session.get_host("10.10.10.5") is not None
        assert (await db.get_campaign_graph(campaign.id)) is not None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_strategy_preflight_does_not_reserve_a_slot_for_unknown_campaign(
    monkeypatch: Any,
) -> None:
    from datetime import datetime, timedelta, timezone
    from unittest.mock import MagicMock

    from ares.api.rbac import AuthenticatedUser
    from ares.db.websocket_tickets import BearerTicketSource

    server._active_engagements.clear()
    database = SimpleNamespace(get_campaign=AsyncMock(return_value=None))
    engine = MagicMock()
    engine.run_module = AsyncMock()
    engine.run_plan = AsyncMock()
    runtime = MagicMock()
    planning_seam = MagicMock()
    broadcast = AsyncMock()
    monkeypatch.setattr(server, "_strategy_test_plan", planning_seam)
    monkeypatch.setattr(server, "_broadcast_event", broadcast)
    request = server.Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/strategy/engage",
            "raw_path": b"/strategy/engage",
            "query_string": b"",
            "headers": [
                (b"authorization", b"Bearer test-only-preflight"),
                (
                    b"idempotency-key",
                    b"11111111-1111-4111-8111-111111111111",
                ),
            ],
            "client": ("127.0.0.1", 40123),
            "server": ("testserver", 80),
            "app": server.app,
        }
    )
    response = server.Response()
    actor = AuthenticatedUser(
        username="owner",
        role="team_lead",
        websocket_ticket_source=BearerTicketSource(
            user_id="11111111-1111-4111-8111-111111111111",
            subject="owner",
            jti="preflight-jti",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            family_id="A" * 43,
            auth_epoch=1,
        ),
    )
    body = server.AutonomousEngagementRequest(
        campaign_id="missing",
        llm_backend="local",
    )

    with pytest.raises(server.HTTPException) as exc_info:
        await server.start_autonomous_engagement(
            body,
            request,
            response,
            actor=actor,
            engine=engine,
            db=database,
            c_live_runtime=runtime,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Campaign 'missing' not found"
    database.get_campaign.assert_awaited_once_with("missing")
    planning_seam.assert_not_called()
    runtime.bind.assert_not_called()
    engine.run_module.assert_not_awaited()
    engine.run_plan.assert_not_awaited()
    broadcast.assert_not_awaited()
    assert server._active_engagements == {}


@pytest.mark.asyncio
async def test_persisted_graph_and_attack_paths_use_safe_durable_rows(tmp_path: Any) -> None:
    settings = _settings()
    db = await AresDatabase.create(tmp_path / "phase1-graph.db", settings.encryption_key_value)
    campaign = _campaign("phase1-graph")
    await db.save_campaign(campaign)
    await db.upsert_host(
        Host(
            campaign_id=campaign.id,
            ip_address="10.10.10.5",
            hostname="dc01",
            is_dc=True,
        )
    )
    await db.save_finding(
        campaign.id,
        Finding(
            title="Persisted graph finding",
            description="Verified durable graph fixture.",
            severity=Severity.CRITICAL,
            host="10.10.10.5",
            module_id="ad.phase1_probe",
            validated=True,
        ),
    )
    await db.save_credential(
        DBCredential(
            campaign_id=campaign.id,
            username="svc_graph",
            cred_type="cleartext",
            secret="graph-secret-must-not-leak",
            domain="LAB.LOCAL",
        )
    )
    engine = _engine(settings, db)
    actor = SimpleNamespace(username="owner", role="team_lead")
    try:
        graph_payload = await server.campaign_graph(campaign.id, actor=actor, engine=engine, db=db)
        path_payload = await server.campaign_attack_paths(
            campaign.id, actor=actor, engine=engine, db=db
        )

        assert graph_payload["stats"]["hosts"] == 1
        assert graph_payload["stats"]["findings"] == 1
        assert "graph-secret-must-not-leak" not in json.dumps(graph_payload)
        assert path_payload["stats"]["nodes"] >= 3
    finally:
        await db.close()
