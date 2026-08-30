"""C-LIVE-v1 fail-closed admission coordinator.

This module is the only first-party bridge from durable lifecycle admission to
the in-process execution engine.  It deliberately does not make descriptors
eligible: the generation-11 policy/catalog gate remains authoritative.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping, Protocol

from ares.db.execution_lifecycle import (
    AdmissionIntentV3,
    AttemptState,
    FixedResult,
    OperationResult,
    OutcomeCode,
    RetryIntentV3,
    TerminalCommitIntentV3,
    TransitionRequest,
    TrustedPrincipal,
    canonical_operation_binding_digest,
    valid_uuid,
)

if TYPE_CHECKING:
    from ares.core.campaign import Campaign
    from ares.core.engine import AresEngine, EngineModuleResult


C_LIVE_SUBMISSION_DOMAIN = "ares.c-live.v1.submission"
C_LIVE_LOGICAL_DOMAIN = "ares.c-live.v1.logical"
C_LIVE_ATTEMPT_DOMAIN = "ares.c-live.v1.attempt"
C_LIVE_OPERATION_DOMAIN = "ares.c-live.v1.operation"
C_LIVE_PLAN_CHILD_DOMAIN = "ares.c-live.v1.plan-child"
C_LIVE_STRATEGY_CHILD_DOMAIN = "ares.c-live.v1.strategy-child"
C_LIVE_RETRY_CHILD_DOMAIN = "ares.c-live.v1.retry-child"
C_LIVE_RESULT_DOMAIN = b"ares.c-live.v1.execution-result\x00"

_CHILD_DOMAINS = frozenset(
    {
        C_LIVE_PLAN_CHILD_DOMAIN,
        C_LIVE_STRATEGY_CHILD_DOMAIN,
        C_LIVE_RETRY_CHILD_DOMAIN,
    }
)
_ISSUER = object()
_PROCESS_SEAL_KEY = secrets.token_bytes(32)


def _uuid_from_digest(digest: str) -> str:
    """Return the lifecycle-compatible deterministic UUID projection."""
    if type(digest) is not str or len(digest) != 64:
        raise ValueError("C-LIVE digest must be a lowercase SHA-256 value")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise ValueError("C-LIVE digest must be a lowercase SHA-256 value") from exc
    if digest != digest.lower():
        raise ValueError("C-LIVE digest must be a lowercase SHA-256 value")
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def derive_c_live_uuid(
    domain: str,
    fields: tuple[tuple[str, str | int | bool | None], ...],
) -> str:
    """Derive one UUID from the existing typed-length lifecycle framing."""
    return _uuid_from_digest(canonical_operation_binding_digest(domain, fields))


def derive_submission_id(campaign_id: str, ingress_code: str, idempotency_key: str) -> str:
    """Submission namespace: campaign + ingress + client Idempotency-Key."""
    return derive_c_live_uuid(
        C_LIVE_SUBMISSION_DOMAIN,
        (
            ("campaign_id", campaign_id),
            ("ingress_code", ingress_code),
            ("idempotency_key", idempotency_key),
        ),
    )


def derive_logical_execution_id(
    campaign_id: str,
    submission_id: str,
    *,
    whole_intent_digest: str | None = None,
) -> str:
    fields: tuple[tuple[str, str | int | bool | None], ...] = (
        ("campaign_id", campaign_id),
        ("submission_id", submission_id),
    )
    if whole_intent_digest is not None:
        fields += (("whole_intent_digest", whole_intent_digest),)
    return derive_c_live_uuid(
        C_LIVE_LOGICAL_DOMAIN,
        fields,
    )


def derive_attempt_id(
    parent_id: str,
    module_id: str,
    *,
    occurrence: int = 0,
    stage_ordinal: int = 0,
    decision_ordinal: int = 0,
    module_ordinal: int = 0,
    domain: str = C_LIVE_ATTEMPT_DOMAIN,
) -> str:
    if domain not in _CHILD_DOMAINS | {C_LIVE_ATTEMPT_DOMAIN}:
        raise ValueError("Unsupported C-LIVE attempt domain")
    return derive_c_live_uuid(
        domain,
        (
            ("parent_id", parent_id),
            ("occurrence", occurrence),
            ("stage_ordinal", stage_ordinal),
            ("decision_ordinal", decision_ordinal),
            ("module_ordinal", module_ordinal),
            ("module_id", module_id),
        ),
    )


def derive_child_submission_id(
    parent_submission_id: str,
    module_id: str,
    *,
    occurrence: int,
    stage_ordinal: int,
    decision_ordinal: int,
    module_ordinal: int,
    domain: str,
) -> str:
    """Project one child submission from the shared HTTP submission authority."""
    if not valid_uuid(parent_submission_id) or domain not in _CHILD_DOMAINS:
        raise ValueError("invalid C-LIVE child identity authority")
    return derive_attempt_id(
        parent_submission_id,
        module_id,
        occurrence=occurrence,
        stage_ordinal=stage_ordinal,
        decision_ordinal=decision_ordinal,
        module_ordinal=module_ordinal,
        domain=domain,
    )


def derive_operation_id(
    attempt_id: str,
    action: str,
    *,
    ordinal: int = 0,
) -> str:
    """Derive a stable operation authority from attempt + fixed action."""
    return derive_c_live_uuid(
        C_LIVE_OPERATION_DOMAIN,
        (
            ("attempt_id", attempt_id),
            ("action", action),
            ("ordinal", ordinal),
        ),
    )


def canonical_intent_digest(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("C-LIVE intent must be canonical JSON") from exc
    return hashlib.sha256(b"ares.c-live.v1.intent\x00" + encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RevalidatedPrincipalV1:
    """Point-in-time bearer authority returned by the route revalidator."""

    principal: TrustedPrincipal
    authority_revision: int
    role: str


class DispatchDispositionV1(str, Enum):
    TERMINAL = "terminal"
    REPLAYED = "replayed"
    NON_DISPATCHABLE = "non_dispatchable"
    CONFLICT = "conflict"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class DispatchRequestV1:
    campaign_id: str
    module_id: str
    ingress_code: str
    idempotency_key: str
    raw_parameters: Mapping[str, Any]
    whole_intent_digest: str
    occurrence: int = 0
    stage_ordinal: int = 0
    decision_ordinal: int = 0
    module_ordinal: int = 0
    credential_ids: tuple[str, ...] = ()
    approval_ref: str | None = None
    noise_units: int = 0
    exfiltration_units: int = 0
    timeout_seconds: int = 120
    skip_validation: bool = False


@dataclass(frozen=True, slots=True)
class DispatchIdentityV1:
    submission_id: str
    logical_execution_id: str
    attempt_id: str
    admission_operation_id: str
    queue_operation_id: str
    dispatch_operation_id: str
    start_operation_id: str
    owner_ref: str


@dataclass(frozen=True, slots=True)
class DispatchOutcomeV1:
    disposition: DispatchDispositionV1
    identity: DispatchIdentityV1 | None
    lifecycle_result: FixedResult
    revision: int | None
    module_result: Any = None
    effect_started: bool = False
    terminal_committed: bool = False


class _LifecycleStoreV1(Protocol):
    async def create_initial_execution_v3(
        self, principal: TrustedPrincipal, intent: AdmissionIntentV3
    ) -> OperationResult: ...

    async def create_retry_attempt_v3(
        self, principal: TrustedPrincipal, intent: RetryIntentV3
    ) -> OperationResult: ...

    async def transition_attempt(self, request: TransitionRequest) -> OperationResult: ...

    async def enter_settlement_pending(self, request: TransitionRequest) -> OperationResult: ...

    async def commit_terminal_attempt_v3(
        self, intent: TerminalCommitIntentV3
    ) -> OperationResult: ...


RevalidateCallbackV1 = Callable[
    [TrustedPrincipal, str, str],
    RevalidatedPrincipalV1 | None | Awaitable[RevalidatedPrincipalV1 | None],
]


def _seal_signature(parts: tuple[str, ...]) -> str:
    value = "\x00".join(parts).encode("utf-8")
    return hmac.new(_PROCESS_SEAL_KEY, value, hashlib.sha256).hexdigest()


class AdmittedDispatchContextV1:
    """Coordinator-issued, process-local, single-use RUNNING capability."""

    __slots__ = (
        "campaign_id",
        "submission_id",
        "logical_execution_id",
        "attempt_id",
        "module_id",
        "attempt_revision",
        "_consumer_id",
        "_store_id",
        "_dispatch_nonce",
        "_signature",
        "_consumed",
        "_effect_started",
        "_settlement_proof",
        "_terminal_committed",
        "_finalized",
    )

    def __init__(
        self,
        *,
        campaign_id: str,
        submission_id: str,
        logical_execution_id: str,
        attempt_id: str,
        module_id: str,
        attempt_revision: int,
        consumer: object,
        store: object,
        _issuer: object,
    ) -> None:
        if _issuer is not _ISSUER:
            raise TypeError("dispatch contexts are coordinator-created only")
        self.campaign_id = campaign_id
        self.submission_id = submission_id
        self.logical_execution_id = logical_execution_id
        self.attempt_id = attempt_id
        self.module_id = module_id
        self.attempt_revision = attempt_revision
        self._consumer_id = id(consumer)
        self._store_id = id(store)
        self._dispatch_nonce = secrets.token_hex(32)
        self._consumed = False
        self._effect_started = False
        self._settlement_proof = "none"
        self._terminal_committed = False
        self._finalized = False
        self._signature = _seal_signature(self._parts())
        register = getattr(consumer, "_register_admitted_dispatch_context", None)
        if callable(register):
            register(self)

    def _parts(self) -> tuple[str, ...]:
        return (
            self.campaign_id,
            self.submission_id,
            self.logical_execution_id,
            self.attempt_id,
            self.module_id,
            str(self.attempt_revision),
            str(self._consumer_id),
            str(self._store_id),
            self._dispatch_nonce,
        )

    def __repr__(self) -> str:
        return "<AdmittedDispatchContextV1 sealed>"

    def __reduce__(self) -> Any:
        raise TypeError("dispatch contexts are not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("dispatch contexts are not serializable")


class AdmittedPlanContextV1:
    """Single-use whole-plan seal containing an ordered child capability tuple."""

    __slots__ = (
        "campaign_id",
        "whole_intent_digest",
        "children",
        "_consumer_id",
        "_signature",
        "_consumed",
    )

    def __init__(
        self,
        *,
        campaign_id: str,
        whole_intent_digest: str,
        children: tuple[AdmittedDispatchContextV1, ...],
        consumer: object,
        _issuer: object,
    ) -> None:
        if _issuer is not _ISSUER:
            raise TypeError("plan contexts are coordinator-created only")
        self.campaign_id = campaign_id
        self.whole_intent_digest = whole_intent_digest
        self.children = children
        self._consumer_id = id(consumer)
        self._consumed = False
        self._signature = _seal_signature(
            (
                campaign_id,
                whole_intent_digest,
                str(self._consumer_id),
                *(child._signature for child in children),
            )
        )

    def __repr__(self) -> str:
        return "<AdmittedPlanContextV1 sealed>"

    def __reduce__(self) -> Any:
        raise TypeError("plan contexts are not serializable")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("plan contexts are not serializable")


def consume_dispatch_context(
    context: object,
    *,
    consumer: object,
    campaign_id: str,
    module_id: str,
) -> AdmittedDispatchContextV1:
    """Validate and consume a sealed capability before any module code runs."""
    if type(context) is not AdmittedDispatchContextV1:
        raise PermissionError("live module execution requires a sealed admission context")
    try:
        registry_consumer = getattr(consumer, "_consume_registered_dispatch_context", None)
        registration_valid = callable(registry_consumer) and registry_consumer(context)
        valid = (
            registration_valid
            and hmac.compare_digest(context._signature, _seal_signature(context._parts()))
            and context._consumer_id == id(consumer)
            and context.campaign_id == campaign_id
            and context.module_id == module_id
            and context.attempt_revision == 3
            and not context._consumed
        )
    except (AttributeError, TypeError, ValueError):
        valid = False
    if not valid:
        raise PermissionError("dispatch context is stale, transferred, fabricated, or already used")
    context._consumed = True
    return context


def mark_effect_started(context: AdmittedDispatchContextV1) -> None:
    if type(context) is not AdmittedDispatchContextV1 or not context._consumed:
        raise PermissionError("effect boundary requires a consumed dispatch context")
    context._effect_started = True


def mark_terminal_committed(context: AdmittedDispatchContextV1) -> None:
    if type(context) is not AdmittedDispatchContextV1 or not context._consumed:
        raise PermissionError("terminal commit requires a consumed dispatch context")
    context._terminal_committed = True


def consume_terminal_commit_context(
    context: object,
    *,
    consumer: object,
    campaign_id: str,
    module_id: str,
) -> AdmittedDispatchContextV1:
    if type(context) is not AdmittedDispatchContextV1:
        raise PermissionError("committed result publication requires a sealed context")
    valid = (
        hmac.compare_digest(context._signature, _seal_signature(context._parts()))
        and context._consumer_id == id(consumer)
        and context.campaign_id == campaign_id
        and context.module_id == module_id
        and context._consumed
        and context._terminal_committed
        and not context._finalized
    )
    if not valid:
        raise PermissionError("terminal context is stale, transferred, or not committed")
    context._finalized = True
    return context


def dispatch_effect_started(context: AdmittedDispatchContextV1) -> bool:
    return type(context) is AdmittedDispatchContextV1 and bool(context._effect_started)


def _mark_test_settlement_proof(
    context: AdmittedDispatchContextV1,
    proof: str,
) -> None:
    """Private proof seam; production engine timeouts never call this helper."""
    if (
        type(context) is not AdmittedDispatchContextV1
        or not context._consumed
        or proof not in {"cancellation_no_result_ack", "timeout_termination_ack"}
    ):
        raise PermissionError("invalid settlement proof")
    context._settlement_proof = proof


def _settlement_proof(context: AdmittedDispatchContextV1) -> str:
    if type(context) is not AdmittedDispatchContextV1 or not context._consumed:
        return "none"
    return context._settlement_proof


def consume_plan_context(
    context: object,
    *,
    consumer: object,
    campaign_id: str,
    module_ids: tuple[str, ...],
) -> tuple[AdmittedDispatchContextV1, ...]:
    if type(context) is not AdmittedPlanContextV1:
        raise PermissionError("live plan execution requires a sealed plan context")
    was_consumed = context._consumed
    context._consumed = True
    valid = not (
        was_consumed
        or context._consumer_id != id(consumer)
        or context.campaign_id != campaign_id
        or tuple(child.module_id for child in context.children) != module_ids
        or not hmac.compare_digest(
            context._signature,
            _seal_signature(
                (
                    context.campaign_id,
                    context.whole_intent_digest,
                    str(context._consumer_id),
                    *(child._signature for child in context.children),
                )
            ),
        )
    )
    if not valid:
        registry_consumer = getattr(consumer, "_consume_registered_dispatch_context", None)
        if callable(registry_consumer):
            for child in context.children:
                try:
                    registry_consumer(child)
                    child._consumed = True
                except (AttributeError, TypeError, ValueError):
                    pass
        raise PermissionError("plan context is stale, transferred, or already used")
    return context.children


def _issue_dispatch_context(
    *,
    consumer: object,
    store: object,
    identity: DispatchIdentityV1,
    campaign_id: str,
    module_id: str,
) -> AdmittedDispatchContextV1:
    return AdmittedDispatchContextV1(
        campaign_id=campaign_id,
        submission_id=identity.submission_id,
        logical_execution_id=identity.logical_execution_id,
        attempt_id=identity.attempt_id,
        module_id=module_id,
        attempt_revision=3,
        consumer=consumer,
        store=store,
        _issuer=_ISSUER,
    )


def _mint_test_dispatch_context(
    consumer: object,
    campaign_id: str,
    module_id: str,
    *,
    store: object | None = None,
    ordinal: int = 0,
) -> AdmittedDispatchContextV1:
    """Private test seam; production coordinators never call this shortcut."""
    store = store if store is not None else consumer
    idempotency_key = _uuid_from_digest(
        hashlib.sha256(f"test-idempotency:{ordinal}".encode("ascii")).hexdigest()
    )
    submission_id = derive_submission_id(campaign_id, "direct_engine", idempotency_key)
    logical_id = derive_logical_execution_id(campaign_id, submission_id)
    attempt_id = derive_attempt_id(logical_id, module_id, module_ordinal=ordinal)
    identity = DispatchIdentityV1(
        submission_id,
        logical_id,
        attempt_id,
        derive_operation_id(attempt_id, "admission"),
        derive_operation_id(attempt_id, "queue"),
        derive_operation_id(attempt_id, "dispatch"),
        derive_operation_id(attempt_id, "start"),
        derive_operation_id(attempt_id, "dispatch-owner"),
    )
    return _issue_dispatch_context(
        consumer=consumer,
        store=store,
        identity=identity,
        campaign_id=campaign_id,
        module_id=module_id,
    )


def _mint_test_plan_context(
    consumer: object,
    campaign_id: str,
    module_ids: tuple[str, ...],
) -> AdmittedPlanContextV1:
    children = tuple(
        _mint_test_dispatch_context(consumer, campaign_id, module_id, ordinal=ordinal)
        for ordinal, module_id in enumerate(module_ids)
    )
    return AdmittedPlanContextV1(
        campaign_id=campaign_id,
        whole_intent_digest=canonical_intent_digest(list(module_ids)),
        children=children,
        consumer=consumer,
        _issuer=_ISSUER,
    )


def _validate_request(request: DispatchRequestV1) -> bool:
    return (
        type(request) is DispatchRequestV1
        and valid_uuid(request.campaign_id)
        and type(request.module_id) is str
        and bool(request.module_id)
        and type(request.ingress_code) is str
        and type(request.idempotency_key) is str
        and valid_uuid(request.idempotency_key)
        and type(request.whole_intent_digest) is str
        and len(request.whole_intent_digest) == 64
        and request.whole_intent_digest == request.whole_intent_digest.lower()
        and all(character in "0123456789abcdef" for character in request.whole_intent_digest)
        and isinstance(request.raw_parameters, Mapping)
        and all(
            type(value) is int and 0 <= value <= 9_007_199_254_740_991
            for value in (
                request.occurrence,
                request.stage_ordinal,
                request.decision_ordinal,
                request.module_ordinal,
                request.noise_units,
                request.exfiltration_units,
            )
        )
        and type(request.timeout_seconds) is int
        and 1 <= request.timeout_seconds <= 86_400
        and type(request.skip_validation) is bool
    )


def _identity(request: DispatchRequestV1, *, parent_id: str | None = None) -> DispatchIdentityV1:
    root_submission_id = derive_submission_id(
        request.campaign_id, request.ingress_code, request.idempotency_key
    )
    attempt_domain = {
        "api_campaign_plan": C_LIVE_PLAN_CHILD_DOMAIN,
        "goal_api": C_LIVE_PLAN_CHILD_DOMAIN,
        "goal_cli": C_LIVE_PLAN_CHILD_DOMAIN,
        "cli_chain": C_LIVE_PLAN_CHILD_DOMAIN,
        "strategy": C_LIVE_STRATEGY_CHILD_DOMAIN,
    }.get(request.ingress_code, C_LIVE_ATTEMPT_DOMAIN)
    if parent_id is not None:
        attempt_domain = C_LIVE_RETRY_CHILD_DOMAIN
    submission_id = root_submission_id
    if attempt_domain in {C_LIVE_PLAN_CHILD_DOMAIN, C_LIVE_STRATEGY_CHILD_DOMAIN}:
        submission_id = derive_child_submission_id(
            root_submission_id,
            request.module_id,
            occurrence=request.occurrence,
            stage_ordinal=request.stage_ordinal,
            decision_ordinal=request.decision_ordinal,
            module_ordinal=request.module_ordinal,
            domain=attempt_domain,
        )
    logical_id = derive_logical_execution_id(
        request.campaign_id,
        submission_id,
        whole_intent_digest=(
            request.whole_intent_digest
            if attempt_domain in {C_LIVE_PLAN_CHILD_DOMAIN, C_LIVE_STRATEGY_CHILD_DOMAIN}
            else None
        ),
    )
    attempt_id = derive_attempt_id(
        parent_id or logical_id,
        request.module_id,
        occurrence=request.occurrence,
        stage_ordinal=request.stage_ordinal,
        decision_ordinal=request.decision_ordinal,
        module_ordinal=request.module_ordinal,
        domain=attempt_domain,
    )
    return DispatchIdentityV1(
        submission_id=submission_id,
        logical_execution_id=logical_id,
        attempt_id=attempt_id,
        admission_operation_id=derive_operation_id(attempt_id, "admission"),
        queue_operation_id=derive_operation_id(attempt_id, "queue"),
        dispatch_operation_id=derive_operation_id(attempt_id, "dispatch"),
        start_operation_id=derive_operation_id(attempt_id, "start"),
        owner_ref=derive_operation_id(attempt_id, "dispatch-owner"),
    )


async def _await_revalidation(
    callback: RevalidateCallbackV1,
    principal: TrustedPrincipal,
    campaign_id: str,
    module_id: str,
) -> RevalidatedPrincipalV1 | None:
    try:
        value = callback(principal, campaign_id, module_id)
        if inspect.isawaitable(value):
            value = await value
    except Exception:
        return None
    if (
        type(value) is not RevalidatedPrincipalV1
        or type(value.principal) is not TrustedPrincipal
        or value.principal.subject_ref != principal.subject_ref
        or value.principal.user_id != principal.user_id
        or type(value.authority_revision) is not int
        or not 0 <= value.authority_revision < 9_007_199_254_740_991
        or value.role not in {"operator", "team_lead"}
    ):
        return None
    return value


def _disposition(result: FixedResult) -> DispatchDispositionV1:
    if result in {
        FixedResult.REPLAYED,
        FixedResult.REPLAYED_BOUND_CHILD,
        FixedResult.REPLAYED_CLOSED,
    }:
        return DispatchDispositionV1.REPLAYED
    if result in {
        FixedResult.CONFLICT_OPERATION,
        FixedResult.CONFLICT_REVISION,
        FixedResult.CONFLICT_STATE,
        FixedResult.CONFLICT_OWNER,
        FixedResult.CONFLICT_GENERATION,
    }:
        return DispatchDispositionV1.CONFLICT
    return DispatchDispositionV1.NON_DISPATCHABLE


def _execution_result_digest(result: Any) -> str:
    if hasattr(result, "model_dump"):
        value = result.model_dump(mode="json")
    else:
        value = result
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(C_LIVE_RESULT_DOMAIN + encoded).hexdigest()


class ExecutionAdmissionCoordinatorV1:
    """At-most-once, fail-closed coordinator for one known module attempt."""

    def __init__(
        self,
        store: _LifecycleStoreV1,
        engine: AresEngine,
        revalidate: RevalidateCallbackV1,
        *,
        lease_duration_ms: int = 30_000,
    ) -> None:
        if type(lease_duration_ms) is not int or not 1_000 <= lease_duration_ms <= 86_400_000:
            raise ValueError("invalid C-LIVE lease duration")
        self._store = store
        self._engine = engine
        self._revalidate = revalidate
        self._lease_duration_ms = lease_duration_ms
        bind_store = getattr(engine, "_bind_admission_store", None)
        if not callable(bind_store):
            raise TypeError("engine does not implement the sealed admission boundary")
        bind_store(store)

    async def execute_module(
        self,
        principal: TrustedPrincipal,
        request: DispatchRequestV1,
        campaign: Campaign,
    ) -> DispatchOutcomeV1:
        if not _validate_request(request) or getattr(campaign, "id", None) != request.campaign_id:
            return DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                None,
                FixedResult.INVALID_CONTRACT,
                None,
            )
        identity = _identity(request)
        admission = await self._store.create_initial_execution_v3(
            principal,
            AdmissionIntentV3(
                logical_execution_id=identity.logical_execution_id,
                submission_id=identity.submission_id,
                attempt_id=identity.attempt_id,
                outbox_id=None,
                publication_key=None,
                campaign_id=request.campaign_id,
                module_id=request.module_id,
                ingress_code=request.ingress_code,
                operation_id=identity.admission_operation_id,
                evaluation_mode="live",
                raw_parameters=dict(request.raw_parameters),
                credential_ids=request.credential_ids,
                approval_ref=request.approval_ref,
                noise_units=request.noise_units,
                exfiltration_units=request.exfiltration_units,
            ),
        )
        if admission.result is not FixedResult.APPLIED or admission.revision != 0:
            return DispatchOutcomeV1(
                _disposition(admission.result), identity, admission.result, admission.revision
            )
        revalidated = await _await_revalidation(
            self._revalidate, principal, request.campaign_id, request.module_id
        )
        if revalidated is None:
            return DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                identity,
                FixedResult.AUTHORITY_STALE,
                0,
            )
        return await self._advance_and_execute(identity, request, campaign, revalidated)

    async def retry_module(
        self,
        principal: TrustedPrincipal,
        request: DispatchRequestV1,
        campaign: Campaign,
        *,
        logical_execution_id: str,
        parent_attempt_id: str,
        expected_parent_revision: int,
    ) -> DispatchOutcomeV1:
        """Create and own exactly one durable retry child; replay never dispatches."""
        if (
            not _validate_request(request)
            or getattr(campaign, "id", None) != request.campaign_id
            or not valid_uuid(logical_execution_id)
            or not valid_uuid(parent_attempt_id)
            or type(expected_parent_revision) is not int
            or not 0 <= expected_parent_revision < 9_007_199_254_740_991
        ):
            return DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                None,
                FixedResult.INVALID_CONTRACT,
                None,
            )
        identity = _identity(request, parent_id=parent_attempt_id)
        identity = DispatchIdentityV1(
            identity.submission_id,
            logical_execution_id,
            identity.attempt_id,
            derive_operation_id(identity.attempt_id, "retry-admission"),
            identity.queue_operation_id,
            identity.dispatch_operation_id,
            identity.start_operation_id,
            identity.owner_ref,
        )
        created = await self._store.create_retry_attempt_v3(
            principal,
            RetryIntentV3(
                logical_execution_id=logical_execution_id,
                parent_attempt_id=parent_attempt_id,
                child_attempt_id=identity.attempt_id,
                outbox_id=None,
                publication_key=None,
                operation_id=identity.admission_operation_id,
                expected_parent_revision=expected_parent_revision,
                evaluation_mode="live",
                raw_parameters=dict(request.raw_parameters),
                credential_ids=request.credential_ids,
                approval_ref=request.approval_ref,
                noise_units=request.noise_units,
                exfiltration_units=request.exfiltration_units,
            ),
        )
        if created.result is not FixedResult.APPLIED or created.revision != 0:
            return DispatchOutcomeV1(
                _disposition(created.result), identity, created.result, created.revision
            )
        revalidated = await _await_revalidation(
            self._revalidate, principal, request.campaign_id, request.module_id
        )
        if revalidated is None:
            return DispatchOutcomeV1(
                DispatchDispositionV1.NON_DISPATCHABLE,
                identity,
                FixedResult.AUTHORITY_STALE,
                0,
            )
        return await self._advance_and_execute(identity, request, campaign, revalidated)

    async def _advance_and_execute(
        self,
        identity: DispatchIdentityV1,
        request: DispatchRequestV1,
        campaign: Campaign,
        revalidated: RevalidatedPrincipalV1,
    ) -> DispatchOutcomeV1:
        queue = await self._store.transition_attempt(
            TransitionRequest(
                identity.attempt_id,
                0,
                AttemptState.QUEUED,
                identity.queue_operation_id,
                campaign_id=request.campaign_id,
                actor_subject_ref=revalidated.principal.subject_ref,
                actor_user_id=revalidated.principal.user_id,
                actor_authority_revision=revalidated.authority_revision,
            )
        )
        if queue.result is not FixedResult.APPLIED or queue.revision != 1:
            return DispatchOutcomeV1(
                _disposition(queue.result), identity, queue.result, queue.revision
            )
        dispatch = await self._store.transition_attempt(
            TransitionRequest(
                identity.attempt_id,
                1,
                AttemptState.DISPATCHING,
                identity.dispatch_operation_id,
                owner_ref=identity.owner_ref,
                lease_generation=1,
                lease_duration_ms=self._lease_duration_ms,
                campaign_id=request.campaign_id,
            )
        )
        if dispatch.result is not FixedResult.APPLIED or dispatch.revision != 2:
            return DispatchOutcomeV1(
                _disposition(dispatch.result), identity, dispatch.result, dispatch.revision
            )
        running = await self._store.transition_attempt(
            TransitionRequest(
                identity.attempt_id,
                2,
                AttemptState.RUNNING,
                identity.start_operation_id,
                owner_ref=identity.owner_ref,
                lease_generation=1,
                campaign_id=request.campaign_id,
            )
        )
        if running.result is not FixedResult.APPLIED or running.revision != 3:
            return DispatchOutcomeV1(
                _disposition(running.result), identity, running.result, running.revision
            )

        context = _issue_dispatch_context(
            consumer=self._engine,
            store=self._store,
            identity=identity,
            campaign_id=request.campaign_id,
            module_id=request.module_id,
        )
        try:
            module_result = await self._engine.run_module(
                request.module_id,
                campaign,
                dict(request.raw_parameters),
                skip_validation=request.skip_validation,
                timeout_seconds=request.timeout_seconds,
                actor_role=revalidated.role,
                dispatch_context=context,
            )
        except asyncio.CancelledError:
            await self._park_uncertain_after_cancellation(identity, request, context)
            raise
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return await self._park_uncertain(identity, request, context)

        from ares.core.engine import ModuleStatus

        proof = _settlement_proof(context)
        if module_result.status is ModuleStatus.CANCELLED and proof != "cancellation_no_result_ack":
            return await self._park_uncertain(
                identity, request, context, module_result=module_result
            )
        if module_result.status is ModuleStatus.TIMEOUT and proof != "timeout_termination_ack":
            return await self._park_uncertain(
                identity, request, context, module_result=module_result
            )
        if module_result.status is ModuleStatus.CANCELLED:
            cancelling = await self._store.transition_attempt(
                TransitionRequest(
                    identity.attempt_id,
                    3,
                    AttemptState.CANCELLING,
                    derive_operation_id(identity.attempt_id, "cancel-request"),
                    owner_ref=identity.owner_ref,
                    lease_generation=1,
                    campaign_id=request.campaign_id,
                )
            )
            if cancelling.result is not FixedResult.APPLIED or cancelling.revision != 4:
                return await self._park_uncertain(
                    identity, request, context, module_result=module_result
                )
            outcome = OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT
            result_digest = None
            terminal_revision = 4
        elif module_result.status is ModuleStatus.TIMEOUT:
            outcome = OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED
            result_digest = None
            terminal_revision = 3
        elif module_result.status is ModuleStatus.DONE:
            outcome = OutcomeCode.CONFIRMED_SUCCESS
            result_digest = _execution_result_digest(module_result)
            terminal_revision = 3
        else:
            outcome = OutcomeCode.CONFIRMED_FAILURE
            result_digest = _execution_result_digest(module_result)
            terminal_revision = 3

        try:
            terminal = await self._store.commit_terminal_attempt_v3(
                TerminalCommitIntentV3(
                    logical_execution_id=identity.logical_execution_id,
                    campaign_id=request.campaign_id,
                    attempt_id=identity.attempt_id,
                    expected_attempt_revision=terminal_revision,
                    outcome_code=outcome,
                    noise_actual=0,
                    exfiltration_actual=0,
                    concurrency_actual=0,
                    execution_result_digest=result_digest,
                    outputs=(),
                )
            )
        except asyncio.CancelledError:
            await self._park_uncertain_after_cancellation(
                identity,
                request,
                context,
                module_result=module_result,
                expected_revision=terminal_revision,
            )
            raise
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return await self._park_uncertain(
                identity,
                request,
                context,
                module_result=module_result,
                expected_revision=terminal_revision,
            )
        if terminal.result is FixedResult.APPLIED and terminal.revision != terminal_revision + 1:
            return await self._park_uncertain(
                identity,
                request,
                context,
                module_result=module_result,
                expected_revision=terminal_revision,
                fallback_result=OperationResult(
                    FixedResult.INVARIANT_FAILURE, terminal.revision
                ),
                result_override=OperationResult(
                    FixedResult.INVARIANT_FAILURE, terminal.revision
                ),
            )
        if terminal.result is not FixedResult.APPLIED:
            return await self._park_uncertain(
                identity,
                request,
                context,
                module_result=module_result,
                expected_revision=terminal_revision,
                fallback_result=terminal,
            )
        mark_terminal_committed(context)
        committed = await self._engine._finalize_committed_module_result(
            campaign, request.module_id, module_result, context
        )
        return DispatchOutcomeV1(
            DispatchDispositionV1.TERMINAL,
            identity,
            terminal.result,
            terminal.revision,
            committed,
            dispatch_effect_started(context),
            True,
        )

    async def _park_uncertain_after_cancellation(
        self,
        identity: DispatchIdentityV1,
        request: DispatchRequestV1,
        context: AdmittedDispatchContextV1,
        *,
        module_result: Any = None,
        expected_revision: int = 3,
    ) -> None:
        """Bound and own settlement parking before propagating task cancellation."""
        parking = asyncio.create_task(
            self._park_uncertain(
                identity,
                request,
                context,
                module_result=module_result,
                expected_revision=expected_revision,
            ),
            name=f"c-live-settlement-pending-{identity.attempt_id}",
        )
        try:
            await asyncio.wait_for(asyncio.shield(parking), timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            parking.cancel()
            try:
                await parking
            except BaseException:
                pass
        except Exception:
            # The original cancellation remains authoritative.  Parking is a
            # best-effort bounded safety write and never becomes an HTTP result.
            pass

    async def _park_uncertain(
        self,
        identity: DispatchIdentityV1,
        request: DispatchRequestV1,
        context: AdmittedDispatchContextV1,
        *,
        module_result: Any = None,
        expected_revision: int = 3,
        fallback_result: OperationResult | None = None,
        result_override: OperationResult | None = None,
    ) -> DispatchOutcomeV1:
        operation_id = derive_operation_id(identity.attempt_id, "settlement-pending")
        outbox_id = derive_operation_id(identity.attempt_id, "settlement-pending-outbox")
        publication_key = derive_operation_id(identity.attempt_id, "settlement-pending-publication")
        try:
            parked = await self._store.enter_settlement_pending(
                TransitionRequest(
                    identity.attempt_id,
                    expected_revision,
                    AttemptState.SETTLEMENT_PENDING,
                    operation_id,
                    owner_ref=identity.owner_ref,
                    lease_generation=1,
                    cancellation_request_revision=(
                        expected_revision if expected_revision == 4 else None
                    ),
                    authoritative_proof="unresolved",
                    outbox_id=outbox_id,
                    publication_key=publication_key,
                    campaign_id=request.campaign_id,
                )
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError):
            raise
        except Exception:
            parked = (
                fallback_result
                if fallback_result is not None
                else OperationResult(FixedResult.INVARIANT_FAILURE, None)
            )
        if parked.result is not FixedResult.APPLIED and fallback_result is not None:
            parked = fallback_result
        reported = result_override if result_override is not None else parked
        return DispatchOutcomeV1(
            DispatchDispositionV1.INDETERMINATE,
            identity,
            reported.result,
            reported.revision,
            module_result,
            dispatch_effect_started(context),
            False,
        )


__all__ = [
    "AdmittedDispatchContextV1",
    "AdmittedPlanContextV1",
    "C_LIVE_ATTEMPT_DOMAIN",
    "C_LIVE_LOGICAL_DOMAIN",
    "C_LIVE_OPERATION_DOMAIN",
    "C_LIVE_PLAN_CHILD_DOMAIN",
    "C_LIVE_RETRY_CHILD_DOMAIN",
    "C_LIVE_STRATEGY_CHILD_DOMAIN",
    "C_LIVE_SUBMISSION_DOMAIN",
    "DispatchDispositionV1",
    "DispatchIdentityV1",
    "DispatchOutcomeV1",
    "DispatchRequestV1",
    "ExecutionAdmissionCoordinatorV1",
    "RevalidatedPrincipalV1",
    "canonical_intent_digest",
    "derive_attempt_id",
    "derive_child_submission_id",
    "derive_c_live_uuid",
    "derive_logical_execution_id",
    "derive_operation_id",
    "derive_submission_id",
]
