"""Deterministic SQLite contract tests for revision-0010 lifecycle storage."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass, replace
from typing import Any, get_type_hints

import aiosqlite
import pytest

import ares.modules.descriptors as descriptor_module
from ares.core.capabilities import Capability
from ares.db.database import AresDatabase
from ares.db.execution_lifecycle import (
    ACTOR_ROLES,
    CAPABILITY_BITS_V1,
    DESCRIPTOR_BLOCKER_BITS_V1,
    LIFECYCLE_TABLES,
    MAX_I53,
    OUTBOX_LEASE_MS,
    SYSTEM_PRINCIPAL_SUBJECT_REF,
    ActorAuthorityMutation,
    AdmissionIntentV3,
    AdmissionRequest,
    ApprovalAuthorityGrant,
    ApprovalAuthorityMutation,
    AttemptPolicySnapshot,
    AttemptState,
    BudgetConfiguration,
    BudgetReservation,
    BudgetSettlement,
    CampaignActorGrantMutation,
    CampaignAuthorityMutation,
    ClosureRequest,
    CredentialAuthorityMutation,
    DestinationAuthorityMutation,
    ExecutionLifecycleStore,
    FixedResult,
    GatewayAuthorityMutation,
    OperationResult,
    OutboxMutation,
    OutcomeCode,
    OutputKind,
    OutputObservation,
    PolicyReasonBit,
    RetryIntentV3,
    RetryRequest,
    TerminalCommitIntentV3,
    TerminalCommitRequest,
    TransitionRequest,
    TrustedPrincipal,
    _AbortOperationError,
    canonical_operation_binding_digest,
    retry_delay_ms,
    valid_uuid,
    validate_sqlite_lifecycle_catalog,
)
from ares.db.schema import CREATE_TABLES, SCHEMA_VERSION
from ares.modules.descriptors import (
    CancellationOwnership,
    CompensationClass,
    ContractState,
    DestinationCardinality,
    DestinationKind,
    DestinationSpec,
    ExternalEffectClass,
    IdempotencyClass,
    MinimumRole,
    ModuleDescriptor,
    OpsecClassification,
    ResultContract,
    RetryEligibility,
    ScopeSemantics,
    TimeoutPolicy,
    TimeoutSettlement,
)

_UUIDS = (
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "00000000-0000-4000-8000-000000000003",
    "00000000-0000-4000-8000-000000000004",
    "00000000-0000-4000-8000-000000000005",
    "00000000-0000-4000-8000-000000000006",
    "00000000-0000-4000-8000-000000000007",
    "00000000-0000-4000-8000-000000000008",
)

_STATE_VALUES = (
    "rejected",
    "blocked",
    "accepted",
    "queued",
    "dispatching",
    "running",
    "cancelling",
    "settlement_pending",
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "cancelled",
    "timed_out",
    "indeterminate",
)

_EXPECTED_LEGAL = frozenset(
    {
        ("accepted", "queued"),
        ("accepted", "dispatching"),
        ("accepted", "cancelling"),
        ("accepted", "skipped"),
        ("accepted", "failed"),
        ("queued", "dispatching"),
        ("queued", "cancelling"),
        ("queued", "skipped"),
        ("queued", "failed"),
        ("dispatching", "running"),
        ("dispatching", "cancelling"),
        ("dispatching", "failed"),
        ("dispatching", "settlement_pending"),
        ("running", "cancelling"),
        ("running", "succeeded"),
        ("running", "partial"),
        ("running", "failed"),
        ("running", "timed_out"),
        ("running", "settlement_pending"),
        ("cancelling", "succeeded"),
        ("cancelling", "partial"),
        ("cancelling", "failed"),
        ("cancelling", "cancelled"),
        ("cancelling", "timed_out"),
        ("cancelling", "settlement_pending"),
        ("settlement_pending", "succeeded"),
        ("settlement_pending", "partial"),
        ("settlement_pending", "failed"),
        ("settlement_pending", "cancelled"),
        ("settlement_pending", "timed_out"),
        ("settlement_pending", "indeterminate"),
    }
)

_ALL_ORDERED_PAIRS = tuple((source, target) for source in _STATE_VALUES for target in _STATE_VALUES)
_ILLEGAL = tuple(pair for pair in _ALL_ORDERED_PAIRS if pair not in _EXPECTED_LEGAL)


@pytest.mark.parametrize(
    ("source", "target"),
    tuple(sorted(_EXPECTED_LEGAL)),
    ids=lambda value: value,
)
@pytest.mark.asyncio
async def test_each_legal_transition_is_frozen(tmp_path, source: str, target: str) -> None:
    result, before, after, observer = await _exercise_transition_pair(
        tmp_path / f"legal-{source}-{target}.db", source, target
    )
    assert result is FixedResult.APPLIED, "legal persistence transition failed"
    assert after != before, "legal persistence transition did not mutate"
    assert observer == after, "legal transition was not durably observable"


@pytest.mark.parametrize(
    ("source", "target"),
    _ILLEGAL,
    ids=lambda value: value,
)
@pytest.mark.asyncio
async def test_each_illegal_transition_is_rejected(tmp_path, source: str, target: str) -> None:
    result, before, after, observer = await _exercise_transition_pair(
        tmp_path / f"illegal-{source}-{target}.db", source, target
    )
    assert result is not FixedResult.APPLIED, "illegal persistence transition applied"
    assert after == before, "illegal persistence transition mutated state"
    assert observer == before, "illegal transition leaked a committed mutation"


def test_transition_matrix_has_exact_recomputed_totals() -> None:
    assert len(_EXPECTED_LEGAL) == 31, "legal transition total changed"
    assert len(_ILLEGAL) == 194, "illegal transition total changed"
    assert len(_ALL_ORDERED_PAIRS) == 225, "state matrix total changed"


def test_self_transitions_are_never_legal() -> None:
    assert all((state, state) in _ILLEGAL for state in _STATE_VALUES), "self transition accepted"


def test_runtime_catalog_has_exact_eleven_tables_and_disabled_gateway() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(CREATE_TABLES)
        validate_sqlite_lifecycle_catalog(connection)
        rows = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' "
            "AND name IN (?,?,?,?,?,?,?,?,?,?,?) ORDER BY name",
            LIFECYCLE_TABLES,
        ).fetchall()
        gateway = connection.execute(
            "SELECT mode,revision,catalog_digest,activation_revision,activation_at "
            "FROM execution_gateway_state"
        ).fetchall()
    finally:
        connection.close()
    assert tuple(row[0] for row in rows) == tuple(sorted(LIFECYCLE_TABLES)), (
        "lifecycle table inventory changed"
    )
    assert gateway == [("disabled", 0, None, None, None)], "gateway bootstrap changed"
    assert SCHEMA_VERSION == 9, "legacy schema marker changed"


def _independent_binding_digest(
    domain: str, values: tuple[tuple[str, str | int | bool | None], ...]
) -> str:
    import struct

    encoded = bytearray(b"ares.execution-operation-binding.v2\x00")

    def frame(value: bytes) -> None:
        encoded.extend(struct.pack(">I", len(value)))
        encoded.extend(value)

    frame(domain.encode("ascii"))
    for name, value in values:
        frame(name.encode("ascii"))
        if value is None:
            encoded.extend(b"n")
        elif type(value) is bool:
            encoded.extend(b"b\x01" if value else b"b\x00")
        elif type(value) is int:
            encoded.extend(b"i")
            frame(value.to_bytes(8, "big"))
        else:
            encoded.extend(b"s")
            frame(value.encode("utf-8"))
    return hashlib.sha256(encoded).hexdigest()


def test_operation_binding_uses_independent_typed_length_framing() -> None:
    fields = (("alpha", "value"), ("beta", 7), ("gamma", True), ("delta", None))
    expected = "ef0eb625d5c662f1f1b30a1e72facc1871aa242627ccd7756f706eecc4b6401d"
    assert _independent_binding_digest("test.operation", fields) == expected, (
        "independent operation binding oracle changed"
    )
    assert canonical_operation_binding_digest("test.operation", fields) == expected, (
        "operation binding canonicalization changed"
    )


@pytest.mark.asyncio
async def test_authority_receipt_replay_is_stable_after_later_revision() -> None:
    connection = await _new_connection()
    try:
        await connection.executemany(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (
                (_uuid(900), "receipt-a", "fixed-hash", "admin", "fixed"),
                (_uuid(901), "receipt-b", "fixed-hash", "admin", "fixed"),
            ),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        applied = await store.ensure_actor_authority(_uuid(900), _uuid(902))
        replayed = await store.ensure_actor_authority(_uuid(900), _uuid(902))
        conflicted = await store.ensure_actor_authority(_uuid(901), _uuid(902))
        invalidated = await store.invalidate_actor_authority(_uuid(900), 0, _uuid(903))
        replayed_after_revision = await store.ensure_actor_authority(_uuid(900), _uuid(902))
        counts = await (
            await connection.execute(
                "SELECT (SELECT count(*) FROM execution_actor_authority_revisions),"
                "(SELECT count(*) FROM execution_operation_receipts)"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert (
        applied.result,
        replayed.result,
        conflicted.result,
        invalidated.result,
        replayed_after_revision.result,
    ) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
        FixedResult.CONFLICT_OPERATION,
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
    ), "authority receipt classification changed"
    assert tuple(counts) == (1, 2), "authority receipt cardinality changed"


@pytest.mark.asyncio
async def test_receipt_failure_rolls_back_domain_mutation(monkeypatch) -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(910), "receipt-rollback", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")

        async def fail_receipt(*_args, **_kwargs) -> None:
            raise RuntimeError("fixed-receipt-failure")

        monkeypatch.setattr(store, "_insert_receipt", fail_receipt)
        with pytest.raises(RuntimeError, match="fixed-receipt-failure"):
            await store.ensure_actor_authority(_uuid(910), _uuid(911))
        counts = await (
            await connection.execute(
                "SELECT (SELECT count(*) FROM execution_actor_authority_revisions),"
                "(SELECT count(*) FROM execution_operation_receipts)"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert tuple(counts) == (0, 0), "receipt failure split the atomic mutation"


@pytest.mark.asyncio
async def test_forced_zero_row_cas_never_reports_applied(monkeypatch) -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(920), "zero-row", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        assert (
            await store.ensure_actor_authority(_uuid(920), _uuid(921))
        ).result is FixedResult.APPLIED, "zero-row authority setup failed"

        async def zero_rows(*_args, **_kwargs):
            return ()

        monkeypatch.setattr(store, "_returning_rows", zero_rows)
        result = await store.invalidate_actor_authority(_uuid(920), 0, _uuid(922))
        row = await (
            await connection.execute(
                "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=?",
                (_uuid(920),),
            )
        ).fetchone()
    finally:
        await connection.close()
    assert result.result is FixedResult.CONFLICT_REVISION, "zero-row CAS reported success"
    assert int(row[0]) == 0, "zero-row CAS mutated authority"


@pytest.mark.asyncio
async def test_unexpected_returning_set_rolls_back_and_fails_fixed(monkeypatch) -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(930), "returning-set", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        assert (
            await store.ensure_actor_authority(_uuid(930), _uuid(931))
        ).result is FixedResult.APPLIED, "returning-set authority setup failed"
        original = store._returning_rows

        async def duplicate_rows(*args, **kwargs):
            rows = await original(*args, **kwargs)
            return rows + rows

        monkeypatch.setattr(store, "_returning_rows", duplicate_rows)
        result = await store.invalidate_actor_authority(_uuid(930), 0, _uuid(932))
        row = await (
            await connection.execute(
                "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=?",
                (_uuid(930),),
            )
        ).fetchone()
        receipt = await (
            await connection.execute(
                "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                (_uuid(932),),
            )
        ).fetchone()
    finally:
        await connection.close()
    assert result.result is FixedResult.INVARIANT_FAILURE, "returned-set mismatch was accepted"
    assert (int(row[0]), int(receipt[0])) == (0, 0), "returned-set mismatch split atomic state"


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("00000000-0000-4000-8000-000000000001", True),
        ("00000000-0000-5000-8000-000000000001", False),
        ("00000000-0000-4000-7000-000000000001", False),
        ("00000000-0000-4000-8000-00000000000A", False),
        (True, False),
        (1, False),
        (None, False),
    ],
    ids=("valid", "wrong-version", "wrong-variant", "uppercase", "bool", "int", "none"),
)
def test_uuid_contract_is_exact(value: object, accepted: bool) -> None:
    assert valid_uuid(value) is accepted, "UUID contract changed"


def test_stable_mask_allocations_are_literal() -> None:
    assert CAPABILITY_BITS_V1 == {
        "network": 1,
        "execution": 2,
        "filesystem": 4,
        "process": 8,
    }, "capability allocation changed"
    assert DESCRIPTOR_BLOCKER_BITS_V1 == {
        "ambient_credentials_forbidden": 1,
        "cancellation_ownership_unproven": 2,
        "dynamic_destination_unbounded": 4,
        "default_factory_unevaluated": 8,
        "llm_egress_policy_required": 16,
        "lifecycle_contract_unproven": 32,
        "raw_credential_input": 64,
        "result_authority_unproven": 128,
        "sensitive_nonempty_default": 256,
    }, "descriptor blocker allocation changed"
    assert {member.name: member.value for member in PolicyReasonBit} == {
        "INVALID_CONTRACT": 1,
        "INCONSISTENT_CONTRACT": 2,
        "INVALID_REQUEST": 4,
        "DESCRIPTOR_UNTRUSTED": 8,
        "DESCRIPTOR_BINDING_INVALID": 16,
        "DESCRIPTOR_INCOMPLETE": 32,
        "STATIC_POLICY_UNAVAILABLE": 64,
        "AUTHORITY_RESOLUTION_REQUIRED": 128,
        "STALE_AUTHORITY": 256,
        "ACTOR_UNAUTHENTICATED": 512,
        "ACTOR_INACTIVE": 1_024,
        "CAMPAIGN_INACTIVE": 2_048,
        "CAMPAIGN_UNAUTHORIZED": 4_096,
        "INSUFFICIENT_ROLE": 8_192,
        "HIGH_NOISE_ROLE_REQUIRED": 16_384,
        "APPROVAL_REQUIRED": 32_768,
        "APPROVAL_STALE": 65_536,
        "APPROVAL_BINDING_INVALID": 131_072,
        "CAPABILITY_REQUIRED": 262_144,
        "DESTINATION_RESOLUTION_REQUIRED": 524_288,
        "DESTINATION_OUT_OF_SCOPE": 1_048_576,
        "CREDENTIAL_AUTHORITY_REQUIRED": 2_097_152,
        "CREDENTIAL_AUTHORITY_STALE": 4_194_304,
        "RAW_CREDENTIAL_FORBIDDEN": 8_388_608,
        "AMBIENT_CREDENTIAL_FORBIDDEN": 16_777_216,
        "CREDENTIAL_HANDLE_POLICY_VIOLATION": 33_554_432,
        "BUDGET_AUTHORITY_REQUIRED": 67_108_864,
        "BUDGET_AUTHORITY_STALE": 134_217_728,
        "BUDGET_CAPACITY_UNAVAILABLE": 268_435_456,
        "DESCRIPTOR_BLOCKED": 536_870_912,
        "PREVIEW_NOT_READY": 1_073_741_824,
        "LIFECYCLE_NOT_READY": 2_147_483_648,
        "RESULT_AUTHORITY_NOT_READY": 4_294_967_296,
        "TRANSPORT_NOT_READY": 8_589_934_592,
        "FUTURE_GATEWAY_INELIGIBLE": 17_179_869_184,
    }, "policy reason allocation changed"


@pytest.mark.parametrize(
    ("actor", "minimum", "satisfies"),
    tuple(
        (actor, minimum, actor_rank >= minimum_rank and actor != "reporter")
        for actor, actor_rank in (("reporter", 0), ("operator", 1), ("team_lead", 2), ("admin", 3))
        for minimum, minimum_rank in (("operator", 1), ("team_lead", 2), ("admin", 3))
    ),
    ids=lambda value: value,
)
@pytest.mark.asyncio
async def test_every_actor_minimum_role_pair(actor: str, minimum: str, satisfies: bool) -> None:
    persisted_state, result = await _persist_role_cell(actor, minimum, satisfies)
    assert result is FixedResult.APPLIED, "role admission did not commit"
    assert persisted_state == ("accepted" if satisfies else "blocked"), (
        "role admission state changed"
    )
    assert actor in ACTOR_ROLES, "actor role domain changed"


@pytest.mark.parametrize(
    ("attempt", "delay"),
    tuple((attempt, min((1 << (attempt - 1)) * 1_000, 600_000)) for attempt in range(1, 20)),
    ids=lambda value: str(value),
)
def test_each_retry_delay_is_bounded(attempt: int, delay: int) -> None:
    assert retry_delay_ms(attempt) == delay, "outbox retry delay changed"


def test_public_operation_records_are_immutable_and_unhashable() -> None:
    request = TransitionRequest(
        _UUIDS[0],
        0,
        AttemptState.QUEUED,
        _UUIDS[1],
        campaign_id=_UUIDS[2],
        actor_subject_ref=_UUIDS[3],
        actor_user_id=_UUIDS[3],
        actor_authority_revision=0,
    )
    mutation = OutboxMutation(
        _UUIDS[2],
        0,
        _UUIDS[3],
        _UUIDS[4],
        0,
        _UUIDS[5],
        _UUIDS[6],
        _UUIDS[7],
        "execution_failed",
    )
    assert request.__hash__ is None, "transition request became hashable"
    assert mutation.__hash__ is None, "outbox mutation became hashable"
    assert tuple(field.name for field in fields(request)) == (
        "attempt_id",
        "expected_revision",
        "target_state",
        "operation_id",
        "owner_ref",
        "lease_generation",
        "lease_duration_ms",
        "cancellation_request_revision",
        "outcome_code",
        "authoritative_proof",
        "resolver_subject_ref",
        "resolver_user_id",
        "resolver_authority_revision",
        "outbox_id",
        "publication_key",
        "campaign_id",
        "actor_subject_ref",
        "actor_user_id",
        "actor_authority_revision",
    ), "transition request shape changed"


async def _new_connection(path: str = ":memory:") -> aiosqlite.Connection:
    connection = await aiosqlite.connect(path)
    connection.row_factory = aiosqlite.Row
    await connection.execute("PRAGMA foreign_keys=ON")
    await connection.executescript(CREATE_TABLES)
    return connection


def _uuid(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012x}"


_P1C_AUTHORITY_MUTATOR_ALIASES = (
    "gateway-update",
    "actor-activate",
    "actor-update",
    "actor-revoke",
    "campaign-activate",
    "campaign-update",
    "campaign-revoke",
    "grant-put",
    "grant-revoke",
    "destination-update",
    "destination-revoke",
    "credential-update",
    "credential-revoke",
    "approval-grant",
    "approval-revoke",
)

_P1C_INITIAL_AUTHORITY_ALIASES = (
    "new-v3-applied",
    "v3-exact-replay",
    "v3-logical-id-conflict",
    "v3-attempt-id-conflict",
    "v3-operation-id-conflict",
    "v3-module-id-conflict",
    "v3-ingress-conflict",
    "v3-trusted-principal-conflict",
    "v3-after-gateway-change",
    "v3-after-authority-deletion",
    "v2-exact-replay",
    "v2-changed-intent-conflict",
    "v2-after-gateway-change",
    "v2-after-authority-deletion",
    "new-v2-rejected",
    "v3-row-downgrade-rejected",
)

_P1C_UNTRUSTED_AUTHORITY_CLAIM_ALIASES = (
    "gateway-mode-claim",
    "gateway-revision-claim",
    "actor-user-claim",
    "actor-role-claim",
    "actor-revision-claim",
    "campaign-status-claim",
    "campaign-revision-claim",
    "campaign-owner-claim",
    "descriptor-authority-claim",
    "destination-authority-claim",
    "credential-authority-claim",
    "budget-authority-claim",
)

_P1C_AUTHORITY_DELETION_ALIASES = (
    "campaign-authority-cascade",
    "actor-authority-cascade",
    "destination-credential-authority-cascade",
    "snapshot-no-live-fk",
)

_P1C_PERSISTED_AUTHORITY_ALIASES = (
    "gateway-mode",
    "gateway-revision",
    "gateway-catalog-digest",
    "actor-identity",
    "actor-active",
    "actor-role",
    "actor-authority-revision",
    "campaign-status",
    "campaign-authority-revision",
    "campaign-ownership",
    "destination-extraction",
    "destination-campaign-scope",
    "destination-authority-revision",
    "credential-exists",
    "credential-ownership",
    "credential-authority-revision",
    "descriptor-module-identity",
    "descriptor-contract-version",
    "descriptor-semantic-digest",
    "policy-minimum-role",
    "policy-noise-class",
    "policy-required-capabilities",
    "policy-approval",
    "budget-authority-revisions",
    "budget-capacity",
)

_P1C_RETRY_AUTHORITY_ALIASES = (
    "v3-retry-applied",
    "v3-retry-exact-replay",
    "v3-retry-child-binding-conflict",
    "v3-retry-parent-revision-conflict",
    "v3-retry-after-authority-change",
    "v2-retry-exact-replay",
    "v2-retry-child-binding-conflict",
    "v2-retry-after-authority-change",
    "new-v2-retry-rejected",
    "v3-retry-downgrade-rejected",
)


async def _p1c_sqlite_authority_store(
    tmp_path: Any,
) -> tuple[
    AresDatabase,
    ExecutionLifecycleStore,
    TrustedPrincipal,
    str,
    str,
    str,
]:
    database = AresDatabase(tmp_path / "p1c-authority.db")
    await database.connect()
    principal_id = _uuid(12_000)
    actor_id = _uuid(12_001)
    campaign_id = _uuid(12_002)
    credential_id = _uuid(12_003)
    await database.conn.executemany(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (
            (principal_id, "p1c-admin", "fixed", "admin", "fixed"),
            (actor_id, "p1c-actor", "fixed", "operator", "fixed"),
        ),
    )
    await database.conn.execute(
        "INSERT INTO campaigns(id,name,operator,scope_json,targets_json) VALUES(?,?,?,?,?)",
        (campaign_id, "p1c-authority", "p1c-admin", "[]", '["host.example"]'),
    )
    await database.conn.execute(
        "INSERT INTO credentials(id,campaign_id,username,cred_type,source_module) "
        "VALUES(?,?,?,?,?)",
        (credential_id, campaign_id, "opaque-user", "cleartext", "p1c-fixture"),
    )
    await database.conn.commit()
    store = ExecutionLifecycleStore(database.conn, "sqlite")
    for user_id, operation in (
        (principal_id, _uuid(12_010)),
        (actor_id, _uuid(12_011)),
    ):
        assert (
            await store.ensure_actor_authority(user_id, operation)
        ).result is FixedResult.APPLIED
    assert (
        await store.ensure_campaign_authority(campaign_id, _uuid(12_012))
    ).result is FixedResult.APPLIED
    return (
        database,
        store,
        TrustedPrincipal(principal_id, principal_id),
        actor_id,
        campaign_id,
        credential_id,
    )


def _p1c_v3_intent(campaign_id: str) -> AdmissionIntentV3:
    return AdmissionIntentV3(
        logical_execution_id=_uuid(12_500),
        submission_id=_uuid(12_501),
        attempt_id=_uuid(12_502),
        outbox_id=None,
        publication_key=None,
        campaign_id=campaign_id,
        module_id="opsec.coverage_predictor",
        ingress_code="sdk",
        operation_id=_uuid(12_503),
        evaluation_mode="live",
        raw_parameters={"noise_profile": "stealth"},
    )


def _p1c_eligible_descriptor(monkeypatch: pytest.MonkeyPatch) -> ModuleDescriptor:
    source = descriptor_module.FIRST_PARTY_DESCRIPTORS["opsec.coverage_predictor"]
    values = {
        field.name: getattr(source, field.name) for field in fields(ModuleDescriptor) if field.init
    }
    values.update(
        idempotency=IdempotencyClass.PROVEN_IDEMPOTENT,
        external_effect=ExternalEffectClass.READ_ONLY,
        retry_eligibility=RetryEligibility.AFTER_REVALIDATION,
        cancellation_ownership=CancellationOwnership.OWNED,
        compensation=CompensationClass.NOT_APPLICABLE,
        timeout=TimeoutPolicy(
            source.timeout.seconds,
            source.timeout.source,
            TimeoutSettlement.PROVEN,
        ),
        result_contract=ResultContract(
            findings=ContractState.PROVEN_NONE,
            credentials=ContractState.PROVEN_NONE,
            discovered_hosts=ContractState.PROVEN_NONE,
            loot_artifacts=ContractState.PROVEN_NONE,
            authoritative_evidence=ContractState.SUPPORTED,
        ),
        blocker_codes=(),
        future_gateway_eligible=True,
    )
    descriptor = ModuleDescriptor(**values)
    descriptors = dict(descriptor_module.FIRST_PARTY_DESCRIPTORS)
    descriptors[descriptor.module_id] = descriptor
    monkeypatch.setattr(descriptor_module, "FIRST_PARTY_DESCRIPTORS", descriptors)
    return descriptor


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_UNTRUSTED_AUTHORITY_CLAIM_ALIASES,
    ids=_P1C_UNTRUSTED_AUTHORITY_CLAIM_ALIASES,
)
def test_admission_intent_rejects_each_untrusted_authority_claim(
    _case_alias: str,
) -> None:
    intent = _p1c_v3_intent(_uuid(12_002))
    claims: dict[str, object] = {
        "gateway-mode-claim": "enforced",
        "gateway-revision-claim": 7,
        "actor-user-claim": _uuid(12_900),
        "actor-role-claim": "admin",
        "actor-revision-claim": 7,
        "campaign-status-claim": "running",
        "campaign-revision-claim": 7,
        "campaign-owner-claim": _uuid(12_901),
        "descriptor-authority-claim": "a" * 64,
        "destination-authority-claim": "b" * 64,
        "credential-authority-claim": "c" * 64,
        "budget-authority-claim": 7,
    }
    field_name = _case_alias.removesuffix("-claim").replace("-", "_")
    with pytest.raises(TypeError):
        replace(intent, **{field_name: claims[_case_alias]})


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_AUTHORITY_DELETION_ALIASES,
    ids=_P1C_AUTHORITY_DELETION_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_authority_deletion_and_fk_contract(
    tmp_path, monkeypatch, _case_alias: str
) -> None:
    _p1c_eligible_descriptor(monkeypatch)
    (
        database,
        store,
        principal,
        actor_id,
        campaign_id,
        credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    try:
        grant_actor = principal.user_id if _case_alias == "snapshot-no-live-fk" else actor_id
        assert (
            await store.put_campaign_actor_grant(
                principal,
                CampaignActorGrantMutation(_uuid(12_950), campaign_id, grant_actor, None),
            )
        ).result is FixedResult.APPLIED
        if _case_alias == "campaign-authority-cascade":
            deleted = await database.delete_campaign_lifecycle(
                campaign_id,
                operation_id=_uuid(12_951),
            )
            observed = await (
                await database.conn.execute(
                    "SELECT "
                    "(SELECT count(*) FROM campaigns WHERE id=?),"
                    "(SELECT count(*) FROM campaign_execution_authority_revisions "
                    "WHERE campaign_id=?),"
                    "(SELECT count(*) FROM campaign_execution_actor_grants "
                    "WHERE campaign_id=?),"
                    "(SELECT count(*) FROM execution_operation_receipts "
                    "WHERE operation_id=?)",
                    (campaign_id, campaign_id, campaign_id, _uuid(12_951)),
                )
            ).fetchone()
            assert deleted.result is FixedResult.APPLIED, "campaign purge was rejected"
            assert tuple(observed) == (0, 0, 0, 1), (
                "campaign purge retained mutable authority or lost its receipt"
            )
        elif _case_alias == "actor-authority-cascade":
            await database.conn.execute(
                "DELETE FROM campaign_execution_actor_grants WHERE actor_user_id=?",
                (actor_id,),
            )
            await database.conn.execute("DELETE FROM users WHERE id=?", (actor_id,))
            await database.conn.commit()
            observed = await (
                await database.conn.execute(
                    "SELECT "
                    "(SELECT count(*) FROM execution_actor_authority_revisions "
                    "WHERE user_id=?),"
                    "(SELECT count(*) FROM users WHERE id=?)",
                    (actor_id, actor_id),
                )
            ).fetchone()
            assert tuple(observed) == (0, 0), "actor authority did not cascade with user"
        elif _case_alias == "destination-credential-authority-cascade":
            deleted = await database.delete_campaign_lifecycle(
                campaign_id,
                operation_id=_uuid(12_952),
            )
            observed = await (
                await database.conn.execute(
                    "SELECT "
                    "(SELECT count(*) FROM campaign_execution_destination_authorities "
                    "WHERE campaign_id=?),"
                    "(SELECT count(*) FROM credentials WHERE id=?)",
                    (campaign_id, credential_id),
                )
            ).fetchone()
            assert deleted.result is FixedResult.APPLIED, "campaign purge was rejected"
            assert tuple(observed) == (0, 0), (
                "campaign purge retained destination or credential authority"
            )
        else:
            intent = _p1c_v3_intent(campaign_id)
            applied = await store.create_initial_execution_v3(principal, intent)
            assert applied.result is FixedResult.APPLIED
            await database.conn.execute(
                "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=?",
                (campaign_id,),
            )
            await database.conn.execute(
                "DELETE FROM campaign_execution_destination_authorities WHERE campaign_id=?",
                (campaign_id,),
            )
            await database.conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
            await database.conn.commit()
            observed = await (
                await database.conn.execute(
                    "SELECT authority_contract_version,trusted_principal_user_id,"
                    "destination_authority_binding_digest,credential_authority_binding_digest "
                    "FROM execution_attempts WHERE id=?",
                    (intent.attempt_id,),
                )
            ).fetchone()
            assert observed is not None, "historical snapshot row is missing"
            assert tuple(observed[:2]) == (
                3,
                principal.user_id,
            ), "historical snapshot depended on live authority"
            assert all(isinstance(value, str) and len(value) == 64 for value in observed[2:]), (
                "historical snapshot lost authority digests"
            )
            purged = await database.delete_campaign_lifecycle(
                campaign_id,
                operation_id=_uuid(12_953),
            )
            remaining = await (
                await database.conn.execute(
                    "SELECT count(*) FROM execution_attempts WHERE id=?",
                    (intent.attempt_id,),
                )
            ).fetchone()
            assert purged.result is FixedResult.APPLIED, "historical campaign purge failed"
            assert int(remaining[0]) == 0, "historical snapshot survived campaign purge"
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_actor_revocation_and_admission_are_linearized(tmp_path, monkeypatch) -> None:
    _p1c_eligible_descriptor(monkeypatch)
    (
        database,
        setup_store,
        principal,
        _actor_id,
        campaign_id,
        _credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    contender_connection = await aiosqlite.connect((tmp_path / "p1c-authority.db").as_posix())
    contender_connection.row_factory = aiosqlite.Row
    await contender_connection.execute("PRAGMA foreign_keys=ON")
    await contender_connection.execute("PRAGMA busy_timeout=5000")
    await contender_connection.commit()
    admission_entered = asyncio.Event()
    revocation_attempted = asyncio.Event()
    admission_store = _SQLiteWinnerBarrierStore(
        database.conn,
        admission_entered,
        revocation_attempted,
    )
    revocation_store = _SQLiteContenderBarrierStore(
        contender_connection,
        revocation_attempted,
    )
    admission_task: asyncio.Task[OperationResult] | None = None
    revocation_task: asyncio.Task[OperationResult] | None = None
    try:
        assert (
            await setup_store.put_campaign_actor_grant(
                principal,
                CampaignActorGrantMutation(_uuid(12_960), campaign_id, principal.user_id, None),
            )
        ).result is FixedResult.APPLIED
        await _p1c_enable_acceptance(setup_store, principal, campaign_id)
        intent = _p1c_v3_intent(campaign_id)
        revoke_operation_id = _uuid(12_961)
        admission_task = asyncio.create_task(
            admission_store.create_initial_execution_v3(principal, intent)
        )
        await asyncio.wait_for(admission_entered.wait(), timeout=2)
        revocation_task = asyncio.create_task(
            revocation_store.revoke_actor_authority(
                principal,
                ActorAuthorityMutation(revoke_operation_id, principal.user_id, 0),
            )
        )
        await asyncio.wait_for(revocation_attempted.wait(), timeout=2)
        admitted, revoked = await asyncio.wait_for(
            asyncio.gather(admission_task, revocation_task),
            timeout=10,
        )
        observed_attempt = await (
            await database.conn.execute(
                "SELECT state,actor_authority_revision FROM execution_attempts WHERE id=?",
                (intent.attempt_id,),
            )
        ).fetchone()
        observed_actor = await (
            await database.conn.execute(
                "SELECT authority_state,authority_revision "
                "FROM execution_actor_authority_revisions WHERE user_id=?",
                (principal.user_id,),
            )
        ).fetchone()
        receipt_counts = await (
            await database.conn.execute(
                "SELECT "
                "sum(CASE WHEN operation_id=? THEN 1 ELSE 0 END),"
                "sum(CASE WHEN operation_id=? THEN 1 ELSE 0 END) "
                "FROM execution_operation_receipts",
                (intent.operation_id, revoke_operation_id),
            )
        ).fetchone()
    finally:
        for task in (admission_task, revocation_task):
            if task is not None and not task.done():
                task.cancel()
        pending = tuple(
            task
            for task in (admission_task, revocation_task)
            if task is not None and not task.done()
        )
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await contender_connection.close()
        await database.close()
    assert (admitted.result, revoked.result) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
    ), "serialized admission/revocation result changed"
    assert tuple(observed_attempt) == ("accepted", 0), (
        "admission did not retain its locked actor authority revision"
    )
    assert tuple(observed_actor) == ("revoked", 1), "revocation did not serialize after admission"
    assert tuple(receipt_counts) == (0, 1), (
        "serialized operations wrote the wrong receipt cardinality"
    )


def _p1c_v2_request(principal: TrustedPrincipal, campaign_id: str) -> AdmissionRequest:
    return AdmissionRequest(
        _uuid(12_500),
        _uuid(12_501),
        _uuid(12_502),
        _uuid(12_504),
        _uuid(12_505),
        campaign_id,
        principal.subject_ref,
        principal.user_id,
        "opsec.coverage_predictor",
        "sdk",
        AttemptState.BLOCKED,
        _uuid(12_503),
        replace(_blocked_snapshot(), actor_role="admin"),
    )


async def _p1c_admission_counts(
    connection: aiosqlite.Connection, operation_id: str
) -> tuple[int, int, int, int]:
    values = []
    for statement, parameters in (
        ("SELECT count(*) FROM logical_executions", ()),
        ("SELECT count(*) FROM execution_attempts", ()),
        ("SELECT count(*) FROM execution_publication_outbox", ()),
        (
            "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
            (operation_id,),
        ),
    ):
        row = await (await connection.execute(statement, parameters)).fetchone()
        values.append(int(row[0]))
    return tuple(values)  # type: ignore[return-value]


async def _p1c_zero_delta_snapshot(
    connection: aiosqlite.Connection,
) -> tuple[int, ...]:
    row = await (
        await connection.execute(
            "SELECT "
            "(SELECT count(*) FROM logical_executions),"
            "(SELECT count(*) FROM execution_attempts),"
            "(SELECT count(*) FROM execution_publication_outbox),"
            "(SELECT count(*) FROM execution_attempt_approvals),"
            "(SELECT count(*) FROM campaign_execution_budget_ledger),"
            "(SELECT count(*) FROM execution_attempt_destination_observations),"
            "(SELECT count(*) FROM execution_attempt_credential_observations),"
            "(SELECT coalesce(sum(reserved_units),0) "
            "FROM campaign_execution_budgets),"
            "(SELECT coalesce(sum(consumed_units),0) "
            "FROM campaign_execution_budgets)"
        )
    ).fetchone()
    return tuple(int(value) for value in row)


def _p1c_mutate_descriptor_without_rebinding(
    descriptor: ModuleDescriptor,
    case_alias: str,
) -> None:
    if case_alias == "destination-extraction":
        value: object = (
            DestinationSpec(
                DestinationKind.HOST,
                "noise_profile",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
                ContractState.SUPPORTED,
            ),
        )
        field_name = "destinations"
    else:
        field_name, value = {
            "descriptor-module-identity": ("module_id", "opsec.changed_identity"),
            "descriptor-contract-version": (
                "contract_version",
                "ares.module-descriptor.invalid",
            ),
            "descriptor-semantic-digest": ("semantic_digest", "0" * 64),
            "policy-minimum-role": ("minimum_role", MinimumRole.TEAM_LEAD),
            "policy-noise-class": ("opsec", OpsecClassification.HIGH_NOISE),
            "policy-required-capabilities": (
                "required_capabilities",
                (Capability.CAP_NET,),
            ),
            "policy-approval": ("explicit_attempt_approval", True),
        }[case_alias]
    object.__setattr__(descriptor, field_name, value)
    if field_name != "semantic_digest":
        object.__setattr__(
            descriptor,
            "semantic_digest",
            hashlib.sha256(case_alias.encode("ascii")).hexdigest(),
        )


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_PERSISTED_AUTHORITY_ALIASES,
    ids=_P1C_PERSISTED_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_each_persisted_authority_contradiction_is_atomic(
    tmp_path, monkeypatch, _case_alias: str
) -> None:
    descriptor = _p1c_eligible_descriptor(monkeypatch)
    (
        database,
        store,
        principal,
        _actor_id,
        campaign_id,
        credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    try:
        assert (
            await store.put_campaign_actor_grant(
                principal,
                CampaignActorGrantMutation(_uuid(12_700), campaign_id, principal.user_id, None),
            )
        ).result is FixedResult.APPLIED
        await _p1c_enable_acceptance(store, principal, campaign_id)
        intent = _p1c_v3_intent(campaign_id)
        if _case_alias.startswith("credential-"):
            intent = replace(intent, credential_ids=(credential_id,))

        if _case_alias == "gateway-mode":
            await database.conn.execute("PRAGMA ignore_check_constraints=ON")
            await database.conn.execute(
                "UPDATE execution_gateway_state SET mode='invalid-persisted-mode'"
            )
            await database.conn.execute("PRAGMA ignore_check_constraints=OFF")
        elif _case_alias == "gateway-revision":
            await database.conn.execute(
                "UPDATE execution_gateway_state SET activation_revision=revision+1"
            )
        elif _case_alias == "gateway-catalog-digest":
            await database.conn.execute(
                "UPDATE execution_gateway_state SET catalog_digest=?",
                ("0" * 64,),
            )
        elif _case_alias == "actor-identity":
            principal = TrustedPrincipal(_uuid(12_701), _uuid(12_701))
        elif _case_alias == "actor-active":
            await database.conn.execute(
                "UPDATE users SET is_active=0 WHERE id=?", (principal.user_id,)
            )
        elif _case_alias == "actor-role":
            await database.conn.execute("PRAGMA ignore_check_constraints=ON")
            await database.conn.execute(
                "UPDATE users SET role='recon' WHERE id=?", (principal.user_id,)
            )
            await database.conn.execute("PRAGMA ignore_check_constraints=OFF")
        elif _case_alias == "actor-authority-revision":
            await database.conn.execute(
                "UPDATE execution_actor_authority_revisions "
                "SET authority_revision=authority_revision+1 WHERE user_id=?",
                (principal.user_id,),
            )
        elif _case_alias == "campaign-status":
            await database.conn.execute(
                "UPDATE campaigns SET status='completed' WHERE id=?", (campaign_id,)
            )
        elif _case_alias == "campaign-authority-revision":
            await database.conn.execute(
                "UPDATE campaign_execution_authority_revisions "
                "SET authority_revision=authority_revision+1 WHERE campaign_id=?",
                (campaign_id,),
            )
        elif _case_alias == "campaign-ownership":
            await database.conn.execute(
                "UPDATE campaigns SET operator='different-owner' WHERE id=?",
                (campaign_id,),
            )
        elif _case_alias == "destination-campaign-scope":
            await database.conn.execute(
                "UPDATE campaigns SET targets_json='[\"other.example\"]' WHERE id=?",
                (campaign_id,),
            )
        elif _case_alias == "destination-authority-revision":
            await database.conn.execute(
                "UPDATE campaign_execution_destination_authorities "
                "SET revision=revision+1 WHERE campaign_id=?",
                (campaign_id,),
            )
        elif _case_alias == "credential-exists":
            await database.conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        elif _case_alias == "credential-ownership":
            other_campaign = _uuid(12_702)
            await database.conn.execute(
                "INSERT INTO campaigns(id,name) VALUES(?,?)",
                (other_campaign, "other-authority"),
            )
            await database.conn.execute(
                "UPDATE credentials SET campaign_id=? WHERE id=?",
                (other_campaign, credential_id),
            )
        elif _case_alias == "credential-authority-revision":
            await database.conn.execute(
                "UPDATE credentials SET execution_authority_revision="
                "execution_authority_revision+1 WHERE id=?",
                (credential_id,),
            )
        elif _case_alias in {
            "destination-extraction",
            "descriptor-module-identity",
            "descriptor-contract-version",
            "descriptor-semantic-digest",
            "policy-minimum-role",
            "policy-noise-class",
            "policy-required-capabilities",
            "policy-approval",
        }:
            _p1c_mutate_descriptor_without_rebinding(descriptor, _case_alias)
        elif _case_alias == "budget-authority-revisions":
            await database.conn.execute(
                "UPDATE campaign_execution_budgets SET revision=revision+1,"
                "latest_operation_code='reserve' WHERE budget_kind='noise' "
                "AND campaign_id=?",
                (campaign_id,),
            )
        else:
            await database.conn.execute(
                "UPDATE campaign_execution_budgets SET reserved_units=capacity_units "
                "WHERE budget_kind='concurrency' AND campaign_id=?",
                (campaign_id,),
            )
        await database.conn.commit()
        before = await _p1c_zero_delta_snapshot(database.conn)
        result = await store.create_initial_execution_v3(principal, intent)
        observer = await aiosqlite.connect((tmp_path / "p1c-authority.db").as_posix())
        try:
            after = await _p1c_zero_delta_snapshot(observer)
        finally:
            await observer.close()
        expected = (
            FixedResult.CAPACITY_UNAVAILABLE
            if _case_alias == "budget-capacity"
            else FixedResult.AUTHORITY_STALE
        )
        assert result.result is expected, "persisted contradiction classification changed"
        assert after == before, "persisted contradiction leaked durable admission state"
    finally:
        await database.close()


async def _p1c_enable_acceptance(
    store: ExecutionLifecycleStore,
    principal: TrustedPrincipal,
    campaign_id: str,
) -> None:
    assert (
        await store.update_gateway_authority(
            principal,
            GatewayAuthorityMutation(_uuid(12_530), 0, "enforced"),
        )
    ).result is FixedResult.APPLIED
    assert (
        await store.configure_campaign_budgets(
            BudgetConfiguration(
                campaign_id,
                _uuid(12_531),
                10,
                _uuid(12_532),
                10,
                _uuid(12_533),
                1,
                _uuid(12_534),
                "actor",
                principal.subject_ref,
                principal.user_id,
                0,
            )
        )
    ).result is FixedResult.APPLIED


async def _p1c_fail_accepted_parent_for_retry(
    connection: aiosqlite.Connection,
    store: ExecutionLifecycleStore,
    principal: TrustedPrincipal,
    intent: AdmissionIntentV3,
) -> int:
    budgets = await (
        await connection.execute(
            "SELECT budget_kind,id,revision FROM campaign_execution_budgets "
            "WHERE campaign_id=? ORDER BY budget_kind",
            (intent.campaign_id,),
        )
    ).fetchall()
    by_kind = {str(row[0]): (str(row[1]), int(row[2])) for row in budgets}
    transition = TransitionRequest(
        intent.attempt_id,
        0,
        AttemptState.FAILED,
        _uuid(12_540),
        outcome_code=OutcomeCode.CONFIRMED_FAILURE_NO_DISPATCH,
        authoritative_proof="no_dispatch",
        campaign_id=intent.campaign_id,
        actor_subject_ref=principal.subject_ref,
        actor_user_id=principal.user_id,
        actor_authority_revision=0,
    )
    settlement = BudgetSettlement(
        intent.campaign_id,
        intent.attempt_id,
        by_kind["noise"][0],
        intent.noise_units,
        0,
        by_kind["noise"][1],
        by_kind["exfiltration"][0],
        intent.exfiltration_units,
        0,
        by_kind["exfiltration"][1],
        by_kind["concurrency"][0],
        by_kind["concurrency"][1],
        _uuid(12_541),
        "actor",
        principal.subject_ref,
        principal.user_id,
        0,
    )
    result = await store.commit_terminal_attempt(
        TerminalCommitRequest(
            intent.logical_execution_id,
            intent.campaign_id,
            _uuid(12_542),
            _uuid(12_543),
            transition,
            settlement,
        )
    )
    assert result.result is FixedResult.APPLIED, "v3 retry parent did not fail"
    observed = await (
        await connection.execute(
            "SELECT revision,retry_disposition FROM execution_attempts WHERE id=?",
            (intent.attempt_id,),
        )
    ).fetchone()
    assert tuple(observed) == (1, "eligible"), "v3 retry parent was not promoted"
    return 1


def _p1c_v3_retry_intent(intent: AdmissionIntentV3) -> RetryIntentV3:
    return RetryIntentV3(
        intent.logical_execution_id,
        intent.attempt_id,
        _uuid(12_550),
        None,
        None,
        _uuid(12_551),
        1,
        "live",
        intent.raw_parameters,
    )


def _p1c_v2_retry_request(principal: TrustedPrincipal) -> RetryRequest:
    child = AdmissionRequest(
        _uuid(4),
        _uuid(12_560),
        _uuid(12_561),
        _uuid(12_562),
        _uuid(12_563),
        _uuid(2),
        principal.subject_ref,
        principal.user_id,
        "test.module",
        "sdk",
        AttemptState.BLOCKED,
        _uuid(12_564),
        replace(_blocked_snapshot(), actor_role="admin"),
    )
    return RetryRequest(_uuid(4), _uuid(6), child, 0)


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_RETRY_AUTHORITY_ALIASES,
    ids=_P1C_RETRY_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_retry_v2_v3_authority(tmp_path, monkeypatch, _case_alias: str) -> None:
    if _case_alias.startswith("v2-") or _case_alias == "new-v2-retry-rejected":
        connection = await _new_connection((tmp_path / "p1c-v2-retry.db").as_posix())
        principal = TrustedPrincipal(_uuid(1), _uuid(1))
        request = _p1c_v2_retry_request(principal)
        try:
            await _insert_retryable_attempt(connection)
            store = ExecutionLifecycleStore(connection, "sqlite")
            if _case_alias == "new-v2-retry-rejected":
                result = await store.create_retry_attempt(request)
                attempts = await (
                    await connection.execute("SELECT count(*) FROM execution_attempts")
                ).fetchone()
                assert result.result is FixedResult.INVALID_CONTRACT, (
                    "public fresh-v2 retry was accepted"
                )
                assert int(attempts[0]) == 1, "fresh-v2 rejection created a child"
                return
            assert (
                await store._create_retry_attempt_v2_for_migration_fixture(request)
            ).result is FixedResult.APPLIED
            if _case_alias == "v2-retry-child-binding-conflict":
                request = replace(
                    request,
                    child=replace(request.child, attempt_id=_uuid(12_565)),
                )
                expected = FixedResult.CONFLICT_OPERATION
            else:
                if _case_alias == "v2-retry-after-authority-change":
                    await connection.execute(
                        "UPDATE execution_actor_authority_revisions "
                        "SET authority_revision=authority_revision+1 WHERE user_id=?",
                        (principal.user_id,),
                    )
                    await connection.commit()
                expected = FixedResult.REPLAYED_BOUND_CHILD
            result = await store.replay_retry_attempt_v2(principal, request)
            assert result.result is expected, "historical v2 retry replay changed"
        finally:
            await connection.close()
        return

    _p1c_eligible_descriptor(monkeypatch)
    (
        database,
        store,
        principal,
        _actor_id,
        campaign_id,
        _credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    try:
        assert (
            await store.put_campaign_actor_grant(
                principal,
                CampaignActorGrantMutation(_uuid(12_570), campaign_id, principal.user_id, None),
            )
        ).result is FixedResult.APPLIED
        await _p1c_enable_acceptance(store, principal, campaign_id)
        initial = _p1c_v3_intent(campaign_id)
        assert (
            await store.create_initial_execution_v3(principal, initial)
        ).result is FixedResult.APPLIED
        await _p1c_fail_accepted_parent_for_retry(database.conn, store, principal, initial)
        intent = _p1c_v3_retry_intent(initial)
        applied = await store.create_retry_attempt_v3(principal, intent)
        assert applied.result is FixedResult.APPLIED, "first v3 retry was not applied"
        if _case_alias == "v3-retry-applied":
            result = applied
            expected = FixedResult.APPLIED
        elif _case_alias == "v3-retry-exact-replay":
            result = await store.create_retry_attempt_v3(principal, intent)
            expected = FixedResult.REPLAYED_BOUND_CHILD
        elif _case_alias == "v3-retry-child-binding-conflict":
            result = await store.create_retry_attempt_v3(
                principal,
                replace(intent, child_attempt_id=_uuid(12_571)),
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-retry-parent-revision-conflict":
            result = await store.create_retry_attempt_v3(
                principal,
                replace(intent, expected_parent_revision=2),
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-retry-after-authority-change":
            assert (
                await store.update_actor_authority(
                    principal,
                    ActorAuthorityMutation(_uuid(12_572), principal.user_id, 0),
                )
            ).result is FixedResult.APPLIED
            result = await store.create_retry_attempt_v3(principal, intent)
            expected = FixedResult.REPLAYED_BOUND_CHILD
        else:
            result = await store.replay_retry_attempt_v2(
                principal,
                RetryRequest(
                    intent.logical_execution_id,
                    intent.parent_attempt_id,
                    AdmissionRequest(
                        intent.logical_execution_id,
                        initial.submission_id,
                        intent.child_attempt_id,
                        _uuid(12_573),
                        _uuid(12_574),
                        campaign_id,
                        principal.subject_ref,
                        principal.user_id,
                        initial.module_id,
                        initial.ingress_code,
                        AttemptState.BLOCKED,
                        intent.operation_id,
                        replace(_blocked_snapshot(), actor_role="admin"),
                    ),
                    intent.expected_parent_revision,
                ),
            )
            expected = FixedResult.CONFLICT_OPERATION
        assert result.result is expected, "v3 retry replay authority changed"
        rows = await (
            await database.conn.execute(
                "SELECT id,parent_attempt_id,authority_contract_version "
                "FROM execution_attempts WHERE logical_execution_id=? ORDER BY ordinal",
                (initial.logical_execution_id,),
            )
        ).fetchall()
        receipts = await (
            await database.conn.execute(
                "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                (intent.operation_id,),
            )
        ).fetchone()
        assert tuple(tuple(row) for row in rows) == (
            (initial.attempt_id, None, 3),
            (intent.child_attempt_id, initial.attempt_id, 3),
        ), "v3 retry child binding changed"
        assert int(receipts[0]) == 1, "v3 retry lost or duplicated its receipt"
    finally:
        await database.close()


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_INITIAL_AUTHORITY_ALIASES,
    ids=_P1C_INITIAL_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_initial_v2_v3_submission_authority(
    tmp_path, monkeypatch, _case_alias: str
) -> None:
    _p1c_eligible_descriptor(monkeypatch)
    (
        database,
        store,
        principal,
        _actor_id,
        campaign_id,
        _credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    try:
        grant = CampaignActorGrantMutation(_uuid(12_510), campaign_id, principal.user_id, None)
        assert (
            await store.put_campaign_actor_grant(principal, grant)
        ).result is FixedResult.APPLIED
        intent = _p1c_v3_intent(campaign_id)
        v2_request = _p1c_v2_request(principal, campaign_id)

        if _case_alias.startswith("v2-") or _case_alias == "new-v2-rejected":
            if _case_alias == "new-v2-rejected":
                result = await store.create_initial_execution(v2_request)
                assert result.result is FixedResult.INVALID_CONTRACT, (
                    "public fresh-v2 creation was accepted"
                )
                assert await _p1c_admission_counts(database.conn, v2_request.operation_id) == (
                    0,
                    0,
                    0,
                    0,
                ), "fresh-v2 rejection created durable state"
                return

            assert (
                await store._create_initial_execution_v2_for_migration_fixture(v2_request)
            ).result is FixedResult.APPLIED
            if _case_alias == "v2-exact-replay":
                result = await store.replay_initial_execution_v2(principal, v2_request)
                expected = FixedResult.REPLAYED
            elif _case_alias == "v2-changed-intent-conflict":
                result = await store.replay_initial_execution_v2(
                    principal,
                    replace(v2_request, module_id="opsec.coverage_predictor.changed"),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v2-after-gateway-change":
                assert (
                    await store.update_gateway_authority(
                        principal,
                        GatewayAuthorityMutation(_uuid(12_511), 0, "enforced"),
                    )
                ).result is FixedResult.APPLIED
                result = await store.replay_initial_execution_v2(principal, v2_request)
                expected = FixedResult.REPLAYED
            else:
                await database.conn.execute(
                    "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=?",
                    (campaign_id,),
                )
                await database.conn.execute(
                    "DELETE FROM campaign_execution_destination_authorities WHERE campaign_id=?",
                    (campaign_id,),
                )
                await database.conn.commit()
                result = await store.replay_initial_execution_v2(principal, v2_request)
                expected = FixedResult.REPLAYED
            assert result.result is expected, "historical v2 replay authority changed"
            return

        await _p1c_enable_acceptance(store, principal, campaign_id)
        applied = await store.create_initial_execution_v3(principal, intent)
        assert applied.result is FixedResult.APPLIED, "first v3 admission was not applied"
        if _case_alias == "new-v3-applied":
            result = applied
            expected = FixedResult.APPLIED
        elif _case_alias == "v3-exact-replay":
            result = await store.create_initial_execution_v3(principal, intent)
            expected = FixedResult.REPLAYED
        elif _case_alias == "v3-logical-id-conflict":
            result = await store.create_initial_execution_v3(
                principal, replace(intent, logical_execution_id=_uuid(12_520))
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-attempt-id-conflict":
            result = await store.create_initial_execution_v3(
                principal, replace(intent, attempt_id=_uuid(12_521))
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-operation-id-conflict":
            result = await store.create_initial_execution_v3(
                principal, replace(intent, operation_id=_uuid(12_522))
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-module-id-conflict":
            result = await store.create_initial_execution_v3(
                principal, replace(intent, module_id="opsec.coverage_predictor.changed")
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-ingress-conflict":
            result = await store.create_initial_execution_v3(
                principal, replace(intent, ingress_code="cli_module")
            )
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-trusted-principal-conflict":
            changed = TrustedPrincipal(_uuid(12_523), _uuid(12_523))
            result = await store.create_initial_execution_v3(changed, intent)
            expected = FixedResult.CONFLICT_OPERATION
        elif _case_alias == "v3-after-gateway-change":
            assert (
                await store.update_gateway_authority(
                    principal,
                    GatewayAuthorityMutation(_uuid(12_524), 1, "shadow_candidate"),
                )
            ).result is FixedResult.APPLIED
            result = await store.create_initial_execution_v3(principal, intent)
            expected = FixedResult.REPLAYED
        elif _case_alias == "v3-after-authority-deletion":
            await database.conn.execute(
                "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=?",
                (campaign_id,),
            )
            await database.conn.execute(
                "DELETE FROM campaign_execution_destination_authorities WHERE campaign_id=?",
                (campaign_id,),
            )
            await database.conn.commit()
            result = await store.create_initial_execution_v3(principal, intent)
            expected = FixedResult.REPLAYED
        else:
            result = await store.replay_initial_execution_v2(principal, v2_request)
            expected = FixedResult.CONFLICT_OPERATION

        assert result.result is expected, "v3 submission replay authority changed"
        counts = await _p1c_admission_counts(database.conn, intent.operation_id)
        assert counts[:3] == (1, 1, 0), "v3 accepted admission cardinality changed"
        assert counts[3] == 0, "initial admission created a redundant operation receipt"
        attempt = await (
            await database.conn.execute(
                "SELECT state,retry_disposition FROM execution_attempts WHERE id=?",
                (intent.attempt_id,),
            )
        ).fetchone()
        reservations = await (
            await database.conn.execute(
                "SELECT count(*) FROM campaign_execution_budget_ledger WHERE attempt_id=?",
                (intent.attempt_id,),
            )
        ).fetchone()
        assert tuple(attempt) == (
            "accepted",
            "not_applicable",
        ), "v3 acceptance state changed"
        assert int(reservations[0]) == 3, "v3 acceptance missed budget reservations"
    finally:
        await database.close()


@pytest.mark.parametrize(
    "_case_alias",
    _P1C_AUTHORITY_MUTATOR_ALIASES,
    ids=_P1C_AUTHORITY_MUTATOR_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_each_authority_mutator_is_exactly_replayable(
    tmp_path, monkeypatch, _case_alias: str
) -> None:
    descriptor = (
        _p1c_eligible_descriptor(monkeypatch)
        if _case_alias in {"gateway-update", "approval-grant"}
        else None
    )
    (
        database,
        store,
        principal,
        actor_id,
        campaign_id,
        credential_id,
    ) = await _p1c_sqlite_authority_store(tmp_path)
    operation_id = _uuid(12_100 + _P1C_AUTHORITY_MUTATOR_ALIASES.index(_case_alias))
    approval_id = _uuid(12_200)
    approval_ref = _uuid(12_201)
    try:
        if _case_alias == "gateway-update":
            request: Any = GatewayAuthorityMutation(operation_id, 0, "enforced")
            method_name = "update_gateway_authority"
        elif _case_alias.startswith("actor-"):
            action = _case_alias.removeprefix("actor-")
            expected_revision = 0
            if action == "activate":
                assert (
                    await store.revoke_actor_authority(
                        principal,
                        ActorAuthorityMutation(_uuid(12_300), actor_id, 0),
                    )
                ).result is FixedResult.APPLIED
                expected_revision = 1
            request = ActorAuthorityMutation(operation_id, actor_id, expected_revision)
            method_name = f"{action}_actor_authority"
        elif _case_alias.startswith("campaign-"):
            action = _case_alias.removeprefix("campaign-")
            expected_revision = 0
            if action == "activate":
                assert (
                    await store.revoke_campaign_authority(
                        principal,
                        CampaignAuthorityMutation(_uuid(12_301), campaign_id, 0),
                    )
                ).result is FixedResult.APPLIED
                expected_revision = 1
            request = CampaignAuthorityMutation(operation_id, campaign_id, expected_revision)
            method_name = f"{action}_campaign_authority"
        elif _case_alias.startswith("grant-"):
            action = _case_alias.removeprefix("grant-")
            expected_revision = None
            if action == "revoke":
                assert (
                    await store.put_campaign_actor_grant(
                        principal,
                        CampaignActorGrantMutation(_uuid(12_302), campaign_id, actor_id, None),
                    )
                ).result is FixedResult.APPLIED
                expected_revision = 0
            request = CampaignActorGrantMutation(
                operation_id, campaign_id, actor_id, expected_revision
            )
            method_name = f"{action}_campaign_actor_grant"
        elif _case_alias.startswith("destination-"):
            action = _case_alias.removeprefix("destination-")
            request = DestinationAuthorityMutation(operation_id, campaign_id, 0)
            method_name = f"{action}_destination_authority"
        elif _case_alias.startswith("credential-"):
            action = _case_alias.removeprefix("credential-")
            request = CredentialAuthorityMutation(operation_id, credential_id, 0)
            method_name = f"{action}_credential_authority"
        elif _case_alias == "approval-grant":
            request = ApprovalAuthorityGrant(
                operation_id,
                approval_id,
                approval_ref,
                campaign_id,
                _uuid(12_202),
                _uuid(12_203),
                actor_id,
                actor_id,
                "opsec.coverage_predictor",
                0,
            )
            method_name = "grant_approval_authority"
        else:
            grant = ApprovalAuthorityGrant(
                _uuid(12_303),
                approval_id,
                approval_ref,
                campaign_id,
                _uuid(12_202),
                _uuid(12_203),
                actor_id,
                actor_id,
                "opsec.coverage_predictor",
                0,
            )
            assert (
                await store.grant_approval_authority(principal, grant)
            ).result is FixedResult.APPLIED
            request = ApprovalAuthorityMutation(operation_id, approval_id, 0)
            method_name = "revoke_approval_authority"

        async def invoke() -> OperationResult:
            method = getattr(store, method_name)
            return await method(principal, request)

        def changed_request() -> Any:
            if type(request) is GatewayAuthorityMutation:
                return replace(request, mode="shadow_candidate")
            if type(request) in {
                ActorAuthorityMutation,
                CampaignAuthorityMutation,
                DestinationAuthorityMutation,
                CredentialAuthorityMutation,
                ApprovalAuthorityMutation,
            }:
                return replace(request, expected_revision=request.expected_revision + 1)
            if type(request) is CampaignActorGrantMutation:
                expected = 0 if request.expected_revision is None else request.expected_revision + 1
                return replace(request, expected_revision=expected)
            if type(request) is ApprovalAuthorityGrant:
                return replace(request, granted_capability_mask=1)
            raise AssertionError("unsupported authority mutation request")

        async def observe_target() -> tuple[tuple[object, ...], ...]:
            table, where, parameters = {
                "gateway-update": (
                    "execution_gateway_state",
                    "singleton_id=1",
                    (),
                ),
                "actor-activate": (
                    "execution_actor_authority_revisions",
                    "user_id=?",
                    (actor_id,),
                ),
                "actor-update": (
                    "execution_actor_authority_revisions",
                    "user_id=?",
                    (actor_id,),
                ),
                "actor-revoke": (
                    "execution_actor_authority_revisions",
                    "user_id=?",
                    (actor_id,),
                ),
                "campaign-activate": (
                    "campaign_execution_authority_revisions",
                    "campaign_id=?",
                    (campaign_id,),
                ),
                "campaign-update": (
                    "campaign_execution_authority_revisions",
                    "campaign_id=?",
                    (campaign_id,),
                ),
                "campaign-revoke": (
                    "campaign_execution_authority_revisions",
                    "campaign_id=?",
                    (campaign_id,),
                ),
                "grant-put": (
                    "campaign_execution_actor_grants",
                    "campaign_id=? AND actor_user_id=?",
                    (campaign_id, actor_id),
                ),
                "grant-revoke": (
                    "campaign_execution_actor_grants",
                    "campaign_id=? AND actor_user_id=?",
                    (campaign_id, actor_id),
                ),
                "destination-update": (
                    "campaign_execution_destination_authorities",
                    "campaign_id=?",
                    (campaign_id,),
                ),
                "destination-revoke": (
                    "campaign_execution_destination_authorities",
                    "campaign_id=?",
                    (campaign_id,),
                ),
                "credential-update": ("credentials", "id=?", (credential_id,)),
                "credential-revoke": ("credentials", "id=?", (credential_id,)),
                "approval-grant": (
                    "execution_approval_authorities",
                    "id=?",
                    (approval_id,),
                ),
                "approval-revoke": (
                    "execution_approval_authorities",
                    "id=?",
                    (approval_id,),
                ),
            }[_case_alias]
            rows = await (
                await database.conn.execute(
                    f"SELECT * FROM {table} WHERE {where}",  # noqa: S608
                    parameters,
                )
            ).fetchall()
            return tuple(tuple(row) for row in rows)

        applied = await invoke()
        receipt_count_after_apply = int(
            (
                await (
                    await database.conn.execute(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                        (operation_id,),
                    )
                ).fetchone()
            )[0]
        )
        replayed = await invoke()
        receipt_count_after_replay = int(
            (
                await (
                    await database.conn.execute(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                        (operation_id,),
                    )
                ).fetchone()
            )[0]
        )
        target_before_conflict = await observe_target()
        method = getattr(store, method_name)
        conflicting = await method(principal, changed_request())
        target_after_conflict = await observe_target()
        receipt_count_after_conflict = int(
            (
                await (
                    await database.conn.execute(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                        (operation_id,),
                    )
                ).fetchone()
            )[0]
        )
        receipt_first: OperationResult | None = None
        if _case_alias == "gateway-update":
            assert descriptor is not None
            _p1c_mutate_descriptor_without_rebinding(
                descriptor,
                "descriptor-semantic-digest",
            )
            receipt_first = await invoke()
        elif _case_alias.startswith("credential-"):
            await database.conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
            await database.conn.commit()
            receipt_first = await invoke()
        elif _case_alias.startswith("approval-"):
            if descriptor is not None:
                _p1c_mutate_descriptor_without_rebinding(
                    descriptor,
                    "descriptor-semantic-digest",
                )
            await database.conn.execute(
                "DELETE FROM execution_approval_authorities WHERE id=?",
                (approval_id,),
            )
            await database.conn.commit()
            receipt_first = await invoke()
        assert (applied.result, replayed.result) == (
            FixedResult.APPLIED,
            FixedResult.REPLAYED,
        ), "authority mutation lost exact replay"
        assert conflicting.result is FixedResult.CONFLICT_OPERATION, (
            "changed authority mutation reused an immutable operation"
        )
        assert target_after_conflict == target_before_conflict, (
            "changed authority mutation altered its target"
        )
        assert (
            receipt_count_after_apply
            == receipt_count_after_replay
            == receipt_count_after_conflict
            == 1
        ), "authority mutation replay duplicated its receipt"
        if receipt_first is not None:
            assert receipt_first.result is FixedResult.REPLAYED, (
                "authority mutation replay consulted mutable current authority"
            )
    finally:
        await database.close()


_P1B_AUTHORITY_CASES = (
    ("actor-authority-ensure", "actor_authority_ensure"),
    ("campaign-authority-ensure", "campaign_authority_ensure"),
    ("actor-authority-invalidate", "actor_authority_invalidate"),
    ("campaign-authority-invalidate", "campaign_authority_invalidate"),
    ("budget-configure", "budget_configure"),
    ("budget-reserve", "budget_reserve"),
    ("budget-settle", "budget_settle"),
    ("admission", "admission"),
    ("retry-attempt", "retry"),
    ("attempt-transition", "queue"),
    ("settlement-pending", "settlement_pending"),
    ("expired-lease-settlement", "lease_loss"),
    ("terminal-commit", "terminal_failed"),
    ("close-without-retry", "close_without_retry"),
    ("outbox-claim", "outbox_claim"),
    ("outbox-reclaim", "outbox_reclaim"),
    ("outbox-poison", "outbox_poison"),
    ("outbox-renew", "outbox_renew"),
    ("outbox-publish", "outbox_publish"),
    ("outbox-fail-retryable", "outbox_retryable_failure"),
    ("outbox-fail-nonretryable", "outbox_nonretryable_failure"),
    ("outbox-purge", "outbox_purge"),
    ("campaign-delete", "campaign_delete"),
)

_P1B_PUBLIC_METHOD_MAP = (
    ("actor-authority-ensure", "ExecutionLifecycleStore.ensure_actor_authority"),
    ("campaign-authority-ensure", "ExecutionLifecycleStore.ensure_campaign_authority"),
    ("actor-authority-invalidate", "ExecutionLifecycleStore.invalidate_actor_authority"),
    (
        "campaign-authority-invalidate",
        "ExecutionLifecycleStore.invalidate_campaign_authority",
    ),
    ("budget-configure", "ExecutionLifecycleStore.configure_campaign_budgets"),
    ("budget-reserve", "ExecutionLifecycleStore.reserve_budgets"),
    ("budget-settle", "ExecutionLifecycleStore.settle_budgets"),
    ("admission", "ExecutionLifecycleStore.create_initial_execution"),
    ("retry-attempt", "ExecutionLifecycleStore.create_retry_attempt"),
    ("attempt-transition", "ExecutionLifecycleStore.transition_attempt"),
    ("settlement-pending", "ExecutionLifecycleStore.enter_settlement_pending"),
    (
        "expired-lease-settlement",
        "ExecutionLifecycleStore.mark_expired_lease_settlement_pending",
    ),
    ("terminal-commit", "ExecutionLifecycleStore.commit_terminal_attempt"),
    ("close-without-retry", "ExecutionLifecycleStore.close_without_retry"),
    ("outbox-claim", "ExecutionLifecycleStore.claim_outbox"),
    ("outbox-reclaim", "ExecutionLifecycleStore.claim_outbox(reclaim=True)"),
    ("outbox-poison", "ExecutionLifecycleStore.poison_expired_attempt_twenty"),
    ("outbox-renew", "ExecutionLifecycleStore.renew_outbox"),
    ("outbox-publish", "ExecutionLifecycleStore.publish_outbox"),
    ("outbox-fail-retryable", "ExecutionLifecycleStore.fail_outbox(retryable=True)"),
    (
        "outbox-fail-nonretryable",
        "ExecutionLifecycleStore.fail_outbox(retryable=False)",
    ),
    ("outbox-purge", "ExecutionLifecycleStore.purge_outbox"),
    ("campaign-delete", "AresDatabase.delete_campaign_lifecycle"),
)

_P1B_LITERAL_NODE_COUNT = 88
_P1B_LITERAL_NODE_IDS_SHA256 = "77398973391e0092ee8a3979e31ff3cd364d53b786683bae0503266357699f90"

_P1B_BINDING_MUTATIONS = (
    "operation-code-transition",
    "primary-target-transition",
    "secondary-target-retry",
    "campaign-transition",
    "principal-kind-transition",
    "principal-subject-transition",
    "principal-user-transition",
    "principal-authority-revision-transition",
    "expected-revision-presence-transition",
    "expected-revision-value-transition",
    "secondary-expected-presence-budget",
    "secondary-expected-value-budget",
    "owner-presence-outbox",
    "lease-generation-outbox",
    "canonical-request-payload-terminal",
    "canonical-request-payload-budget",
    "submission-operation-id",
    "submission-actor-request",
)

_P1B_RETENTION_CASES = (
    "submission-lookup-precedes-gateway",
    "submission-replay-after-state-advance",
    "submission-changed-request-conflict",
    "receipt-update-rejected",
    "receipt-delete-rejected",
    "receipt-survives-campaign-delete",
    "receipt-survives-target-delete",
    "stored-result-independent-of-mutable-target",
)

_P1B_ATOMICITY_CASES = (
    "shared-authority-receipt-insert-rollback",
    "shared-budget-receipt-insert-rollback",
    "shared-admission-binding-insert-rollback",
    "shared-retry-receipt-insert-rollback",
    "shared-transition-receipt-insert-rollback",
    "shared-terminal-receipt-insert-rollback",
    "shared-outbox-receipt-insert-rollback",
    "shared-purge-receipt-insert-rollback",
    "shared-campaign-delete-receipt-insert-rollback",
    "exact-replay-no-duplicate-side-effects",
)

_P1B_CONCURRENCY_CASES = (
    "shared-submission-identical",
    "shared-authority-identical",
    "shared-transition-identical",
    "shared-budget-identical",
    "shared-outbox-identical",
    "shared-campaign-delete-identical",
)


def _p1b_literal_spec(
    store: ExecutionLifecycleStore,
    operation_code: str,
    *,
    operation_id: str = _uuid(3000),
    primary_target_id: str = _uuid(3001),
):
    no_revision = operation_code in {
        "actor_authority_ensure",
        "campaign_authority_ensure",
        "budget_configure",
        "admission",
        "outbox_insert",
        "campaign_delete",
    }
    dual_revision = operation_code in {"budget_reserve", "budget_settle"}
    owner_bound = operation_code in {
        "outbox_claim",
        "outbox_reclaim",
        "outbox_renew",
        "outbox_publish",
        "outbox_retryable_failure",
        "outbox_nonretryable_failure",
    }
    return store._receipt_spec(
        operation_id=operation_id,
        operation_code=operation_code,
        campaign_id=_uuid(3002),
        primary_target_id=primary_target_id,
        secondary_target_id=_uuid(3003),
        principal_kind="actor",
        principal_subject_ref=_uuid(3004),
        principal_user_id=_uuid(3004),
        principal_authority_revision=7,
        expected_revision=None if no_revision else 9,
        secondary_expected_revision=11 if dual_revision else None,
        owner_ref=_uuid(3005) if owner_bound else None,
        lease_generation=3 if owner_bound else None,
        fields=(("literal_payload", "p1b"),),
    )


def _p1b_independent_request_digest(operation_code: str) -> str:
    no_revision = operation_code in {
        "actor_authority_ensure",
        "campaign_authority_ensure",
        "budget_configure",
        "admission",
        "outbox_insert",
        "campaign_delete",
    }
    dual_revision = operation_code in {"budget_reserve", "budget_settle"}
    owner_bound = operation_code in {
        "outbox_claim",
        "outbox_reclaim",
        "outbox_renew",
        "outbox_publish",
        "outbox_retryable_failure",
        "outbox_nonretryable_failure",
    }
    return _independent_binding_digest(
        operation_code + ".request",
        (
            ("operation_id", _uuid(3000)),
            ("operation_code", operation_code),
            ("campaign_id_present", True),
            ("campaign_id", _uuid(3002)),
            ("primary_target_id", _uuid(3001)),
            ("secondary_target_id_present", True),
            ("secondary_target_id", _uuid(3003)),
            ("principal_kind", "actor"),
            ("principal_subject_ref", _uuid(3004)),
            ("principal_user_id_present", True),
            ("principal_user_id", _uuid(3004)),
            ("principal_authority_revision_present", True),
            ("principal_authority_revision", 7),
            ("expected_revision_present", not no_revision),
            ("expected_revision", None if no_revision else 9),
            ("secondary_expected_revision_present", dual_revision),
            ("secondary_expected_revision", 11 if dual_revision else None),
            ("owner_ref_present", owner_bound),
            ("owner_ref", _uuid(3005) if owner_bound else None),
            ("lease_generation_present", owner_bound),
            ("lease_generation", 3 if owner_bound else None),
            ("literal_payload", "p1b"),
        ),
    )


async def _p1b_insert_literal_receipt(
    connection: aiosqlite.Connection,
    operation_code: str,
    *,
    operation_id: str = _uuid(3000),
) -> tuple[ExecutionLifecycleStore, Any]:
    store = ExecutionLifecycleStore(connection, "sqlite")
    spec = _p1b_literal_spec(store, operation_code, operation_id=operation_id)
    exact = (
        FixedResult.REPLAYED_BOUND_CHILD
        if operation_code == "retry"
        else FixedResult.REPLAYED_CLOSED
        if operation_code == "close_without_retry"
        else FixedResult.REPLAYED
    )
    async with store._transaction() as transaction:
        await store._insert_receipt(
            transaction,
            spec,
            result=FixedResult.APPLIED,
            exact_replay_code=exact,
            result_identity=_uuid(3001),
            result_revision=10,
        )
    return store, spec


async def _p1b_admission_case() -> tuple[
    aiosqlite.Connection, ExecutionLifecycleStore, AdmissionRequest
]:
    connection = await _new_connection()
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (_uuid(3100), "p1b-admission", "fixed-hash", "admin", "fixed"),
    )
    await connection.execute(
        "INSERT INTO campaigns(id,name) VALUES(?,?)", (_uuid(3101), "p1b-admission")
    )
    await connection.execute(
        "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
        "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
        ("c" * 64,),
    )
    await connection.commit()
    store = ExecutionLifecycleStore(connection, "sqlite")
    assert (
        await store.ensure_actor_authority(_uuid(3100), _uuid(3102))
    ).result is FixedResult.APPLIED
    assert (
        await store.ensure_campaign_authority(_uuid(3101), _uuid(3103))
    ).result is FixedResult.APPLIED
    snapshot = replace(
        _blocked_snapshot(),
        actor_role="admin",
        gateway_mode_snapshot="enforced",
        policy_verdict="blocked",
        policy_reason_mask=PolicyReasonBit.INSUFFICIENT_ROLE.value,
    )
    request = AdmissionRequest(
        _uuid(3104),
        _uuid(3105),
        _uuid(3106),
        _uuid(3107),
        _uuid(3108),
        _uuid(3101),
        _uuid(3100),
        _uuid(3100),
        "test.p1b",
        "sdk",
        AttemptState.BLOCKED,
        _uuid(3109),
        snapshot,
    )
    assert (
        await store._create_initial_execution_v2_for_migration_fixture(request)
    ).result is FixedResult.APPLIED
    return connection, store, request


async def _p1b_public_snapshot(
    connection: aiosqlite.Connection,
) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
    tables = (
        "campaigns",
        "execution_actor_authority_revisions",
        "campaign_execution_authority_revisions",
        "campaign_execution_budgets",
        "campaign_execution_budget_ledger",
        "logical_executions",
        "execution_attempts",
        "execution_publication_outbox",
        "execution_operation_receipts",
    )
    snapshot = []
    for table in tables:
        rows = await (
            await connection.execute(
                f"SELECT * FROM {table} ORDER BY 1"  # noqa: S608 - frozen table tuple.
            )
        ).fetchall()
        snapshot.append((table, tuple(tuple(row) for row in rows)))
    return tuple(snapshot)


async def _p1b_prepare_admission() -> tuple[
    aiosqlite.Connection, ExecutionLifecycleStore, AdmissionRequest
]:
    connection = await _new_connection()
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (_uuid(3400), "p1b-public-admission", "fixed-hash", "admin", "fixed"),
    )
    await connection.execute(
        "INSERT INTO campaigns(id,name) VALUES(?,?)",
        (_uuid(3401), "p1b-public-admission"),
    )
    await connection.execute(
        "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
        "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
        ("c" * 64,),
    )
    await connection.commit()
    store = ExecutionLifecycleStore(connection, "sqlite")
    assert (
        await store.ensure_actor_authority(_uuid(3400), _uuid(3402))
    ).result is FixedResult.APPLIED
    assert (
        await store.ensure_campaign_authority(_uuid(3401), _uuid(3403))
    ).result is FixedResult.APPLIED
    request = AdmissionRequest(
        _uuid(3404),
        _uuid(3405),
        _uuid(3406),
        _uuid(3407),
        _uuid(3408),
        _uuid(3401),
        _uuid(3400),
        _uuid(3400),
        "test.p1b.public",
        "sdk",
        AttemptState.BLOCKED,
        _uuid(3409),
        replace(
            _blocked_snapshot(),
            actor_role="admin",
            gateway_mode_snapshot="enforced",
        ),
    )
    return connection, store, request


@pytest.mark.parametrize(
    ("_case_alias", "operation_code"),
    _P1B_AUTHORITY_CASES,
    ids=tuple(alias for alias, _code in _P1B_AUTHORITY_CASES),
)
def test_sqlite_p1b_independent_literal_binding_vector(
    _case_alias: str, operation_code: str
) -> None:
    assert tuple(alias for alias, _method in _P1B_PUBLIC_METHOD_MAP) == tuple(
        alias for alias, _code in _P1B_AUTHORITY_CASES
    )
    assert (_P1B_LITERAL_NODE_COUNT, len(_P1B_LITERAL_NODE_IDS_SHA256)) == (88, 64)
    store = ExecutionLifecycleStore(None, "sqlite")
    spec = _p1b_literal_spec(store, operation_code)
    assert spec.request_binding_digest == _p1b_independent_request_digest(operation_code)


async def _p1b_run_public_triplet(
    connection: aiosqlite.Connection,
    apply_call: Any,
    replay_call: Any,
    conflict_call: Any,
) -> tuple[OperationResult, OperationResult, OperationResult, str]:
    applied = await apply_call()
    after_apply = await _p1b_public_snapshot(connection)
    replayed = await replay_call()
    after_replay = await _p1b_public_snapshot(connection)
    conflicted = await conflict_call()
    after_conflict = await _p1b_public_snapshot(connection)
    assert after_apply == after_replay == after_conflict, (
        "public operation replay or binding conflict duplicated a durable side effect"
    )
    receipt = await (
        await connection.execute(
            "SELECT operation_code FROM execution_operation_receipts ORDER BY rowid DESC LIMIT 1"
        )
    ).fetchone()
    return applied, replayed, conflicted, str(receipt[0])


async def _p1b_insert_outbox_state(
    connection: aiosqlite.Connection,
    *,
    state: str,
    expired: bool = False,
    twentieth: bool = False,
) -> OutboxMutation:
    await _insert_retryable_attempt(connection)
    claimed = state == "claimed"
    terminal = state in {"published", "poisoned"}
    delivery_count = 20 if twentieth else (1 if state != "pending" else 0)
    revision = 20 if twentieth else (1 if state != "pending" else 0)
    owner = _uuid(3510) if claimed else None
    lease_generation = 20 if twentieth else (1 if claimed else 0)
    expires = 1 if expired else (MAX_I53 - OUTBOX_LEASE_MS - 1 if claimed else None)
    latest_code = (
        "nonretryable_failure"
        if state == "poisoned"
        else "publish"
        if state == "published"
        else "claim"
        if state == "claimed"
        else "insert"
    )
    failure = "delivery_nonretryable" if state == "poisoned" else None
    await connection.execute(
        "INSERT INTO execution_publication_outbox("
        "id,publication_key,attempt_id,campaign_id,event_code,is_attempt_terminal,"
        "publication_state,delivery_attempt_count,available_at,claim_owner_ref,"
        "lease_generation,claimed_at,lease_expires_at,published_at,poisoned_at,"
        "failure_code,claim_revision,latest_operation_id,latest_operation_code,"
        "latest_operation_base_revision,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            _uuid(3500),
            _uuid(3501),
            _uuid(6),
            _uuid(2),
            "recovery_required",
            0,
            state,
            delivery_count,
            1 if state == "pending" else None,
            owner,
            lease_generation,
            1 if terminal or claimed else None,
            expires,
            1 if state == "published" else None,
            1 if state == "poisoned" else None,
            failure,
            revision,
            _uuid(3501) if state == "pending" else _uuid(3504),
            latest_code,
            max(0, revision - 1),
            1,
        ),
    )
    await connection.commit()
    return OutboxMutation(
        _uuid(3500),
        revision,
        _uuid(3505),
        owner_ref=(
            _uuid(3511)
            if state == "pending"
            else _uuid(3510)
            if state == "claimed" and not twentieth
            else None
        ),
        lease_generation=(
            lease_generation if state in {"pending", "claimed"} and not twentieth else None
        ),
        campaign_id=_uuid(2),
        attempt_id=_uuid(6),
        publication_key=_uuid(3501),
        event_code="recovery_required",
    )


async def _p1b_exercise_public_operation(
    case_alias: str, tmp_path: Any
) -> tuple[OperationResult, OperationResult, OperationResult, str]:
    if case_alias == "campaign-delete":
        database = AresDatabase(tmp_path / "p1b-public-delete.db")
        await database.connect()
        try:
            await database.conn.executemany(
                "INSERT INTO campaigns(id,name) VALUES(?,?)",
                (
                    (_uuid(3600), "p1b-public-delete"),
                    (_uuid(3601), "p1b-public-delete-conflict"),
                ),
            )
            await database.conn.commit()
            operation_id = _uuid(3602)
            return await _p1b_run_public_triplet(
                database.conn,
                lambda: database.delete_campaign_lifecycle(_uuid(3600), operation_id=operation_id),
                lambda: database.delete_campaign_lifecycle(_uuid(3600), operation_id=operation_id),
                lambda: database.delete_campaign_lifecycle(_uuid(3601), operation_id=operation_id),
            )
        finally:
            await database.close()

    if case_alias == "admission":
        connection, store, request = await _p1b_prepare_admission()
        try:
            applied = await store._create_initial_execution_v2_for_migration_fixture(request)
            after_apply = await _p1b_public_snapshot(connection)
            replayed = await store._create_initial_execution_v2_for_migration_fixture(request)
            after_replay = await _p1b_public_snapshot(connection)
            conflicted = await store._create_initial_execution_v2_for_migration_fixture(
                replace(request, module_id="test.p1b.public.changed")
            )
            after_conflict = await _p1b_public_snapshot(connection)
            assert after_apply == after_replay == after_conflict
            submission = await (
                await connection.execute(
                    "SELECT admission_operation_id,submission_binding_contract_version,"
                    "submission_result_code,submission_exact_replay_code "
                    "FROM logical_executions WHERE campaign_id=? AND submission_id=?",
                    (request.campaign_id, request.submission_id),
                )
            ).fetchone()
            receipt_count = await (
                await connection.execute(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                    (request.operation_id,),
                )
            ).fetchone()
            assert tuple(submission) == (
                request.operation_id,
                2,
                FixedResult.APPLIED.value,
                FixedResult.REPLAYED.value,
            )
            assert int(receipt_count[0]) == 0
            return applied, replayed, conflicted, "admission"
        finally:
            await connection.close()

    if case_alias in {"actor-authority-ensure", "actor-authority-invalidate"}:
        connection = await _new_connection()
        try:
            await connection.executemany(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
                (
                    (_uuid(3410), "p1b-public-actor", "fixed", "admin", "fixed"),
                    (_uuid(3411), "p1b-public-actor-conflict", "fixed", "admin", "fixed"),
                ),
            )
            await connection.commit()
            store = ExecutionLifecycleStore(connection, "sqlite")
            operation_id = _uuid(3412)
            if case_alias.endswith("invalidate"):
                assert (
                    await store.ensure_actor_authority(_uuid(3410), _uuid(3413))
                ).result is FixedResult.APPLIED

                async def apply() -> OperationResult:
                    return await store.invalidate_actor_authority(_uuid(3410), 0, operation_id)

                async def conflict() -> OperationResult:
                    return await store.invalidate_actor_authority(_uuid(3410), 1, operation_id)
            else:

                async def apply() -> OperationResult:
                    return await store.ensure_actor_authority(_uuid(3410), operation_id)

                async def conflict() -> OperationResult:
                    return await store.ensure_actor_authority(_uuid(3411), operation_id)

            return await _p1b_run_public_triplet(connection, apply, apply, conflict)
        finally:
            await connection.close()

    if case_alias in {"campaign-authority-ensure", "campaign-authority-invalidate"}:
        connection = await _new_connection()
        try:
            await connection.executemany(
                "INSERT INTO campaigns(id,name) VALUES(?,?)",
                (
                    (_uuid(3420), "p1b-public-campaign"),
                    (_uuid(3421), "p1b-public-campaign-conflict"),
                ),
            )
            await connection.commit()
            store = ExecutionLifecycleStore(connection, "sqlite")
            operation_id = _uuid(3422)
            if case_alias.endswith("invalidate"):
                assert (
                    await store.ensure_campaign_authority(_uuid(3420), _uuid(3423))
                ).result is FixedResult.APPLIED

                async def apply() -> OperationResult:
                    return await store.invalidate_campaign_authority(_uuid(3420), 0, operation_id)

                async def conflict() -> OperationResult:
                    return await store.invalidate_campaign_authority(_uuid(3420), 1, operation_id)
            else:

                async def apply() -> OperationResult:
                    return await store.ensure_campaign_authority(_uuid(3420), operation_id)

                async def conflict() -> OperationResult:
                    return await store.ensure_campaign_authority(_uuid(3421), operation_id)

            return await _p1b_run_public_triplet(connection, apply, apply, conflict)
        finally:
            await connection.close()

    if case_alias in {"budget-configure", "budget-reserve", "budget-settle"}:
        connection = await _new_connection()
        try:
            await _insert_retryable_attempt(connection)
            store = ExecutionLifecycleStore(connection, "sqlite")
            configuration = BudgetConfiguration(
                _uuid(2), _uuid(3430), 20, _uuid(3431), 20, _uuid(3432), 2, _uuid(3433)
            )
            if case_alias == "budget-configure":
                return await _p1b_run_public_triplet(
                    connection,
                    lambda: store.configure_campaign_budgets(configuration),
                    lambda: store.configure_campaign_budgets(configuration),
                    lambda: store.configure_campaign_budgets(
                        replace(configuration, noise_capacity=19)
                    ),
                )
            assert (
                await store.configure_campaign_budgets(configuration)
            ).result is FixedResult.APPLIED
            reservation = BudgetReservation(
                _uuid(2),
                _uuid(6),
                _uuid(3430),
                _uuid(3434),
                4,
                0,
                _uuid(3431),
                _uuid(3435),
                5,
                0,
                _uuid(3432),
                _uuid(3436),
                0,
                _uuid(3437),
            )
            if case_alias == "budget-reserve":
                return await _p1b_run_public_triplet(
                    connection,
                    lambda: store.reserve_budgets(reservation),
                    lambda: store.reserve_budgets(reservation),
                    lambda: store.reserve_budgets(replace(reservation, noise_units=3)),
                )
            assert (await store.reserve_budgets(reservation)).result is FixedResult.APPLIED
            settlement = BudgetSettlement(
                _uuid(2),
                _uuid(6),
                _uuid(3430),
                4,
                3,
                1,
                _uuid(3431),
                5,
                2,
                1,
                _uuid(3432),
                1,
                _uuid(3438),
            )
            return await _p1b_run_public_triplet(
                connection,
                lambda: store.settle_budgets(settlement),
                lambda: store.settle_budgets(settlement),
                lambda: store.settle_budgets(replace(settlement, noise_actual=2)),
            )
        finally:
            await connection.close()

    if case_alias in {"retry-attempt", "close-without-retry"}:
        connection = await _new_connection()
        try:
            await _insert_retryable_attempt(connection)
            store = ExecutionLifecycleStore(connection, "sqlite")
            if case_alias == "close-without-retry":
                request = ClosureRequest(
                    _uuid(4), _uuid(6), _uuid(3440), 0, _uuid(3441), _uuid(1), _uuid(1), 0, _uuid(2)
                )
                return await _p1b_run_public_triplet(
                    connection,
                    lambda: store.close_without_retry(request),
                    lambda: store.close_without_retry(request),
                    lambda: store.close_without_retry(replace(request, outbox_id=_uuid(3442))),
                )
            child = AdmissionRequest(
                _uuid(4),
                _uuid(3443),
                _uuid(3444),
                _uuid(3445),
                _uuid(3446),
                _uuid(2),
                _uuid(1),
                _uuid(1),
                "test.p1b.retry",
                "sdk",
                AttemptState.BLOCKED,
                _uuid(3447),
                replace(_blocked_snapshot(), actor_role="admin"),
            )
            request = RetryRequest(_uuid(4), _uuid(6), child, 0)
            return await _p1b_run_public_triplet(
                connection,
                lambda: store._create_retry_attempt_v2_for_migration_fixture(request),
                lambda: store._create_retry_attempt_v2_for_migration_fixture(request),
                lambda: store._create_retry_attempt_v2_for_migration_fixture(
                    replace(request, child=replace(child, module_id="test.p1b.retry.changed"))
                ),
            )
        finally:
            await connection.close()

    if case_alias.startswith("outbox-"):
        state = "pending" if case_alias == "outbox-claim" else "claimed"
        connection = await _new_connection()
        try:
            request = await _p1b_insert_outbox_state(
                connection,
                state=state,
                expired=case_alias in {"outbox-reclaim", "outbox-poison"},
                twentieth=case_alias == "outbox-poison",
            )
            if case_alias == "outbox-reclaim":
                request = replace(request, owner_ref=_uuid(3511))
            store = ExecutionLifecycleStore(connection, "sqlite")
            changed = replace(request, event_code="logical_execution_closed")
            if case_alias == "outbox-claim":

                async def call(candidate=request):
                    return await store.claim_outbox(candidate)
            elif case_alias == "outbox-reclaim":

                async def call(candidate=request):
                    return await store.claim_outbox(candidate, reclaim=True)
            elif case_alias == "outbox-poison":

                async def call(candidate=request):
                    return await store.poison_expired_attempt_twenty(candidate)
            elif case_alias == "outbox-renew":

                async def call(candidate=request):
                    return await store.renew_outbox(candidate)
            elif case_alias == "outbox-publish":

                async def call(candidate=request):
                    return await store.publish_outbox(candidate)
            elif case_alias == "outbox-fail-retryable":

                async def call(candidate=request):
                    return await store.fail_outbox(candidate, retryable=True)
            elif case_alias == "outbox-fail-nonretryable":

                async def call(candidate=request):
                    return await store.fail_outbox(candidate, retryable=False)
            else:
                prior = replace(request, operation_id=_uuid(3506))
                published = await store.publish_outbox(prior)
                assert published.result is FixedResult.APPLIED
                request = replace(
                    request,
                    expected_revision=published.revision,
                    operation_id=_uuid(3505),
                    owner_ref=None,
                    lease_generation=None,
                    purge_poisoned=False,
                )
                changed = replace(request, event_code="logical_execution_closed")

                async def call(candidate=request):
                    return await store.purge_outbox(
                        candidate.outbox_id,
                        candidate.expected_revision,
                        candidate.operation_id,
                        poisoned=bool(candidate.purge_poisoned),
                        campaign_id=candidate.campaign_id,
                        attempt_id=candidate.attempt_id,
                        publication_key=candidate.publication_key,
                        event_code=candidate.event_code,
                    )

            return await _p1b_run_public_triplet(
                connection,
                call,
                call,
                lambda: call(changed),
            )
        finally:
            await connection.close()

    connection, store = await _new_transition_case(":memory:", AttemptState.ACCEPTED)
    try:
        if case_alias == "attempt-transition":
            request = TransitionRequest(
                _uuid(210),
                0,
                AttemptState.QUEUED,
                _uuid(3450),
                campaign_id=_uuid(201),
                actor_subject_ref=_uuid(200),
                actor_user_id=_uuid(200),
                actor_authority_revision=0,
            )
            return await _p1b_run_public_triplet(
                connection,
                lambda: store.transition_attempt(request),
                lambda: store.transition_attempt(request),
                lambda: store.transition_attempt(
                    replace(request, target_state=AttemptState.CANCELLING)
                ),
            )

        dispatched = await _nonterminal_transition(
            store, connection, AttemptState.DISPATCHING, 3451
        )
        assert dispatched.result is FixedResult.APPLIED
        running = await _nonterminal_transition(store, connection, AttemptState.RUNNING, 3452)
        assert running.result is FixedResult.APPLIED
        if case_alias in {"settlement-pending", "expired-lease-settlement"}:
            request = TransitionRequest(
                _uuid(210),
                2,
                AttemptState.SETTLEMENT_PENDING,
                _uuid(3453),
                owner_ref=_uuid(220),
                lease_generation=1,
                outbox_id=_uuid(3454),
                publication_key=_uuid(3455),
                campaign_id=_uuid(201),
            )
            active_store = (
                _AdvancedClockLifecycleStore(connection, "sqlite")
                if case_alias == "expired-lease-settlement"
                else store
            )
            method = (
                active_store.mark_expired_lease_settlement_pending
                if case_alias == "expired-lease-settlement"
                else active_store.enter_settlement_pending
            )
            return await _p1b_run_public_triplet(
                connection,
                lambda: method(request),
                lambda: method(request),
                lambda: method(replace(request, publication_key=_uuid(3456))),
            )

        assert case_alias == "terminal-commit"
        transition = TransitionRequest(
            _uuid(210),
            2,
            AttemptState.FAILED,
            _uuid(3457),
            owner_ref=_uuid(220),
            lease_generation=1,
            outcome_code=OutcomeCode.CONFIRMED_FAILURE,
            authoritative_proof="worker_terminal_ack",
            campaign_id=_uuid(201),
        )
        request = TerminalCommitRequest(
            _uuid(208),
            _uuid(201),
            _uuid(3458),
            _uuid(3459),
            transition,
            BudgetSettlement(
                _uuid(201),
                _uuid(210),
                _uuid(204),
                2,
                0,
                1,
                _uuid(205),
                3,
                0,
                1,
                _uuid(206),
                1,
                _uuid(3460),
            ),
        )
        return await _p1b_run_public_triplet(
            connection,
            lambda: store.commit_terminal_attempt(request),
            lambda: store.commit_terminal_attempt(request),
            lambda: store.commit_terminal_attempt(replace(request, publication_key=_uuid(3461))),
        )
    finally:
        await connection.close()


@pytest.mark.parametrize(
    ("case_alias", "_operation_code"),
    _P1B_AUTHORITY_CASES,
    ids=tuple(alias for alias, _code in _P1B_AUTHORITY_CASES),
)
@pytest.mark.asyncio
async def test_sqlite_p1b_each_public_authority_replays_exactly(
    case_alias: str, _operation_code: str, tmp_path
) -> None:
    applied, replayed, conflicted, recorded_operation_code = await _p1b_exercise_public_operation(
        case_alias, tmp_path
    )
    expected_replay = (
        FixedResult.REPLAYED_BOUND_CHILD
        if case_alias == "retry-attempt"
        else FixedResult.REPLAYED_CLOSED
        if case_alias == "close-without-retry"
        else FixedResult.REPLAYED
    )
    assert (applied.result, replayed.result, conflicted.result) == (
        FixedResult.APPLIED,
        expected_replay,
        FixedResult.CONFLICT_OPERATION,
    )
    assert recorded_operation_code == _operation_code


@pytest.mark.parametrize("case_alias", _P1B_BINDING_MUTATIONS, ids=_P1B_BINDING_MUTATIONS)
@pytest.mark.asyncio
async def test_sqlite_p1b_each_binding_mutation_conflicts(case_alias: str) -> None:
    if case_alias.startswith("submission-"):
        connection, store, request = await _p1b_admission_case()
        try:
            changed = (
                replace(request, operation_id=_uuid(3110))
                if case_alias == "submission-operation-id"
                else replace(request, module_id="test.p1b.changed")
            )
            result = await store._create_initial_execution_v2_for_migration_fixture(changed)
        finally:
            await connection.close()
        assert result.result is FixedResult.CONFLICT_OPERATION
        return
    connection = await _new_connection()
    try:
        operation_code = (
            "budget_reserve"
            if case_alias.startswith("secondary-expected-")
            or case_alias == "canonical-request-payload-budget"
            else "outbox_claim"
            if case_alias in {"owner-presence-outbox", "lease-generation-outbox"}
            else "retry"
            if case_alias == "secondary-target-retry"
            else "terminal_failed"
            if case_alias == "canonical-request-payload-terminal"
            else "queue"
        )
        store, spec = await _p1b_insert_literal_receipt(connection, operation_code)
        mutations = {
            "operation-code-transition": {"operation_code": "dispatch"},
            "primary-target-transition": {"primary_target_id": _uuid(3010)},
            "secondary-target-retry": {"secondary_target_id": _uuid(3011)},
            "campaign-transition": {"campaign_id": _uuid(3012)},
            "principal-kind-transition": {"principal_kind": "resolver"},
            "principal-subject-transition": {"principal_subject_ref": _uuid(3013)},
            "principal-user-transition": {"principal_user_id": _uuid(3014)},
            "principal-authority-revision-transition": {"principal_authority_revision": 8},
            "expected-revision-presence-transition": {"expected_revision": None},
            "expected-revision-value-transition": {"expected_revision": 10},
            "secondary-expected-presence-budget": {"secondary_expected_revision": None},
            "secondary-expected-value-budget": {"secondary_expected_revision": 12},
            "owner-presence-outbox": {"owner_ref": None, "lease_generation": None},
            "lease-generation-outbox": {"lease_generation": 4},
            "canonical-request-payload-terminal": {"request_binding_digest": "a" * 64},
            "canonical-request-payload-budget": {"request_binding_digest": "b" * 64},
        }
        changed = replace(spec, **mutations[case_alias])
        async with store._transaction() as transaction:
            result = await store._classify_receipt(transaction, changed, current_revision=None)
    finally:
        await connection.close()
    assert (result.result, result.revision) == (FixedResult.CONFLICT_OPERATION, None)


@pytest.mark.parametrize("case_alias", _P1B_RETENTION_CASES, ids=_P1B_RETENTION_CASES)
@pytest.mark.asyncio
async def test_sqlite_p1b_submission_and_receipt_retention_contract(case_alias: str) -> None:
    if case_alias.startswith("submission-"):
        connection, store, request = await _p1b_admission_case()
        try:
            if case_alias == "submission-lookup-precedes-gateway":
                await connection.execute(
                    "UPDATE execution_gateway_state SET mode='emergency_disabled',"
                    "catalog_digest=?,activation_revision=2,activation_at=2,"
                    "revision=revision+1",
                    ("d" * 64,),
                )
                await connection.commit()
                candidate = request
            elif case_alias == "submission-replay-after-state-advance":
                await connection.execute(
                    "UPDATE logical_executions SET revision=revision+1 WHERE id=?",
                    (request.logical_execution_id,),
                )
                await connection.commit()
                candidate = request
            else:
                candidate = replace(request, module_id="test.p1b.changed")
            result = await store._create_initial_execution_v2_for_migration_fixture(candidate)
        finally:
            await connection.close()
        assert result.result is (
            FixedResult.CONFLICT_OPERATION
            if case_alias == "submission-changed-request-conflict"
            else FixedResult.REPLAYED
        )
        return
    connection = await _new_connection()
    try:
        store, spec = await _p1b_insert_literal_receipt(connection, "outbox_purge")
        if case_alias == "receipt-update-rejected":
            with pytest.raises(
                sqlite3.IntegrityError,
                match="immutable execution operation receipt",
            ):
                await connection.execute(
                    "UPDATE execution_operation_receipts SET result_revision=result_revision+1"
                )
        elif case_alias == "receipt-delete-rejected":
            with pytest.raises(
                sqlite3.IntegrityError,
                match="immutable execution operation receipt",
            ):
                await connection.execute("DELETE FROM execution_operation_receipts")
        else:
            async with store._transaction() as transaction:
                result = await store._classify_receipt(transaction, spec, current_revision=None)
            assert (result.result, result.revision) == (FixedResult.REPLAYED, 10)
    finally:
        await connection.close()


@pytest.mark.parametrize("case_alias", _P1B_ATOMICITY_CASES, ids=_P1B_ATOMICITY_CASES)
@pytest.mark.asyncio
async def test_sqlite_p1b_receipt_atomicity_and_nonduplication(
    case_alias: str, monkeypatch
) -> None:
    connection = await _new_connection()
    store = ExecutionLifecycleStore(connection, "sqlite")
    try:
        if case_alias == "exact-replay-no-duplicate-side-effects":
            store, spec = await _p1b_insert_literal_receipt(connection, "actor_authority_ensure")
            async with store._transaction() as transaction:
                replay = await store._classify_receipt(transaction, spec, current_revision=None)
            assert (replay.result, replay.revision) == (FixedResult.REPLAYED, 10)
        else:
            await connection.execute(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
                (_uuid(3200), "p1b-atomic", "fixed", "admin", "fixed"),
            )
            await connection.commit()

            async def fail_receipt(*_args, **_kwargs) -> None:
                raise RuntimeError("fixed-p1b-receipt-failure")

            monkeypatch.setattr(store, "_insert_receipt", fail_receipt)
            with pytest.raises(RuntimeError, match="fixed-p1b-receipt-failure"):
                await store.ensure_actor_authority(_uuid(3200), _uuid(3201))
            authority = int(
                (
                    await (
                        await connection.execute(
                            "SELECT count(*) FROM execution_actor_authority_revisions "
                            "WHERE user_id=?",
                            (_uuid(3200),),
                        )
                    ).fetchone()
                )[0]
            )
            assert authority == 0
        receipt_row = await (
            await connection.execute("SELECT count(*) FROM execution_operation_receipts")
        ).fetchone()
        receipts = int(receipt_row[0])
    finally:
        await connection.close()
    assert receipts == (1 if case_alias == "exact-replay-no-duplicate-side-effects" else 0)


@pytest.mark.parametrize("_case_alias", _P1B_CONCURRENCY_CASES, ids=_P1B_CONCURRENCY_CASES)
@pytest.mark.asyncio
async def test_sqlite_p1b_identical_operation_concurrency(tmp_path, _case_alias: str) -> None:
    path = (tmp_path / "p1b-identical.db").as_posix()
    first = await _new_connection(path)
    await first.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (_uuid(3300), "p1b-race", "fixed", "admin", "fixed"),
    )
    await first.commit()
    second = await aiosqlite.connect(path)
    second.row_factory = aiosqlite.Row
    await second.execute("PRAGMA foreign_keys=ON")
    try:
        results = await asyncio.gather(
            ExecutionLifecycleStore(first, "sqlite").ensure_actor_authority(
                _uuid(3300), _uuid(3301)
            ),
            ExecutionLifecycleStore(second, "sqlite").ensure_actor_authority(
                _uuid(3300), _uuid(3301)
            ),
        )
        observed = await (
            await first.execute(
                "SELECT (SELECT count(*) FROM execution_actor_authority_revisions),"
                "(SELECT count(*) FROM execution_operation_receipts)"
            )
        ).fetchone()
    finally:
        await second.close()
        await first.close()
    assert {result.result for result in results} == {FixedResult.APPLIED, FixedResult.REPLAYED}
    assert tuple(observed) == (1, 1)


def _blocked_snapshot() -> AttemptPolicySnapshot:
    return AttemptPolicySnapshot(
        actor_authority_revision=0,
        campaign_authority_revision=0,
        destination_authority_revision=0,
        credential_authority_revision=0,
        evaluation_mode="live",
        request_structure_valid=True,
        canonicalization_complete=True,
        unknown_fields_absent=True,
        alternate_transport_absent=True,
        bounded_shape_valid=True,
        request_shape_units=1,
        descriptor_semantic_digest="a" * 64,
        catalog_digest="b" * 64,
        trusted_first_party_binding=True,
        descriptor_binding_current=True,
        descriptor_complete=True,
        static_policy_evaluable=True,
        minimum_role="operator",
        noise_class="low",
        approval_policy="none",
        required_capability_mask=1,
        descriptor_blocker_mask=0,
        preview_ready=False,
        lifecycle_ready=False,
        result_authority_ready=False,
        transport_ready=False,
        future_gateway_eligible=False,
        authority_snapshots_complete=True,
        authority_revisions_current=True,
        actor_authenticated=True,
        actor_active=True,
        actor_role="reporter",
        campaign_active=True,
        actor_campaign_authorized=True,
        approval_present=False,
        approval_current=False,
        approval_exactly_bound=False,
        granted_capability_mask=0,
        destination_extraction_complete=True,
        destinations_in_scope=True,
        credential_authority_resolved=True,
        credential_authority_current=True,
        opaque_handles_only=True,
        permitted_handle_kinds_only=True,
        raw_credentials_absent=True,
        ambient_credentials_absent=True,
        budget_authority_resolved=True,
        budget_authority_current=True,
        budget_capacity_available=False,
        gateway_mode_snapshot="disabled",
        gateway_decision_code="none",
        policy_evaluation_state="evaluated",
        policy_verdict="blocked",
        policy_reason_mask=PolicyReasonBit.INSUFFICIENT_ROLE.value,
        external_effect_class="read_only",
        idempotency_class="unproven_current_contract",
        retry_policy="blocked_unproven_prior_attempt",
        retry_disposition="forbidden",
        cancellation_ownership="unproven_current_contract",
        compensation_class="unproven_current_contract",
        timeout_origin="observed_legacy_engine_default",
        timeout_limit_ms=1_000,
        timeout_settlement="unproven_current_contract",
    )


async def _persist_role_cell(actor: str, minimum: str, satisfies: bool) -> tuple[str, FixedResult]:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(110), "role-cell", "fixed-hash", actor, "fixed"),
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name) VALUES(?,?)", (_uuid(111), "role-cell")
        )
        await connection.execute(
            "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
            "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
            ("c" * 64,),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        assert (
            await store.ensure_actor_authority(_uuid(110), _uuid(112))
        ).result is FixedResult.APPLIED, "actor authority setup failed"
        assert (
            await store.ensure_campaign_authority(_uuid(111), _uuid(113))
        ).result is FixedResult.APPLIED, "campaign authority setup failed"
        budgets = None
        initial_state = AttemptState.BLOCKED
        snapshot = replace(
            _blocked_snapshot(),
            actor_role=actor,
            minimum_role=minimum,
            gateway_mode_snapshot="enforced",
            policy_verdict="blocked",
            policy_reason_mask=PolicyReasonBit.INSUFFICIENT_ROLE.value,
        )
        if satisfies:
            configured = await store.configure_campaign_budgets(
                BudgetConfiguration(
                    _uuid(111), _uuid(114), 10, _uuid(115), 10, _uuid(116), 1, _uuid(117)
                )
            )
            assert configured.result is FixedResult.APPLIED, "budget setup failed"
            budgets = BudgetReservation(
                _uuid(111),
                _uuid(120),
                _uuid(114),
                _uuid(121),
                1,
                0,
                _uuid(115),
                _uuid(122),
                1,
                0,
                _uuid(116),
                _uuid(123),
                0,
                _uuid(124),
            )
            initial_state = AttemptState.ACCEPTED
            snapshot = replace(
                snapshot,
                preview_ready=True,
                lifecycle_ready=True,
                result_authority_ready=True,
                transport_ready=True,
                future_gateway_eligible=True,
                budget_capacity_available=True,
                gateway_mode_snapshot="enforced",
                granted_capability_mask=1,
                policy_verdict="live_candidate",
                policy_reason_mask=0,
            )
        result = await store._create_initial_execution_v2_for_migration_fixture(
            AdmissionRequest(
                _uuid(118),
                _uuid(119),
                _uuid(120),
                _uuid(125) if not satisfies else None,
                _uuid(126) if not satisfies else None,
                _uuid(111),
                _uuid(110),
                _uuid(110),
                "test.role-cell",
                "sdk",
                initial_state,
                _uuid(127),
                snapshot,
                budgets=budgets,
            )
        )
        row = await (
            await connection.execute(
                "SELECT state FROM execution_attempts WHERE id=?", (_uuid(120),)
            )
        ).fetchone()
        return str(row[0]), result.result
    finally:
        await connection.close()


def _accepted_snapshot() -> AttemptPolicySnapshot:
    return replace(
        _blocked_snapshot(),
        actor_role="operator",
        granted_capability_mask=1,
        preview_ready=True,
        lifecycle_ready=True,
        result_authority_ready=True,
        transport_ready=True,
        future_gateway_eligible=True,
        budget_capacity_available=True,
        gateway_mode_snapshot="enforced",
        policy_verdict="live_candidate",
        policy_reason_mask=0,
    )


_ACCEPTANCE_FACT_MUTATIONS = (
    ("evaluation-mode", "evaluation_mode", "preview"),
    ("request-structure", "request_structure_valid", False),
    ("canonicalization", "canonicalization_complete", False),
    ("unknown-fields", "unknown_fields_absent", False),
    ("alternate-transport", "alternate_transport_absent", False),
    ("bounded-shape", "bounded_shape_valid", False),
    ("descriptor-trust", "trusted_first_party_binding", False),
    ("descriptor-current", "descriptor_binding_current", False),
    ("descriptor-complete", "descriptor_complete", False),
    ("static-policy", "static_policy_evaluable", False),
    ("descriptor-blocker", "descriptor_blocker_mask", 1),
    ("preview-ready", "preview_ready", False),
    ("lifecycle-ready", "lifecycle_ready", False),
    ("result-ready", "result_authority_ready", False),
    ("transport-ready", "transport_ready", False),
    ("gateway-eligible", "future_gateway_eligible", False),
    ("authority-snapshots", "authority_snapshots_complete", False),
    ("authority-current", "authority_revisions_current", False),
    ("actor-authenticated", "actor_authenticated", False),
    ("actor-active", "actor_active", False),
    ("campaign-active", "campaign_active", False),
    ("campaign-authorized", "actor_campaign_authorized", False),
    ("minimum-role", "minimum_role", "admin"),
    ("high-noise", "noise_class", "high_noise"),
    ("capability-all-of", "granted_capability_mask", 0),
    ("destination-extraction", "destination_extraction_complete", False),
    ("destination-scope", "destinations_in_scope", False),
    ("credential-resolved", "credential_authority_resolved", False),
    ("credential-current", "credential_authority_current", False),
    ("opaque-handles", "opaque_handles_only", False),
    ("handle-kinds", "permitted_handle_kinds_only", False),
    ("raw-credentials", "raw_credentials_absent", False),
    ("ambient-credentials", "ambient_credentials_absent", False),
    ("budget-resolved", "budget_authority_resolved", False),
    ("budget-current", "budget_authority_current", False),
    ("budget-capacity", "budget_capacity_available", False),
    ("gateway-decision", "gateway_decision_code", "emergency_disabled"),
    ("policy-state", "policy_evaluation_state", "not_evaluated"),
    ("policy-verdict", "policy_verdict", "preview_ready"),
    ("policy-reason", "policy_reason_mask", 1),
)


@pytest.mark.parametrize(
    ("_case", "field_name", "mutant"),
    _ACCEPTANCE_FACT_MUTATIONS,
    ids=tuple(item[0] for item in _ACCEPTANCE_FACT_MUTATIONS),
)
@pytest.mark.asyncio
async def test_each_acceptance_fact_fails_before_insert(
    _case: str, field_name: str, mutant: object
) -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(940), "admission-fact", "fixed-hash", "operator", "fixed"),
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name) VALUES(?,?)", (_uuid(941), "admission-fact")
        )
        await connection.execute(
            "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
            "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
            ("c" * 64,),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        assert (
            await store.ensure_actor_authority(_uuid(940), _uuid(942))
        ).result is FixedResult.APPLIED, "admission actor setup failed"
        assert (
            await store.ensure_campaign_authority(_uuid(941), _uuid(943))
        ).result is FixedResult.APPLIED, "admission campaign setup failed"
        assert (
            await store.configure_campaign_budgets(
                BudgetConfiguration(
                    _uuid(941), _uuid(944), 10, _uuid(945), 10, _uuid(946), 1, _uuid(947)
                )
            )
        ).result is FixedResult.APPLIED, "admission budget setup failed"
        snapshot = replace(_accepted_snapshot(), actor_role="operator", **{field_name: mutant})
        request = AdmissionRequest(
            _uuid(948),
            _uuid(949),
            _uuid(950),
            None,
            None,
            _uuid(941),
            _uuid(940),
            _uuid(940),
            "test.admission-fact",
            "sdk",
            AttemptState.ACCEPTED,
            _uuid(951),
            snapshot,
            budgets=BudgetReservation(
                _uuid(941),
                _uuid(950),
                _uuid(944),
                _uuid(952),
                1,
                0,
                _uuid(945),
                _uuid(953),
                1,
                0,
                _uuid(946),
                _uuid(954),
                0,
                _uuid(955),
            ),
        )
        result = await store._create_initial_execution_v2_for_migration_fixture(request)
        counts = await (
            await connection.execute(
                "SELECT (SELECT count(*) FROM logical_executions),"
                "(SELECT count(*) FROM execution_attempts),"
                "(SELECT count(*) FROM campaign_execution_budget_ledger)"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert result.result is not FixedResult.APPLIED, "invalid acceptance fact committed"
    assert tuple(counts) == (0, 0, 0), "invalid acceptance fact left partial state"


class _AdvancedClockLifecycleStore(ExecutionLifecycleStore):
    @property
    def _now_sql(self) -> str:
        return "9007199254740990"


async def _new_transition_case(
    path: str, initial: AttemptState
) -> tuple[aiosqlite.Connection, ExecutionLifecycleStore]:
    connection = await _new_connection(path)
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (_uuid(200), "transition-admin", "fixed-hash", "admin", "fixed"),
    )
    await connection.execute(
        "INSERT INTO campaigns(id,name) VALUES(?,?)", (_uuid(201), "transition-case")
    )
    await connection.execute(
        "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
        "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
        ("c" * 64,),
    )
    await connection.commit()
    store = ExecutionLifecycleStore(connection, "sqlite")
    assert (
        await store.ensure_actor_authority(_uuid(200), _uuid(202))
    ).result is FixedResult.APPLIED, "transition actor authority setup failed"
    assert (
        await store.ensure_campaign_authority(_uuid(201), _uuid(203))
    ).result is FixedResult.APPLIED, "transition campaign authority setup failed"
    if initial is AttemptState.ACCEPTED:
        assert (
            await store.configure_campaign_budgets(
                BudgetConfiguration(
                    _uuid(201), _uuid(204), 20, _uuid(205), 20, _uuid(206), 1, _uuid(207)
                )
            )
        ).result is FixedResult.APPLIED, "transition budget setup failed"
        budgets = BudgetReservation(
            _uuid(201),
            _uuid(210),
            _uuid(204),
            _uuid(214),
            2,
            0,
            _uuid(205),
            _uuid(215),
            3,
            0,
            _uuid(206),
            _uuid(216),
            0,
            _uuid(217),
        )
        request = AdmissionRequest(
            _uuid(208),
            _uuid(209),
            _uuid(210),
            None,
            None,
            _uuid(201),
            _uuid(200),
            _uuid(200),
            "test.transition",
            "sdk",
            AttemptState.ACCEPTED,
            _uuid(211),
            replace(_accepted_snapshot(), actor_role="admin"),
            budgets=budgets,
        )
    else:
        snapshot = replace(
            _blocked_snapshot(),
            actor_role="admin",
            gateway_mode_snapshot="enforced",
            policy_verdict="rejected" if initial is AttemptState.REJECTED else "blocked",
            policy_reason_mask=(
                PolicyReasonBit.INVALID_REQUEST.value
                if initial is AttemptState.REJECTED
                else PolicyReasonBit.INSUFFICIENT_ROLE.value
            ),
        )
        request = AdmissionRequest(
            _uuid(208),
            _uuid(209),
            _uuid(210),
            _uuid(212),
            _uuid(213),
            _uuid(201),
            _uuid(200),
            _uuid(200),
            "test.transition",
            "sdk",
            initial,
            _uuid(211),
            snapshot,
        )
    assert (
        await store._create_initial_execution_v2_for_migration_fixture(request)
    ).result is FixedResult.APPLIED, "transition admission setup failed"
    await connection.execute(
        "INSERT INTO hosts(id,campaign_id,ip_address) VALUES(?,?,?)",
        (_uuid(260), _uuid(201), "192.0.2.1"),
    )
    await connection.commit()
    return connection, store


async def _attempt_row(connection: aiosqlite.Connection):
    return await (
        await connection.execute(
            "SELECT state,revision,dispatch_owner_ref,lease_generation,"
            "cancellation_request_revision,start_operation_id FROM execution_attempts "
            "WHERE id=?",
            (_uuid(210),),
        )
    ).fetchone()


async def _nonterminal_transition(
    store: ExecutionLifecycleStore,
    connection: aiosqlite.Connection,
    target: AttemptState,
    operation_number: int,
):
    row = await _attempt_row(connection)
    state = AttemptState(str(row[0]))
    revision = int(row[1])
    dispatched = row[2] is not None
    values: dict[str, object] = {}
    if target is AttemptState.DISPATCHING:
        values = {"owner_ref": _uuid(220), "lease_generation": 1, "lease_duration_ms": 1_000}
    elif dispatched:
        values = {"owner_ref": _uuid(220), "lease_generation": int(row[3])}
    if state is AttemptState.CANCELLING:
        values["cancellation_request_revision"] = int(row[4])
    values["campaign_id"] = _uuid(201)
    if "owner_ref" not in values:
        values.update(
            actor_subject_ref=_uuid(200),
            actor_user_id=_uuid(200),
            actor_authority_revision=0,
        )
    request = TransitionRequest(_uuid(210), revision, target, _uuid(operation_number), **values)
    if target is AttemptState.SETTLEMENT_PENDING:
        request = replace(
            request,
            outbox_id=_uuid(operation_number + 1),
            publication_key=_uuid(operation_number + 2),
        )
        return await store.enter_settlement_pending(request)
    return await store.transition_attempt(request)


async def _terminal_transition(
    store: ExecutionLifecycleStore,
    connection: aiosqlite.Connection,
    target: AttemptState,
    operation_number: int,
):
    row = await _attempt_row(connection)
    state = AttemptState(str(row[0]))
    revision = int(row[1])
    started = row[5] is not None
    values: dict[str, object] = {}
    if row[2] is not None and target is not AttemptState.INDETERMINATE:
        values.update(owner_ref=_uuid(220), lease_generation=int(row[3]))
    if state is AttemptState.CANCELLING:
        values["cancellation_request_revision"] = int(row[4])
    outcome = {
        AttemptState.SUCCEEDED: OutcomeCode.CONFIRMED_SUCCESS,
        AttemptState.PARTIAL: OutcomeCode.CONFIRMED_PARTIAL,
        AttemptState.SKIPPED: OutcomeCode.ORCHESTRATION_SKIPPED,
        AttemptState.CANCELLED: OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
        AttemptState.TIMED_OUT: OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
        AttemptState.INDETERMINATE: OutcomeCode.UNKNOWN_AFTER_RECOVERY,
    }.get(target)
    if target is AttemptState.FAILED:
        outcome = (
            OutcomeCode.CONFIRMED_FAILURE if started else OutcomeCode.CONFIRMED_FAILURE_NO_DISPATCH
        )
    proof = {
        AttemptState.SUCCEEDED: "worker_terminal_ack",
        AttemptState.PARTIAL: "worker_terminal_ack",
        AttemptState.FAILED: "worker_terminal_ack" if started else "no_dispatch",
        AttemptState.SKIPPED: "no_dispatch",
        AttemptState.CANCELLED: "cancellation_no_result_ack",
        AttemptState.TIMED_OUT: "timeout_termination_ack",
        AttemptState.INDETERMINATE: "bounded_recovery_exhausted",
    }.get(target)
    if target is AttemptState.INDETERMINATE:
        values.update(
            resolver_subject_ref=_uuid(200),
            resolver_user_id=_uuid(200),
            resolver_authority_revision=0,
        )
    transition = TransitionRequest(
        _uuid(210),
        revision,
        target,
        _uuid(operation_number),
        outcome_code=outcome,
        authoritative_proof=proof,
        campaign_id=_uuid(201),
        actor_subject_ref=(
            None if "owner_ref" in values or "resolver_subject_ref" in values else _uuid(200)
        ),
        actor_user_id=(
            None if "owner_ref" in values or "resolver_subject_ref" in values else _uuid(200)
        ),
        actor_authority_revision=(
            None if "owner_ref" in values or "resolver_subject_ref" in values else 0
        ),
        **values,
    )
    assert not (
        transition.resolver_subject_ref is not None and transition.actor_subject_ref is not None
    ), "transition principal bindings overlapped"
    budget_rows = await (
        await connection.execute(
            "SELECT budget_kind,id,revision FROM campaign_execution_budgets "
            "WHERE campaign_id=? ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
            "WHEN 'exfiltration' THEN 2 ELSE 3 END",
            (_uuid(201),),
        )
    ).fetchall()
    budget_by_kind = {str(item[0]): (str(item[1]), int(item[2])) for item in budget_rows}
    full = target is AttemptState.INDETERMINATE
    if not budget_by_kind:
        budget_by_kind = {
            "noise": (_uuid(204), 0),
            "exfiltration": (_uuid(205), 0),
            "concurrency": (_uuid(206), 0),
        }
    settlement = BudgetSettlement(
        _uuid(201),
        _uuid(210),
        budget_by_kind["noise"][0],
        2,
        2 if full else 0,
        budget_by_kind["noise"][1],
        budget_by_kind["exfiltration"][0],
        3,
        3 if full else 0,
        budget_by_kind["exfiltration"][1],
        budget_by_kind["concurrency"][0],
        budget_by_kind["concurrency"][1],
        _uuid(operation_number + 1),
    )
    outputs = (
        (OutputObservation(_uuid(operation_number + 4), OutputKind.HOST, _uuid(260)),)
        if target is AttemptState.PARTIAL
        else ()
    )
    return await store.commit_terminal_attempt(
        TerminalCommitRequest(
            _uuid(208),
            _uuid(201),
            _uuid(operation_number + 2),
            _uuid(operation_number + 3),
            transition,
            settlement,
            outputs,
        )
    )


async def _build_source_state(
    store: ExecutionLifecycleStore,
    connection: aiosqlite.Connection,
    source: AttemptState,
) -> None:
    if source is AttemptState.ACCEPTED:
        return
    if source is AttemptState.QUEUED:
        result = await _nonterminal_transition(store, connection, source, 230)
    elif source is AttemptState.DISPATCHING:
        result = await _nonterminal_transition(store, connection, source, 231)
    else:
        result = await _nonterminal_transition(store, connection, AttemptState.DISPATCHING, 231)
        assert result.result is FixedResult.APPLIED, "source dispatch failed"
        if source is AttemptState.CANCELLING and False:
            return
        result = await _nonterminal_transition(store, connection, AttemptState.RUNNING, 232)
        if source in {AttemptState.RUNNING}:
            pass
        elif source is AttemptState.CANCELLING:
            assert result.result is FixedResult.APPLIED, "source start failed"
            result = await _nonterminal_transition(store, connection, source, 233)
        elif source is AttemptState.SETTLEMENT_PENDING:
            assert result.result is FixedResult.APPLIED, "source start failed"
            result = await _nonterminal_transition(store, connection, source, 234)
        elif source in {
            AttemptState.SUCCEEDED,
            AttemptState.PARTIAL,
            AttemptState.TIMED_OUT,
            AttemptState.INDETERMINATE,
        }:
            assert result.result is FixedResult.APPLIED, "source start failed"
            if source is AttemptState.INDETERMINATE:
                pending = await _nonterminal_transition(
                    store, connection, AttemptState.SETTLEMENT_PENDING, 234
                )
                assert pending.result is FixedResult.APPLIED, "source recovery failed"
                store = _AdvancedClockLifecycleStore(connection, "sqlite")
            result = await _terminal_transition(store, connection, source, 270)
        elif source in {AttemptState.FAILED, AttemptState.SKIPPED}:
            raise AssertionError("terminal source must use no-dispatch builder")
        elif source is AttemptState.CANCELLED:
            assert result.result is FixedResult.APPLIED, "source start failed"
            cancelling = await _nonterminal_transition(
                store, connection, AttemptState.CANCELLING, 233
            )
            assert cancelling.result is FixedResult.APPLIED, "source cancel failed"
            result = await _terminal_transition(store, connection, source, 270)
        else:
            raise AssertionError("unsupported source state")
    assert result.result is FixedResult.APPLIED, "source transition failed"


async def _snapshot_case(
    connection: aiosqlite.Connection,
) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
    tables = (
        "logical_executions",
        "execution_attempts",
        "campaign_execution_budgets",
        "campaign_execution_budget_ledger",
        "execution_output_links",
        "execution_publication_outbox",
        "execution_operation_receipts",
        "hosts",
    )
    observed = []
    for table in tables:
        rows = await (
            await connection.execute(
                f"SELECT * FROM {table} ORDER BY 1"  # noqa: S608 - fixed tuple.
            )
        ).fetchall()
        observed.append((table, tuple(tuple(row) for row in rows)))
    return tuple(observed)


async def _exercise_transition_pair(path, source: str, target: str):
    source_state = AttemptState(source)
    target_state = AttemptState(target)
    initial = (
        source_state
        if source_state in {AttemptState.REJECTED, AttemptState.BLOCKED}
        else AttemptState.ACCEPTED
    )
    connection, store = await _new_transition_case(path.as_posix(), initial)
    observer = await aiosqlite.connect(path.as_posix())
    try:
        if initial is AttemptState.ACCEPTED:
            if source_state in {AttemptState.FAILED, AttemptState.SKIPPED}:
                result = await _terminal_transition(store, connection, source_state, 270)
                assert result.result is FixedResult.APPLIED, "terminal source setup failed"
            else:
                await _build_source_state(store, connection, source_state)
        before = await _snapshot_case(connection)
        if target_state in {
            AttemptState.QUEUED,
            AttemptState.DISPATCHING,
            AttemptState.RUNNING,
            AttemptState.CANCELLING,
            AttemptState.SETTLEMENT_PENDING,
        }:
            result = await _nonterminal_transition(store, connection, target_state, 400)
        elif target_state in {
            AttemptState.SUCCEEDED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.SKIPPED,
            AttemptState.CANCELLED,
            AttemptState.TIMED_OUT,
            AttemptState.INDETERMINATE,
        }:
            if (
                target_state is AttemptState.INDETERMINATE
                and source_state is AttemptState.SETTLEMENT_PENDING
            ):
                store = _AdvancedClockLifecycleStore(connection, "sqlite")
            result = await _terminal_transition(store, connection, target_state, 400)
        else:
            row = await _attempt_row(connection)
            result = await store.transition_attempt(
                TransitionRequest(
                    _uuid(210),
                    int(row[1]),
                    target_state,
                    _uuid(400),
                    campaign_id=_uuid(201),
                    actor_subject_ref=_uuid(200),
                    actor_user_id=_uuid(200),
                    actor_authority_revision=0,
                )
            )
        after = await _snapshot_case(connection)
        observer.row_factory = aiosqlite.Row
        durable = await _snapshot_case(observer)
        return result.result, before, after, durable
    finally:
        await observer.close()
        await connection.close()


async def _insert_retryable_attempt(connection: aiosqlite.Connection) -> None:
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
        (_uuid(1), "closure-admin", "fixed-hash", "admin", "fixed"),
    )
    await connection.execute(
        "INSERT INTO campaigns(id,name) VALUES(?,?)",
        (_uuid(2), "closure-campaign"),
    )
    await connection.execute(
        "INSERT INTO execution_actor_authority_revisions("
        "user_id,revision,latest_operation_id,latest_operation_base_revision,"
        "latest_operation_code,updated_at) VALUES(?,0,?,0,'ensure',1)",
        (_uuid(1), _uuid(3)),
    )
    await connection.execute(
        "INSERT INTO campaign_execution_authority_revisions("
        "campaign_id,revision,latest_operation_id,latest_operation_base_revision,"
        "latest_operation_code,updated_at) VALUES(?,0,?,0,'ensure',1)",
        (_uuid(2), _uuid(30)),
    )
    await connection.execute(
        "INSERT INTO logical_executions("
        "id,submission_id,campaign_id,actor_subject_ref,actor_user_id,module_id,"
        "ingress_code,admission_operation_id,submission_binding_contract_version,"
        "submission_request_binding_digest,submission_result_code,"
        "submission_exact_replay_code,submission_result_binding_digest,"
        "highest_attempt_ordinal,revision,created_at) "
        "VALUES(?,?,?,?,?,'test.module','sdk',?,2,?,'applied','replayed',?,0,0,1)",
        (
            _uuid(4),
            _uuid(5),
            _uuid(2),
            _uuid(1),
            _uuid(1),
            _uuid(31),
            "a" * 64,
            "b" * 64,
        ),
    )
    columns = (
        "id",
        "logical_execution_id",
        "campaign_id",
        "ordinal",
        "revision",
        "state",
        "closes_logical",
        "actor_subject_ref",
        "actor_user_id",
        "actor_authority_revision",
        "campaign_authority_revision",
        "destination_authority_revision",
        "credential_authority_revision",
        "request_contract_version",
        "evaluation_mode",
        "request_structure_valid",
        "canonicalization_complete",
        "unknown_fields_absent",
        "alternate_transport_absent",
        "bounded_shape_valid",
        "request_shape_units",
        "descriptor_contract_version",
        "descriptor_semantic_digest",
        "catalog_digest",
        "trusted_first_party_binding",
        "descriptor_binding_current",
        "descriptor_complete",
        "static_policy_evaluable",
        "minimum_role",
        "noise_class",
        "approval_policy",
        "capability_mask_version",
        "required_capability_mask",
        "descriptor_blocker_mask_version",
        "descriptor_blocker_mask",
        "preview_ready",
        "lifecycle_ready",
        "result_authority_ready",
        "transport_ready",
        "future_gateway_eligible",
        "authority_snapshots_complete",
        "authority_revisions_current",
        "actor_authenticated",
        "actor_active",
        "actor_role",
        "campaign_active",
        "actor_campaign_authorized",
        "approval_present",
        "approval_current",
        "approval_exactly_bound",
        "granted_capability_mask",
        "destination_extraction_complete",
        "destinations_in_scope",
        "credential_authority_resolved",
        "credential_authority_current",
        "opaque_handles_only",
        "permitted_handle_kinds_only",
        "raw_credentials_absent",
        "ambient_credentials_absent",
        "budget_authority_resolved",
        "budget_authority_current",
        "budget_capacity_available",
        "gateway_mode_snapshot",
        "gateway_decision_code",
        "policy_evaluation_state",
        "policy_contract_version",
        "policy_verdict",
        "policy_reason_mask_version",
        "policy_reason_mask",
        "external_effect_class",
        "idempotency_class",
        "retry_policy",
        "retry_disposition",
        "cancellation_ownership",
        "compensation_class",
        "timeout_origin",
        "timeout_limit_ms",
        "timeout_settlement",
        "outcome_code",
        "error_action_code",
        "settlement_state",
        "settlement_proof_code",
        "termination_confirmed",
        "lease_generation",
        "terminal_operation_id",
        "created_at",
        "finished_at",
        "settled_at",
    )
    values = (
        _uuid(6),
        _uuid(4),
        _uuid(2),
        0,
        0,
        "failed",
        0,
        _uuid(1),
        _uuid(1),
        0,
        0,
        0,
        0,
        1,
        "live",
        1,
        1,
        1,
        1,
        1,
        1,
        "ares.module-descriptor.v2",
        "a" * 64,
        "b" * 64,
        1,
        1,
        1,
        1,
        "operator",
        "low",
        "none",
        1,
        0,
        1,
        0,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        "admin",
        1,
        1,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        "enforced",
        "none",
        "evaluated",
        1,
        "live_candidate",
        1,
        0,
        "read_only",
        "proven_idempotent",
        "after_revalidation",
        "eligible",
        "owned",
        "not_applicable",
        "module_defined_bounded",
        1_000,
        "proven",
        "confirmed_failure_no_dispatch",
        "none",
        "not_applicable",
        "no_dispatch",
        0,
        0,
        _uuid(7),
        1,
        1,
        1,
    )
    await connection.execute(
        "INSERT INTO execution_attempts("
        + ",".join(columns)
        + ") VALUES("
        + ",".join("?" for _ in columns)
        + ")",
        values,
    )
    await connection.commit()


@pytest.mark.asyncio
async def test_authority_ensure_and_invalidate_are_exactly_replayable() -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_UUIDS[0], "fixed-user", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        created = await store.ensure_actor_authority(_UUIDS[0], _UUIDS[1])
        replay = await store.ensure_actor_authority(_UUIDS[0], _UUIDS[1])
        invalidated = await store.invalidate_actor_authority(_UUIDS[0], 0, _UUIDS[2])
        stale = await store.invalidate_actor_authority(_UUIDS[0], 0, _UUIDS[3])
    finally:
        await connection.close()
    assert (created.result, replay.result, invalidated.result, stale.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
        FixedResult.APPLIED,
        FixedResult.CONFLICT_REVISION,
    ), "authority CAS result changed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("snapshot", "reason"),
    [
        (_blocked_snapshot(), PolicyReasonBit.INSUFFICIENT_ROLE.value),
        (
            replace(
                _blocked_snapshot(),
                actor_role="operator",
                required_capability_mask=3,
                granted_capability_mask=1,
                policy_reason_mask=PolicyReasonBit.CAPABILITY_REQUIRED.value,
            ),
            PolicyReasonBit.CAPABILITY_REQUIRED.value,
        ),
        (
            replace(
                _blocked_snapshot(),
                actor_role="operator",
                policy_verdict="preview_ready",
                policy_reason_mask=PolicyReasonBit.PREVIEW_NOT_READY.value,
            ),
            PolicyReasonBit.PREVIEW_NOT_READY.value,
        ),
    ],
    ids=("reporter-role", "capability", "preview-live"),
)
async def test_durable_block_creates_zero_budget_terminal_snapshot(
    snapshot: AttemptPolicySnapshot, reason: int
) -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(40), "blocked-user", "fixed-hash", snapshot.actor_role, "fixed"),
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name) VALUES(?,?)",
            (_uuid(41), "blocked-campaign"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        await store.ensure_actor_authority(_uuid(40), _uuid(42))
        await store.ensure_campaign_authority(_uuid(41), _uuid(43))
        request = AdmissionRequest(
            _uuid(44),
            _uuid(45),
            _uuid(46),
            _uuid(47),
            _uuid(48),
            _uuid(41),
            _uuid(40),
            _uuid(40),
            "test.module",
            "sdk",
            AttemptState.BLOCKED,
            _uuid(49),
            snapshot,
        )
        created = await store._create_initial_execution_v2_for_migration_fixture(request)
        replayed = await store._create_initial_execution_v2_for_migration_fixture(request)
        attempt = await (
            await connection.execute(
                "SELECT state,policy_reason_mask,closes_logical,outcome_code "
                "FROM execution_attempts"
            )
        ).fetchone()
        observed_counts = []
        for table in (
            "execution_attempt_approvals",
            "campaign_execution_budget_ledger",
            "campaign_execution_budgets",
        ):
            cursor = await connection.execute(
                "SELECT count(*) FROM " + table  # noqa: S608
            )
            row = await cursor.fetchone()
            observed_counts.append(int(row[0]))
        counts = tuple(observed_counts)
    finally:
        await connection.close()
    assert (created.result, replayed.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
    ), "durable block replay changed"
    assert tuple(attempt) == ("blocked", reason, 1, "policy_blocked"), "blocked snapshot changed"
    assert counts == (0, 0, 0), "blocked decision reserved budget"


@pytest.mark.asyncio
async def test_accepted_creation_reserves_all_budgets_in_one_transaction() -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(60), "accept-admin", "fixed-hash", "admin", "fixed"),
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name) VALUES(?,?)", (_uuid(61), "accept")
        )
        await connection.execute(
            "UPDATE execution_gateway_state SET mode='enforced',catalog_digest=?,"
            "activation_revision=1,activation_at=1,revision=1 WHERE singleton_id=1",
            ("c" * 64,),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        await store.ensure_actor_authority(_uuid(60), _uuid(62))
        await store.ensure_campaign_authority(_uuid(61), _uuid(63))
        await store.configure_campaign_budgets(
            BudgetConfiguration(
                _uuid(61),
                _uuid(64),
                10,
                _uuid(65),
                10,
                _uuid(66),
                1,
                _uuid(67),
            )
        )
        snapshot = replace(
            _blocked_snapshot(),
            actor_role="admin",
            required_capability_mask=1,
            granted_capability_mask=1,
            preview_ready=True,
            lifecycle_ready=True,
            result_authority_ready=True,
            transport_ready=True,
            future_gateway_eligible=True,
            budget_capacity_available=True,
            gateway_mode_snapshot="enforced",
            policy_verdict="live_candidate",
            policy_reason_mask=0,
        )
        budgets = BudgetReservation(
            _uuid(61),
            _uuid(70),
            _uuid(64),
            _uuid(71),
            2,
            0,
            _uuid(65),
            _uuid(72),
            3,
            0,
            _uuid(66),
            _uuid(73),
            0,
            _uuid(74),
        )
        request = AdmissionRequest(
            _uuid(68),
            _uuid(69),
            _uuid(70),
            None,
            None,
            _uuid(61),
            _uuid(60),
            _uuid(60),
            "test.module",
            "sdk",
            AttemptState.ACCEPTED,
            _uuid(75),
            snapshot,
            budgets=budgets,
        )
        created = await store._create_initial_execution_v2_for_migration_fixture(request)
        attempt = await (
            await connection.execute(
                "SELECT state,settlement_state,closes_logical FROM execution_attempts"
            )
        ).fetchone()
        ledgers = await (
            await connection.execute(
                "SELECT budget_kind,reservation_units,disposition "
                "FROM campaign_execution_budget_ledger ORDER BY budget_kind"
            )
        ).fetchall()
        outbox_count = await (
            await connection.execute("SELECT count(*) FROM execution_publication_outbox")
        ).fetchone()
        dispatched = await store.transition_attempt(
            TransitionRequest(
                _uuid(70),
                0,
                AttemptState.DISPATCHING,
                _uuid(76),
                owner_ref=_uuid(77),
                lease_generation=1,
                lease_duration_ms=1_000,
                campaign_id=_uuid(61),
            )
        )
        running = await store.transition_attempt(
            TransitionRequest(
                _uuid(70),
                1,
                AttemptState.RUNNING,
                _uuid(78),
                owner_ref=_uuid(77),
                lease_generation=1,
                campaign_id=_uuid(61),
            )
        )
        terminal_request = TerminalCommitRequest(
            _uuid(68),
            _uuid(61),
            _uuid(79),
            _uuid(80),
            TransitionRequest(
                _uuid(70),
                2,
                AttemptState.SUCCEEDED,
                _uuid(81),
                owner_ref=_uuid(77),
                lease_generation=1,
                outcome_code=OutcomeCode.CONFIRMED_SUCCESS,
                authoritative_proof="worker_terminal_ack",
                campaign_id=_uuid(61),
            ),
            BudgetSettlement(
                _uuid(61),
                _uuid(70),
                _uuid(64),
                2,
                1,
                1,
                _uuid(65),
                3,
                2,
                1,
                _uuid(66),
                1,
                _uuid(82),
            ),
        )
        terminal = await store.commit_terminal_attempt(terminal_request)
        terminal_replay = await store.commit_terminal_attempt(terminal_request)
        finished = await (
            await connection.execute(
                "SELECT state,closes_logical,settlement_state,outcome_code FROM execution_attempts"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert created.result is FixedResult.APPLIED, "acceptance failed"
    assert tuple(attempt) == ("accepted", "reserved", 0), "attempt changed"
    assert tuple(tuple(row) for row in ledgers) == (
        ("concurrency", 1, "held"),
        ("exfiltration", 3, "held"),
        ("noise", 2, "held"),
    ), "acceptance reservations changed"
    assert int(outbox_count[0]) == 0, "acceptance published an event"
    assert (dispatched.result, running.result, terminal.result, terminal_replay.result) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
    ), "terminal transaction changed"
    assert tuple(finished) == ("succeeded", 1, "settled", "confirmed_success"), (
        "terminal state changed"
    )


@pytest.mark.asyncio
async def test_outbox_claim_renew_retry_reclaim_and_poison_are_cas_bound() -> None:
    connection = await _new_connection()
    try:
        await connection.execute("PRAGMA foreign_keys=OFF")
        await connection.execute(
            "INSERT INTO execution_publication_outbox("
            "id,publication_key,attempt_id,campaign_id,event_code,is_attempt_terminal,"
            "publication_state,delivery_attempt_count,available_at,lease_generation,"
            "claim_revision,latest_operation_id,latest_operation_code,"
            "latest_operation_base_revision,created_at) "
            "VALUES(?,?,?,?,?,0,'pending',0,1,0,0,?,'insert',0,1)",
            (_UUIDS[0], _UUIDS[1], _UUIDS[2], _UUIDS[3], "recovery_required", _UUIDS[1]),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        claimed = await store.claim_outbox(
            OutboxMutation(
                _UUIDS[0],
                0,
                _UUIDS[4],
                _UUIDS[5],
                0,
                _UUIDS[3],
                _UUIDS[2],
                _UUIDS[1],
                "recovery_required",
            )
        )
        renewed = await store.renew_outbox(
            OutboxMutation(
                _UUIDS[0],
                1,
                _UUIDS[6],
                _UUIDS[5],
                1,
                _UUIDS[3],
                _UUIDS[2],
                _UUIDS[1],
                "recovery_required",
            )
        )
        retried = await store.fail_outbox(
            OutboxMutation(
                _UUIDS[0],
                2,
                _UUIDS[7],
                _UUIDS[5],
                1,
                _UUIDS[3],
                _UUIDS[2],
                _UUIDS[1],
                "recovery_required",
            ),
            retryable=True,
        )
        row = await (
            await connection.execute(
                "SELECT publication_state,delivery_attempt_count,claim_revision,"
                "latest_operation_code FROM execution_publication_outbox"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert (claimed.result, renewed.result, retried.result) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
        FixedResult.APPLIED,
    ), "outbox CAS result changed"
    assert tuple(row) == ("pending", 1, 3, "retryable_failure"), "outbox state changed"


@pytest.mark.asyncio
async def test_expired_twentieth_claim_is_poisoned_without_owner_cooperation() -> None:
    connection = await _new_connection()
    try:
        await connection.execute("PRAGMA foreign_keys=OFF")
        await connection.execute(
            "INSERT INTO execution_publication_outbox("
            "id,publication_key,attempt_id,campaign_id,event_code,is_attempt_terminal,"
            "publication_state,delivery_attempt_count,available_at,claim_owner_ref,"
            "lease_generation,claimed_at,lease_expires_at,failure_code,claim_revision,"
            "latest_operation_id,latest_operation_code,latest_operation_base_revision,"
            "created_at) VALUES(?,?,?,?,?,0,'claimed',20,NULL,?,20,1,1,NULL,20,?,"
            "'reclaim',19,1)",
            (
                _uuid(100),
                _uuid(101),
                _uuid(102),
                _uuid(103),
                "recovery_required",
                _uuid(104),
                _uuid(105),
            ),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        request = OutboxMutation(
            _uuid(100),
            20,
            _uuid(106),
            campaign_id=_uuid(103),
            attempt_id=_uuid(102),
            publication_key=_uuid(101),
            event_code="recovery_required",
        )
        applied = await store.poison_expired_attempt_twenty(request)
        replayed = await store.poison_expired_attempt_twenty(request)
        row = await (
            await connection.execute(
                "SELECT publication_state,claim_owner_ref,lease_generation,"
                "delivery_attempt_count,failure_code,claim_revision,latest_operation_id,"
                "latest_operation_code,latest_operation_base_revision "
                "FROM execution_publication_outbox"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert (applied.result, replayed.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
    ), "attempt-limit poison replay changed"
    assert tuple(row) == (
        "poisoned",
        None,
        20,
        20,
        "delivery_attempt_limit",
        21,
        _uuid(106),
        "poison",
        20,
    ), "attempt-limit poison state changed"


@pytest.mark.asyncio
async def test_budget_reserve_and_settle_use_post_cas_revisions() -> None:
    connection = await _new_connection()
    try:
        await _insert_retryable_attempt(connection)
        store = ExecutionLifecycleStore(connection, "sqlite")
        configured = await store.configure_campaign_budgets(
            BudgetConfiguration(
                _uuid(2),
                _uuid(110),
                10,
                _uuid(111),
                10,
                _uuid(112),
                2,
                _uuid(113),
            )
        )
        reserved = await store.reserve_budgets(
            BudgetReservation(
                _uuid(2),
                _uuid(6),
                _uuid(110),
                _uuid(114),
                4,
                0,
                _uuid(111),
                _uuid(115),
                5,
                0,
                _uuid(112),
                _uuid(116),
                0,
                _uuid(117),
            )
        )
        settled = await store.settle_budgets(
            BudgetSettlement(
                _uuid(2),
                _uuid(6),
                _uuid(110),
                4,
                3,
                1,
                _uuid(111),
                5,
                0,
                1,
                _uuid(112),
                1,
                _uuid(118),
            )
        )
        budget_rows = await (
            await connection.execute(
                "SELECT budget_kind,reserved_units,consumed_units,revision "
                "FROM campaign_execution_budgets ORDER BY CASE budget_kind "
                "WHEN 'noise' THEN 1 WHEN 'exfiltration' THEN 2 ELSE 3 END"
            )
        ).fetchall()
        ledger_rows = await (
            await connection.execute(
                "SELECT budget_kind,disposition,consumed_units,"
                "budget_revision_reserved,budget_revision_settled "
                "FROM campaign_execution_budget_ledger ORDER BY CASE budget_kind "
                "WHEN 'noise' THEN 1 WHEN 'exfiltration' THEN 2 ELSE 3 END"
            )
        ).fetchall()
    finally:
        await connection.close()
    assert (configured.result, reserved.result, settled.result) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
        FixedResult.APPLIED,
    ), "budget CAS result changed"
    assert tuple(tuple(row) for row in budget_rows) == (
        ("noise", 0, 3, 2),
        ("exfiltration", 0, 0, 2),
        ("concurrency", 0, 0, 2),
    ), "budget arithmetic changed"
    assert tuple(tuple(row) for row in ledger_rows) == (
        ("noise", "consumed", 3, 1, 2),
        ("exfiltration", "released", 0, 1, 2),
        ("concurrency", "released", 0, 1, 2),
    ), "ledger post-CAS revisions changed"


@pytest.mark.asyncio
async def test_budget_reservation_conflict_rolls_back_all_three_kinds() -> None:
    connection = await _new_connection()
    try:
        await _insert_retryable_attempt(connection)
        store = ExecutionLifecycleStore(connection, "sqlite")
        await store.configure_campaign_budgets(
            BudgetConfiguration(
                _uuid(2),
                _uuid(21),
                10,
                _uuid(22),
                10,
                _uuid(23),
                1,
                _uuid(24),
            )
        )
        result = await store.reserve_budgets(
            BudgetReservation(
                _uuid(2),
                _uuid(6),
                _uuid(21),
                _uuid(26),
                4,
                0,
                _uuid(22),
                _uuid(27),
                4,
                1,
                _uuid(23),
                _uuid(28),
                0,
                _uuid(29),
            )
        )
        rows = await (
            await connection.execute(
                "SELECT reserved_units,revision FROM campaign_execution_budgets "
                "ORDER BY budget_kind"
            )
        ).fetchall()
        ledgers = await (
            await connection.execute("SELECT count(*) FROM campaign_execution_budget_ledger")
        ).fetchone()
    finally:
        await connection.close()
    assert result.result is FixedResult.CONFLICT_REVISION, "conflict changed"
    assert tuple(tuple(row) for row in rows) == ((0, 0), (0, 0), (0, 0)), (
        "reservation conflict committed a partial mutation"
    )
    assert int(ledgers[0]) == 0, "reservation conflict created a ledger"


@pytest.mark.asyncio
async def test_close_without_retry_is_permanent_after_outbox_purge() -> None:
    connection = await _new_connection()
    try:
        await _insert_retryable_attempt(connection)
        store = ExecutionLifecycleStore(connection, "sqlite")
        request = ClosureRequest(
            _uuid(4),
            _uuid(6),
            _uuid(8),
            0,
            _uuid(9),
            _uuid(1),
            _uuid(1),
            0,
            _uuid(2),
        )
        applied = await store.close_without_retry(request)
        await connection.execute("DELETE FROM execution_publication_outbox WHERE id=?", (_uuid(8),))
        await connection.commit()
        replayed = await store.close_without_retry(request)
        conflicting = await store.close_without_retry(
            ClosureRequest(
                _uuid(4),
                _uuid(6),
                _uuid(10),
                1,
                _uuid(11),
                _uuid(1),
                _uuid(1),
                0,
                _uuid(2),
            )
        )
        logical = await (
            await connection.execute(
                "SELECT closure_operation_id,closing_attempt_id FROM logical_executions"
            )
        ).fetchone()
    finally:
        await connection.close()
    assert (applied.result, replayed.result, conflicting.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED_CLOSED,
        FixedResult.ALREADY_CLOSED,
    ), "closure replay changed"
    assert tuple(logical) == (_uuid(9), _uuid(6)), "permanent closure changed"


@pytest.mark.asyncio
async def test_retry_denial_child_uuid_replays_and_excludes_closure() -> None:
    connection = await _new_connection()
    try:
        await _insert_retryable_attempt(connection)
        store = ExecutionLifecycleStore(connection, "sqlite")
        child = AdmissionRequest(
            _uuid(4),
            _uuid(80),
            _uuid(81),
            _uuid(82),
            _uuid(83),
            _uuid(2),
            _uuid(1),
            _uuid(1),
            "test.module",
            "sdk",
            AttemptState.BLOCKED,
            _uuid(84),
            replace(
                _blocked_snapshot(),
                actor_role="admin",
                required_capability_mask=1,
                granted_capability_mask=0,
                policy_reason_mask=PolicyReasonBit.CAPABILITY_REQUIRED.value,
            ),
        )
        retry = RetryRequest(_uuid(4), _uuid(6), child, 0)
        applied = await store._create_retry_attempt_v2_for_migration_fixture(retry)
        replayed = await store._create_retry_attempt_v2_for_migration_fixture(retry)
        closure_loser = await store.close_without_retry(
            ClosureRequest(
                _uuid(4),
                _uuid(6),
                _uuid(85),
                1,
                _uuid(86),
                _uuid(1),
                _uuid(1),
                0,
                _uuid(2),
            )
        )
        attempts = await (
            await connection.execute(
                "SELECT id,parent_attempt_id,ordinal,state FROM execution_attempts ORDER BY ordinal"
            )
        ).fetchall()
    finally:
        await connection.close()
    assert (applied.result, replayed.result, closure_loser.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED_BOUND_CHILD,
        FixedResult.ALREADY_CLOSED,
    ), "retry/closure race changed"
    assert tuple(tuple(row) for row in attempts) == (
        (_uuid(6), None, 0, "failed"),
        (_uuid(81), _uuid(6), 1, "blocked"),
    ), "linear retry chain changed"


@pytest.mark.asyncio
async def test_closure_winner_excludes_retry_child() -> None:
    connection = await _new_connection()
    try:
        await _insert_retryable_attempt(connection)
        store = ExecutionLifecycleStore(connection, "sqlite")
        closed = await store.close_without_retry(
            ClosureRequest(
                _uuid(4),
                _uuid(6),
                _uuid(87),
                0,
                _uuid(88),
                _uuid(1),
                _uuid(1),
                0,
                _uuid(2),
            )
        )
        child = AdmissionRequest(
            _uuid(4),
            _uuid(89),
            _uuid(90),
            _uuid(91),
            _uuid(92),
            _uuid(2),
            _uuid(1),
            _uuid(1),
            "test.module",
            "sdk",
            AttemptState.BLOCKED,
            _uuid(93),
            _blocked_snapshot(),
        )
        retry = await store._create_retry_attempt_v2_for_migration_fixture(
            RetryRequest(_uuid(4), _uuid(6), child, 1)
        )
        attempt_count = await (
            await connection.execute("SELECT count(*) FROM execution_attempts")
        ).fetchone()
    finally:
        await connection.close()
    assert (closed.result, retry.result) == (
        FixedResult.APPLIED,
        FixedResult.ALREADY_CLOSED,
    ), "closure/retry race changed"
    assert int(attempt_count[0]) == 1, "closure loser created a child"


def test_only_exact_receipt_immutability_triggers_are_created() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(CREATE_TABLES)
        rows = connection.execute(
            "SELECT name,tbl_name FROM sqlite_schema WHERE type='trigger' "
            "AND tbl_name IN (?,?,?,?,?,?,?,?,?,?,?)",
            LIFECYCLE_TABLES,
        ).fetchall()
    finally:
        connection.close()
    assert tuple(sorted(rows)) == (
        ("trg_eor_immutable_delete", "execution_operation_receipts"),
        ("trg_eor_immutable_update", "execution_operation_receipts"),
    ), "lifecycle trigger inventory changed"


def test_exact_sqlite_catalog_validator_rejects_extra_lifecycle_index() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(CREATE_TABLES)
        connection.execute("CREATE INDEX unexpected_lifecycle_index ON execution_attempts(state)")
        rejected = False
        try:
            validate_sqlite_lifecycle_catalog(connection)
        except RuntimeError:
            rejected = True
    finally:
        connection.close()
    assert rejected is True, "unexpected lifecycle index passed validation"


def test_i53_boundary_is_exact() -> None:
    assert MAX_I53 == 9_007_199_254_740_991, "I53 boundary changed"


class _SQLiteZeroRowTraceStore(ExecutionLifecycleStore):
    """Record the real connection and transaction used after a zero-row write."""

    def __init__(self, connection: aiosqlite.Connection) -> None:
        super().__init__(connection, "sqlite")
        self.zero_connection_id: int | None = None
        self.zero_in_transaction = False
        self.classifier_connection_ids: list[int] = []
        self.classifier_in_transaction: list[bool] = []
        self._awaiting_classifier = False

    async def _returning_rows(
        self, connection: Any, sql: str, params: tuple[Any, ...]
    ) -> tuple[Any, ...]:
        rows = await super()._returning_rows(connection, sql, params)
        if not rows and "UPDATE execution_attempts SET" in sql:
            self.zero_connection_id = id(connection)
            self.zero_in_transaction = bool(connection.in_transaction)
            self._awaiting_classifier = True
        return rows

    async def _fetchrow(self, connection: Any, sql: str, params: tuple[Any, ...]) -> Any:
        if self._awaiting_classifier:
            self.classifier_connection_ids.append(id(connection))
            self.classifier_in_transaction.append(bool(connection.in_transaction))
        return await super()._fetchrow(connection, sql, params)


class _SQLiteWinnerBarrierStore(ExecutionLifecycleStore):
    def __init__(
        self,
        connection: aiosqlite.Connection,
        winner_entered: asyncio.Event,
        contender_attempted: asyncio.Event,
    ) -> None:
        super().__init__(connection, "sqlite")
        self._winner_entered = winner_entered
        self._contender_attempted = contender_attempted

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        async with super()._transaction() as connection:
            self._winner_entered.set()
            await self._contender_attempted.wait()
            yield connection


class _SQLiteContenderBarrierStore(ExecutionLifecycleStore):
    def __init__(
        self,
        connection: aiosqlite.Connection,
        contender_attempted: asyncio.Event,
    ) -> None:
        super().__init__(connection, "sqlite")
        self._contender_attempted = contender_attempted

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        self._contender_attempted.set()
        async with super()._transaction() as connection:
            yield connection


class _SQLiteCancellationGateStore(ExecutionLifecycleStore):
    def __init__(
        self,
        connection: aiosqlite.Connection,
        receipt_entered: asyncio.Event,
        receipt_release: asyncio.Event,
    ) -> None:
        super().__init__(connection, "sqlite")
        self.receipt_entered = receipt_entered
        self.receipt_release = receipt_release
        self.armed = True

    async def _insert_receipt(self, *args: Any, **kwargs: Any) -> None:
        if self.armed:
            self.receipt_entered.set()
            await self.receipt_release.wait()
        await super()._insert_receipt(*args, **kwargs)


class _SQLiteCleanupFailureStore(ExecutionLifecycleStore):
    def __init__(
        self,
        connection: aiosqlite.Connection,
        stage: str,
        cleanup_faults: list[str],
    ) -> None:
        super().__init__(connection, "sqlite")
        self.stage = stage
        self.cleanup_faults = cleanup_faults
        self.armed = True

    async def _returning_rows(
        self, connection: Any, sql: str, params: tuple[Any, ...]
    ) -> tuple[Any, ...]:
        rows = await super()._returning_rows(connection, sql, params)
        if self.armed and rows and "UPDATE execution_attempts SET" in sql:
            return rows + rows
        return rows

    async def _execute(self, connection: Any, sql: str, params: tuple[Any, ...]) -> None:
        await super()._execute(connection, sql, params)
        expected = {
            "savepoint-rollback": "ROLLBACK TO SAVEPOINT lifecycle_compound",
            "savepoint-release": "RELEASE SAVEPOINT lifecycle_compound",
        }.get(self.stage)
        if self.armed and expected == sql:
            self.cleanup_faults.append(self.stage)
            raise RuntimeError("fixed-sqlite-cleanup-failure")


_SQLITE_P1A_ZERO_ROW_TRIGGERS = {
    "missing": (
        "CREATE TEMP TRIGGER p1a_zero_missing BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "DELETE FROM campaign_execution_budget_ledger "
        "WHERE attempt_id='00000000-0000-4000-8000-0000000000d2'; "
        "DELETE FROM execution_attempts "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-revision": (
        "CREATE TEMP TRIGGER p1a_zero_stale_revision BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts SET revision=revision+1 "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-state": (
        "CREATE TEMP TRIGGER p1a_zero_stale_state BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts SET state='queued',"
        "queue_operation_id='00000000-0000-4000-8000-0000000003d5',"
        "queued_at=accepted_at "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-authority": (
        "CREATE TEMP TRIGGER p1a_zero_stale_authority BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_actor_authority_revisions SET revision=revision+1,"
        "latest_operation_id='00000000-0000-4000-8000-0000000003d6',"
        "latest_operation_base_revision=revision,latest_operation_code='invalidate' "
        "WHERE user_id='00000000-0000-4000-8000-0000000000c8'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-owner": (
        "CREATE TEMP TRIGGER p1a_zero_stale_owner BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts "
        "SET dispatch_owner_ref='00000000-0000-4000-8000-0000000003d7' "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-generation": (
        "CREATE TEMP TRIGGER p1a_zero_stale_generation BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts SET lease_generation=lease_generation+1 "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-lease": (
        "CREATE TEMP TRIGGER p1a_zero_stale_lease BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts SET lease_expires_at=created_at "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "stale-cancellation": (
        "CREATE TEMP TRIGGER p1a_zero_stale_cancellation BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "UPDATE execution_attempts SET cancellation_request_revision="
        "cancellation_request_revision+1 "
        "WHERE id='00000000-0000-4000-8000-0000000000d2'; "
        "SELECT RAISE(IGNORE); END;"
    ),
    "operation-conflict": (
        "CREATE TEMP TRIGGER p1a_zero_operation_conflict BEFORE UPDATE OF state "
        "ON execution_attempts "
        "WHEN OLD.id='00000000-0000-4000-8000-0000000000d2' BEGIN "
        "INSERT INTO execution_operation_receipts("
        "operation_id,operation_code,campaign_id,primary_target_id,secondary_target_id,"
        "principal_kind,principal_subject_ref,principal_user_id,"
        "principal_authority_revision_present,principal_authority_revision,"
        "binding_contract_version,request_binding_digest,"
        "expected_revision_present,expected_revision,"
        "secondary_expected_revision_present,secondary_expected_revision,"
        "owner_ref,lease_generation,result_code,exact_replay_code,result_binding_digest,"
        "result_identity,result_revision_present,result_revision,"
        "secondary_result_identity,secondary_result_revision_present,"
        "secondary_result_revision) VALUES("
        "'00000000-0000-4000-8000-0000000003d4','queue',"
        "'00000000-0000-4000-8000-0000000000c9',"
        "'00000000-0000-4000-8000-0000000003d8',NULL,"
        "'system','004cb934-3a47-4cd0-b0cb-a5b18df76a48',NULL,0,NULL,2,"
        "'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',"
        "1,0,0,NULL,NULL,NULL,'conflict_operation','replayed',"
        "'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',"
        "'00000000-0000-4000-8000-0000000003d8',1,0,NULL,0,NULL); "
        "SELECT RAISE(IGNORE); END;"
    ),
}


async def _install_zero_row_trigger(connection: aiosqlite.Connection, case: str) -> None:
    await connection.execute("PRAGMA recursive_triggers=OFF")
    await connection.executescript(_SQLITE_P1A_ZERO_ROW_TRIGGERS[case])
    await connection.commit()


async def _p1a_transition_request(
    connection: aiosqlite.Connection,
    case: str,
) -> tuple[TransitionRequest, bool]:
    setup_store = ExecutionLifecycleStore(connection, "sqlite")
    if case in {"stale-owner", "stale-generation", "stale-lease", "stale-cancellation"}:
        dispatched = await _nonterminal_transition(
            setup_store, connection, AttemptState.DISPATCHING, 970
        )
        assert dispatched.result is FixedResult.APPLIED, "P1-A dispatch setup failed"
    if case == "stale-cancellation":
        running = await _nonterminal_transition(setup_store, connection, AttemptState.RUNNING, 971)
        assert running.result is FixedResult.APPLIED, "P1-A running setup failed"
        cancelling = await _nonterminal_transition(
            setup_store, connection, AttemptState.CANCELLING, 972
        )
        assert cancelling.result is FixedResult.APPLIED, "P1-A cancellation setup failed"
        row = await _attempt_row(connection)
        return (
            TransitionRequest(
                _uuid(210),
                int(row[1]),
                AttemptState.SETTLEMENT_PENDING,
                _uuid(980),
                owner_ref=_uuid(220),
                lease_generation=int(row[3]),
                cancellation_request_revision=int(row[4]),
                outbox_id=_uuid(985),
                publication_key=_uuid(986),
                campaign_id=_uuid(201),
            ),
            True,
        )
    row = await _attempt_row(connection)
    values: dict[str, object] = {}
    target = AttemptState.QUEUED
    if case in {"stale-owner", "stale-generation", "stale-lease"}:
        target = AttemptState.RUNNING
        values = {"owner_ref": _uuid(220), "lease_generation": int(row[3])}
    else:
        values = {
            "actor_subject_ref": _uuid(200),
            "actor_user_id": _uuid(200),
            "actor_authority_revision": 0,
        }
    return (
        TransitionRequest(
            _uuid(210),
            int(row[1]),
            target,
            _uuid(980),
            campaign_id=_uuid(201),
            **values,
        ),
        False,
    )


@pytest.mark.asyncio
async def test_sqlite_truth_write_exactly_one_row_is_applied() -> None:
    connection = await _new_connection()
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(960), "p1a-exact-one", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        ensured = await store.ensure_actor_authority(_uuid(960), _uuid(961))
        updated = await store.invalidate_actor_authority(_uuid(960), 0, _uuid(962))
        row = await (
            await connection.execute(
                "SELECT revision,latest_operation_id FROM execution_actor_authority_revisions "
                "WHERE user_id=?",
                (_uuid(960),),
            )
        ).fetchone()
        receipt_count = await (
            await connection.execute(
                "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=?",
                (_uuid(962),),
            )
        ).fetchone()
    finally:
        await connection.close()
    assert (ensured.result, updated.result, updated.revision) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
        1,
    ), "exactly-one truth write was not applied"
    assert tuple(row) == (1, _uuid(962)), "exactly-one truth write returned the wrong row"
    assert int(receipt_count[0]) == 1, "exactly-one truth write lost its receipt"


@pytest.mark.asyncio
async def test_sqlite_returning_row_disagrees_with_changes_is_invariant_failure() -> None:
    connection = await _new_connection()
    try:
        await connection.executescript(
            "CREATE TABLE p1a_changes_backing(id TEXT PRIMARY KEY,revision INTEGER NOT NULL);"
            "INSERT INTO p1a_changes_backing "
            "VALUES('00000000-0000-4000-8000-0000000003c3',0);"
            "CREATE VIEW p1a_changes_view AS SELECT id,revision FROM p1a_changes_backing;"
            "CREATE TRIGGER p1a_changes_view_update INSTEAD OF UPDATE ON p1a_changes_view "
            "BEGIN UPDATE p1a_changes_backing SET revision=NEW.revision WHERE id=OLD.id; END;"
        )
        await connection.commit()
        store = ExecutionLifecycleStore(connection, "sqlite")
        with pytest.raises(_AbortOperationError) as raised:
            async with store._transaction() as transaction:
                await store.cas_update_one(
                    transaction,
                    "UPDATE p1a_changes_view SET revision=revision+1 "
                    "WHERE id=? AND revision=? RETURNING id,revision",
                    (_uuid(963), 0),
                    identity=_uuid(963),
                    post_revision=1,
                    zero_classifier=None,
                )
        row = await (
            await connection.execute(
                "SELECT revision FROM p1a_changes_backing WHERE id=?", (_uuid(963),)
            )
        ).fetchone()
    finally:
        await connection.close()
    assert raised.value.result.result is FixedResult.INVARIANT_FAILURE, (
        "RETURNING/changes disagreement was not fixed invariant failure"
    )
    assert int(row[0]) == 0, "RETURNING/changes invariant failure was not rolled back"


@pytest.mark.parametrize(
    ("case", "expected_result", "expected_revision"),
    [
        ("missing", FixedResult.NOT_FOUND_OR_PURGED, None),
        ("stale-revision", FixedResult.CONFLICT_REVISION, 1),
        ("stale-state", FixedResult.CONFLICT_STATE, 0),
        ("stale-authority", FixedResult.AUTHORITY_STALE, 0),
        ("stale-owner", FixedResult.CONFLICT_OWNER, 1),
        ("stale-generation", FixedResult.CONFLICT_GENERATION, 1),
        ("stale-lease", FixedResult.CONFLICT_STATE, 1),
        ("stale-cancellation", FixedResult.CONFLICT_REVISION, 3),
        ("operation-conflict", FixedResult.CONFLICT_OPERATION, 0),
    ],
    ids=(
        "missing",
        "stale-revision",
        "stale-state",
        "stale-authority",
        "stale-owner",
        "stale-generation",
        "stale-lease",
        "stale-cancellation",
        "operation-conflict",
    ),
)
@pytest.mark.asyncio
async def test_sqlite_zero_row_truth_write_is_reclassified_in_same_transaction(
    tmp_path,
    case: str,
    expected_result: FixedResult,
    expected_revision: int | None,
) -> None:
    connection, _setup_store = await _new_transition_case(
        (tmp_path / f"p1a-zero-{case}.db").as_posix(), AttemptState.ACCEPTED
    )
    try:
        request, settlement = await _p1a_transition_request(connection, case)
        await _install_zero_row_trigger(connection, case)
        store = _SQLiteZeroRowTraceStore(connection)
        result = (
            await store.enter_settlement_pending(request)
            if settlement
            else await store.transition_attempt(request)
        )
        assert store.zero_connection_id == id(connection), "zero-row write used another connection"
        assert store.zero_in_transaction is True, "zero-row write escaped its transaction"
        assert store.classifier_connection_ids, "zero-row write was not reread"
        assert set(store.classifier_connection_ids) == {id(connection)}, (
            "zero-row classifier changed connection"
        )
        assert all(store.classifier_in_transaction), (
            "zero-row classifier ran after transaction exit"
        )
    finally:
        await connection.close()
    assert (result.result, result.revision) == (expected_result, expected_revision), (
        "zero-row write received the wrong fixed classification"
    )


@pytest.mark.asyncio
async def test_sqlite_concurrent_cas_has_one_winner_and_fixed_loser(tmp_path) -> None:
    path = tmp_path / "p1a-concurrent-cas.db"
    winner_connection, _setup_store = await _new_transition_case(
        path.as_posix(), AttemptState.ACCEPTED
    )
    contender_connection = await aiosqlite.connect(path.as_posix())
    contender_connection.row_factory = aiosqlite.Row
    await contender_connection.execute("PRAGMA foreign_keys=ON")
    await contender_connection.execute("PRAGMA busy_timeout=5000")
    await contender_connection.commit()
    winner_entered = asyncio.Event()
    contender_attempted = asyncio.Event()
    winner_store = _SQLiteWinnerBarrierStore(winner_connection, winner_entered, contender_attempted)
    contender_store = _SQLiteContenderBarrierStore(contender_connection, contender_attempted)
    winner_task: asyncio.Task[Any] | None = None
    contender_task: asyncio.Task[Any] | None = None
    observer: aiosqlite.Connection | None = None
    try:
        winner_task = asyncio.create_task(
            winner_store.transition_attempt(
                TransitionRequest(
                    _uuid(210),
                    0,
                    AttemptState.QUEUED,
                    _uuid(987),
                    campaign_id=_uuid(201),
                    actor_subject_ref=_uuid(200),
                    actor_user_id=_uuid(200),
                    actor_authority_revision=0,
                )
            )
        )
        await asyncio.wait_for(winner_entered.wait(), timeout=2)
        contender_task = asyncio.create_task(
            contender_store.transition_attempt(
                TransitionRequest(
                    _uuid(210),
                    0,
                    AttemptState.CANCELLING,
                    _uuid(988),
                    campaign_id=_uuid(201),
                    actor_subject_ref=_uuid(200),
                    actor_user_id=_uuid(200),
                    actor_authority_revision=0,
                )
            )
        )
        await asyncio.wait_for(contender_attempted.wait(), timeout=2)
        winner, contender = await asyncio.wait_for(
            asyncio.gather(winner_task, contender_task), timeout=10
        )
        observer = await aiosqlite.connect(path.as_posix())
        row = await (
            await observer.execute(
                "SELECT state,revision FROM execution_attempts WHERE id=?", (_uuid(210),)
            )
        ).fetchone()
        receipt_count = await (
            await observer.execute(
                "SELECT count(*) FROM execution_operation_receipts WHERE operation_id IN (?,?)",
                (_uuid(987), _uuid(988)),
            )
        ).fetchone()
    finally:
        for task in (winner_task, contender_task):
            if task is not None and not task.done():
                task.cancel()
        pending = tuple(
            task for task in (winner_task, contender_task) if task is not None and not task.done()
        )
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if observer is not None:
            await observer.close()
        await contender_connection.close()
        await winner_connection.close()
    assert (winner.result, contender.result) == (
        FixedResult.APPLIED,
        FixedResult.CONFLICT_REVISION,
    ), "concurrent SQLite CAS winner/loser changed"
    assert tuple(row) == (AttemptState.QUEUED.value, 1), "concurrent CAS changed more than once"
    assert int(receipt_count[0]) == 1, "concurrent CAS wrote a loser receipt"


@pytest.mark.asyncio
async def test_sqlite_cancelled_truth_write_rolls_back_and_connection_reuses(tmp_path) -> None:
    path = tmp_path / "p1a-cancelled-write.db"
    connection = await _new_connection(path.as_posix())
    receipt_entered = asyncio.Event()
    receipt_release = asyncio.Event()
    store = _SQLiteCancellationGateStore(connection, receipt_entered, receipt_release)
    task: asyncio.Task[Any] | None = None
    observer: aiosqlite.Connection | None = None
    try:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (_uuid(964), "p1a-cancelled", "fixed-hash", "admin", "fixed"),
        )
        await connection.commit()
        task = asyncio.create_task(store.ensure_actor_authority(_uuid(964), _uuid(965)))
        await asyncio.wait_for(receipt_entered.wait(), timeout=2)
        assert connection.in_transaction is True, "cancellation gate was outside the transaction"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert connection.in_transaction is False, "cancelled write retained a transaction"
        observer = await aiosqlite.connect(path.as_posix())
        counts = await (
            await observer.execute(
                "SELECT (SELECT count(*) FROM execution_actor_authority_revisions),"
                "(SELECT count(*) FROM execution_operation_receipts)"
            )
        ).fetchone()
        await observer.close()
        observer = None
        store.armed = False
        reused = await store.ensure_actor_authority(_uuid(964), _uuid(965))
    finally:
        receipt_release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if observer is not None:
            await observer.close()
        await connection.close()
    assert tuple(counts) == (0, 0), "cancelled truth write leaked partial state"
    assert reused.result is FixedResult.APPLIED, "cancelled SQLite connection was not reusable"


@pytest.mark.parametrize(
    "stage",
    ["transaction-rollback", "savepoint-rollback", "savepoint-release"],
    ids=("transaction-rollback", "savepoint-rollback", "savepoint-release"),
)
@pytest.mark.asyncio
async def test_sqlite_primary_fixed_failure_survives_cleanup_failure(
    monkeypatch, stage: str
) -> None:
    cleanup_faults: list[str] = []
    if stage == "transaction-rollback":
        connection = await _new_connection()
        try:
            await connection.execute(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
                (_uuid(966), "p1a-cleanup", "fixed-hash", "admin", "fixed"),
            )
            await connection.commit()
            original_rollback = connection.rollback

            async def rollback_then_fail() -> None:
                await original_rollback()
                cleanup_faults.append(stage)
                raise RuntimeError("fixed-sqlite-cleanup-failure")

            monkeypatch.setattr(connection, "rollback", rollback_then_fail)
            store = _SQLiteCleanupFailureStore(connection, stage, cleanup_faults)
            original_returning = store._returning_rows

            async def duplicate_insert_rows(
                fault_connection: Any, sql: str, params: tuple[Any, ...]
            ) -> tuple[Any, ...]:
                rows = await original_returning(fault_connection, sql, params)
                if store.armed and rows and "execution_actor_authority_revisions" in sql:
                    return rows + rows
                return rows

            monkeypatch.setattr(store, "_returning_rows", duplicate_insert_rows)
            failed = await store.ensure_actor_authority(_uuid(966), _uuid(967))
            store.armed = False
            reused = await store.ensure_actor_authority(_uuid(966), _uuid(967))
        finally:
            await connection.close()
    else:
        connection, _setup_store = await _new_transition_case(":memory:", AttemptState.ACCEPTED)
        try:
            store = _SQLiteCleanupFailureStore(connection, stage, cleanup_faults)
            request = TransitionRequest(
                _uuid(210),
                0,
                AttemptState.QUEUED,
                _uuid(968),
                campaign_id=_uuid(201),
                actor_subject_ref=_uuid(200),
                actor_user_id=_uuid(200),
                actor_authority_revision=0,
            )
            failed = await store.transition_attempt(request)
            store.armed = False
            reused = await store.transition_attempt(request)
        finally:
            await connection.close()
    assert failed.result is FixedResult.INVARIANT_FAILURE, (
        "cleanup failure replaced the primary fixed failure"
    )
    assert cleanup_faults == [stage], "cleanup failure stage was not deterministic"
    assert reused.result is FixedResult.APPLIED, "cleanup failure left SQLite unusable"


_SQLITE_P1C_TERMINAL_V3_ALIASES = (
    "invalid-contract-before-receipt",
    "v3-binding-vector-and-operation-codes",
    "receipt-replay-after-target-deletion",
    "receipt-replay-zero-mutable-reads",
    "changed-intent-conflict-operation",
    "known-success-atomic",
    "known-failure-atomic",
    "acknowledged-cancellation-atomic",
    "acknowledged-timeout-atomic",
    "uncertain-outcome-invalid-contract",
    "single-transaction-zero-nested-acquire",
    "derive-exact-three-held-ledgers",
    "missing-ledger-inconsistent-set-rollback",
    "duplicate-extra-ledger-inconsistent-set-rollback",
    "wrong-kind-ledger-inconsistent-set-rollback",
    "wrong-campaign-attempt-ledger-inconsistent-set-rollback",
    "non-held-ledger-conflict-operation-rollback",
    "current-budget-lock-no-toctou",
    "budget-capacity-inconsistent-set-rollback",
    "budget-write-failure-rollback",
    "output-write-failure-rollback",
    "terminal-write-failure-rollback",
    "logical-closure-write-failure-rollback",
    "outbox-write-failure-rollback",
    "receipt-write-failure-rollback",
    "public-intent-excludes-derived-fields",
    "missing-attempt-not-found-or-purged",
    "non-running-attempt-conflict-state",
    "stale-attempt-revision-conflict",
    "invariant-failure-rollback",
    "cancellation-rollback-and-reuse",
    "exception-rollback-and-reuse",
    "legacy-terminal-apply-replay-bytes-unchanged",
    "legacy-v3-crossing-conflict-operation",
    "changed-outcome-conflict-operation",
    "changed-result-digest-conflict-operation",
    "cancellation-caller-result-digest-invalid-contract",
    "timeout-caller-result-digest-invalid-contract",
    "canonical-output-order-exact-replay",
    "terminal-operation-and-system-principal-namespace",
    "derived-revision-overflow-invariant-failure-rollback",
)

_SQLITE_P1C_TERMINAL_NODE_COUNT = 41
_SQLITE_P1C_TERMINAL_NODE_ID_SHA256 = (
    "5d7df72980bd3e7fdc4bf809965568b127a19f5a080a95b116b221cafb347e4e"
)


def _sqlite_p1c_terminal_inventory_digest() -> str:
    encoded = bytearray(b"ares.p1c-terminal-v3-sqlite-test-inventory.v1\x00")
    for alias in _SQLITE_P1C_TERMINAL_V3_ALIASES:
        node_id = (
            "tests/unit/test_execution_lifecycle_persistence.py::"
            f"test_sqlite_p1c_terminal_v3_seam[{alias}]"
        ).encode()
        encoded.extend(struct.pack(">I", len(node_id)))
        encoded.extend(node_id)
    return hashlib.sha256(encoded).hexdigest()


assert len(_SQLITE_P1C_TERMINAL_V3_ALIASES) == _SQLITE_P1C_TERMINAL_NODE_COUNT
assert len(set(_SQLITE_P1C_TERMINAL_V3_ALIASES)) == _SQLITE_P1C_TERMINAL_NODE_COUNT
assert _sqlite_p1c_terminal_inventory_digest() == _SQLITE_P1C_TERMINAL_NODE_ID_SHA256

_SQLITE_P1C_TERMINAL_RESULT_DIGEST = hashlib.sha256(
    b"sqlite-p1c-terminal-v3-known-result"
).hexdigest()


def _sqlite_p1c_binding_digest(
    domain: str,
    values: tuple[tuple[str, str | int | bool | None], ...],
) -> str:
    """Independent literal oracle for the protected v2 typed framing."""
    encoded = bytearray(b"ares.execution-operation-binding.v2\x00")

    def frame(value: bytes) -> None:
        encoded.extend(struct.pack(">I", len(value)))
        encoded.extend(value)

    frame(domain.encode("ascii"))
    seen: set[str] = set()
    for name, value in values:
        assert name not in seen, "SQLite terminal oracle contains a duplicate field"
        seen.add(name)
        frame(name.encode("ascii"))
        if value is None:
            encoded.extend(b"n")
        elif type(value) is bool:
            encoded.extend(b"b\x01" if value else b"b\x00")
        elif type(value) is int:
            encoded.extend(b"i")
            frame(value.to_bytes(8, "big", signed=False))
        elif type(value) is str:
            encoded.extend(b"s")
            frame(value.encode("utf-8"))
        else:  # pragma: no cover - a broken test oracle must be loud.
            raise AssertionError("unsupported SQLite terminal oracle value")
    return hashlib.sha256(encoded).hexdigest()


def _sqlite_p1c_terminal_operation_id(attempt_id: str) -> str:
    digest = _sqlite_p1c_binding_digest(
        "terminal-commit-operation-id.v3",
        (("attempt_id", attempt_id), ("action", "commit-known-settled")),
    )
    return (
        digest[:8]
        + "-"
        + digest[8:12]
        + "-4"
        + digest[13:16]
        + "-8"
        + digest[17:20]
        + "-"
        + digest[20:32]
    )


def _sqlite_p1c_terminal_operation_code(outcome: OutcomeCode) -> str:
    return {
        OutcomeCode.CONFIRMED_SUCCESS: "terminal_succeeded",
        OutcomeCode.CONFIRMED_FAILURE: "terminal_failed",
        OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT: "cancellation_acknowledgement",
        OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED: "timeout",
    }[outcome]


def _sqlite_p1c_terminal_request_digest(intent: TerminalCommitIntentV3) -> str:
    operation_id = _sqlite_p1c_terminal_operation_id(intent.attempt_id)
    operation_code = _sqlite_p1c_terminal_operation_code(intent.outcome_code)
    canonical_outputs = tuple(
        sorted(
            intent.outputs,
            key=lambda item: (item.kind.value, item.target_id, item.link_id),
        )
    )
    output_fields = tuple(
        field
        for index, output in enumerate(canonical_outputs)
        for field in (
            (f"output_{index}_link_id", output.link_id),
            (f"output_{index}_kind", output.kind.value),
            (f"output_{index}_target_id", output.target_id),
        )
    )
    return _sqlite_p1c_binding_digest(
        "execution-terminal-commit.v3.request",
        (
            ("terminal_commit_contract_version", 3),
            ("logical_execution_id", intent.logical_execution_id),
            ("campaign_id", intent.campaign_id),
            ("attempt_id", intent.attempt_id),
            ("operation_id", operation_id),
            ("expected_attempt_revision", intent.expected_attempt_revision),
            ("operation_code", operation_code),
            ("outcome_code", intent.outcome_code.value),
            ("noise_actual", intent.noise_actual),
            ("exfiltration_actual", intent.exfiltration_actual),
            ("concurrency_actual", intent.concurrency_actual),
            (
                "execution_result_digest_present",
                intent.execution_result_digest is not None,
            ),
            ("execution_result_digest", intent.execution_result_digest),
            ("output_count", len(canonical_outputs)),
        )
        + output_fields,
    )


def _sqlite_p1c_terminal_derived_uuid(operation_id: str, label: str) -> str:
    digest = hashlib.sha256((operation_id + "\x00" + label).encode("ascii")).hexdigest()
    return (
        digest[:8]
        + "-"
        + digest[8:12]
        + "-4"
        + digest[13:16]
        + "-8"
        + digest[17:20]
        + "-"
        + digest[20:32]
    )


def _sqlite_p1c_terminal_result_digest(intent: TerminalCommitIntentV3) -> str:
    operation_id = _sqlite_p1c_terminal_operation_id(intent.attempt_id)
    operation_code = _sqlite_p1c_terminal_operation_code(intent.outcome_code)
    target, proof = {
        OutcomeCode.CONFIRMED_SUCCESS: (AttemptState.SUCCEEDED, "local_completion"),
        OutcomeCode.CONFIRMED_FAILURE: (AttemptState.FAILED, "local_completion"),
        OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT: (
            AttemptState.CANCELLED,
            "cancellation_no_result_ack",
        ),
        OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED: (
            AttemptState.TIMED_OUT,
            "timeout_termination_ack",
        ),
    }[intent.outcome_code]
    post_revision = intent.expected_attempt_revision + 1
    outbox_id = _sqlite_p1c_terminal_derived_uuid(operation_id, "terminal-outbox")
    publication_key = _sqlite_p1c_terminal_derived_uuid(
        operation_id,
        "terminal-publication",
    )
    counts = tuple(
        sum(output.kind is kind for output in intent.outputs)
        for kind in (
            OutputKind.FINDING,
            OutputKind.CREDENTIAL,
            OutputKind.HOST,
            OutputKind.ARTIFACT,
        )
    )
    return _sqlite_p1c_binding_digest(
        "execution-terminal-commit.v3.result",
        (
            ("result_code", FixedResult.APPLIED.value),
            ("exact_replay_code", FixedResult.REPLAYED.value),
            ("result_identity_present", True),
            ("result_identity", intent.attempt_id),
            ("result_revision_present", True),
            ("result_revision", post_revision),
            ("secondary_result_identity_present", True),
            ("secondary_result_identity", intent.logical_execution_id),
            ("secondary_result_revision_present", True),
            ("secondary_result_revision", 1),
            ("state", target.value),
            ("revision", post_revision),
            ("closes_logical", True),
            ("finding_count", counts[0]),
            ("credential_count", counts[1]),
            ("host_count", counts[2]),
            ("artifact_count", counts[3]),
            ("outbox_id", outbox_id),
            ("terminal_commit_contract_version", 3),
            ("operation_id", operation_id),
            ("operation_code", operation_code),
            ("campaign_id", intent.campaign_id),
            ("logical_execution_id", intent.logical_execution_id),
            ("attempt_id", intent.attempt_id),
            ("outcome_code", intent.outcome_code.value),
            ("authoritative_proof", proof),
            ("retry_eligible", False),
            (
                "execution_result_digest_present",
                intent.execution_result_digest is not None,
            ),
            ("execution_result_digest", intent.execution_result_digest),
            ("publication_key", publication_key),
        ),
    )


async def _sqlite_p1c_terminal_case(
    path: Any,
    *,
    predecessor: AttemptState = AttemptState.RUNNING,
) -> tuple[aiosqlite.Connection, ExecutionLifecycleStore, int]:
    connection, store = await _new_transition_case(path.as_posix(), AttemptState.ACCEPTED)
    if predecessor is AttemptState.ACCEPTED:
        return connection, store, 0
    dispatched = await _nonterminal_transition(store, connection, AttemptState.DISPATCHING, 20_100)
    assert dispatched.result is FixedResult.APPLIED, "terminal fixture dispatch failed"
    running = await _nonterminal_transition(store, connection, AttemptState.RUNNING, 20_101)
    assert running.result is FixedResult.APPLIED, "terminal fixture start failed"
    if predecessor is AttemptState.CANCELLING:
        cancelling = await _nonterminal_transition(
            store, connection, AttemptState.CANCELLING, 20_102
        )
        assert cancelling.result is FixedResult.APPLIED, "terminal fixture cancel failed"
        return connection, store, 3
    assert predecessor is AttemptState.RUNNING, "unsupported terminal fixture predecessor"
    return connection, store, 2


def _sqlite_p1c_terminal_intent(
    expected_revision: int,
    *,
    outcome: OutcomeCode = OutcomeCode.CONFIRMED_SUCCESS,
    execution_result_digest: str | None | object = ...,
    outputs: tuple[OutputObservation, ...] = (),
    noise_actual: int = 1,
    exfiltration_actual: int = 2,
    concurrency_actual: int = 0,
) -> TerminalCommitIntentV3:
    if execution_result_digest is ...:
        execution_result_digest = (
            None
            if outcome
            in {
                OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
                OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
            }
            else _SQLITE_P1C_TERMINAL_RESULT_DIGEST
        )
    return TerminalCommitIntentV3(
        logical_execution_id=_uuid(208),
        campaign_id=_uuid(201),
        attempt_id=_uuid(210),
        expected_attempt_revision=expected_revision,
        outcome_code=outcome,
        noise_actual=noise_actual,
        exfiltration_actual=exfiltration_actual,
        concurrency_actual=concurrency_actual,
        execution_result_digest=execution_result_digest,  # type: ignore[arg-type]
        outputs=outputs,
    )


async def _sqlite_p1c_terminal_receipt(
    connection: aiosqlite.Connection, attempt_id: str = _uuid(210)
) -> Any:
    return await (
        await connection.execute(
            "SELECT operation_id,operation_code,campaign_id,primary_target_id,"
            "secondary_target_id,principal_kind,principal_subject_ref,principal_user_id,"
            "principal_authority_revision_present,principal_authority_revision,"
            "binding_contract_version,request_binding_digest,result_code,exact_replay_code,"
            "result_binding_digest,result_identity,result_revision,secondary_result_identity,"
            "secondary_result_revision FROM execution_operation_receipts "
            "WHERE operation_id=?",
            (_sqlite_p1c_terminal_operation_id(attempt_id),),
        )
    ).fetchone()


async def _sqlite_p1c_terminal_state(connection: aiosqlite.Connection) -> Any:
    return await (
        await connection.execute(
            "SELECT state,revision,outcome_code,settlement_state,settlement_proof_code,"
            "termination_confirmed,closes_logical,retry_disposition,terminal_operation_id,"
            "cancellation_ack_operation_id,timeout_operation_id "
            "FROM execution_attempts WHERE id=?",
            (_uuid(210),),
        )
    ).fetchone()


def _sqlite_p1c_legacy_terminal_request(
    operation_id: str,
    expected_revision: int,
) -> TerminalCommitRequest:
    return TerminalCommitRequest(
        _uuid(208),
        _uuid(201),
        _uuid(20_200),
        _uuid(20_201),
        TransitionRequest(
            _uuid(210),
            expected_revision,
            AttemptState.SUCCEEDED,
            operation_id,
            owner_ref=_uuid(220),
            lease_generation=1,
            outcome_code=OutcomeCode.CONFIRMED_SUCCESS,
            authoritative_proof="local_completion",
            campaign_id=_uuid(201),
        ),
        BudgetSettlement(
            _uuid(201),
            _uuid(210),
            _uuid(204),
            2,
            1,
            1,
            _uuid(205),
            3,
            2,
            1,
            _uuid(206),
            1,
            _uuid(20_202),
        ),
    )


_SQLITE_P1C_LEGACY_TERMINAL_RECEIPT_VECTORS = (
    (
        _uuid(20_200),
        "outbox_insert",
        2,
        "5dccdba355c4feef9cd6df03d5d6b3c8af06feee7ee618108615a35a545425e7",
        "7a50d0b26f31239a9fba139b28affd32750988bb7d6dc360c0a570ea8856a0d3",
    ),
    (
        _uuid(20_202),
        "budget_settle",
        2,
        "e0d4a8b6ca4ea2e38967e3158283cd1fa175279a41b1c55490cebbf76b48a9a1",
        "04f8900897528d734dd7f4fd030af712b34e2cd18ddf929f247b20494f5ddcad",
    ),
    (
        _uuid(20_400),
        "terminal_succeeded",
        2,
        "da5caf4a079873de9cdea7f31a284bcac45bdd3526c602038aaeb66147fc5cb8",
        "0b15cef8a5886d92669f712e36c80a91e4e10d00a1e0d92d6a479ad1bde08278",
    ),
)


class _SQLiteP1CTerminalTraceStore(ExecutionLifecycleStore):
    def __init__(
        self,
        backend: Any,
        *,
        receipt_only: bool = False,
        duplicate_ledger_row: bool = False,
        ledger_mutation: str | None = None,
        fail_at: str | None = None,
        cancel_at: str | None = None,
        duplicate_terminal_returning: bool = False,
    ) -> None:
        super().__init__(backend, "sqlite")
        self.receipt_only = receipt_only
        self.duplicate_ledger_row = duplicate_ledger_row
        self.ledger_mutation = ledger_mutation
        self.fail_at = fail_at
        self.cancel_at = cancel_at
        self.duplicate_terminal_returning = duplicate_terminal_returning
        self.transaction_entries = 0
        self.connection_identities: set[int] = set()
        self.read_events: list[str] = []
        self.budget_writes = 0
        self.output_insert_order: list[str] = []

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        self.transaction_entries += 1
        async with super()._transaction() as connection:
            self.connection_identities.add(id(connection))
            yield connection

    async def _fetchrow(self, connection: Any, sql: str, params: Any) -> Any:
        self.connection_identities.add(id(connection))
        self.read_events.append("receipt" if "execution_operation_receipts" in sql else "mutable")
        if self.receipt_only and "execution_operation_receipts" not in sql:
            raise AssertionError("exact terminal replay read a mutable target")
        return await super()._fetchrow(connection, sql, params)

    async def _fetchall(self, connection: Any, sql: str, params: Any) -> Any:
        self.connection_identities.add(id(connection))
        self.read_events.append("mutable")
        if self.receipt_only:
            raise AssertionError("exact terminal receipt classification read a mutable set")
        rows = tuple(await super()._fetchall(connection, sql, params))
        if self.duplicate_ledger_row and "FROM campaign_execution_budget_ledger" in sql and rows:
            return rows + (rows[0],)
        if (
            self.ledger_mutation is not None
            and "FROM campaign_execution_budget_ledger" in sql
            and rows
        ):
            mutable = [list(row) for row in rows]
            if self.ledger_mutation == "kind":
                mutable[0][4] = "exfiltration"
            elif self.ledger_mutation == "campaign":
                mutable[0][2] = _uuid(20_300)
            elif self.ledger_mutation == "attempt":
                mutable[0][1] = _uuid(20_301)
            else:  # pragma: no cover - invalid fault label is a broken test.
                raise AssertionError("unknown terminal ledger mutation")
            return tuple(tuple(row) for row in mutable)
        return rows

    async def _returning_rows(self, connection: Any, sql: str, params: Any) -> Any:
        self.connection_identities.add(id(connection))
        rows = await super()._returning_rows(connection, sql, params)
        if (
            self.duplicate_terminal_returning
            and "UPDATE execution_attempts SET state=" in sql
            and rows
        ):
            return rows + rows
        return rows

    async def cas_update_one(self, connection: Any, sql: str, params: Any, **kwargs: Any) -> Any:
        row = await super().cas_update_one(connection, sql, params, **kwargs)
        if "UPDATE campaign_execution_budgets" in sql:
            self.budget_writes += 1
            if self.fail_at == "budget" and self.budget_writes == 2:
                raise RuntimeError("fixed-terminal-budget-write-failure")
        if self.fail_at == "terminal" and "UPDATE execution_attempts SET state=" in sql:
            raise RuntimeError("fixed-terminal-attempt-write-failure")
        if self.fail_at == "logical" and "UPDATE logical_executions SET closure" in sql:
            raise RuntimeError("fixed-terminal-logical-write-failure")
        return row

    async def _insert_output_links(self, *args: Any, **kwargs: Any) -> Any:
        counts = await super()._insert_output_links(*args, **kwargs)
        if self.fail_at == "output":
            raise RuntimeError("fixed-terminal-output-write-failure")
        if self.fail_at == "exception":
            raise RuntimeError("fixed-terminal-exception")
        if self.cancel_at == "output":
            raise asyncio.CancelledError
        return counts

    async def update_exact_set(
        self,
        connection: Any,
        sql: str,
        params: Any,
        **kwargs: Any,
    ) -> Any:
        result = await super().update_exact_set(connection, sql, params, **kwargs)
        if "INSERT INTO execution_output_links" in sql:
            self.output_insert_order.append(str(params[0]))
        return result

    async def _insert_terminal_outbox(self, *args: Any, **kwargs: Any) -> Any:
        result = await super()._insert_terminal_outbox(*args, **kwargs)
        if self.fail_at == "outbox":
            raise RuntimeError("fixed-terminal-outbox-write-failure")
        return result

    async def _insert_receipt(self, connection: Any, spec: Any, **kwargs: Any) -> Any:
        result = await super()._insert_receipt(connection, spec, **kwargs)
        if self.fail_at == "receipt" and spec.operation_code in {
            "terminal_succeeded",
            "terminal_failed",
            "cancellation_acknowledgement",
            "timeout",
        }:
            raise RuntimeError("fixed-terminal-receipt-write-failure")
        return result

    async def _insert_terminal_v3_receipt(self, *args: Any, **kwargs: Any) -> Any:
        result = await super()._insert_terminal_v3_receipt(*args, **kwargs)
        if self.fail_at == "receipt":
            raise RuntimeError("fixed-terminal-v3-receipt-write-failure")
        return result


async def _sqlite_p1c_assert_rollback(
    connection: aiosqlite.Connection,
    store: ExecutionLifecycleStore,
    intent: TerminalCommitIntentV3,
    *,
    expected_result: FixedResult | None = None,
    expected_exception: type[BaseException] | None = None,
) -> OperationResult | None:
    before = await _snapshot_case(connection)
    if expected_exception is None:
        result = await store.commit_terminal_attempt_v3(intent)
        assert result.result is expected_result, "terminal rollback result changed"
    else:
        with pytest.raises(expected_exception):
            await store.commit_terminal_attempt_v3(intent)
        result = None
    after = await _snapshot_case(connection)
    assert after == before, "terminal failure committed partial state"
    return result


@pytest.mark.parametrize(
    "case_alias",
    _SQLITE_P1C_TERMINAL_V3_ALIASES,
    ids=_SQLITE_P1C_TERMINAL_V3_ALIASES,
)
@pytest.mark.asyncio
async def test_sqlite_p1c_terminal_v3_seam(tmp_path, case_alias: str) -> None:  # noqa: C901, PLR0912, PLR0915
    if case_alias == "public-intent-excludes-derived-fields":
        public_dataclass_fields = fields(TerminalCommitIntentV3)
        public_fields = tuple(item.name for item in public_dataclass_fields)
        assert public_fields == (
            "logical_execution_id",
            "campaign_id",
            "attempt_id",
            "expected_attempt_revision",
            "outcome_code",
            "noise_actual",
            "exfiltration_actual",
            "concurrency_actual",
            "execution_result_digest",
            "outputs",
        ), "terminal public authority surface changed"
        assert get_type_hints(TerminalCommitIntentV3) == {
            "logical_execution_id": str,
            "campaign_id": str,
            "attempt_id": str,
            "expected_attempt_revision": int,
            "outcome_code": OutcomeCode,
            "noise_actual": int,
            "exfiltration_actual": int,
            "concurrency_actual": int,
            "execution_result_digest": str | None,
            "outputs": tuple[OutputObservation, ...],
        }, "terminal public field types changed"
        assert all(item.default is MISSING for item in public_dataclass_fields[:-1])
        assert public_dataclass_fields[-1].default == (), "terminal output default changed"
        dataclass_parameters = TerminalCommitIntentV3.__dataclass_params__
        assert is_dataclass(TerminalCommitIntentV3)
        assert (
            dataclass_parameters.init,
            dataclass_parameters.repr,
            dataclass_parameters.eq,
            dataclass_parameters.order,
            dataclass_parameters.unsafe_hash,
            dataclass_parameters.frozen,
        ) == (True, False, False, False, False, True)
        assert TerminalCommitIntentV3.__slots__ == public_fields
        assert TerminalCommitIntentV3.__hash__ is None
        forbidden = {
            "operation_id",
            "principal_kind",
            "principal_subject_ref",
            "principal_user_id",
            "principal_authority_revision",
            "actor_subject_ref",
            "actor_user_id",
            "actor_authority_revision",
            "campaign_authority_revision",
            "budget_id",
            "budget_ids",
            "ledger_id",
            "ledger_ids",
            "reserved_units",
            "budget_revision",
            "current_budget_revision",
            "retry_eligibility",
            "retry_eligible",
            "policy_result",
            "closure_disposition",
            "receipt_classification",
        }
        assert not forbidden.intersection(public_fields), (
            "caller authority leaked into terminal intent"
        )
        baseline = _sqlite_p1c_terminal_intent(2)
        assert not hasattr(baseline, "__dict__"), "terminal intent lost its slot boundary"
        with pytest.raises(FrozenInstanceError):
            baseline.campaign_id = _uuid(20_299)
        values = {item.name: getattr(baseline, item.name) for item in fields(baseline)}
        for name in sorted(forbidden):
            with pytest.raises(TypeError):
                TerminalCommitIntentV3(**values, **{name: "caller-controlled"})
        return

    if case_alias == "missing-attempt-not-found-or-purged":
        connection = await _new_connection()
        try:
            result = await ExecutionLifecycleStore(connection, "sqlite").commit_terminal_attempt_v3(
                _sqlite_p1c_terminal_intent(0)
            )
            receipt = await _sqlite_p1c_terminal_receipt(connection)
        finally:
            await connection.close()
        assert (result.result, result.revision) == (
            FixedResult.NOT_FOUND_OR_PURGED,
            None,
        )
        assert receipt is None, "missing attempt created a receipt"
        return

    if case_alias == "v3-binding-vector-and-operation-codes":
        cases = (
            (OutcomeCode.CONFIRMED_SUCCESS, AttemptState.RUNNING, "terminal_succeeded"),
            (OutcomeCode.CONFIRMED_FAILURE, AttemptState.RUNNING, "terminal_failed"),
            (
                OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
                AttemptState.CANCELLING,
                "cancellation_acknowledgement",
            ),
            (OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED, AttemptState.RUNNING, "timeout"),
        )
        for index, (outcome, predecessor, operation_code) in enumerate(cases):
            connection, store, revision = await _sqlite_p1c_terminal_case(
                tmp_path / f"binding-{index}.db", predecessor=predecessor
            )
            try:
                intent = _sqlite_p1c_terminal_intent(revision, outcome=outcome)
                result = await store.commit_terminal_attempt_v3(intent)
                receipt = await _sqlite_p1c_terminal_receipt(connection)
            finally:
                await connection.close()
            assert result.result is FixedResult.APPLIED, "terminal binding case failed"
            assert receipt[0] == _sqlite_p1c_terminal_operation_id(intent.attempt_id)
            assert receipt[1] == operation_code, "terminal operation code changed"
            assert receipt[10] == 2, "receipt storage contract version changed"
            assert receipt[11] == _sqlite_p1c_terminal_request_digest(intent), (
                "terminal request binding vector changed"
            )
            assert receipt[14] == _sqlite_p1c_terminal_result_digest(intent), (
                "terminal result binding vector changed"
            )
            assert receipt[14] != intent.execution_result_digest, (
                "terminal receipt result binding conflated the execution-result digest"
            )
        return

    predecessor = (
        AttemptState.CANCELLING
        if case_alias
        in {
            "acknowledged-cancellation-atomic",
            "cancellation-caller-result-digest-invalid-contract",
        }
        else AttemptState.ACCEPTED
        if case_alias == "non-running-attempt-conflict-state"
        else AttemptState.RUNNING
    )
    connection, base_store, revision = await _sqlite_p1c_terminal_case(
        tmp_path / "terminal.db", predecessor=predecessor
    )
    store: ExecutionLifecycleStore = base_store
    intent = _sqlite_p1c_terminal_intent(revision)
    try:
        if case_alias == "invalid-contract-before-receipt":
            trace = _SQLiteP1CTerminalTraceStore(connection)
            duplicate_output = OutputObservation(_uuid(20_610), OutputKind.HOST, _uuid(260))
            same_link_other_target = OutputObservation(
                duplicate_output.link_id,
                OutputKind.HOST,
                _uuid(261),
            )
            same_target_other_link = OutputObservation(
                _uuid(20_611),
                OutputKind.HOST,
                duplicate_output.target_id,
            )
            oversized_outputs = tuple(
                OutputObservation(_uuid(21_000 + index), OutputKind.HOST, _uuid(22_000 + index))
                for index in range(257)
            )
            invalids = (
                replace(intent, expected_attempt_revision=MAX_I53),
                replace(intent, expected_attempt_revision=True),
                replace(intent, expected_attempt_revision=-1),
                replace(intent, attempt_id="not-a-canonical-uuid"),
                replace(intent, noise_actual=True),
                replace(intent, exfiltration_actual=True),
                replace(intent, concurrency_actual=True),
                replace(intent, noise_actual=-1),
                replace(intent, noise_actual=MAX_I53 + 1),
                replace(intent, concurrency_actual=1),
                replace(intent, execution_result_digest=None),
                replace(
                    intent,
                    execution_result_digest=_SQLITE_P1C_TERMINAL_RESULT_DIGEST.upper(),
                ),
                replace(intent, execution_result_digest="a" * 63),
                replace(intent, outputs=(duplicate_output, duplicate_output)),
                replace(intent, outputs=(duplicate_output, same_link_other_target)),
                replace(intent, outputs=(duplicate_output, same_target_other_link)),
                replace(intent, outputs=[duplicate_output]),  # type: ignore[arg-type]
                replace(intent, outputs=oversized_outputs),
                replace(
                    intent,
                    outcome_code=OutcomeCode.CONFIRMED_FAILURE,
                    outputs=(duplicate_output,),
                ),
            )
            before = await _snapshot_case(connection)
            results = tuple([await trace.commit_terminal_attempt_v3(item) for item in invalids])
            assert all(item.result is FixedResult.INVALID_CONTRACT for item in results)
            assert trace.transaction_entries == 0, "invalid intent entered a transaction"
            assert await _snapshot_case(connection) == before
        elif case_alias == "receipt-replay-after-target-deletion":
            applied = await store.commit_terminal_attempt_v3(intent)
            receipt_before = await _sqlite_p1c_terminal_receipt(connection)
            await connection.execute("PRAGMA foreign_keys=OFF")
            await connection.execute("DELETE FROM campaigns WHERE id=?", (_uuid(201),))
            await connection.execute("DELETE FROM logical_executions WHERE id=?", (_uuid(208),))
            await connection.execute("DELETE FROM execution_attempts WHERE id=?", (_uuid(210),))
            await connection.execute("DELETE FROM campaign_execution_budgets")
            await connection.execute("DELETE FROM campaign_execution_budget_ledger")
            await connection.execute("DELETE FROM execution_publication_outbox")
            await connection.commit()
            mutable_counts = []
            for table, predicate, parameters in (
                ("campaigns", "id=?", (_uuid(201),)),
                ("logical_executions", "id=?", (_uuid(208),)),
                ("execution_attempts", "id=?", (_uuid(210),)),
                ("campaign_execution_budgets", "campaign_id=?", (_uuid(201),)),
                ("campaign_execution_budget_ledger", "campaign_id=?", (_uuid(201),)),
                ("execution_publication_outbox", "campaign_id=?", (_uuid(201),)),
            ):
                row = await (
                    await connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {predicate}",  # noqa: S608
                        parameters,
                    )
                ).fetchone()
                mutable_counts.append(int(row[0]))
            assert mutable_counts == [0] * 6, "terminal replay targets were not deleted"
            replayed = await store.commit_terminal_attempt_v3(intent)
            receipt_after = await _sqlite_p1c_terminal_receipt(connection)
            assert (applied.result, replayed.result, replayed.revision) == (
                FixedResult.APPLIED,
                FixedResult.REPLAYED,
                revision + 1,
            )
            assert tuple(receipt_before) == tuple(receipt_after), (
                "terminal replay changed its immutable result identities"
            )
        elif case_alias == "receipt-replay-zero-mutable-reads":
            applied = await store.commit_terminal_attempt_v3(intent)
            trace = _SQLiteP1CTerminalTraceStore(connection, receipt_only=True)
            replayed = await trace.commit_terminal_attempt_v3(intent)
            assert (applied.result, replayed.result) == (
                FixedResult.APPLIED,
                FixedResult.REPLAYED,
            )
            assert trace.transaction_entries == 1
        elif case_alias == "changed-intent-conflict-operation":
            applied = await store.commit_terminal_attempt_v3(intent)
            receipt_only = _SQLiteP1CTerminalTraceStore(connection, receipt_only=True)
            changed = tuple(
                [
                    await receipt_only.commit_terminal_attempt_v3(changed_intent)
                    for changed_intent in (
                        replace(intent, noise_actual=0),
                        replace(
                            intent,
                            outputs=(
                                OutputObservation(
                                    _uuid(20_612),
                                    OutputKind.HOST,
                                    _uuid(260),
                                ),
                            ),
                        ),
                    )
                ]
            )
            assert applied.result is FixedResult.APPLIED
            assert all(item.result is FixedResult.CONFLICT_OPERATION for item in changed)
            assert receipt_only.transaction_entries == 2
        elif case_alias in {
            "known-success-atomic",
            "known-failure-atomic",
            "acknowledged-cancellation-atomic",
            "acknowledged-timeout-atomic",
        }:
            outcome, state, proof, event_code, operation_columns = {
                "known-success-atomic": (
                    OutcomeCode.CONFIRMED_SUCCESS,
                    AttemptState.SUCCEEDED,
                    "local_completion",
                    "execution_succeeded",
                    "terminal",
                ),
                "known-failure-atomic": (
                    OutcomeCode.CONFIRMED_FAILURE,
                    AttemptState.FAILED,
                    "local_completion",
                    "execution_failed",
                    "terminal",
                ),
                "acknowledged-cancellation-atomic": (
                    OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
                    AttemptState.CANCELLED,
                    "cancellation_no_result_ack",
                    "execution_cancelled",
                    "cancellation",
                ),
                "acknowledged-timeout-atomic": (
                    OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
                    AttemptState.TIMED_OUT,
                    "timeout_termination_ack",
                    "execution_timed_out",
                    "timeout",
                ),
            }[case_alias]
            intent = _sqlite_p1c_terminal_intent(revision, outcome=outcome)
            result = await store.commit_terminal_attempt_v3(intent)
            attempt = await _sqlite_p1c_terminal_state(connection)
            receipt = await _sqlite_p1c_terminal_receipt(connection)
            logical = await (
                await connection.execute(
                    "SELECT closure_operation_id,closing_attempt_id,revision "
                    "FROM logical_executions WHERE id=?",
                    (_uuid(208),),
                )
            ).fetchone()
            outbox = await (
                await connection.execute(
                    "SELECT event_code,is_attempt_terminal FROM execution_publication_outbox "
                    "WHERE attempt_id=?",
                    (_uuid(210),),
                )
            ).fetchone()
            settled_ledgers = await (
                await connection.execute(
                    "SELECT COUNT(*) FROM campaign_execution_budget_ledger "
                    "WHERE attempt_id=? AND disposition IN ('consumed','released') "
                    "AND budget_revision_settled IS NOT NULL",
                    (_uuid(210),),
                )
            ).fetchone()
            operation_id = _sqlite_p1c_terminal_operation_id(intent.attempt_id)
            expected_operation_columns = {
                "terminal": (operation_id, None, None),
                "cancellation": (None, operation_id, None),
                "timeout": (None, None, operation_id),
            }[operation_columns]
            assert (result.result, result.revision) == (
                FixedResult.APPLIED,
                revision + 1,
            )
            assert tuple(attempt[:6]) == (
                state.value,
                revision + 1,
                outcome.value,
                "settled",
                proof,
                1,
            ), "known terminal settlement changed"
            assert tuple(attempt[6:]) == (
                1,
                "closed_without_retry",
                *expected_operation_columns,
            ), "known terminal closure facts changed"
            assert tuple(logical) == (operation_id, _uuid(210), 1), (
                "known terminal logical closure changed"
            )
            assert (receipt[12], receipt[13], receipt[15], receipt[16]) == (
                FixedResult.APPLIED.value,
                FixedResult.REPLAYED.value,
                _uuid(210),
                revision + 1,
            ), "known terminal receipt result changed"
            assert tuple(outbox) == (event_code, 1), "known terminal outbox binding changed"
            assert int(settled_ledgers[0]) == 3, "known terminal budget settlement was incomplete"
        elif case_alias == "uncertain-outcome-invalid-contract":
            uncertain = replace(
                intent,
                outcome_code=OutcomeCode.UNKNOWN_AFTER_RECOVERY,
                execution_result_digest=None,
            )
            trace = _SQLiteP1CTerminalTraceStore(connection)
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                uncertain,
                expected_result=FixedResult.INVALID_CONTRACT,
            )
            assert trace.transaction_entries == 0, "uncertain outcome reached persistence"
        elif case_alias == "single-transaction-zero-nested-acquire":
            trace = _SQLiteP1CTerminalTraceStore(connection)
            applied = await trace.commit_terminal_attempt_v3(intent)
            assert applied.result is FixedResult.APPLIED
            assert trace.transaction_entries == 1, "terminal seam nested a transaction"
            assert trace.connection_identities == {id(connection)}, (
                "terminal seam acquired another connection"
            )
            assert trace.read_events[0] == "receipt", (
                "terminal apply read mutable state before receipt classification"
            )
        elif case_alias == "derive-exact-three-held-ledgers":
            applied = await store.commit_terminal_attempt_v3(intent)
            ledgers = await (
                await connection.execute(
                    "SELECT budget_kind,disposition,consumed_units "
                    "FROM campaign_execution_budget_ledger WHERE attempt_id=? "
                    "ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                    "WHEN 'exfiltration' THEN 2 ELSE 3 END",
                    (_uuid(210),),
                )
            ).fetchall()
            assert applied.result is FixedResult.APPLIED
            assert tuple(tuple(row) for row in ledgers) == (
                ("noise", "consumed", 1),
                ("exfiltration", "consumed", 2),
                ("concurrency", "released", 0),
            )
        elif case_alias == "missing-ledger-inconsistent-set-rollback":
            await connection.execute(
                "DELETE FROM campaign_execution_budget_ledger "
                "WHERE attempt_id=? AND budget_kind='noise'",
                (_uuid(210),),
            )
            await connection.commit()
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                intent,
                expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
            )
        elif case_alias == "duplicate-extra-ledger-inconsistent-set-rollback":
            trace = _SQLiteP1CTerminalTraceStore(connection, duplicate_ledger_row=True)
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
            )
        elif case_alias == "wrong-kind-ledger-inconsistent-set-rollback":
            trace = _SQLiteP1CTerminalTraceStore(connection, ledger_mutation="kind")
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
            )
        elif case_alias == "wrong-campaign-attempt-ledger-inconsistent-set-rollback":
            for mutation in ("campaign", "attempt"):
                trace = _SQLiteP1CTerminalTraceStore(connection, ledger_mutation=mutation)
                await _sqlite_p1c_assert_rollback(
                    connection,
                    trace,
                    intent,
                    expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
                )
        elif case_alias == "non-held-ledger-conflict-operation-rollback":
            await connection.execute(
                "UPDATE campaign_execution_budget_ledger SET disposition='released',"
                "consumed_units=0,budget_revision_settled=1,settled_at=reserved_at "
                "WHERE attempt_id=? AND budget_kind='noise'",
                (_uuid(210),),
            )
            await connection.commit()
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                intent,
                expected_result=FixedResult.CONFLICT_OPERATION,
            )
        elif case_alias == "current-budget-lock-no-toctou":
            await connection.execute(
                "UPDATE campaign_execution_budgets SET revision=2,latest_operation_id=?,"
                "latest_operation_base_revision=1,latest_operation_code='configure' "
                "WHERE campaign_id=?",
                (_uuid(20_310), _uuid(201)),
            )
            await connection.commit()
            applied = await store.commit_terminal_attempt_v3(intent)
            revisions = await (
                await connection.execute(
                    "SELECT revision FROM campaign_execution_budgets WHERE campaign_id=? "
                    "ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                    "WHEN 'exfiltration' THEN 2 ELSE 3 END",
                    (_uuid(201),),
                )
            ).fetchall()
            assert applied.result is FixedResult.APPLIED
            assert tuple(int(row[0]) for row in revisions) == (3, 3, 3)
        elif case_alias == "budget-capacity-inconsistent-set-rollback":
            await connection.execute(
                "UPDATE campaign_execution_budgets SET reserved_units=0 "
                "WHERE campaign_id=? AND budget_kind='noise'",
                (_uuid(201),),
            )
            await connection.commit()
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                intent,
                expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
            )
        elif case_alias in {
            "budget-write-failure-rollback",
            "output-write-failure-rollback",
            "terminal-write-failure-rollback",
            "logical-closure-write-failure-rollback",
            "outbox-write-failure-rollback",
            "receipt-write-failure-rollback",
        }:
            fail_at = {
                "budget-write-failure-rollback": "budget",
                "output-write-failure-rollback": "output",
                "terminal-write-failure-rollback": "terminal",
                "logical-closure-write-failure-rollback": "logical",
                "outbox-write-failure-rollback": "outbox",
                "receipt-write-failure-rollback": "receipt",
            }[case_alias]
            if fail_at == "output":
                intent = replace(
                    intent,
                    outputs=(OutputObservation(_uuid(20_320), OutputKind.HOST, _uuid(260)),),
                )
            trace = _SQLiteP1CTerminalTraceStore(connection, fail_at=fail_at)
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_exception=RuntimeError,
            )
        elif case_alias == "non-running-attempt-conflict-state":
            result = await _sqlite_p1c_assert_rollback(
                connection,
                store,
                replace(intent, expected_attempt_revision=revision + 1),
                expected_result=FixedResult.CONFLICT_STATE,
            )
            assert result is not None
            assert result.revision == revision, (
                "attempt-state precedence did not dominate stale revision"
            )
        elif case_alias == "stale-attempt-revision-conflict":
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                replace(intent, expected_attempt_revision=revision - 1),
                expected_result=FixedResult.CONFLICT_REVISION,
            )
        elif case_alias == "invariant-failure-rollback":
            trace = _SQLiteP1CTerminalTraceStore(connection, duplicate_terminal_returning=True)
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_result=FixedResult.INVARIANT_FAILURE,
            )
        elif case_alias == "cancellation-rollback-and-reuse":
            trace = _SQLiteP1CTerminalTraceStore(connection, cancel_at="output")
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_exception=asyncio.CancelledError,
            )
            reused = await base_store.commit_terminal_attempt_v3(intent)
            assert reused.result is FixedResult.APPLIED, "cancelled connection was not reusable"
        elif case_alias == "exception-rollback-and-reuse":
            trace = _SQLiteP1CTerminalTraceStore(connection, fail_at="exception")
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                intent,
                expected_exception=RuntimeError,
            )
            reused = await base_store.commit_terminal_attempt_v3(intent)
            assert reused.result is FixedResult.APPLIED, "failed connection was not reusable"
        elif case_alias == "legacy-terminal-apply-replay-bytes-unchanged":
            operation_id = _uuid(20_400)
            legacy = _sqlite_p1c_legacy_terminal_request(operation_id, revision)
            applied = await store.commit_terminal_attempt(legacy)
            vector_rows = await (
                await connection.execute(
                    "SELECT operation_id,operation_code,binding_contract_version,"
                    "request_binding_digest,result_binding_digest "
                    "FROM execution_operation_receipts WHERE operation_id IN (?,?,?) "
                    "ORDER BY operation_id",
                    (_uuid(20_200), _uuid(20_202), operation_id),
                )
            ).fetchall()
            all_receipts_before = await (
                await connection.execute(
                    "SELECT * FROM execution_operation_receipts ORDER BY operation_id"
                )
            ).fetchall()
            replayed = await store.commit_terminal_attempt(legacy)
            all_receipts_after = await (
                await connection.execute(
                    "SELECT * FROM execution_operation_receipts ORDER BY operation_id"
                )
            ).fetchall()
            assert (applied.result, replayed.result) == (
                FixedResult.APPLIED,
                FixedResult.REPLAYED,
            )
            assert tuple(tuple(row) for row in vector_rows) == (
                _SQLITE_P1C_LEGACY_TERMINAL_RECEIPT_VECTORS
            ), "legacy terminal receipt vectors drifted"
            assert tuple(tuple(row) for row in all_receipts_before) == tuple(
                tuple(row) for row in all_receipts_after
            ), "legacy replay changed a receipt row"
        elif case_alias == "legacy-v3-crossing-conflict-operation":
            operation_id = _sqlite_p1c_terminal_operation_id(intent.attempt_id)
            legacy = _sqlite_p1c_legacy_terminal_request(operation_id, revision)
            applied = await store.commit_terminal_attempt(legacy)
            receipt_only = _SQLiteP1CTerminalTraceStore(connection, receipt_only=True)
            crossed = await receipt_only.commit_terminal_attempt_v3(intent)
            assert (applied.result, crossed.result) == (
                FixedResult.APPLIED,
                FixedResult.CONFLICT_OPERATION,
            )
            assert receipt_only.transaction_entries == 1
            second_connection, second_store, second_revision = await _sqlite_p1c_terminal_case(
                tmp_path / "cross-v3-first.db"
            )
            try:
                second_intent = _sqlite_p1c_terminal_intent(second_revision)
                v3_applied = await second_store.commit_terminal_attempt_v3(second_intent)
                second_receipt_only = _SQLiteP1CTerminalTraceStore(
                    second_connection, receipt_only=True
                )
                legacy_crossed = await second_receipt_only.commit_terminal_attempt(
                    _sqlite_p1c_legacy_terminal_request(
                        _sqlite_p1c_terminal_operation_id(second_intent.attempt_id),
                        second_revision,
                    )
                )
            finally:
                await second_connection.close()
            assert (v3_applied.result, legacy_crossed.result) == (
                FixedResult.APPLIED,
                FixedResult.CONFLICT_OPERATION,
            )
            assert second_receipt_only.transaction_entries == 1
        elif case_alias == "changed-outcome-conflict-operation":
            applied = await store.commit_terminal_attempt_v3(intent)
            receipt_only = _SQLiteP1CTerminalTraceStore(connection, receipt_only=True)
            changed = await receipt_only.commit_terminal_attempt_v3(
                replace(
                    intent,
                    outcome_code=OutcomeCode.CONFIRMED_FAILURE,
                    outputs=(),
                    execution_result_digest=hashlib.sha256(b"changed-outcome").hexdigest(),
                )
            )
            assert (applied.result, changed.result) == (
                FixedResult.APPLIED,
                FixedResult.CONFLICT_OPERATION,
            )
            assert receipt_only.transaction_entries == 1
        elif case_alias == "changed-result-digest-conflict-operation":
            applied = await store.commit_terminal_attempt_v3(intent)
            receipt_only = _SQLiteP1CTerminalTraceStore(connection, receipt_only=True)
            changed = await receipt_only.commit_terminal_attempt_v3(
                replace(intent, execution_result_digest=hashlib.sha256(b"changed").hexdigest())
            )
            assert (applied.result, changed.result) == (
                FixedResult.APPLIED,
                FixedResult.CONFLICT_OPERATION,
            )
            assert receipt_only.transaction_entries == 1
        elif case_alias in {
            "cancellation-caller-result-digest-invalid-contract",
            "timeout-caller-result-digest-invalid-contract",
        }:
            outcome = (
                OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT
                if case_alias.startswith("cancellation")
                else OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED
            )
            invalid = _sqlite_p1c_terminal_intent(
                revision,
                outcome=outcome,
                execution_result_digest=_SQLITE_P1C_TERMINAL_RESULT_DIGEST,
            )
            trace = _SQLiteP1CTerminalTraceStore(connection)
            await _sqlite_p1c_assert_rollback(
                connection,
                trace,
                invalid,
                expected_result=FixedResult.INVALID_CONTRACT,
            )
            assert trace.transaction_entries == 0, "no-result digest reached persistence"
        elif case_alias == "canonical-output-order-exact-replay":
            await connection.execute(
                "INSERT INTO hosts(id,campaign_id,ip_address) VALUES(?,?,?)",
                (_uuid(20_500), _uuid(201), "192.0.2.2"),
            )
            await connection.execute(
                "INSERT INTO loot(id,campaign_id,host_id,loot_type,name) VALUES(?,?,?,?,?)",
                (_uuid(20_503), _uuid(201), _uuid(260), "artifact", "fixed-output"),
            )
            await connection.commit()
            outputs = (
                OutputObservation(_uuid(20_502), OutputKind.HOST, _uuid(20_500)),
                OutputObservation(_uuid(20_503), OutputKind.ARTIFACT, _uuid(20_503)),
                OutputObservation(_uuid(20_501), OutputKind.HOST, _uuid(260)),
            )
            forward = replace(intent, outputs=outputs)
            reversed_intent = replace(intent, outputs=tuple(reversed(outputs)))
            trace = _SQLiteP1CTerminalTraceStore(connection)
            applied = await trace.commit_terminal_attempt_v3(forward)
            replayed = await trace.commit_terminal_attempt_v3(reversed_intent)
            rows = await (
                await connection.execute(
                    "SELECT id,host_id,loot_id FROM execution_output_links "
                    "WHERE attempt_id=? ORDER BY id",
                    (_uuid(210),),
                )
            ).fetchall()
            assert (applied.result, replayed.result) == (
                FixedResult.APPLIED,
                FixedResult.REPLAYED,
            )
            assert _sqlite_p1c_terminal_request_digest(
                forward
            ) == _sqlite_p1c_terminal_request_digest(reversed_intent)
            assert tuple(tuple(row) for row in rows) == (
                (_uuid(20_501), _uuid(260), None),
                (_uuid(20_502), _uuid(20_500), None),
                (_uuid(20_503), None, _uuid(20_503)),
            )
            assert trace.output_insert_order == [
                _uuid(20_503),
                _uuid(20_501),
                _uuid(20_502),
            ], "persisted output insertion order was not canonical"
        elif case_alias == "terminal-operation-and-system-principal-namespace":
            applied = await store.commit_terminal_attempt_v3(intent)
            receipt = await _sqlite_p1c_terminal_receipt(connection)
            actor = await (
                await connection.execute(
                    "SELECT actor_subject_ref,actor_user_id FROM execution_attempts WHERE id=?",
                    (_uuid(210),),
                )
            ).fetchone()
            assert applied.result is FixedResult.APPLIED
            assert tuple(receipt[:11]) == (
                _sqlite_p1c_terminal_operation_id(_uuid(210)),
                "terminal_succeeded",
                _uuid(201),
                _uuid(210),
                _uuid(208),
                "system",
                SYSTEM_PRINCIPAL_SUBJECT_REF,
                None,
                0,
                None,
                2,
            )
            assert tuple(actor) == (_uuid(200), _uuid(200))
            assert SYSTEM_PRINCIPAL_SUBJECT_REF != str(actor[0]), (
                "reserved system subject collided with the persisted actor"
            )
            assert ("system", SYSTEM_PRINCIPAL_SUBJECT_REF) != (
                "actor",
                str(actor[0]),
            ), "typed system namespace collided with the user-principal namespace"
        elif case_alias == "derived-revision-overflow-invariant-failure-rollback":
            await connection.execute(
                "UPDATE campaign_execution_budgets SET revision=?,"
                "latest_operation_base_revision=? "
                "WHERE campaign_id=? AND budget_kind='noise'",
                (MAX_I53, MAX_I53 - 1, _uuid(201)),
            )
            await connection.commit()
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                intent,
                expected_result=FixedResult.INVARIANT_FAILURE,
            )
            await connection.close()
            connection, store, revision = await _sqlite_p1c_terminal_case(
                tmp_path / "logical-overflow.db"
            )
            intent = _sqlite_p1c_terminal_intent(revision)
            await connection.execute(
                "UPDATE logical_executions SET revision=? WHERE id=?",
                (MAX_I53, _uuid(208)),
            )
            await connection.commit()
            await _sqlite_p1c_assert_rollback(
                connection,
                store,
                intent,
                expected_result=FixedResult.INVARIANT_FAILURE,
            )
            await connection.close()
            connection, store, revision = await _sqlite_p1c_terminal_case(
                tmp_path / "actual-max.db"
            )
            await connection.execute(
                "UPDATE campaign_execution_budgets SET capacity_units=?,reserved_units=? "
                "WHERE campaign_id=? AND budget_kind='noise'",
                (MAX_I53, MAX_I53, _uuid(201)),
            )
            await connection.execute(
                "UPDATE campaign_execution_budget_ledger SET reservation_units=? "
                "WHERE attempt_id=? AND budget_kind='noise'",
                (MAX_I53, _uuid(210)),
            )
            await connection.commit()
            max_actual = await store.commit_terminal_attempt_v3(
                _sqlite_p1c_terminal_intent(revision, noise_actual=MAX_I53)
            )
            max_rows = await (
                await connection.execute(
                    "SELECT b.reserved_units,b.consumed_units,l.consumed_units "
                    "FROM campaign_execution_budgets b "
                    "JOIN campaign_execution_budget_ledger l ON l.budget_id=b.id "
                    "WHERE b.campaign_id=? AND b.budget_kind='noise' AND l.attempt_id=?",
                    (_uuid(201), _uuid(210)),
                )
            ).fetchone()
            assert max_actual.result is FixedResult.APPLIED, "MAX_I53 actual usage was rejected"
            assert tuple(max_rows) == (0, MAX_I53, MAX_I53), (
                "MAX_I53 actual usage was not settled with checked arithmetic"
            )
        else:  # pragma: no cover - tuple/dispatcher drift must be loud.
            raise AssertionError(f"unhandled SQLite terminal alias: {case_alias}")
    finally:
        await connection.close()
