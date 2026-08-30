"""Real PostgreSQL persistence-operation tests for lifecycle generation 10."""

from __future__ import annotations

import asyncio
import hashlib
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass, replace
from typing import Any, get_type_hints

import asyncpg
import pytest
import pytest_asyncio

import ares.modules.descriptors as _descriptors
from ares.db.execution_lifecycle import (
    MAX_I53,
    SYSTEM_PRINCIPAL_SUBJECT_REF,
    ActorAuthorityMutation,
    AdmissionIntentV3,
    AdmissionRequest,
    ApprovalAuthorityGrant,
    ApprovalAuthorityMutation,
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
    RetryIntentV3,
    RetryRequest,
    TerminalCommitIntentV3,
    TerminalCommitRequest,
    TransitionRequest,
    TrustedPrincipal,
    validate_postgresql_lifecycle_catalog,
)
from ares.db.postgres import PostgresDatabase
from ares.modules.descriptors import (
    CancellationOwnership,
    CompensationClass,
    ContractState,
    ExternalEffectClass,
    IdempotencyClass,
    ResultContract,
    RetryEligibility,
    TimeoutPolicy,
    TimeoutSettlement,
)
from tests.integration.test_postgres_migration_portability import (
    _alembic,
    _migration_url,
    _MigrationHarness,
    _postgres_harness,
)
from tests.unit.test_execution_lifecycle_persistence import (
    _ACCEPTANCE_FACT_MUTATIONS,
    _EXPECTED_LEGAL,
    _ILLEGAL,
    _accepted_snapshot,
    _AdvancedClockLifecycleStore,
    _attempt_row,
    _blocked_snapshot,
    _build_source_state,
    _nonterminal_transition,
    _snapshot_case,
    _terminal_transition,
    _uuid,
)

_USER_ID = "00000000-0000-4000-8000-000000000001"
_CAMPAIGN_ID = "00000000-0000-4000-8000-000000000002"
_OPERATION_A = "00000000-0000-4000-8000-000000000003"
_OPERATION_B = "00000000-0000-4000-8000-000000000004"

_TERMINAL_TARGETS = frozenset(
    {
        "rejected",
        "blocked",
        "succeeded",
        "partial",
        "failed",
        "skipped",
        "cancelled",
        "timed_out",
        "indeterminate",
    }
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("_case", "field_name", "mutant"),
    _ACCEPTANCE_FACT_MUTATIONS,
    ids=[case for case, _field_name, _mutant in _ACCEPTANCE_FACT_MUTATIONS],
)
async def test_postgres_real_admission_rejects_each_invalid_fact(
    _case: str,
    field_name: str,
    mutant: Any,
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        results: list[FixedResult] = []
        try:
            snapshot = replace(_accepted_snapshot(), **{field_name: mutant})
            _store, _adapter, connection = await _postgres_transition_case(
                database,
                AttemptState.ACCEPTED,
                snapshot_override=snapshot,
                admission_results=results,
                expected_applied=False,
            )
            observer = await database._pool.acquire()
            logical_count = await observer.fetchval("SELECT COUNT(*) FROM logical_executions")
            attempt_count = await observer.fetchval("SELECT COUNT(*) FROM execution_attempts")
            ledger_count = await observer.fetchval(
                "SELECT COUNT(*) FROM campaign_execution_budget_ledger"
            )
            outbox_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_publication_outbox"
            )
            admission_receipt_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_operation_receipts WHERE operation_id = $1",
                _uuid(211),
            )
            reserved_total = await observer.fetchval(
                "SELECT COALESCE(SUM(reserved_units), 0) FROM campaign_execution_budgets"
            )
            assert results == [results[0]]
            assert results[0] is not FixedResult.APPLIED
            assert (logical_count, attempt_count, ledger_count, outbox_count) == (
                0,
                0,
                0,
                0,
            )
            assert admission_receipt_count == 0
            assert reserved_total == 0
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "mutant"),
    [
        ("attempt_id", _uuid(890)),
        ("expected_revision", 1),
        ("target_state", AttemptState.DISPATCHING),
    ],
    ids=("attempt-binding", "revision-binding", "state-binding"),
)
async def test_postgres_transition_receipt_replay_and_binding_conflict(
    field_name: str,
    mutant: Any,
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        try:
            store, _adapter, connection = await _postgres_transition_case(
                database, AttemptState.ACCEPTED
            )
            request = TransitionRequest(
                _uuid(210),
                0,
                AttemptState.QUEUED,
                _uuid(880),
                campaign_id=_uuid(201),
                actor_subject_ref=_uuid(200),
                actor_user_id=_uuid(200),
                actor_authority_revision=0,
            )
            applied = await store.transition_attempt(request)
            replayed = await store.transition_attempt(request)
            conflict = await store.transition_attempt(replace(request, **{field_name: mutant}))
            observer = await database._pool.acquire()
            row = await observer.fetchrow(
                "SELECT state, revision FROM execution_attempts WHERE id = $1",
                _uuid(210),
            )
            receipt_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_operation_receipts WHERE operation_id = $1",
                _uuid(880),
            )
            assert applied.result is FixedResult.APPLIED
            assert replayed.result is FixedResult.REPLAYED
            assert conflict.result is FixedResult.CONFLICT_OPERATION
            assert tuple(row) == (AttemptState.QUEUED.value, 1)
            assert receipt_count == 1
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_budget_replay_and_terminal_release_are_exact(
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        try:
            store, adapter, connection = await _postgres_transition_case(
                database, AttemptState.ACCEPTED
            )
            configuration = BudgetConfiguration(
                _uuid(201),
                _uuid(204),
                20,
                _uuid(205),
                20,
                _uuid(206),
                1,
                _uuid(207),
            )
            replayed = await store.configure_campaign_budgets(configuration)
            conflict = await store.configure_campaign_budgets(
                replace(configuration, noise_capacity=21)
            )
            terminal = await _terminal_transition(
                store,
                adapter,
                AttemptState.SKIPPED,
                880,
            )
            observer = await database._pool.acquire()
            balances = await observer.fetchrow(
                "SELECT COALESCE(SUM(reserved_units), 0), "
                "MIN(revision), MAX(revision) "
                "FROM campaign_execution_budgets WHERE campaign_id = $1",
                _uuid(201),
            )
            dispositions = await observer.fetch(
                "SELECT disposition FROM campaign_execution_budget_ledger "
                "WHERE attempt_id = $1 ORDER BY budget_kind",
                _uuid(210),
            )
            assert replayed.result is FixedResult.REPLAYED
            assert conflict.result is FixedResult.CONFLICT_OPERATION
            assert terminal.result is FixedResult.APPLIED
            assert tuple(balances) == (0, 2, 2)
            assert [row["disposition"] for row in dispositions] == [
                "released",
                "released",
                "released",
            ]
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_outbox_replay_owner_binding_and_publish_are_exact(
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        try:
            store, _adapter, connection = await _postgres_transition_case(
                database, AttemptState.BLOCKED
            )
            claim = OutboxMutation(
                _uuid(212),
                0,
                _uuid(880),
                _uuid(882),
                0,
                _uuid(201),
                _uuid(210),
                _uuid(213),
                "execution_blocked",
            )
            applied = await store.claim_outbox(claim)
            replayed = await store.claim_outbox(claim)
            conflict = await store.claim_outbox(replace(claim, owner_ref=_uuid(883)))
            published = await store.publish_outbox(
                OutboxMutation(
                    _uuid(212),
                    1,
                    _uuid(881),
                    _uuid(882),
                    1,
                    _uuid(201),
                    _uuid(210),
                    _uuid(213),
                    "execution_blocked",
                )
            )
            observer = await database._pool.acquire()
            row = await observer.fetchrow(
                "SELECT publication_state, claim_revision, delivery_attempt_count "
                "FROM execution_publication_outbox WHERE id = $1",
                _uuid(212),
            )
            receipt_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_operation_receipts WHERE operation_id IN ($1, $2)",
                _uuid(880),
                _uuid(881),
            )
            assert applied.result is FixedResult.APPLIED
            assert replayed.result is FixedResult.REPLAYED
            assert conflict.result is FixedResult.CONFLICT_OPERATION
            assert published.result is FixedResult.APPLIED
            assert tuple(row) == ("published", 2, 1)
            assert receipt_count == 2
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_terminal_output_commit_is_atomically_observable(
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        try:
            store, adapter, connection = await _postgres_transition_case(
                database, AttemptState.ACCEPTED
            )
            await _build_source_state(store, adapter, AttemptState.RUNNING)
            result = await _terminal_transition(
                store,
                adapter,
                AttemptState.PARTIAL,
                880,
            )
            observer = await database._pool.acquire()
            attempt = await observer.fetchrow(
                "SELECT state, closes_logical FROM execution_attempts WHERE id = $1",
                _uuid(210),
            )
            link_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_output_links "
                "WHERE attempt_id = $1 AND host_id = $2",
                _uuid(210),
                _uuid(260),
            )
            outbox_count = await observer.fetchval(
                "SELECT COUNT(*) FROM execution_publication_outbox "
                "WHERE attempt_id = $1 AND event_code = $2",
                _uuid(210),
                "execution_partial",
            )
            reserved_total = await observer.fetchval(
                "SELECT COALESCE(SUM(reserved_units), 0) "
                "FROM campaign_execution_budgets WHERE campaign_id = $1",
                _uuid(201),
            )
            assert result.result is FixedResult.APPLIED
            assert tuple(attempt) == (AttemptState.PARTIAL.value, True)
            assert link_count == 1
            assert outbox_count == 1
            assert reserved_total == 0
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_settled_campaign_deletion_removes_lifecycle_tree(
    postgres_lifecycle_template: str,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        connection = None
        observer = None
        try:
            store, adapter, connection = await _postgres_transition_case(
                database, AttemptState.ACCEPTED
            )
            terminal = await _terminal_transition(
                store,
                adapter,
                AttemptState.SKIPPED,
                880,
            )
            await database._pool.release(connection)
            connection = None
            deleted = await database.delete_campaign_lifecycle(
                _uuid(201), lifecycle_operation_id=_uuid(884)
            )
            observer = await database._pool.acquire()
            counts = (
                await observer.fetchval("SELECT COUNT(*) FROM campaigns WHERE id = $1", _uuid(201)),
                await observer.fetchval(
                    "SELECT COUNT(*) FROM logical_executions WHERE campaign_id = $1",
                    _uuid(201),
                ),
                await observer.fetchval(
                    "SELECT COUNT(*) FROM execution_attempts WHERE campaign_id = $1",
                    _uuid(201),
                ),
                await observer.fetchval(
                    "SELECT COUNT(*) FROM campaign_execution_budgets WHERE campaign_id = $1",
                    _uuid(201),
                ),
            )
            assert terminal.result is FixedResult.APPLIED
            assert deleted.result is FixedResult.APPLIED
            assert counts == (0, 0, 0, 0)
        finally:
            if observer is not None:
                await database._pool.release(observer)
            if connection is not None:
                await database._pool.release(connection)
            await database.close()


def _question_to_dollar(sql: str) -> str:
    parts = sql.split("?")
    return parts[0] + "".join(f"${index}{part}" for index, part in enumerate(parts[1:], 1))


class _PostgresCursor:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    async def fetchone(self) -> Any | None:
        return self._rows[0] if self._rows else None

    async def fetchall(self) -> list[Any]:
        return list(self._rows)


class _PostgresConnectionAdapter:
    """Test-owned aiosqlite-shaped view over one real asyncpg connection."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _PostgresCursor:
        statement = _question_to_dollar(sql)
        if statement.lstrip().upper().startswith("SELECT") or " RETURNING " in statement.upper():
            rows = list(await self._connection.fetch(statement, *params))
            return _PostgresCursor(rows)
        await self._connection.execute(statement, *params)
        return _PostgresCursor([])

    async def commit(self) -> None:
        await self._connection.execute("COMMIT")

    async def rollback(self) -> None:
        await self._connection.execute("ROLLBACK")

    async def fetchrow(self, statement: str, *parameters: object):
        return await self._connection.fetchrow(_question_to_dollar(statement), *parameters)


async def _replace_database_from_template(
    candidate: _MigrationHarness,
    template: _MigrationHarness,
) -> None:
    names = (candidate.database_name, template.database_name)
    if not all(name.replace("_", "").isalnum() for name in names):
        raise AssertionError("POSTGRES_TEMPLATE_NAME_INVALID")
    config = candidate.config
    connection = await asyncpg.connect(
        host=config.host,
        port=config.port,
        user=config.user,
        database=config.maintenance_database,
    )
    try:
        await connection.execute(  # noqa: S608
            f'DROP DATABASE "{candidate.database_name}"'
        )
        await connection.execute(  # noqa: S608
            f'CREATE DATABASE "{candidate.database_name}" TEMPLATE "{template.database_name}"'
        )
    finally:
        await connection.close()


@asynccontextmanager
async def _cloned_postgres_harness(
    template: _MigrationHarness,
) -> AsyncIterator[_MigrationHarness]:
    async with _postgres_harness() as candidate:
        await _replace_database_from_template(candidate, template)
        yield candidate


@pytest_asyncio.fixture(scope="module")
async def postgres_lifecycle_template() -> AsyncIterator[_MigrationHarness]:
    async with _postgres_harness() as template:
        await _alembic(template, "upgrade", "head", timeout=60.0)
        yield template


async def _postgres_transition_case(
    database: PostgresDatabase,
    initial: str,
    *,
    snapshot_override: Any | None = None,
    admission_results: list[FixedResult] | None = None,
    expected_applied: bool = True,
) -> tuple[ExecutionLifecycleStore, _PostgresConnectionAdapter, Any]:
    async with database._pool.acquire() as gateway_connection:
        initial not in {"rejected", "blocked"} and await gateway_connection.execute(
            """
            UPDATE execution_gateway_state
            SET mode = 'enforced',
                catalog_digest = repeat('0', 64),
                activation_revision = 1,
                activation_at = updated_at,
                revision = revision + 1
            """
        )
    connection = await database._pool.acquire()
    handed_off = False
    try:
        result = await _initialize_postgres_transition_case(
            database,
            connection,
            initial,
            snapshot_override=snapshot_override,
            admission_results=admission_results,
            expected_applied=expected_applied,
        )
        handed_off = True
        return result
    finally:
        if not handed_off:
            await database._pool.release(connection)


async def _initialize_postgres_transition_case(
    database: PostgresDatabase,
    connection: Any,
    initial: str,
    *,
    snapshot_override: Any | None,
    admission_results: list[FixedResult] | None,
    expected_applied: bool,
) -> tuple[ExecutionLifecycleStore, _PostgresConnectionAdapter, Any]:
    adapter = _PostgresConnectionAdapter(connection)
    await connection.execute(
        "INSERT INTO users(id,username,hashed_password,role,created_by) "
        "VALUES($1,'transition-user','fixed-hash','admin','fixed')",
        _uuid(200),
    )
    await connection.execute(
        "INSERT INTO campaigns(id,name) VALUES($1,'transition-campaign')",
        _uuid(201),
    )
    await connection.execute(
        "INSERT INTO hosts (id, campaign_id, ip_address) VALUES ($1, $2, $3)",
        _uuid(260),
        _uuid(201),
        "192.0.2.1",
    )

    store = ExecutionLifecycleStore(database._pool, "postgresql")
    assert (
        await store.ensure_actor_authority(_uuid(200), _uuid(202))
    ).result is FixedResult.APPLIED
    assert (
        await store.ensure_campaign_authority(_uuid(201), _uuid(203))
    ).result is FixedResult.APPLIED

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
    if initial not in {"rejected", "blocked"}:
        configured = await store.configure_campaign_budgets(
            BudgetConfiguration(
                _uuid(201),
                _uuid(204),
                20,
                _uuid(205),
                20,
                _uuid(206),
                1,
                _uuid(207),
            )
        )
        assert configured.result is FixedResult.APPLIED

    if initial == "accepted":
        snapshot = _accepted_snapshot()
        outbox_id = None
        publication_key = None
        request_budgets = budgets
    elif initial == "rejected":
        snapshot = replace(
            _blocked_snapshot(),
            policy_verdict="rejected",
            policy_reason_mask=1,
        )
        outbox_id = _uuid(212)
        publication_key = _uuid(213)
        request_budgets = None
    else:
        snapshot = _blocked_snapshot()
        outbox_id = _uuid(212)
        publication_key = _uuid(213)
        request_budgets = None
    if snapshot_override is not None:
        snapshot = snapshot_override
    await connection.execute(
        "UPDATE users SET role=$1 WHERE id=$2",
        snapshot.actor_role,
        _uuid(200),
    )
    admitted = await store._create_initial_execution_v2_for_migration_fixture(
        AdmissionRequest(
            _uuid(208),
            _uuid(209),
            _uuid(210),
            outbox_id,
            publication_key,
            _uuid(201),
            _uuid(200),
            _uuid(200),
            "test-transition",
            "sdk",
            AttemptState(initial),
            _uuid(211),
            snapshot,
            None,
            request_budgets,
        )
    )
    if admission_results is not None:
        admission_results.append(admitted.result)
    if expected_applied:
        assert admitted.result is FixedResult.APPLIED
    else:
        assert admitted.result is not FixedResult.APPLIED
    return store, adapter, connection


async def _exercise_postgres_pair(
    database: PostgresDatabase,
    source: str,
    target: str,
) -> tuple[Any, tuple[Any, ...], tuple[Any, ...], tuple[Any, ...], Any, Any]:
    initial = source if source in {"rejected", "blocked"} else "accepted"
    store, adapter, connection = await _postgres_transition_case(database, initial)
    try:
        if source not in {"rejected", "blocked", "accepted"}:
            source_state = AttemptState(source)
            if source_state in {AttemptState.FAILED, AttemptState.SKIPPED}:
                result = await _terminal_transition(store, adapter, source_state, 270)
                assert result.result is FixedResult.APPLIED
            elif source_state is AttemptState.INDETERMINATE:
                await _build_source_state(
                    store,
                    adapter,
                    AttemptState.SETTLEMENT_PENDING,
                )
                await connection.execute(
                    "UPDATE users SET role = $1 WHERE id = $2",
                    "admin",
                    _uuid(200),
                )
                terminal_store = _AdvancedClockLifecycleStore(
                    database._pool,
                    "postgresql",
                )
                result = await _terminal_transition(
                    terminal_store,
                    adapter,
                    source_state,
                    700,
                )
                assert result.result is FixedResult.APPLIED
            else:
                await _build_source_state(store, adapter, source_state)
        before_row = await _attempt_row(adapter)
        before = await _snapshot_case(adapter)
        if target in _TERMINAL_TARGETS:
            if target == AttemptState.INDETERMINATE.value:
                await connection.execute(
                    "UPDATE users SET role = $1 WHERE id = $2",
                    "admin",
                    _uuid(200),
                )
            terminal_store = (
                _AdvancedClockLifecycleStore(database._pool, "postgresql")
                if target == AttemptState.INDETERMINATE.value
                else store
            )
            result = await _terminal_transition(terminal_store, adapter, AttemptState(target), 700)
        else:
            result = await _nonterminal_transition(store, adapter, AttemptState(target), 700)
        after_row = await _attempt_row(adapter)
        after = await _snapshot_case(adapter)
    finally:
        await database._pool.release(connection)
    async with database._pool.acquire() as observer:
        durable = await _snapshot_case(_PostgresConnectionAdapter(observer))
    return result, before, after, durable, before_row, after_row


@pytest.mark.asyncio
async def test_postgres_runtime_validates_0010_and_authority_cas_replays() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "head")
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=1,
            pool_max=2,
        )
        await database.connect()
        try:
            async with database._pool.acquire() as connection:
                await validate_postgresql_lifecycle_catalog(connection)
                await connection.execute(
                    "INSERT INTO users(id,username,hashed_password,role,created_by) "
                    "VALUES($1,'fixed-user','fixed-hash','admin','fixed')",
                    _USER_ID,
                )
                await connection.execute(
                    "INSERT INTO campaigns(id,name) VALUES($1,'fixed-campaign')",
                    _CAMPAIGN_ID,
                )
            store = ExecutionLifecycleStore(database._pool, "postgresql")
            created = await store.ensure_actor_authority(_USER_ID, _OPERATION_A)
            replay = await store.ensure_actor_authority(_USER_ID, _OPERATION_A)
            invalidated = await store.invalidate_actor_authority(_USER_ID, 0, _OPERATION_B)
        finally:
            await database.close()
    assert (created.result, replay.result, invalidated.result) == (
        FixedResult.APPLIED,
        FixedResult.REPLAYED,
        FixedResult.APPLIED,
    ), "PostgreSQL authority CAS changed"


@pytest.mark.asyncio
async def test_empty_postgres_runtime_refuses_without_fallback() -> None:
    async with _postgres_harness() as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=1,
            pool_max=1,
        )
        with pytest.raises(RuntimeError, match="PostgreSQL schema migration required"):
            await database.connect()
        assert database._pool is None, "failed PostgreSQL startup retained a pool"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "target"),
    _EXPECTED_LEGAL,
    ids=[f"legal-{source}-{target}" for source, target in _EXPECTED_LEGAL],
)
async def test_postgres_real_store_legal_transition(source: str, target: str) -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "head")
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=1,
            pool_max=4,
        )
        await database.connect()
        try:
            result, before, after, durable, before_row, after_row = await _exercise_postgres_pair(
                database,
                source,
                target,
            )
        finally:
            await database.close()
    assert result.result is FixedResult.APPLIED, "legal PostgreSQL transition was not applied"
    assert int(after_row["revision"]) == int(before_row["revision"]) + 1, (
        "legal PostgreSQL transition changed revision incorrectly"
    )
    assert after_row["state"] == target, "legal PostgreSQL transition stored the wrong state"
    assert after != before, "legal PostgreSQL transition made no durable mutation"
    assert durable == after, "legal PostgreSQL transition was not visible on another connection"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source", "target"),
    _ILLEGAL,
    ids=[f"illegal-{source}-{target}" for source, target in _ILLEGAL],
)
async def test_postgres_real_store_illegal_transition(
    source: str,
    target: str,
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=1,
            pool_max=4,
        )
        await database.connect()
        try:
            result, before, after, durable, before_row, after_row = await _exercise_postgres_pair(
                database,
                source,
                target,
            )
        finally:
            await database.close()
    assert result.result is not FixedResult.APPLIED, "illegal PostgreSQL transition was applied"
    assert int(after_row["revision"]) == int(before_row["revision"]), (
        "illegal PostgreSQL transition changed revision"
    )
    assert after == before, "illegal PostgreSQL transition mutated physical state"
    assert durable == before, "illegal PostgreSQL transition mutated durable state"


_POSTGRES_LITERAL_ROLE_CELLS = (
    ("reporter", "operator", False),
    ("reporter", "team_lead", False),
    ("reporter", "admin", False),
    ("operator", "operator", True),
    ("operator", "team_lead", False),
    ("operator", "admin", False),
    ("team_lead", "operator", True),
    ("team_lead", "team_lead", True),
    ("team_lead", "admin", False),
    ("admin", "operator", True),
    ("admin", "team_lead", True),
    ("admin", "admin", True),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("actor_role", "minimum_role", "satisfies"),
    _POSTGRES_LITERAL_ROLE_CELLS,
    ids=[f"role-{actor}-{minimum}" for actor, minimum, _ in _POSTGRES_LITERAL_ROLE_CELLS],
)
async def test_postgres_real_admission_role_cell(
    actor_role: str,
    minimum_role: str,
    satisfies: bool,
) -> None:
    snapshot = replace(
        _accepted_snapshot(),
        actor_role=actor_role,
        minimum_role=minimum_role,
    )
    expected_state = AttemptState.ACCEPTED.value
    if not satisfies:
        denied = _blocked_snapshot()
        snapshot = replace(
            snapshot,
            policy_verdict=denied.policy_verdict,
            policy_reason_mask=denied.policy_reason_mask,
            gateway_mode_snapshot=denied.gateway_mode_snapshot,
            gateway_decision_code=denied.gateway_decision_code,
        )
        expected_state = AttemptState.BLOCKED.value
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "head")
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=1,
            pool_max=2,
        )
        await database.connect()
        try:
            _, adapter, connection = await _postgres_transition_case(
                database,
                expected_state,
                snapshot_override=snapshot,
            )
            row = await _attempt_row(adapter)
        finally:
            if "connection" in locals():
                await database._pool.release(connection)
            await database.close()
    assert row["state"] == expected_state, "PostgreSQL role admission stored the wrong state"


class _ReturningCountStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any, statement_fragment: str) -> None:
        super().__init__(backend, "postgresql")
        self._statement_fragment = statement_fragment
        self.returned_cardinalities: list[int] = []

    async def _returning_rows(
        self,
        connection: Any,
        sql: str,
        params: tuple[Any, ...],
    ) -> tuple[Any, ...]:
        rows = await super()._returning_rows(connection, sql, params)
        if self._statement_fragment in sql:
            self.returned_cardinalities.append(len(rows))
        return rows


class _DuplicateReturningStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any, statement_fragment: str) -> None:
        super().__init__(backend, "postgresql")
        self._statement_fragment = statement_fragment
        self.injected = False

    async def _returning_rows(
        self,
        connection: Any,
        sql: str,
        params: tuple[Any, ...],
    ) -> tuple[Any, ...]:
        rows = await super()._returning_rows(connection, sql, params)
        if not self.injected and self._statement_fragment in sql:
            self.injected = True
            return rows + rows
        return rows


class _ZeroRowClassificationStore(ExecutionLifecycleStore):
    """Test seam which creates a real conflicting catalog row in the same transaction."""

    _FRAGMENTS = {
        "missing": "UPDATE execution_actor_authority_revisions SET",
        "stale-revision": "UPDATE execution_attempts SET state=",
        "stale-state": "UPDATE execution_attempts SET state=",
        "stale-authority": "UPDATE execution_attempts SET closes_logical=",
        "stale-owner": "UPDATE execution_attempts SET state=",
        "stale-generation": "UPDATE execution_attempts SET state=",
        "stale-lease": "UPDATE execution_publication_outbox SET",
        "stale-cancellation": "UPDATE execution_attempts SET state=",
        "operation-conflict": "INSERT INTO execution_actor_authority_revisions",
    }

    def __init__(self, backend: Any, case_alias: str) -> None:
        super().__init__(backend, "postgresql")
        self.case_alias = case_alias
        self.fault_fired = False
        self.fault_connection: Any | None = None
        self.transaction_connection: Any | None = None
        self.classifier_connection: Any | None = None
        self.fault_backend_pid: int | None = None
        self.transaction_backend_pid: int | None = None
        self.classifier_backend_pid: int | None = None
        self.fault_transaction_id: int | None = None
        self.transaction_id: int | None = None
        self.classifier_transaction_id: int | None = None

    async def _identity(self, connection: Any) -> tuple[int, int]:
        row = await connection.fetchrow(
            "SELECT pg_backend_pid() AS backend_pid, txid_current() AS transaction_id"
        )
        return int(row["backend_pid"]), int(row["transaction_id"])

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        async with super()._transaction() as connection:
            self.transaction_connection = connection
            self.transaction_backend_pid, self.transaction_id = await self._identity(connection)
            yield connection

    async def _returning_rows(
        self,
        connection: Any,
        sql: str,
        params: tuple[Any, ...],
    ) -> tuple[Any, ...]:
        fragment = self._FRAGMENTS.get(self.case_alias)
        if not self.fault_fired and fragment is not None and fragment in sql:
            self.fault_fired = True
            self.fault_connection = connection
            self.fault_backend_pid, self.fault_transaction_id = await self._identity(connection)
            if self.case_alias == "missing":
                await connection.execute(
                    "DELETE FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(200),
                )
            elif self.case_alias == "stale-revision":
                await connection.execute(
                    "UPDATE execution_attempts SET revision=revision+1 WHERE id=$1",
                    _uuid(210),
                )
            elif self.case_alias == "stale-state":
                await connection.execute(
                    "UPDATE execution_attempts SET state='queued',queue_operation_id=$1,"
                    "queued_at=accepted_at WHERE id=$2",
                    _uuid(981),
                    _uuid(210),
                )
            elif self.case_alias == "stale-authority":
                await connection.execute(
                    "UPDATE execution_actor_authority_revisions "
                    "SET revision=revision+1 WHERE user_id=$1",
                    _uuid(200),
                )
            elif self.case_alias == "stale-owner":
                await connection.execute(
                    "UPDATE execution_attempts SET dispatch_owner_ref=$1 WHERE id=$2",
                    _uuid(298),
                    _uuid(210),
                )
            elif self.case_alias == "stale-generation":
                await connection.execute(
                    "UPDATE execution_attempts SET lease_generation=lease_generation+1 WHERE id=$1",
                    _uuid(210),
                )
            elif self.case_alias == "stale-lease":
                await connection.execute(
                    "UPDATE execution_publication_outbox "
                    "SET lease_expires_at=claimed_at WHERE id=$1",
                    _uuid(212),
                )
            elif self.case_alias == "stale-cancellation":
                await connection.execute(
                    "UPDATE execution_attempts "
                    "SET cancellation_request_revision=cancellation_request_revision+1 "
                    "WHERE id=$1",
                    _uuid(210),
                )
            elif self.case_alias == "operation-conflict":
                await connection.execute(
                    "INSERT INTO execution_actor_authority_revisions("
                    "user_id,revision,latest_operation_id,latest_operation_base_revision,"
                    "latest_operation_code) VALUES($1,0,$2,0,'ensure')",
                    _uuid(299),
                    _uuid(962),
                )
            return ()
        return await super()._returning_rows(connection, sql, params)

    async def _record_classifier(self, connection: Any) -> None:
        self.classifier_connection = connection
        self.classifier_backend_pid, self.classifier_transaction_id = await self._identity(
            connection
        )

    async def _classify_zero_outbox(self, connection: Any, **kwargs: Any):
        await self._record_classifier(connection)
        return await super()._classify_zero_outbox(connection, **kwargs)

    async def _classify_zero_row(self, connection: Any, **kwargs: Any):
        await self._record_classifier(connection)
        return await super()._classify_zero_row(connection, **kwargs)


class _TransactionBarrierStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any, participant_count: int) -> None:
        super().__init__(backend, "postgresql")
        self._participant_count = participant_count
        self._entered = 0
        self.all_entered = asyncio.Event()
        self.backend_pids: list[int] = []

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        async with super()._transaction() as connection:
            self.backend_pids.append(int(await connection.fetchval("SELECT pg_backend_pid()")))
            self._entered += 1
            if self._entered == self._participant_count:
                self.all_entered.set()
            await asyncio.wait_for(self.all_entered.wait(), timeout=10)
            yield connection


class _PostgresAdmissionWinnerStore(ExecutionLifecycleStore):
    def __init__(
        self,
        backend: Any,
        admission_locked: asyncio.Event,
        revocation_attempted: asyncio.Event,
    ) -> None:
        super().__init__(backend, "postgresql")
        self._admission_locked = admission_locked
        self._revocation_attempted = revocation_attempted

    async def _resolve_principal(self, connection: Any, principal: object, *, suffix: str):
        resolved = await super()._resolve_principal(
            connection,
            principal,
            suffix=suffix,
        )
        self._admission_locked.set()
        await self._revocation_attempted.wait()
        return resolved


class _PostgresRevocationContenderStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any, revocation_attempted: asyncio.Event) -> None:
        super().__init__(backend, "postgresql")
        self._revocation_attempted = revocation_attempted

    async def _mutate_existing_authority_v11(self, *args: Any, **kwargs: Any):
        self._revocation_attempted.set()
        return await super()._mutate_existing_authority_v11(*args, **kwargs)


class _TransactionProxy:
    def __init__(
        self,
        transaction: Any,
        *,
        rollback_started: asyncio.Event | None = None,
        rollback_continue: asyncio.Event | None = None,
        fail_rollback: bool = False,
    ) -> None:
        self._transaction = transaction
        self._rollback_started = rollback_started
        self._rollback_continue = rollback_continue
        self._fail_rollback = fail_rollback

    async def start(self) -> None:
        await self._transaction.start()

    async def commit(self) -> None:
        await self._transaction.commit()

    async def rollback(self) -> None:
        if self._rollback_started is not None:
            self._rollback_started.set()
        if self._rollback_continue is not None:
            await self._rollback_continue.wait()
        await self._transaction.rollback()
        if self._fail_rollback:
            raise RuntimeError("P1_A_PRIVATE_ROLLBACK_FAILURE")


class _ConnectionProxy:
    def __init__(self, connection: Any, pool: _PoolFaultSeam) -> None:
        self._connection = connection
        self._pool = pool

    def transaction(self) -> _TransactionProxy:
        return _TransactionProxy(
            self._connection.transaction(),
            rollback_started=self._pool.rollback_started,
            rollback_continue=self._pool.rollback_continue,
            fail_rollback=self._pool.failure_point == "transaction-rollback",
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _PoolFaultSeam:
    """Delegates to one real pool and injects only after real cleanup completes."""

    def __init__(
        self,
        pool: Any,
        *,
        failure_point: str | None = None,
        rollback_started: asyncio.Event | None = None,
        rollback_continue: asyncio.Event | None = None,
    ) -> None:
        self._pool = pool
        self.failure_point = failure_point
        self.rollback_started = rollback_started
        self.rollback_continue = rollback_continue
        self.release_completed = asyncio.Event()

    async def acquire(self) -> _ConnectionProxy:
        return _ConnectionProxy(await self._pool.acquire(), self)

    async def release(self, connection: _ConnectionProxy) -> None:
        await self._pool.release(connection._connection)
        self.release_completed.set()
        if self.failure_point == "pool-release":
            raise RuntimeError("P1_A_PRIVATE_RELEASE_FAILURE")


class _BlockingReceiptStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any) -> None:
        super().__init__(backend, "postgresql")
        self.receipt_entered = asyncio.Event()
        self.backend_pid: int | None = None

    async def _insert_receipt(self, connection: Any, *args: Any, **kwargs: Any) -> None:
        self.backend_pid = int(await connection.fetchval("SELECT pg_backend_pid()"))
        self.receipt_entered.set()
        await asyncio.Event().wait()


class _PrimaryReceiptFailureStore(ExecutionLifecycleStore):
    def __init__(self, backend: Any, primary: RuntimeError) -> None:
        super().__init__(backend, "postgresql")
        self.primary = primary
        self.backend_pid: int | None = None

    async def _insert_receipt(self, connection: Any, *args: Any, **kwargs: Any) -> None:
        self.backend_pid = int(await connection.fetchval("SELECT pg_backend_pid()"))
        raise self.primary


async def _postgres_actor_authority_fixture(
    database: PostgresDatabase,
) -> ExecutionLifecycleStore:
    async with database._pool.acquire() as connection:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) "
            "VALUES($1,'p1-a-user','fixed-hash','admin','fixed')",
            _uuid(940),
        )
    store = ExecutionLifecycleStore(database._pool, "postgresql")
    created = await store.ensure_actor_authority(_uuid(940), _uuid(941))
    assert created.result is FixedResult.APPLIED
    return store


@pytest.mark.asyncio
async def test_postgres_p1a_exact_one_returning_row_commits_once(
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=1, pool_max=2
        )
        await database.connect()
        try:
            await _postgres_actor_authority_fixture(database)
            store = _ReturningCountStore(
                database._pool, "UPDATE execution_actor_authority_revisions SET"
            )
            result = await store.invalidate_actor_authority(_uuid(940), 0, _uuid(942))
            async with database._pool.acquire() as observer:
                row = await observer.fetchrow(
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(940),
                )
                receipts = await observer.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    _uuid(942),
                )
            assert (result.result, result.revision) == (FixedResult.APPLIED, 1)
            assert store.returned_cardinalities == [1]
            assert (int(row["revision"]), int(receipts)) == (1, 1)
        finally:
            await database.close()


_POSTGRES_P1A_ZERO_ROW_CASES = (
    ("missing", FixedResult.CONFLICT_STATE),
    ("stale-revision", FixedResult.CONFLICT_REVISION),
    ("stale-state", FixedResult.CONFLICT_STATE),
    ("stale-authority", FixedResult.AUTHORITY_STALE),
    ("stale-owner", FixedResult.CONFLICT_OWNER),
    ("stale-generation", FixedResult.CONFLICT_GENERATION),
    ("stale-lease", FixedResult.CONFLICT_STATE),
    ("stale-cancellation", FixedResult.CONFLICT_REVISION),
    ("operation-conflict", FixedResult.CONFLICT_OPERATION),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_alias", "expected"),
    _POSTGRES_P1A_ZERO_ROW_CASES,
    ids=[alias for alias, _expected in _POSTGRES_P1A_ZERO_ROW_CASES],
)
async def test_postgres_p1a_zero_row_is_classified_in_same_transaction(
    case_alias: str,
    expected: FixedResult,
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=1, pool_max=4
        )
        await database.connect()
        setup_connection = None
        try:
            snapshot_override = None
            if case_alias == "stale-authority":
                snapshot_override = replace(
                    _accepted_snapshot(),
                    actor_role="admin",
                    idempotency_class="proven_idempotent",
                    retry_policy="after_revalidation",
                )
            normal, adapter, setup_connection = await _postgres_transition_case(
                database,
                AttemptState.BLOCKED if case_alias == "stale-lease" else AttemptState.ACCEPTED,
                snapshot_override=snapshot_override,
            )
            store = _ZeroRowClassificationStore(database._pool, case_alias)
            before_attempt = await setup_connection.fetchrow(
                "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                "cancellation_request_revision FROM execution_attempts WHERE id=$1",
                _uuid(210),
            )
            before_authority = await setup_connection.fetchrow(
                "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                _uuid(200),
            )
            before_outbox = await setup_connection.fetchrow(
                "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
                "lease_expires_at FROM execution_publication_outbox WHERE id=$1",
                _uuid(212),
            )
            if case_alias == "missing":
                result = await store.invalidate_actor_authority(_uuid(200), 0, _uuid(950))
            elif case_alias in {"stale-revision", "stale-state"}:
                result = await _nonterminal_transition(store, adapter, AttemptState.QUEUED, 951)
            elif case_alias == "stale-authority":
                terminal = await _terminal_transition(normal, adapter, AttemptState.FAILED, 952)
                assert terminal.result is FixedResult.APPLIED
                async with setup_connection.transaction():
                    await setup_connection.execute(
                        "UPDATE execution_attempts SET closes_logical=FALSE,"
                        "retry_disposition='eligible' WHERE id=$1",
                        _uuid(210),
                    )
                    await setup_connection.execute(
                        "UPDATE logical_executions SET closure_operation_id=NULL,"
                        "closure_authority_subject_ref=NULL,closure_authority_user_id=NULL,"
                        "closure_authority_revision=NULL,closing_attempt_id=NULL,closed_at=NULL "
                        "WHERE id=$1",
                        _uuid(208),
                    )
                before_attempt = await setup_connection.fetchrow(
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "cancellation_request_revision FROM execution_attempts WHERE id=$1",
                    _uuid(210),
                )
                before_outbox = await setup_connection.fetchrow(
                    "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
                    "lease_expires_at FROM execution_publication_outbox WHERE id=$1",
                    _uuid(212),
                )
                result = await store.close_without_retry(
                    ClosureRequest(
                        _uuid(208),
                        _uuid(210),
                        _uuid(955),
                        int(before_attempt["revision"]),
                        _uuid(956),
                        _uuid(200),
                        _uuid(200),
                        0,
                        _uuid(201),
                    )
                )
            elif case_alias in {"stale-owner", "stale-generation"}:
                await _build_source_state(normal, adapter, AttemptState.DISPATCHING)
                before_attempt = await setup_connection.fetchrow(
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "cancellation_request_revision FROM execution_attempts WHERE id=$1",
                    _uuid(210),
                )
                result = await _nonterminal_transition(store, adapter, AttemptState.RUNNING, 957)
            elif case_alias == "stale-lease":
                claimed = await normal.claim_outbox(
                    OutboxMutation(
                        _uuid(212),
                        0,
                        _uuid(958),
                        _uuid(959),
                        0,
                        _uuid(201),
                        _uuid(210),
                        _uuid(213),
                        "execution_blocked",
                    )
                )
                assert claimed.result is FixedResult.APPLIED
                before_outbox = await setup_connection.fetchrow(
                    "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
                    "lease_expires_at FROM execution_publication_outbox WHERE id=$1",
                    _uuid(212),
                )
                result = await store.publish_outbox(
                    OutboxMutation(
                        _uuid(212),
                        1,
                        _uuid(960),
                        _uuid(959),
                        1,
                        _uuid(201),
                        _uuid(210),
                        _uuid(213),
                        "execution_blocked",
                    )
                )
            elif case_alias == "stale-cancellation":
                await _build_source_state(normal, adapter, AttemptState.CANCELLING)
                before_attempt = await setup_connection.fetchrow(
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "cancellation_request_revision FROM execution_attempts WHERE id=$1",
                    _uuid(210),
                )
                result = await _terminal_transition(store, adapter, AttemptState.CANCELLED, 961)
            else:
                await setup_connection.execute(
                    "INSERT INTO users(id,username,hashed_password,role,created_by) "
                    "VALUES($1,'p1-a-operation-conflict','fixed-hash','admin','fixed')",
                    _uuid(299),
                )
                result = await store.ensure_actor_authority(_uuid(299), _uuid(962))

            assert result.result is expected
            async with database._pool.acquire() as observer:
                after_attempt = await observer.fetchrow(
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "cancellation_request_revision FROM execution_attempts WHERE id=$1",
                    _uuid(210),
                )
                after_authority = await observer.fetchrow(
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(200),
                )
                conflicting_authority = await observer.fetchval(
                    "SELECT count(*) FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(299),
                )
                after_outbox = await observer.fetchrow(
                    "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
                    "lease_expires_at FROM execution_publication_outbox WHERE id=$1",
                    _uuid(212),
                )
            assert tuple(after_attempt) == tuple(before_attempt)
            assert tuple(after_authority) == tuple(before_authority)
            assert (None if after_outbox is None else tuple(after_outbox)) == (
                None if before_outbox is None else tuple(before_outbox)
            )
            assert int(conflicting_authority) == 0
            assert store.fault_fired
            assert store.fault_connection is store.transaction_connection
            assert store.fault_backend_pid == store.transaction_backend_pid
            assert store.fault_transaction_id == store.transaction_id
            assert store.fault_connection is store.classifier_connection
            assert store.fault_backend_pid == store.classifier_backend_pid
            assert store.fault_transaction_id == store.classifier_transaction_id
        finally:
            if setup_connection is not None:
                await database._pool.release(setup_connection)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_p1a_multiple_returning_rows_abort_atomically(
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=1, pool_max=2
        )
        await database.connect()
        try:
            await _postgres_actor_authority_fixture(database)
            store = _DuplicateReturningStore(
                database._pool, "UPDATE execution_actor_authority_revisions SET"
            )
            result = await store.invalidate_actor_authority(_uuid(940), 0, _uuid(943))
            async with database._pool.acquire() as observer:
                revision = await observer.fetchval(
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(940),
                )
                receipt_count = await observer.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    _uuid(943),
                )
            assert store.injected
            assert result.result is FixedResult.INVARIANT_FAILURE
            assert (int(revision), int(receipt_count)) == (0, 0)
        finally:
            await database.close()


@pytest.mark.asyncio
async def test_postgres_p1a_concurrent_cas_has_one_winner_and_one_fixed_loser(
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=3, pool_max=3
        )
        await database.connect()
        observer = None
        try:
            await _postgres_actor_authority_fixture(database)
            observer = await database._pool.acquire()
            observer_pid = int(await observer.fetchval("SELECT pg_backend_pid()"))
            store = _TransactionBarrierStore(database._pool, 2)
            left = asyncio.create_task(store.invalidate_actor_authority(_uuid(940), 0, _uuid(944)))
            right = asyncio.create_task(store.invalidate_actor_authority(_uuid(940), 0, _uuid(945)))
            left_result, right_result = await asyncio.gather(left, right)
            row = await observer.fetchrow(
                "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                _uuid(940),
            )
            receipt_count = await observer.fetchval(
                "SELECT count(*) FROM execution_operation_receipts WHERE operation_id IN ($1,$2)",
                _uuid(944),
                _uuid(945),
            )
            assert sorted(
                (left_result.result, right_result.result), key=lambda item: item.value
            ) == [FixedResult.APPLIED, FixedResult.CONFLICT_REVISION]
            assert len(set(store.backend_pids)) == 2
            assert observer_pid not in set(store.backend_pids)
            assert (int(row["revision"]), int(receipt_count)) == (1, 1)
        finally:
            if observer is not None:
                await database._pool.release(observer)
            await database.close()


@pytest.mark.asyncio
async def test_postgres_p1a_cancellation_finishes_rollback_and_reuses_pool_slot(
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=1, pool_max=1
        )
        await database.connect()
        try:
            await _postgres_actor_authority_fixture(database)
            rollback_started = asyncio.Event()
            rollback_continue = asyncio.Event()
            pool = _PoolFaultSeam(
                database._pool,
                rollback_started=rollback_started,
                rollback_continue=rollback_continue,
            )
            store = _BlockingReceiptStore(pool)
            task = asyncio.create_task(store.invalidate_actor_authority(_uuid(940), 0, _uuid(946)))
            await asyncio.wait_for(store.receipt_entered.wait(), timeout=10)
            task.cancel()
            await asyncio.wait_for(rollback_started.wait(), timeout=10)
            task.cancel()
            rollback_continue.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert pool.release_completed.is_set()
            async with database._pool.acquire() as observer:
                reused_pid = int(await observer.fetchval("SELECT pg_backend_pid()"))
                revision = await observer.fetchval(
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(940),
                )
                receipts = await observer.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    _uuid(946),
                )
            assert reused_pid == store.backend_pid
            assert (int(revision), int(receipts)) == (0, 0)
            recovered = await ExecutionLifecycleStore(
                database._pool, "postgresql"
            ).invalidate_actor_authority(_uuid(940), 0, _uuid(947))
            assert recovered.result is FixedResult.APPLIED
        finally:
            await database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_point",
    ["transaction-rollback", "pool-release"],
    ids=("transaction-rollback", "pool-release"),
)
async def test_postgres_p1a_primary_failure_survives_cleanup_failure(
    failure_point: str,
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name), pool_min=1, pool_max=1
        )
        await database.connect()
        try:
            await _postgres_actor_authority_fixture(database)
            pool = _PoolFaultSeam(database._pool, failure_point=failure_point)
            primary = RuntimeError("P1_A_PRIMARY_FIXED")
            store = _PrimaryReceiptFailureStore(pool, primary)
            with pytest.raises(RuntimeError) as raised:
                await store.invalidate_actor_authority(_uuid(940), 0, _uuid(948))
            assert raised.value is primary
            assert "PRIVATE" not in str(raised.value)
            notes = tuple(getattr(raised.value, "__notes__", ()))
            expected_action = (
                "postgresql-rollback"
                if failure_point == "transaction-rollback"
                else "postgresql-release"
            )
            assert notes == (f"Execution lifecycle cleanup failed [{expected_action}]",)
            assert pool.release_completed.is_set()
            async with database._pool.acquire() as observer:
                reused_pid = int(await observer.fetchval("SELECT pg_backend_pid()"))
                revision = await observer.fetchval(
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=$1",
                    _uuid(940),
                )
                receipts = await observer.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    _uuid(948),
                )
            assert reused_pid == store.backend_pid
            assert (int(revision), int(receipts)) == (0, 0)
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

_POSTGRES_P1B_PUBLIC_METHOD_MAP = (
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
    ("campaign-delete", "PostgresDatabase.delete_campaign_lifecycle"),
)

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

_POSTGRES_P1B_LITERAL_NODE_COUNT = 88
_POSTGRES_P1B_LITERAL_NODE_ID_SHA256 = (
    "dcf4cc9ae54a5bc5c793215f42318b1fbb19f826563dc2ae3314c7302c687aa6"
)

assert len(_P1B_AUTHORITY_CASES) == 23
assert len({alias for alias, _operation_code in _P1B_AUTHORITY_CASES}) == 23
assert tuple(alias for alias, _method in _POSTGRES_P1B_PUBLIC_METHOD_MAP) == tuple(
    alias for alias, _operation_code in _P1B_AUTHORITY_CASES
)
assert (
    _POSTGRES_P1B_LITERAL_NODE_COUNT,
    len(_POSTGRES_P1B_LITERAL_NODE_ID_SHA256),
) == (88, 64)
assert (
    sum(
        map(
            len,
            (
                _P1B_AUTHORITY_CASES,
                _P1B_AUTHORITY_CASES,
                _P1B_BINDING_MUTATIONS,
                _P1B_RETENTION_CASES,
                _P1B_ATOMICITY_CASES,
                _P1B_CONCURRENCY_CASES,
            ),
        )
    )
    == _POSTGRES_P1B_LITERAL_NODE_COUNT
)


def _postgres_p1b_independent_binding_digest(
    domain: str, values: tuple[tuple[str, str | int | bool | None], ...]
) -> str:
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


def _postgres_p1b_independent_request_digest(operation_code: str) -> str:
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
    return _postgres_p1b_independent_binding_digest(
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


def _postgres_p1b_literal_spec(
    store: ExecutionLifecycleStore,
    operation_code: str,
    *,
    operation_id: str = _uuid(3000),
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
        primary_target_id=_uuid(3001),
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


async def _postgres_p1b_insert_receipt(store: ExecutionLifecycleStore, operation_code: str):
    spec = _postgres_p1b_literal_spec(store, operation_code)
    exact = (
        FixedResult.REPLAYED_BOUND_CHILD
        if operation_code == "retry"
        else FixedResult.REPLAYED_CLOSED
        if operation_code == "close_without_retry"
        else FixedResult.REPLAYED
    )
    async with store._transaction() as connection:
        await store._insert_receipt(
            connection,
            spec,
            result=FixedResult.APPLIED,
            exact_replay_code=exact,
            result_identity=_uuid(3001),
            result_revision=10,
        )
    return spec


async def _postgres_p1b_effect_snapshot(
    database: PostgresDatabase, operation_id: str
) -> tuple[int, ...]:
    async with database._pool.acquire() as connection:
        row = await connection.fetchrow(
            "SELECT "
            "(SELECT count(*) FROM execution_operation_receipts),"
            "(SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1),"
            "(SELECT count(*) FROM execution_actor_authority_revisions),"
            "(SELECT COALESCE(sum(revision),0) FROM execution_actor_authority_revisions),"
            "(SELECT count(*) FROM campaign_execution_authority_revisions),"
            "(SELECT COALESCE(sum(revision),0) FROM campaign_execution_authority_revisions),"
            "(SELECT count(*) FROM campaign_execution_budgets),"
            "(SELECT COALESCE(sum(capacity_units),0) FROM campaign_execution_budgets),"
            "(SELECT COALESCE(sum(reserved_units),0) FROM campaign_execution_budgets),"
            "(SELECT COALESCE(sum(consumed_units),0) FROM campaign_execution_budgets),"
            "(SELECT COALESCE(sum(revision),0) FROM campaign_execution_budgets),"
            "(SELECT count(*) FROM campaign_execution_budget_ledger),"
            "(SELECT COALESCE(sum(reservation_units),0) "
            " FROM campaign_execution_budget_ledger),"
            "(SELECT COALESCE(sum(consumed_units),0) "
            " FROM campaign_execution_budget_ledger),"
            "(SELECT count(*) FROM logical_executions),"
            "(SELECT COALESCE(sum(revision),0) FROM logical_executions),"
            "(SELECT count(*) FROM execution_attempts),"
            "(SELECT COALESCE(sum(revision),0) FROM execution_attempts),"
            "(SELECT count(*) FROM execution_publication_outbox),"
            "(SELECT COALESCE(sum(claim_revision),0) FROM execution_publication_outbox),"
            "(SELECT COALESCE(sum(delivery_attempt_count),0) "
            " FROM execution_publication_outbox),"
            "(SELECT count(*) FROM campaigns)",
            operation_id,
        )
    return tuple(int(value) for value in row)


async def _postgres_p1b_insert_principal(
    database: PostgresDatabase, *, role: str = "reporter"
) -> ExecutionLifecycleStore:
    async with database._pool.acquire() as connection:
        await connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) "
            "VALUES($1,'p1b-public-user','fixed-hash',$2,'fixed')",
            _uuid(3400),
            role,
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name) VALUES($1,'p1b-public-campaign')",
            _uuid(3401),
        )
    return ExecutionLifecycleStore(database._pool, "postgresql")


async def _postgres_p1b_ensure_principal(
    database: PostgresDatabase, *, role: str = "reporter"
) -> ExecutionLifecycleStore:
    store = await _postgres_p1b_insert_principal(database, role=role)
    actor = await store.ensure_actor_authority(_uuid(3400), _uuid(3480))
    campaign = await store.ensure_campaign_authority(_uuid(3401), _uuid(3481))
    assert (actor.result, campaign.result) == (FixedResult.APPLIED, FixedResult.APPLIED)
    return store


def _postgres_p1b_blocked_admission(operation_id: str) -> AdmissionRequest:
    return AdmissionRequest(
        _uuid(3410),
        _uuid(3411),
        _uuid(3412),
        _uuid(3413),
        _uuid(3414),
        _uuid(3401),
        _uuid(3400),
        _uuid(3400),
        "test.p1b-public",
        "sdk",
        AttemptState.BLOCKED,
        operation_id,
        _blocked_snapshot(),
    )


def _postgres_p1b_budget_configuration(operation_id: str) -> BudgetConfiguration:
    return BudgetConfiguration(
        _uuid(3401),
        _uuid(3420),
        20,
        _uuid(3421),
        20,
        _uuid(3422),
        1,
        operation_id,
    )


def _postgres_p1b_budget_reservation(operation_id: str) -> BudgetReservation:
    return BudgetReservation(
        _uuid(3401),
        _uuid(3412),
        _uuid(3420),
        _uuid(3423),
        2,
        0,
        _uuid(3421),
        _uuid(3424),
        3,
        0,
        _uuid(3422),
        _uuid(3425),
        0,
        operation_id,
    )


def _postgres_p1b_budget_settlement(operation_id: str) -> BudgetSettlement:
    return BudgetSettlement(
        _uuid(3401),
        _uuid(3412),
        _uuid(3420),
        2,
        1,
        1,
        _uuid(3421),
        3,
        2,
        1,
        _uuid(3422),
        1,
        operation_id,
    )


async def _postgres_p1b_prepare_budget_attempt(
    database: PostgresDatabase,
) -> ExecutionLifecycleStore:
    store = await _postgres_p1b_ensure_principal(database)
    configured = await store.configure_campaign_budgets(
        _postgres_p1b_budget_configuration(_uuid(3482))
    )
    admitted = await store._create_initial_execution_v2_for_migration_fixture(
        _postgres_p1b_blocked_admission(_uuid(3483))
    )
    assert (configured.result, admitted.result) == (
        FixedResult.APPLIED,
        FixedResult.APPLIED,
    )
    return store


async def _postgres_p1b_prepare_retryable_parent(
    database: PostgresDatabase,
) -> tuple[ExecutionLifecycleStore, int]:
    snapshot = replace(
        _accepted_snapshot(),
        actor_role="admin",
        idempotency_class="proven_idempotent",
        retry_policy="after_revalidation",
    )
    store, adapter, connection = await _postgres_transition_case(
        database,
        AttemptState.ACCEPTED,
        snapshot_override=snapshot,
    )
    try:
        terminal = await _terminal_transition(store, adapter, AttemptState.FAILED, 3470)
        assert terminal.result is FixedResult.APPLIED
        async with connection.transaction():
            await connection.execute(
                "UPDATE execution_attempts SET closes_logical=FALSE,"
                "retry_disposition='eligible' WHERE id=$1",
                _uuid(210),
            )
            await connection.execute(
                "UPDATE logical_executions SET closure_operation_id=NULL,"
                "closure_authority_subject_ref=NULL,closure_authority_user_id=NULL,"
                "closure_authority_revision=NULL,closing_attempt_id=NULL,closed_at=NULL "
                "WHERE id=$1",
                _uuid(208),
            )
        row = await connection.fetchrow(
            "SELECT revision,retry_disposition FROM execution_attempts WHERE id=$1",
            _uuid(210),
        )
        assert row["retry_disposition"] == "eligible"
        return store, int(row["revision"])
    finally:
        await database._pool.release(connection)


async def _postgres_p1b_prepare_outbox(
    database: PostgresDatabase,
) -> ExecutionLifecycleStore:
    store, _adapter, connection = await _postgres_transition_case(database, AttemptState.BLOCKED)
    await database._pool.release(connection)
    return store


async def _postgres_p1b_admission_case(
    database: PostgresDatabase,
) -> tuple[ExecutionLifecycleStore, AdmissionRequest]:
    store = await _postgres_p1b_ensure_principal(database)
    request = _postgres_p1b_blocked_admission(_uuid(3490))
    applied = await store._create_initial_execution_v2_for_migration_fixture(request)
    assert applied.result is FixedResult.APPLIED
    return store, request


def _postgres_p1b_outbox_request(
    operation_id: str,
    expected_revision: int,
    *,
    owner_ref: str | None,
    lease_generation: int | None,
    purge_poisoned: bool | None = None,
) -> OutboxMutation:
    return OutboxMutation(
        _uuid(212),
        expected_revision,
        operation_id,
        owner_ref,
        lease_generation,
        _uuid(201),
        _uuid(210),
        _uuid(213),
        "execution_blocked",
        purge_poisoned,
    )


_POSTGRES_P1B_PUBLIC_OPERATION_IDS = {
    alias: _uuid(3600 + index)
    for index, (alias, _operation_code) in enumerate(_P1B_AUTHORITY_CASES)
}


async def _postgres_p1b_exercise_public_operation(
    case_alias: str,
    database: PostgresDatabase,
) -> tuple[
    OperationResult,
    OperationResult,
    OperationResult,
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    str,
]:
    operation_id = _POSTGRES_P1B_PUBLIC_OPERATION_IDS[case_alias]

    if case_alias == "actor-authority-ensure":
        store = await _postgres_p1b_insert_principal(database)

        async def invoke() -> OperationResult:
            return await store.ensure_actor_authority(_uuid(3400), operation_id)

        async def invoke_conflict() -> OperationResult:
            return await store.ensure_actor_authority(_uuid(3402), operation_id)

    elif case_alias == "campaign-authority-ensure":
        store = await _postgres_p1b_insert_principal(database)

        async def invoke() -> OperationResult:
            return await store.ensure_campaign_authority(_uuid(3401), operation_id)

        async def invoke_conflict() -> OperationResult:
            return await store.ensure_campaign_authority(_uuid(3402), operation_id)

    elif case_alias == "actor-authority-invalidate":
        store = await _postgres_p1b_insert_principal(database)
        setup = await store.ensure_actor_authority(_uuid(3400), _uuid(3480))
        assert setup.result is FixedResult.APPLIED

        async def invoke() -> OperationResult:
            return await store.invalidate_actor_authority(_uuid(3400), 0, operation_id)

        async def invoke_conflict() -> OperationResult:
            return await store.invalidate_actor_authority(_uuid(3400), 1, operation_id)

    elif case_alias == "campaign-authority-invalidate":
        store = await _postgres_p1b_insert_principal(database)
        setup = await store.ensure_campaign_authority(_uuid(3401), _uuid(3481))
        assert setup.result is FixedResult.APPLIED

        async def invoke() -> OperationResult:
            return await store.invalidate_campaign_authority(_uuid(3401), 0, operation_id)

        async def invoke_conflict() -> OperationResult:
            return await store.invalidate_campaign_authority(_uuid(3401), 1, operation_id)

    elif case_alias == "budget-configure":
        store = await _postgres_p1b_ensure_principal(database)
        request = _postgres_p1b_budget_configuration(operation_id)

        async def invoke() -> OperationResult:
            return await store.configure_campaign_budgets(request)

        async def invoke_conflict() -> OperationResult:
            return await store.configure_campaign_budgets(
                replace(request, noise_capacity=request.noise_capacity + 1)
            )

    elif case_alias == "budget-reserve":
        store = await _postgres_p1b_prepare_budget_attempt(database)
        request = _postgres_p1b_budget_reservation(operation_id)

        async def invoke() -> OperationResult:
            return await store.reserve_budgets(request)

        async def invoke_conflict() -> OperationResult:
            return await store.reserve_budgets(
                replace(request, noise_units=request.noise_units + 1)
            )

    elif case_alias == "budget-settle":
        store = await _postgres_p1b_prepare_budget_attempt(database)
        reserved = await store.reserve_budgets(_postgres_p1b_budget_reservation(_uuid(3484)))
        assert reserved.result is FixedResult.APPLIED
        request = _postgres_p1b_budget_settlement(operation_id)

        async def invoke() -> OperationResult:
            return await store.settle_budgets(request)

        async def invoke_conflict() -> OperationResult:
            return await store.settle_budgets(
                replace(request, noise_actual=request.noise_actual + 1)
            )

    elif case_alias == "admission":
        store = await _postgres_p1b_ensure_principal(database)
        request = _postgres_p1b_blocked_admission(operation_id)

        async def invoke() -> OperationResult:
            return await store._create_initial_execution_v2_for_migration_fixture(request)

        async def invoke_conflict() -> OperationResult:
            return await store._create_initial_execution_v2_for_migration_fixture(
                replace(request, module_id="test.p1b-public.changed")
            )

    elif case_alias == "retry-attempt":
        store, parent_revision = await _postgres_p1b_prepare_retryable_parent(database)
        async with database._pool.acquire() as connection:
            await connection.execute("UPDATE users SET role='reporter' WHERE id=$1", _uuid(200))
        child = AdmissionRequest(
            _uuid(208),
            _uuid(3440),
            _uuid(3441),
            _uuid(3442),
            _uuid(3443),
            _uuid(201),
            _uuid(200),
            _uuid(200),
            "test.p1b-retry",
            "sdk",
            AttemptState.BLOCKED,
            operation_id,
            replace(_blocked_snapshot(), gateway_mode_snapshot="enforced"),
        )
        request = RetryRequest(_uuid(208), _uuid(210), child, parent_revision)

        async def invoke() -> OperationResult:
            return await store._create_retry_attempt_v2_for_migration_fixture(request)

        async def invoke_conflict() -> OperationResult:
            return await store._create_retry_attempt_v2_for_migration_fixture(
                replace(request, child=replace(child, module_id="test.p1b-retry.changed"))
            )

    elif case_alias == "attempt-transition":
        store, _adapter, connection = await _postgres_transition_case(
            database, AttemptState.ACCEPTED
        )
        await database._pool.release(connection)
        request = TransitionRequest(
            _uuid(210),
            0,
            AttemptState.QUEUED,
            operation_id,
            campaign_id=_uuid(201),
            actor_subject_ref=_uuid(200),
            actor_user_id=_uuid(200),
            actor_authority_revision=0,
        )

        async def invoke() -> OperationResult:
            return await store.transition_attempt(request)

        async def invoke_conflict() -> OperationResult:
            return await store.transition_attempt(replace(request, campaign_id=_uuid(299)))

    elif case_alias in {"settlement-pending", "expired-lease-settlement"}:
        store, adapter, connection = await _postgres_transition_case(
            database, AttemptState.ACCEPTED
        )
        try:
            await _build_source_state(store, adapter, AttemptState.RUNNING)
            row = await connection.fetchrow(
                "SELECT revision,dispatch_owner_ref,lease_generation "
                "FROM execution_attempts WHERE id=$1",
                _uuid(210),
            )
            if case_alias == "expired-lease-settlement":
                await connection.execute(
                    "UPDATE execution_attempts SET lease_expires_at=created_at WHERE id=$1",
                    _uuid(210),
                )
        finally:
            await database._pool.release(connection)
        request = TransitionRequest(
            _uuid(210),
            int(row["revision"]),
            AttemptState.SETTLEMENT_PENDING,
            operation_id,
            owner_ref=str(row["dispatch_owner_ref"]),
            lease_generation=int(row["lease_generation"]),
            outbox_id=_uuid(3450),
            publication_key=_uuid(3451),
            campaign_id=_uuid(201),
        )

        async def invoke() -> OperationResult:
            if case_alias == "expired-lease-settlement":
                return await store.mark_expired_lease_settlement_pending(request)
            return await store.enter_settlement_pending(request)

        async def invoke_conflict() -> OperationResult:
            changed = replace(request, publication_key=_uuid(3452))
            if case_alias == "expired-lease-settlement":
                return await store.mark_expired_lease_settlement_pending(changed)
            return await store.enter_settlement_pending(changed)

    elif case_alias == "terminal-commit":
        store, _adapter, connection = await _postgres_transition_case(
            database, AttemptState.ACCEPTED
        )
        await database._pool.release(connection)
        transition = TransitionRequest(
            _uuid(210),
            0,
            AttemptState.FAILED,
            operation_id,
            outcome_code=OutcomeCode.CONFIRMED_FAILURE_NO_DISPATCH,
            authoritative_proof="no_dispatch",
            campaign_id=_uuid(201),
            actor_subject_ref=_uuid(200),
            actor_user_id=_uuid(200),
            actor_authority_revision=0,
        )
        settlement = BudgetSettlement(
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
            _uuid(3453),
        )
        request = TerminalCommitRequest(
            _uuid(208),
            _uuid(201),
            _uuid(3454),
            _uuid(3455),
            transition,
            settlement,
        )

        async def invoke() -> OperationResult:
            return await store.commit_terminal_attempt(request)

        async def invoke_conflict() -> OperationResult:
            return await store.commit_terminal_attempt(
                replace(request, publication_key=_uuid(3456))
            )

    elif case_alias == "close-without-retry":
        store, parent_revision = await _postgres_p1b_prepare_retryable_parent(database)
        request = ClosureRequest(
            _uuid(208),
            _uuid(210),
            _uuid(3457),
            parent_revision,
            operation_id,
            _uuid(200),
            _uuid(200),
            0,
            _uuid(201),
        )

        async def invoke() -> OperationResult:
            return await store.close_without_retry(request)

        async def invoke_conflict() -> OperationResult:
            return await store.close_without_retry(replace(request, outbox_id=_uuid(3458)))

    elif case_alias.startswith("outbox-"):
        store = await _postgres_p1b_prepare_outbox(database)
        setup_owner = _uuid(3460)
        if case_alias == "outbox-claim":
            request = _postgres_p1b_outbox_request(
                operation_id, 0, owner_ref=_uuid(3461), lease_generation=0
            )

            async def invoke() -> OperationResult:
                return await store.claim_outbox(request)

        elif case_alias == "outbox-reclaim":
            setup_claim = await store.claim_outbox(
                _postgres_p1b_outbox_request(
                    _uuid(3462), 0, owner_ref=setup_owner, lease_generation=0
                )
            )
            assert setup_claim.result is FixedResult.APPLIED
            async with database._pool.acquire() as connection:
                await connection.execute(
                    "UPDATE execution_publication_outbox SET lease_expires_at=created_at "
                    "WHERE id=$1",
                    _uuid(212),
                )
            request = _postgres_p1b_outbox_request(
                operation_id, 1, owner_ref=_uuid(3461), lease_generation=1
            )

            async def invoke() -> OperationResult:
                return await store.claim_outbox(request, reclaim=True)

        elif case_alias == "outbox-poison":
            async with database._pool.acquire() as connection:
                await connection.execute(
                    "UPDATE execution_publication_outbox SET "
                    "publication_state='claimed',delivery_attempt_count=20,available_at=NULL,"
                    "claim_owner_ref=$1,lease_generation=20,claimed_at=created_at,"
                    "lease_expires_at=created_at,"
                    "claim_revision=20,latest_operation_id=$2,latest_operation_code='reclaim',"
                    "latest_operation_base_revision=19 WHERE id=$3",
                    setup_owner,
                    _uuid(3462),
                    _uuid(212),
                )
            request = _postgres_p1b_outbox_request(
                operation_id, 20, owner_ref=None, lease_generation=None
            )

            async def invoke() -> OperationResult:
                return await store.poison_expired_attempt_twenty(request)

        elif case_alias in {
            "outbox-renew",
            "outbox-publish",
            "outbox-fail-retryable",
            "outbox-fail-nonretryable",
        }:
            setup_claim = await store.claim_outbox(
                _postgres_p1b_outbox_request(
                    _uuid(3462), 0, owner_ref=setup_owner, lease_generation=0
                )
            )
            assert setup_claim.result is FixedResult.APPLIED
            request = _postgres_p1b_outbox_request(
                operation_id, 1, owner_ref=setup_owner, lease_generation=1
            )

            async def invoke() -> OperationResult:
                if case_alias == "outbox-renew":
                    return await store.renew_outbox(request)
                if case_alias == "outbox-publish":
                    return await store.publish_outbox(request)
                return await store.fail_outbox(
                    request, retryable=case_alias == "outbox-fail-retryable"
                )

        else:
            assert case_alias == "outbox-purge"
            setup_claim = await store.claim_outbox(
                _postgres_p1b_outbox_request(
                    _uuid(3462), 0, owner_ref=setup_owner, lease_generation=0
                )
            )
            published = await store.publish_outbox(
                _postgres_p1b_outbox_request(
                    _uuid(3463), 1, owner_ref=setup_owner, lease_generation=1
                )
            )
            assert (setup_claim.result, published.result) == (
                FixedResult.APPLIED,
                FixedResult.APPLIED,
            )
            request = _postgres_p1b_outbox_request(
                operation_id,
                2,
                owner_ref=None,
                lease_generation=None,
                purge_poisoned=False,
            )

            async def invoke() -> OperationResult:
                return await store.purge_outbox(
                    request.outbox_id,
                    request.expected_revision,
                    request.operation_id,
                    poisoned=False,
                    campaign_id=request.campaign_id,
                    attempt_id=request.attempt_id,
                    publication_key=request.publication_key,
                    event_code=request.event_code,
                )

        async def invoke_conflict() -> OperationResult:
            changed = replace(request, event_code="execution_rejected")
            if case_alias == "outbox-claim":
                return await store.claim_outbox(changed)
            if case_alias == "outbox-reclaim":
                return await store.claim_outbox(changed, reclaim=True)
            if case_alias == "outbox-poison":
                return await store.poison_expired_attempt_twenty(changed)
            if case_alias == "outbox-renew":
                return await store.renew_outbox(changed)
            if case_alias == "outbox-publish":
                return await store.publish_outbox(changed)
            if case_alias == "outbox-fail-retryable":
                return await store.fail_outbox(changed, retryable=True)
            if case_alias == "outbox-fail-nonretryable":
                return await store.fail_outbox(changed, retryable=False)
            return await store.purge_outbox(
                changed.outbox_id,
                changed.expected_revision,
                changed.operation_id,
                poisoned=False,
                campaign_id=changed.campaign_id,
                attempt_id=changed.attempt_id,
                publication_key=changed.publication_key,
                event_code=changed.event_code,
            )

    else:
        assert case_alias == "campaign-delete"
        async with database._pool.acquire() as connection:
            await connection.execute(
                "INSERT INTO campaigns(id,name) VALUES($1,'p1b-delete-campaign')",
                _uuid(3401),
            )

        async def invoke() -> OperationResult:
            return await database.delete_campaign_lifecycle(_uuid(3401), operation_id=operation_id)

        async def invoke_conflict() -> OperationResult:
            return await database.delete_campaign_lifecycle(
                _uuid(3401),
                operation_id=operation_id,
                principal_kind="actor",
                principal_subject_ref=_uuid(3400),
                principal_user_id=_uuid(3400),
                principal_authority_revision=0,
            )

    applied = await invoke()
    after_applied = await _postgres_p1b_effect_snapshot(database, operation_id)
    replayed = await invoke()
    after_replayed = await _postgres_p1b_effect_snapshot(database, operation_id)
    conflicted = await invoke_conflict()
    after_conflicted = await _postgres_p1b_effect_snapshot(database, operation_id)
    async with database._pool.acquire() as connection:
        if case_alias == "admission":
            submission = await connection.fetchrow(
                "SELECT admission_operation_id,submission_binding_contract_version,"
                "submission_result_code,submission_exact_replay_code "
                "FROM logical_executions WHERE campaign_id=$1 AND submission_id=$2",
                request.campaign_id,
                request.submission_id,
            )
            receipt_count = int(
                await connection.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    operation_id,
                )
            )
            assert tuple(submission.values()) == (
                operation_id,
                2,
                FixedResult.APPLIED.value,
                FixedResult.REPLAYED.value,
            )
            assert receipt_count == 0
            recorded_operation_code = "admission"
        else:
            recorded_operation_code = str(
                await connection.fetchval(
                    "SELECT operation_code FROM execution_operation_receipts WHERE operation_id=$1",
                    operation_id,
                )
            )
    return (
        applied,
        replayed,
        conflicted,
        after_applied,
        after_replayed,
        after_conflicted,
        recorded_operation_code,
    )


@pytest.mark.parametrize(
    ("_case_alias", "operation_code"),
    _P1B_AUTHORITY_CASES,
    ids=tuple(alias for alias, _code in _P1B_AUTHORITY_CASES),
)
def test_postgres_p1b_independent_literal_binding_vector(
    _case_alias: str, operation_code: str
) -> None:
    store = ExecutionLifecycleStore(None, "postgresql")
    spec = _postgres_p1b_literal_spec(store, operation_code)
    assert spec.request_binding_digest == _postgres_p1b_independent_request_digest(operation_code)


@pytest.mark.parametrize(
    ("_case_alias", "operation_code"),
    _P1B_AUTHORITY_CASES,
    ids=tuple(alias for alias, _code in _P1B_AUTHORITY_CASES),
)
@pytest.mark.asyncio
async def test_postgres_p1b_each_public_authority_replays_exactly(
    _case_alias: str,
    operation_code: str,
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            (
                applied,
                replayed,
                conflicted,
                after_applied,
                after_replayed,
                after_conflicted,
                recorded_operation_code,
            ) = await _postgres_p1b_exercise_public_operation(_case_alias, database)
        finally:
            await database.close()
    expected_replay = (
        FixedResult.REPLAYED_BOUND_CHILD
        if operation_code == "retry"
        else FixedResult.REPLAYED_CLOSED
        if operation_code == "close_without_retry"
        else FixedResult.REPLAYED
    )
    assert applied.result is FixedResult.APPLIED
    assert replayed.result is expected_replay
    assert conflicted.result is FixedResult.CONFLICT_OPERATION
    assert after_applied == after_replayed == after_conflicted
    assert after_applied[1] == (0 if _case_alias == "admission" else 1)
    assert recorded_operation_code == operation_code


@pytest.mark.parametrize("case_alias", _P1B_BINDING_MUTATIONS, ids=_P1B_BINDING_MUTATIONS)
@pytest.mark.asyncio
async def test_postgres_p1b_each_binding_mutation_conflicts(
    case_alias: str, postgres_lifecycle_template: _MigrationHarness
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            if case_alias.startswith("submission-"):
                store, request = await _postgres_p1b_admission_case(database)
                changed_request = (
                    replace(request, operation_id=_uuid(3491))
                    if case_alias == "submission-operation-id"
                    else replace(request, actor_subject_ref=_uuid(3492))
                )
                result = await store._create_initial_execution_v2_for_migration_fixture(
                    changed_request
                )
                assert result.result is FixedResult.CONFLICT_OPERATION
                return
            store = ExecutionLifecycleStore(database._pool, "postgresql")
            operation_code = (
                "budget_reserve"
                if case_alias.startswith("secondary-expected-")
                else "outbox_claim"
                if case_alias == "lease-generation-outbox"
                else "outbox_poison"
                if case_alias == "owner-presence-outbox"
                else "terminal_failed"
                if case_alias == "canonical-request-payload-terminal"
                else "budget_configure"
                if case_alias == "canonical-request-payload-budget"
                else "queue"
            )
            spec = await _postgres_p1b_insert_receipt(store, operation_code)
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
                "owner-presence-outbox": {"owner_ref": _uuid(3015), "lease_generation": 1},
                "lease-generation-outbox": {"lease_generation": 2},
                "canonical-request-payload-terminal": {"request_binding_digest": "a" * 64},
                "canonical-request-payload-budget": {"request_binding_digest": "b" * 64},
            }
            changed = replace(spec, **mutations[case_alias])
            async with store._transaction() as connection:
                result = await store._classify_receipt(connection, changed, current_revision=None)
        finally:
            await database.close()
    assert (result.result, result.revision) == (FixedResult.CONFLICT_OPERATION, None)


@pytest.mark.parametrize("case_alias", _P1B_RETENTION_CASES, ids=_P1B_RETENTION_CASES)
@pytest.mark.asyncio
async def test_postgres_p1b_submission_and_receipt_retention_contract(
    case_alias: str, postgres_lifecycle_template: _MigrationHarness
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            if case_alias.startswith("submission-"):
                store, request = await _postgres_p1b_admission_case(database)
                if case_alias == "submission-lookup-precedes-gateway":
                    async with database._pool.acquire() as connection:
                        await connection.execute(
                            "UPDATE execution_gateway_state "
                            "SET mode='emergency_disabled',catalog_digest=repeat('c',64),"
                            "activation_revision=1,activation_at=updated_at,"
                            "revision=revision+1 WHERE singleton_id=1"
                        )
                    candidate = request
                elif case_alias == "submission-replay-after-state-advance":
                    async with database._pool.acquire() as connection:
                        await connection.execute(
                            "UPDATE logical_executions SET revision=revision+1 WHERE id=$1",
                            request.logical_execution_id,
                        )
                    candidate = request
                else:
                    candidate = replace(request, module_id="test.p1b.changed")
                result = await store._create_initial_execution_v2_for_migration_fixture(candidate)
                assert result.result is (
                    FixedResult.CONFLICT_OPERATION
                    if case_alias == "submission-changed-request-conflict"
                    else FixedResult.REPLAYED
                )
                return
            store = ExecutionLifecycleStore(database._pool, "postgresql")
            spec = await _postgres_p1b_insert_receipt(store, "outbox_purge")
            if case_alias == "receipt-update-rejected":
                with pytest.raises(asyncpg.PostgresError) as raised:
                    async with database._pool.acquire() as connection:
                        await connection.execute(
                            "UPDATE execution_operation_receipts "
                            "SET result_revision=result_revision+1"
                        )
                assert raised.value.sqlstate == "55000"
            elif case_alias == "receipt-delete-rejected":
                with pytest.raises(asyncpg.PostgresError) as raised:
                    async with database._pool.acquire() as connection:
                        await connection.execute("DELETE FROM execution_operation_receipts")
                assert raised.value.sqlstate == "55000"
            else:
                async with store._transaction() as connection:
                    replay = await store._classify_receipt(connection, spec, current_revision=None)
                assert (replay.result, replay.revision) == (FixedResult.REPLAYED, 10)
        finally:
            await database.close()


@pytest.mark.parametrize("case_alias", _P1B_ATOMICITY_CASES, ids=_P1B_ATOMICITY_CASES)
@pytest.mark.asyncio
async def test_postgres_p1b_receipt_atomicity_and_nonduplication(
    case_alias: str, postgres_lifecycle_template: _MigrationHarness, monkeypatch
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            store = ExecutionLifecycleStore(database._pool, "postgresql")
            if case_alias == "exact-replay-no-duplicate-side-effects":
                spec = await _postgres_p1b_insert_receipt(store, "actor_authority_ensure")
                async with store._transaction() as connection:
                    replay = await store._classify_receipt(connection, spec, current_revision=None)
                assert (replay.result, replay.revision) == (FixedResult.REPLAYED, 10)
            else:
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "INSERT INTO users(id,username,hashed_password,role,created_by) "
                        "VALUES($1,'p1b-atomic','fixed','admin','fixed')",
                        _uuid(3200),
                    )

                async def fail_receipt(*_args, **_kwargs) -> None:
                    raise RuntimeError("fixed-p1b-receipt-failure")

                monkeypatch.setattr(store, "_insert_receipt", fail_receipt)
                with pytest.raises(RuntimeError, match="fixed-p1b-receipt-failure"):
                    await store.ensure_actor_authority(_uuid(3200), _uuid(3201))
                async with database._pool.acquire() as connection:
                    authority = int(
                        await connection.fetchval(
                            "SELECT count(*) FROM execution_actor_authority_revisions "
                            "WHERE user_id=$1",
                            _uuid(3200),
                        )
                    )
                assert authority == 0
            async with database._pool.acquire() as connection:
                receipts = int(
                    await connection.fetchval("SELECT count(*) FROM execution_operation_receipts")
                )
        finally:
            await database.close()
    assert receipts == (1 if case_alias == "exact-replay-no-duplicate-side-effects" else 0)


@pytest.mark.parametrize("_case_alias", _P1B_CONCURRENCY_CASES, ids=_P1B_CONCURRENCY_CASES)
@pytest.mark.asyncio
async def test_postgres_p1b_identical_operation_concurrency(
    _case_alias: str, postgres_lifecycle_template: _MigrationHarness
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            async with database._pool.acquire() as connection:
                await connection.execute(
                    "INSERT INTO users(id,username,hashed_password,role,created_by) "
                    "VALUES($1,'p1b-race','fixed','admin','fixed')",
                    _uuid(3300),
                )
            first = ExecutionLifecycleStore(database._pool, "postgresql")
            second = ExecutionLifecycleStore(database._pool, "postgresql")
            results = await asyncio.gather(
                first.ensure_actor_authority(_uuid(3300), _uuid(3301)),
                second.ensure_actor_authority(_uuid(3300), _uuid(3301)),
            )
            async with database._pool.acquire() as connection:
                counts = (
                    int(
                        await connection.fetchval(
                            "SELECT count(*) FROM execution_actor_authority_revisions "
                            "WHERE user_id=$1",
                            _uuid(3300),
                        )
                    ),
                    int(
                        await connection.fetchval(
                            "SELECT count(*) FROM execution_operation_receipts "
                            "WHERE operation_id=$1",
                            _uuid(3301),
                        )
                    ),
                )
        finally:
            await database.close()
    assert {result.result for result in results} == {FixedResult.APPLIED, FixedResult.REPLAYED}
    assert counts == (1, 1)


_POSTGRES_P1C_AUTHORITY_MUTATOR_ALIASES = (
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

_POSTGRES_P1C_INITIAL_AUTHORITY_ALIASES = (
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

_POSTGRES_P1C_AUTHORITY_DELETION_ALIASES = (
    "campaign-authority-cascade",
    "actor-authority-cascade",
    "destination-credential-authority-cascade",
    "snapshot-no-live-fk",
)

_POSTGRES_P1C_RETRY_AUTHORITY_ALIASES = (
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

_POSTGRES_P1C_PERSISTED_AUTHORITY_ALIASES = (
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


async def _postgres_p1c_authority_store(
    database: PostgresDatabase,
) -> tuple[ExecutionLifecycleStore, TrustedPrincipal, str, str, str]:
    principal_id = _uuid(12_000)
    actor_id = _uuid(12_001)
    campaign_id = _uuid(12_002)
    credential_id = _uuid(12_003)
    async with database._pool.acquire() as connection:
        await connection.executemany(
            "INSERT INTO users(id,username,hashed_password,role,created_by) "
            "VALUES($1,$2,'fixed',$3,'fixed')",
            (
                (principal_id, "p1c-admin", "admin"),
                (actor_id, "p1c-actor", "operator"),
            ),
        )
        await connection.execute(
            "INSERT INTO campaigns(id,name,operator,scope_json,targets_json) "
            "VALUES($1,'p1c-authority','p1c-admin','[]','[\"host.example\"]')",
            campaign_id,
        )
        await connection.execute(
            "INSERT INTO credentials(id,campaign_id,username,cred_type,source_module) "
            "VALUES($1,$2,'opaque-user','cleartext','p1c-fixture')",
            credential_id,
            campaign_id,
        )
    store = ExecutionLifecycleStore(database._pool, "postgresql")
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
        store,
        TrustedPrincipal(principal_id, principal_id),
        actor_id,
        campaign_id,
        credential_id,
    )


def _postgres_p1c_v3_intent(campaign_id: str) -> AdmissionIntentV3:
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


def _postgres_p1c_eligible_descriptor(monkeypatch) -> None:
    descriptor = replace(
        _descriptors.require_descriptor("opsec.coverage_predictor"),
        idempotency=IdempotencyClass.PROVEN_IDEMPOTENT,
        external_effect=ExternalEffectClass.READ_ONLY,
        retry_eligibility=RetryEligibility.AFTER_REVALIDATION,
        cancellation_ownership=CancellationOwnership.OWNED,
        compensation=CompensationClass.NOT_APPLICABLE,
        timeout=TimeoutPolicy(
            30,
            _descriptors.TimeoutSource.MODULE_DEFINED_BOUNDED,
            TimeoutSettlement.PROVEN,
        ),
        result_contract=ResultContract(
            findings=ContractState.PROVEN_NONE,
            credentials=ContractState.PROVEN_NONE,
            discovered_hosts=ContractState.PROVEN_NONE,
            loot_artifacts=ContractState.PROVEN_NONE,
            authoritative_evidence=ContractState.SUPPORTED,
        ),
        future_gateway_eligible=True,
        blocker_codes=(),
    )
    descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
    descriptors[descriptor.module_id] = descriptor
    monkeypatch.setattr(_descriptors, "FIRST_PARTY_DESCRIPTORS", descriptors)


def _postgres_p1c_v2_request(
    principal: TrustedPrincipal,
    campaign_id: str,
) -> AdmissionRequest:
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


async def _postgres_p1c_admission_counts(
    database: PostgresDatabase,
    operation_id: str,
) -> tuple[int, int, int, int]:
    async with database._pool.acquire() as observer:
        return (
            int(await observer.fetchval("SELECT count(*) FROM logical_executions")),
            int(await observer.fetchval("SELECT count(*) FROM execution_attempts")),
            int(await observer.fetchval("SELECT count(*) FROM execution_publication_outbox")),
            int(
                await observer.fetchval(
                    "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                    operation_id,
                )
            ),
        )


async def _postgres_p1c_full_observer_snapshot(
    database: PostgresDatabase,
) -> tuple[str, ...]:
    inventories = (
        ("execution_gateway_state", "singleton_id"),
        ("users", "id"),
        ("campaigns", "id"),
        ("execution_actor_authority_revisions", "user_id"),
        ("campaign_execution_authority_revisions", "campaign_id"),
        ("campaign_execution_actor_grants", "campaign_id,actor_user_id"),
        ("campaign_execution_destination_authorities", "campaign_id"),
        ("credentials", "id"),
        ("execution_approval_authorities", "id"),
        ("campaign_execution_budgets", "id"),
        ("logical_executions", "id"),
        ("execution_attempts", "id"),
        ("execution_attempt_approvals", "id"),
        ("campaign_execution_budget_ledger", "id"),
        ("execution_publication_outbox", "id"),
        ("execution_operation_receipts", "operation_id"),
        ("execution_attempt_destination_observations", "attempt_id,ordinal"),
        ("execution_attempt_credential_observations", "attempt_id,ordinal"),
    )
    async with database._pool.acquire() as observer:
        snapshots: list[str] = []
        for table, order_by in inventories:
            statement = (
                "SELECT jsonb_build_object("  # noqa: S608 - frozen identifiers.
                "'count',count(*),'rows',COALESCE("
                f"jsonb_agg(to_jsonb(snapshot) ORDER BY {order_by}),"
                f"'[]'::jsonb))::text FROM {table} AS snapshot"
            )
            snapshots.append(str(await observer.fetchval(statement)))
        return tuple(snapshots)


def _postgres_p1c_descriptor_mutation(
    monkeypatch,
    case_alias: str,
) -> None:
    source = _descriptors.require_descriptor("opsec.coverage_predictor")
    changes: dict[str, Any] = {}
    if case_alias == "descriptor-module-identity":
        changed = replace(
            source,
            module_id="opsec.coverage_predictor_changed",
        )
        descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
        descriptors["opsec.coverage_predictor"] = changed
        monkeypatch.setattr(_descriptors, "FIRST_PARTY_DESCRIPTORS", descriptors)
        return
    elif case_alias == "descriptor-contract-version":
        changed = object.__new__(type(source))
        for descriptor_field in source.__dataclass_fields__:
            object.__setattr__(changed, descriptor_field, getattr(source, descriptor_field))
        object.__setattr__(changed, "contract_version", "ares.module-descriptor.v1")
        object.__setattr__(
            changed,
            "semantic_digest",
            _descriptors.descriptor_semantic_digest(changed),
        )
        descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
        descriptors[source.module_id] = changed
        monkeypatch.setattr(_descriptors, "FIRST_PARTY_DESCRIPTORS", descriptors)
        return
    elif case_alias == "descriptor-semantic-digest":
        changed = replace(source, declared_outputs=source.declared_outputs + ("changed",))
        object.__setattr__(changed, "semantic_digest", "0" * 64)
        descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
        descriptors[source.module_id] = changed
        monkeypatch.setattr(_descriptors, "FIRST_PARTY_DESCRIPTORS", descriptors)
        return
    elif case_alias == "policy-minimum-role":
        changes["minimum_role"] = _descriptors.MinimumRole.TEAM_LEAD
    elif case_alias == "policy-noise-class":
        changes["opsec"] = _descriptors.OpsecClassification.HIGH_NOISE
    elif case_alias == "policy-required-capabilities":
        from ares.core.capabilities import Capability

        changes["required_capabilities"] = (Capability.CAP_NET,)
    elif case_alias == "policy-approval":
        changes["explicit_attempt_approval"] = True
    elif case_alias == "destination-extraction":
        changes["declared_outputs"] = source.declared_outputs + ("destination-changed",)
    descriptor = replace(source, **changes)
    descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
    descriptors[source.module_id] = descriptor
    monkeypatch.setattr(_descriptors, "FIRST_PARTY_DESCRIPTORS", descriptors)


async def _postgres_p1c_corrupt_authority(
    database: PostgresDatabase,
    case_alias: str,
    *,
    campaign_id: str,
    credential_id: str,
    principal: TrustedPrincipal,
) -> None:
    async with database._pool.acquire() as connection:
        if case_alias == "gateway-mode":
            await connection.execute(
                "UPDATE execution_gateway_state SET mode='emergency_disabled',"
                "catalog_digest=repeat('0',64) WHERE singleton_id=1"
            )
        elif case_alias == "gateway-revision":
            await connection.execute(
                "UPDATE execution_gateway_state SET activation_revision=revision+2 "
                "WHERE singleton_id=1"
            )
        elif case_alias == "gateway-catalog-digest":
            await connection.execute(
                "UPDATE execution_gateway_state SET catalog_digest=repeat('0',64) "
                "WHERE singleton_id=1"
            )
        elif case_alias == "actor-identity":
            await connection.execute(
                "UPDATE users SET username='p1c-other' WHERE id=$1",
                principal.user_id,
            )
        elif case_alias == "actor-active":
            await connection.execute(
                "UPDATE users SET is_active=0 WHERE id=$1",
                principal.user_id,
            )
        elif case_alias == "actor-role":
            await connection.execute(
                "UPDATE users SET role='recon' WHERE id=$1",
                principal.user_id,
            )
        elif case_alias == "actor-authority-revision":
            await connection.execute(
                "UPDATE execution_actor_authority_revisions "
                "SET authority_revision=authority_revision+1,"
                "authority_binding_digest=repeat('0',64) WHERE user_id=$1",
                principal.user_id,
            )
        elif case_alias == "campaign-status":
            await connection.execute(
                "UPDATE campaigns SET status='completed' WHERE id=$1",
                campaign_id,
            )
        elif case_alias == "campaign-authority-revision":
            await connection.execute(
                "UPDATE campaign_execution_authority_revisions "
                "SET authority_revision=authority_revision+1,"
                "authority_binding_digest=repeat('0',64) WHERE campaign_id=$1",
                campaign_id,
            )
        elif case_alias == "campaign-ownership":
            await connection.execute(
                "UPDATE campaigns SET operator='changed-owner' WHERE id=$1",
                campaign_id,
            )
        elif case_alias == "destination-campaign-scope":
            await connection.execute(
                "UPDATE campaigns SET targets_json='[\"different.example\"]' WHERE id=$1",
                campaign_id,
            )
        elif case_alias == "destination-authority-revision":
            await connection.execute(
                "UPDATE campaign_execution_destination_authorities "
                "SET revision=revision+1,binding_digest=repeat('0',64) "
                "WHERE campaign_id=$1",
                campaign_id,
            )
        elif case_alias == "credential-exists":
            await connection.execute("DELETE FROM credentials WHERE id=$1", credential_id)
        elif case_alias == "credential-ownership":
            second_campaign = _uuid(12_980)
            await connection.execute(
                "INSERT INTO campaigns(id,name) VALUES($1,'p1c-other-campaign')",
                second_campaign,
            )
            await connection.execute(
                "UPDATE credentials SET campaign_id=$1 WHERE id=$2",
                second_campaign,
                credential_id,
            )
        elif case_alias == "credential-authority-revision":
            await connection.execute(
                "UPDATE credentials SET execution_authority_revision="
                "execution_authority_revision+1,"
                "execution_authority_binding_digest=repeat('0',64) WHERE id=$1",
                credential_id,
            )
        elif case_alias == "budget-authority-revisions":
            await connection.execute(
                "DELETE FROM campaign_execution_budgets "
                "WHERE campaign_id=$1 AND budget_kind='noise'",
                campaign_id,
            )
        elif case_alias == "budget-capacity":
            await connection.execute(
                "UPDATE campaign_execution_budgets SET reserved_units=capacity_units "
                "WHERE campaign_id=$1 AND budget_kind='concurrency'",
                campaign_id,
            )


@pytest.mark.parametrize(
    "_case_alias",
    _POSTGRES_P1C_PERSISTED_AUTHORITY_ALIASES,
    ids=_POSTGRES_P1C_PERSISTED_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_each_persisted_authority_contradiction_is_atomic(
    _case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            _postgres_p1c_eligible_descriptor(monkeypatch)
            (
                store,
                principal,
                _actor_id,
                campaign_id,
                credential_id,
            ) = await _postgres_p1c_authority_store(database)
            assert (
                await store.put_campaign_actor_grant(
                    principal,
                    CampaignActorGrantMutation(
                        _uuid(12_970),
                        campaign_id,
                        principal.user_id,
                        None,
                    ),
                )
            ).result is FixedResult.APPLIED
            assert (
                await store.update_gateway_authority(
                    principal,
                    GatewayAuthorityMutation(_uuid(12_971), 0, "enforced"),
                )
            ).result is FixedResult.APPLIED
            assert (
                await store.configure_campaign_budgets(
                    BudgetConfiguration(
                        campaign_id,
                        _uuid(12_972),
                        10,
                        _uuid(12_973),
                        10,
                        _uuid(12_974),
                        1,
                        _uuid(12_975),
                        "actor",
                        principal.subject_ref,
                        principal.user_id,
                        0,
                    )
                )
            ).result is FixedResult.APPLIED
            descriptor_cases = {
                "destination-extraction",
                "descriptor-module-identity",
                "descriptor-contract-version",
                "descriptor-semantic-digest",
                "policy-minimum-role",
                "policy-noise-class",
                "policy-required-capabilities",
                "policy-approval",
            }
            if _case_alias in descriptor_cases:
                _postgres_p1c_descriptor_mutation(monkeypatch, _case_alias)
            else:
                await _postgres_p1c_corrupt_authority(
                    database,
                    _case_alias,
                    campaign_id=campaign_id,
                    credential_id=credential_id,
                    principal=principal,
                )
            intent = replace(
                _postgres_p1c_v3_intent(campaign_id),
                credential_ids=(credential_id,) if _case_alias.startswith("credential-") else (),
            )
            before = await _postgres_p1c_full_observer_snapshot(database)
            result = await store.create_initial_execution_v3(principal, intent)
            after = await _postgres_p1c_full_observer_snapshot(database)
            expected = (
                FixedResult.CAPACITY_UNAVAILABLE
                if _case_alias == "budget-capacity"
                else FixedResult.AUTHORITY_STALE
            )
            assert result.result is expected, (
                "persisted authority contradiction had the wrong precedence"
            )
            assert after == before, (
                "persisted authority contradiction created a durable side effect"
            )
        finally:
            await database.close()


async def _postgres_p1c_prepare_retry_parent(
    database: PostgresDatabase,
    store: ExecutionLifecycleStore,
    principal: TrustedPrincipal,
    campaign_id: str,
) -> tuple[AdmissionIntentV3, int]:
    intent = _postgres_p1c_v3_intent(campaign_id)
    assert (
        await store.put_campaign_actor_grant(
            principal,
            CampaignActorGrantMutation(
                _uuid(12_540),
                campaign_id,
                principal.user_id,
                None,
            ),
        )
    ).result is FixedResult.APPLIED
    assert (
        await store.update_gateway_authority(
            principal,
            GatewayAuthorityMutation(_uuid(12_541), 0, "enforced"),
        )
    ).result is FixedResult.APPLIED
    assert (
        await store.configure_campaign_budgets(
            BudgetConfiguration(
                campaign_id,
                _uuid(12_542),
                10,
                _uuid(12_543),
                10,
                _uuid(12_544),
                1,
                _uuid(12_545),
                "actor",
                principal.subject_ref,
                principal.user_id,
                0,
            )
        )
    ).result is FixedResult.APPLIED
    assert (
        await store.create_initial_execution_v3(principal, intent)
    ).result is FixedResult.APPLIED
    transition = TransitionRequest(
        intent.attempt_id,
        0,
        AttemptState.FAILED,
        _uuid(12_546),
        outcome_code=OutcomeCode.CONFIRMED_FAILURE_NO_DISPATCH,
        authoritative_proof="no_dispatch",
        campaign_id=campaign_id,
        actor_subject_ref=principal.subject_ref,
        actor_user_id=principal.user_id,
        actor_authority_revision=0,
    )
    terminal = TerminalCommitRequest(
        intent.logical_execution_id,
        campaign_id,
        _uuid(12_547),
        _uuid(12_548),
        transition,
        BudgetSettlement(
            campaign_id,
            intent.attempt_id,
            _uuid(12_542),
            0,
            0,
            1,
            _uuid(12_543),
            0,
            0,
            1,
            _uuid(12_544),
            1,
            _uuid(12_549),
            "actor",
            principal.subject_ref,
            principal.user_id,
            0,
        ),
    )
    result = await store.commit_terminal_attempt(terminal)
    assert result.result is FixedResult.APPLIED
    async with database._pool.acquire() as observer:
        parent = await observer.fetchrow(
            "SELECT revision,retry_disposition,closes_logical FROM execution_attempts WHERE id=$1",
            intent.attempt_id,
        )
    assert tuple(parent[1:]) == ("eligible", False)
    return intent, int(parent[0])


def _postgres_p1c_retry_intent(
    parent: AdmissionIntentV3,
    parent_revision: int,
) -> RetryIntentV3:
    return RetryIntentV3(
        parent.logical_execution_id,
        parent.attempt_id,
        _uuid(12_560),
        None,
        None,
        _uuid(12_561),
        parent_revision,
        "live",
        parent.raw_parameters,
    )


@pytest.mark.parametrize(
    "_case_alias",
    _POSTGRES_P1C_AUTHORITY_DELETION_ALIASES,
    ids=_POSTGRES_P1C_AUTHORITY_DELETION_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_authority_deletion_and_fk_contract(
    _case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            _postgres_p1c_eligible_descriptor(monkeypatch)
            (
                store,
                principal,
                actor_id,
                campaign_id,
                credential_id,
            ) = await _postgres_p1c_authority_store(database)
            grant_actor = principal.user_id if _case_alias == "snapshot-no-live-fk" else actor_id
            assert (
                await store.put_campaign_actor_grant(
                    principal,
                    CampaignActorGrantMutation(
                        _uuid(12_950),
                        campaign_id,
                        grant_actor,
                        None,
                    ),
                )
            ).result is FixedResult.APPLIED
            if _case_alias == "campaign-authority-cascade":
                deleted = await database.delete_campaign_lifecycle(
                    campaign_id,
                    operation_id=_uuid(12_951),
                )
                async with database._pool.acquire() as observer:
                    observed = await observer.fetchrow(
                        "SELECT "
                        "(SELECT count(*) FROM campaigns WHERE id=$1),"
                        "(SELECT count(*) FROM campaign_execution_authority_revisions "
                        "WHERE campaign_id=$1),"
                        "(SELECT count(*) FROM campaign_execution_actor_grants "
                        "WHERE campaign_id=$1),"
                        "(SELECT count(*) FROM execution_operation_receipts "
                        "WHERE operation_id=$2)",
                        campaign_id,
                        _uuid(12_951),
                    )
                assert deleted.result is FixedResult.APPLIED, "campaign purge was rejected"
                assert tuple(observed) == (0, 0, 0, 1), (
                    "campaign purge retained mutable authority or lost its receipt"
                )
            elif _case_alias == "actor-authority-cascade":
                async with database._pool.acquire() as connection:
                    async with connection.transaction():
                        await connection.execute(
                            "DELETE FROM campaign_execution_actor_grants WHERE actor_user_id=$1",
                            actor_id,
                        )
                        await connection.execute("DELETE FROM users WHERE id=$1", actor_id)
                async with database._pool.acquire() as observer:
                    observed = await observer.fetchrow(
                        "SELECT "
                        "(SELECT count(*) FROM execution_actor_authority_revisions "
                        "WHERE user_id=$1),"
                        "(SELECT count(*) FROM users WHERE id=$1)",
                        actor_id,
                    )
                assert tuple(observed) == (0, 0), "actor authority did not cascade with user"
            elif _case_alias == "destination-credential-authority-cascade":
                deleted = await database.delete_campaign_lifecycle(
                    campaign_id,
                    operation_id=_uuid(12_952),
                )
                async with database._pool.acquire() as observer:
                    observed = await observer.fetchrow(
                        "SELECT "
                        "(SELECT count(*) FROM campaign_execution_destination_authorities "
                        "WHERE campaign_id=$1),"
                        "(SELECT count(*) FROM credentials WHERE id=$2)",
                        campaign_id,
                        credential_id,
                    )
                assert deleted.result is FixedResult.APPLIED, "campaign purge was rejected"
                assert tuple(observed) == (0, 0), (
                    "campaign purge retained destination or credential authority"
                )
            else:
                intent = _postgres_p1c_v3_intent(campaign_id)
                applied = await store.create_initial_execution_v3(principal, intent)
                assert applied.result is FixedResult.APPLIED
                async with database._pool.acquire() as connection:
                    async with connection.transaction():
                        await connection.execute(
                            "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=$1",
                            campaign_id,
                        )
                        await connection.execute(
                            "DELETE FROM campaign_execution_destination_authorities "
                            "WHERE campaign_id=$1",
                            campaign_id,
                        )
                        await connection.execute(
                            "DELETE FROM credentials WHERE id=$1",
                            credential_id,
                        )
                async with database._pool.acquire() as observer:
                    observed = await observer.fetchrow(
                        "SELECT authority_contract_version,trusted_principal_user_id,"
                        "destination_authority_binding_digest,"
                        "credential_authority_binding_digest "
                        "FROM execution_attempts WHERE id=$1",
                        intent.attempt_id,
                    )
                assert observed is not None
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
                async with database._pool.acquire() as observer:
                    remaining = int(
                        await observer.fetchval(
                            "SELECT count(*) FROM execution_attempts WHERE id=$1",
                            intent.attempt_id,
                        )
                    )
                assert purged.result is FixedResult.APPLIED, "historical campaign purge failed"
                assert remaining == 0, "historical snapshot survived campaign purge"
        finally:
            await database.close()


@pytest.mark.asyncio
async def test_postgres_actor_revocation_and_admission_are_linearized(
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(
            _migration_url(harness.config, harness.database_name),
            pool_min=3,
            pool_max=3,
        )
        await database.connect()
        admission_task: asyncio.Task[OperationResult] | None = None
        revocation_task: asyncio.Task[OperationResult] | None = None
        try:
            _postgres_p1c_eligible_descriptor(monkeypatch)
            (
                setup_store,
                principal,
                _actor_id,
                campaign_id,
                _credential_id,
            ) = await _postgres_p1c_authority_store(database)
            assert (
                await setup_store.put_campaign_actor_grant(
                    principal,
                    CampaignActorGrantMutation(
                        _uuid(12_960),
                        campaign_id,
                        principal.user_id,
                        None,
                    ),
                )
            ).result is FixedResult.APPLIED
            assert (
                await setup_store.update_gateway_authority(
                    principal,
                    GatewayAuthorityMutation(_uuid(12_962), 0, "enforced"),
                )
            ).result is FixedResult.APPLIED
            assert (
                await setup_store.configure_campaign_budgets(
                    BudgetConfiguration(
                        campaign_id,
                        _uuid(12_963),
                        10,
                        _uuid(12_964),
                        10,
                        _uuid(12_965),
                        1,
                        _uuid(12_966),
                        "actor",
                        principal.subject_ref,
                        principal.user_id,
                        0,
                    )
                )
            ).result is FixedResult.APPLIED
            admission_locked = asyncio.Event()
            revocation_attempted = asyncio.Event()
            admission_store = _PostgresAdmissionWinnerStore(
                database._pool,
                admission_locked,
                revocation_attempted,
            )
            revocation_store = _PostgresRevocationContenderStore(
                database._pool,
                revocation_attempted,
            )
            intent = _postgres_p1c_v3_intent(campaign_id)
            revoke_operation_id = _uuid(12_961)
            admission_task = asyncio.create_task(
                admission_store.create_initial_execution_v3(principal, intent)
            )
            await asyncio.wait_for(admission_locked.wait(), timeout=10)
            revocation_task = asyncio.create_task(
                revocation_store.revoke_actor_authority(
                    principal,
                    ActorAuthorityMutation(
                        revoke_operation_id,
                        principal.user_id,
                        0,
                    ),
                )
            )
            await asyncio.wait_for(revocation_attempted.wait(), timeout=10)
            admitted, revoked = await asyncio.wait_for(
                asyncio.gather(admission_task, revocation_task),
                timeout=30,
            )
            async with database._pool.acquire() as observer:
                observed_attempt = await observer.fetchrow(
                    "SELECT state,actor_authority_revision FROM execution_attempts WHERE id=$1",
                    intent.attempt_id,
                )
                observed_actor = await observer.fetchrow(
                    "SELECT authority_state,authority_revision "
                    "FROM execution_actor_authority_revisions WHERE user_id=$1",
                    principal.user_id,
                )
                receipt_counts = await observer.fetchrow(
                    "SELECT "
                    "sum(CASE WHEN operation_id=$1 THEN 1 ELSE 0 END),"
                    "sum(CASE WHEN operation_id=$2 THEN 1 ELSE 0 END) "
                    "FROM execution_operation_receipts",
                    intent.operation_id,
                    revoke_operation_id,
                )
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


@pytest.mark.parametrize(
    "_case_alias",
    _POSTGRES_P1C_RETRY_AUTHORITY_ALIASES,
    ids=_POSTGRES_P1C_RETRY_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_retry_v2_v3_authority(
    _case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            _postgres_p1c_eligible_descriptor(monkeypatch)
            (
                store,
                principal,
                _actor_id,
                campaign_id,
                _credential_id,
            ) = await _postgres_p1c_authority_store(database)
            if _case_alias.startswith("v2-") or _case_alias == "new-v2-retry-rejected":
                historical_store, parent_revision = await _postgres_p1b_prepare_retryable_parent(
                    database
                )
                child = AdmissionRequest(
                    _uuid(208),
                    _uuid(12_570),
                    _uuid(12_571),
                    _uuid(12_572),
                    _uuid(12_573),
                    _uuid(201),
                    _uuid(200),
                    _uuid(200),
                    "test-transition",
                    "sdk",
                    AttemptState.BLOCKED,
                    _uuid(12_574),
                    replace(
                        _blocked_snapshot(),
                        actor_role="admin",
                        gateway_mode_snapshot="enforced",
                    ),
                )
                request = RetryRequest(_uuid(208), _uuid(210), child, parent_revision)
                if _case_alias == "new-v2-retry-rejected":
                    result = await historical_store.create_retry_attempt(request)
                    assert result.result is FixedResult.INVALID_CONTRACT
                    return
                assert (
                    await historical_store._create_retry_attempt_v2_for_migration_fixture(request)
                ).result is FixedResult.APPLIED
                if _case_alias == "v2-retry-child-binding-conflict":
                    candidate = replace(
                        request,
                        child=replace(child, module_id="test-transition.changed"),
                    )
                    expected = FixedResult.CONFLICT_OPERATION
                else:
                    if _case_alias == "v2-retry-after-authority-change":
                        async with database._pool.acquire() as connection:
                            await connection.execute(
                                "UPDATE users SET role='reporter' WHERE id=$1",
                                _uuid(200),
                            )
                    candidate = request
                    expected = FixedResult.REPLAYED_BOUND_CHILD
                result = await historical_store.replay_retry_attempt_v2(
                    TrustedPrincipal(_uuid(200), _uuid(200)),
                    candidate,
                )
                assert result.result is expected
                return

            parent, parent_revision = await _postgres_p1c_prepare_retry_parent(
                database,
                store,
                principal,
                campaign_id,
            )
            intent = _postgres_p1c_retry_intent(parent, parent_revision)
            applied = await store.create_retry_attempt_v3(principal, intent)
            assert applied.result is FixedResult.APPLIED
            if _case_alias == "v3-retry-applied":
                result = applied
                expected = FixedResult.APPLIED
            elif _case_alias == "v3-retry-exact-replay":
                result = await store.create_retry_attempt_v3(principal, intent)
                expected = FixedResult.REPLAYED_BOUND_CHILD
            elif _case_alias == "v3-retry-child-binding-conflict":
                result = await store.create_retry_attempt_v3(
                    principal,
                    replace(intent, child_attempt_id=_uuid(12_562)),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-retry-parent-revision-conflict":
                result = await store.create_retry_attempt_v3(
                    principal,
                    replace(intent, expected_parent_revision=parent_revision + 1),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-retry-after-authority-change":
                assert (
                    await store.revoke_actor_authority(
                        principal,
                        ActorAuthorityMutation(
                            _uuid(12_563),
                            principal.user_id,
                            0,
                        ),
                    )
                ).result is FixedResult.APPLIED
                result = await store.create_retry_attempt_v3(principal, intent)
                expected = FixedResult.REPLAYED_BOUND_CHILD
            else:
                child = AdmissionRequest(
                    parent.logical_execution_id,
                    parent.submission_id,
                    intent.child_attempt_id,
                    _uuid(12_562),
                    _uuid(12_563),
                    campaign_id,
                    principal.subject_ref,
                    principal.user_id,
                    parent.module_id,
                    parent.ingress_code,
                    AttemptState.BLOCKED,
                    intent.operation_id,
                    _blocked_snapshot(),
                )
                result = await store.replay_retry_attempt_v2(
                    principal,
                    RetryRequest(
                        parent.logical_execution_id,
                        parent.attempt_id,
                        child,
                        parent_revision,
                    ),
                )
                expected = FixedResult.CONFLICT_OPERATION
            assert result.result is expected
            async with database._pool.acquire() as observer:
                child_count = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM execution_attempts WHERE id=$1",
                        intent.child_attempt_id,
                    )
                )
                receipt_count = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                        intent.operation_id,
                    )
                )
            assert (child_count, receipt_count) == (1, 1)
        finally:
            await database.close()


@pytest.mark.parametrize(
    "_case_alias",
    _POSTGRES_P1C_INITIAL_AUTHORITY_ALIASES,
    ids=_POSTGRES_P1C_INITIAL_AUTHORITY_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_initial_v2_v3_submission_authority(
    _case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            (
                store,
                principal,
                _actor_id,
                campaign_id,
                _credential_id,
            ) = await _postgres_p1c_authority_store(database)
            _postgres_p1c_eligible_descriptor(monkeypatch)
            assert (
                await store.put_campaign_actor_grant(
                    principal,
                    CampaignActorGrantMutation(_uuid(12_510), campaign_id, principal.user_id, None),
                )
            ).result is FixedResult.APPLIED
            intent = _postgres_p1c_v3_intent(campaign_id)
            v2_request = _postgres_p1c_v2_request(principal, campaign_id)

            if _case_alias.startswith("v2-") or _case_alias == "new-v2-rejected":
                if _case_alias == "new-v2-rejected":
                    result = await store.create_initial_execution(v2_request)
                    assert result.result is FixedResult.INVALID_CONTRACT, (
                        "public fresh-v2 creation was accepted"
                    )
                    assert await _postgres_p1c_admission_counts(
                        database, v2_request.operation_id
                    ) == (0, 0, 0, 0), "fresh-v2 rejection created durable state"
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
                        replace(
                            v2_request,
                            module_id="opsec.coverage_predictor.changed",
                        ),
                    )
                    expected = FixedResult.CONFLICT_OPERATION
                elif _case_alias == "v2-after-gateway-change":
                    assert (
                        await store.update_gateway_authority(
                            principal,
                            GatewayAuthorityMutation(
                                _uuid(12_511),
                                0,
                                "shadow_candidate",
                            ),
                        )
                    ).result is FixedResult.APPLIED
                    result = await store.replay_initial_execution_v2(principal, v2_request)
                    expected = FixedResult.REPLAYED
                else:
                    async with database._pool.acquire() as connection:
                        await connection.execute(
                            "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=$1",
                            campaign_id,
                        )
                        await connection.execute(
                            "DELETE FROM campaign_execution_destination_authorities "
                            "WHERE campaign_id=$1",
                            campaign_id,
                        )
                    result = await store.replay_initial_execution_v2(principal, v2_request)
                    expected = FixedResult.REPLAYED
                assert result.result is expected, "historical v2 replay authority changed"
                return

            assert (
                await store.update_gateway_authority(
                    principal,
                    GatewayAuthorityMutation(_uuid(12_509), 0, "enforced"),
                )
            ).result is FixedResult.APPLIED
            assert (
                await store.configure_campaign_budgets(
                    BudgetConfiguration(
                        campaign_id,
                        _uuid(12_530),
                        20,
                        _uuid(12_531),
                        20,
                        _uuid(12_532),
                        1,
                        _uuid(12_533),
                        "actor",
                        principal.subject_ref,
                        principal.user_id,
                        0,
                    )
                )
            ).result is FixedResult.APPLIED
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
                    principal,
                    replace(intent, logical_execution_id=_uuid(12_520)),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-attempt-id-conflict":
                result = await store.create_initial_execution_v3(
                    principal,
                    replace(intent, attempt_id=_uuid(12_521)),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-operation-id-conflict":
                result = await store.create_initial_execution_v3(
                    principal,
                    replace(intent, operation_id=_uuid(12_522)),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-module-id-conflict":
                result = await store.create_initial_execution_v3(
                    principal,
                    replace(intent, module_id="opsec.coverage_predictor.changed"),
                )
                expected = FixedResult.CONFLICT_OPERATION
            elif _case_alias == "v3-ingress-conflict":
                result = await store.create_initial_execution_v3(
                    principal,
                    replace(intent, ingress_code="cli_module"),
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
                        GatewayAuthorityMutation(
                            _uuid(12_524),
                            1,
                            "shadow_candidate",
                        ),
                    )
                ).result is FixedResult.APPLIED
                result = await store.create_initial_execution_v3(principal, intent)
                expected = FixedResult.REPLAYED
            elif _case_alias == "v3-after-authority-deletion":
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=$1",
                        campaign_id,
                    )
                    await connection.execute(
                        "DELETE FROM campaign_execution_destination_authorities "
                        "WHERE campaign_id=$1",
                        campaign_id,
                    )
                result = await store.create_initial_execution_v3(principal, intent)
                expected = FixedResult.REPLAYED
            else:
                result = await store.replay_initial_execution_v2(principal, v2_request)
                expected = FixedResult.CONFLICT_OPERATION

            assert result.result is expected, "v3 submission replay authority changed"
            counts = await _postgres_p1c_admission_counts(database, intent.operation_id)
            assert counts[:3] == (1, 1, 0), "v3 accepted admission cardinality changed"
            assert counts[3] == 0, "initial admission created a redundant operation receipt"
            async with database._pool.acquire() as observer:
                durable = await observer.fetchrow(
                    "SELECT state,authority_contract_version,retry_disposition "
                    "FROM execution_attempts "
                    "WHERE id=$1",
                    intent.attempt_id,
                )
                reservations = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM campaign_execution_budget_ledger "
                        "WHERE attempt_id=$1 AND disposition='held'",
                        intent.attempt_id,
                    )
                )
            assert tuple(durable) == (
                AttemptState.ACCEPTED.value,
                3,
                "not_applicable",
            )
            assert reservations == 3
        finally:
            await database.close()


@pytest.mark.parametrize(
    "_case_alias",
    _POSTGRES_P1C_AUTHORITY_MUTATOR_ALIASES,
    ids=_POSTGRES_P1C_AUTHORITY_MUTATOR_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_each_authority_mutator_is_exactly_replayable(
    _case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
    monkeypatch,
) -> None:
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        try:
            (
                store,
                principal,
                actor_id,
                campaign_id,
                credential_id,
            ) = await _postgres_p1c_authority_store(database)
            operation_id = _uuid(
                12_100 + _POSTGRES_P1C_AUTHORITY_MUTATOR_ALIASES.index(_case_alias)
            )
            approval_id = _uuid(12_200)
            approval_ref = _uuid(12_201)
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
                request = CampaignAuthorityMutation(
                    operation_id,
                    campaign_id,
                    expected_revision,
                )
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
                    operation_id,
                    campaign_id,
                    actor_id,
                    expected_revision,
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
                    return replace(
                        request,
                        expected_revision=request.expected_revision + 1,
                    )
                if type(request) is CampaignActorGrantMutation:
                    expected = (
                        0 if request.expected_revision is None else request.expected_revision + 1
                    )
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
                        "user_id=$1",
                        (actor_id,),
                    ),
                    "actor-update": (
                        "execution_actor_authority_revisions",
                        "user_id=$1",
                        (actor_id,),
                    ),
                    "actor-revoke": (
                        "execution_actor_authority_revisions",
                        "user_id=$1",
                        (actor_id,),
                    ),
                    "campaign-activate": (
                        "campaign_execution_authority_revisions",
                        "campaign_id=$1",
                        (campaign_id,),
                    ),
                    "campaign-update": (
                        "campaign_execution_authority_revisions",
                        "campaign_id=$1",
                        (campaign_id,),
                    ),
                    "campaign-revoke": (
                        "campaign_execution_authority_revisions",
                        "campaign_id=$1",
                        (campaign_id,),
                    ),
                    "grant-put": (
                        "campaign_execution_actor_grants",
                        "campaign_id=$1 AND actor_user_id=$2",
                        (campaign_id, actor_id),
                    ),
                    "grant-revoke": (
                        "campaign_execution_actor_grants",
                        "campaign_id=$1 AND actor_user_id=$2",
                        (campaign_id, actor_id),
                    ),
                    "destination-update": (
                        "campaign_execution_destination_authorities",
                        "campaign_id=$1",
                        (campaign_id,),
                    ),
                    "destination-revoke": (
                        "campaign_execution_destination_authorities",
                        "campaign_id=$1",
                        (campaign_id,),
                    ),
                    "credential-update": ("credentials", "id=$1", (credential_id,)),
                    "credential-revoke": ("credentials", "id=$1", (credential_id,)),
                    "approval-grant": (
                        "execution_approval_authorities",
                        "id=$1",
                        (approval_id,),
                    ),
                    "approval-revoke": (
                        "execution_approval_authorities",
                        "id=$1",
                        (approval_id,),
                    ),
                }[_case_alias]
                async with database._pool.acquire() as observer:
                    rows = await observer.fetch(
                        f"SELECT * FROM {table} WHERE {where}",  # noqa: S608
                        *parameters,
                    )
                return tuple(tuple(row.values()) for row in rows)

            applied = await invoke()
            async with database._pool.acquire() as observer:
                receipt_count_after_apply = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                        operation_id,
                    )
                )
            replayed = await invoke()
            async with database._pool.acquire() as observer:
                receipt_count_after_replay = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                        operation_id,
                    )
                )
            target_before_conflict = await observe_target()
            conflicting = await getattr(store, method_name)(
                principal,
                changed_request(),
            )
            target_after_conflict = await observe_target()
            async with database._pool.acquire() as observer:
                receipt_count_after_conflict = int(
                    await observer.fetchval(
                        "SELECT count(*) FROM execution_operation_receipts WHERE operation_id=$1",
                        operation_id,
                    )
                )

            receipt_first: OperationResult | None = None
            if _case_alias == "gateway-update":
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "UPDATE execution_gateway_state SET catalog_digest=repeat('f',64) "
                        "WHERE singleton_id=1"
                    )
                receipt_first = await invoke()
            elif _case_alias.startswith("credential-"):
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "DELETE FROM credentials WHERE id=$1",
                        credential_id,
                    )
                receipt_first = await invoke()
            elif _case_alias.startswith("approval-"):
                if _case_alias == "approval-grant":
                    descriptors = dict(_descriptors.FIRST_PARTY_DESCRIPTORS)
                    descriptors["opsec.coverage_predictor"] = replace(
                        descriptors["opsec.coverage_predictor"],
                        minimum_role=_descriptors.MinimumRole.TEAM_LEAD,
                    )
                    monkeypatch.setattr(
                        _descriptors,
                        "FIRST_PARTY_DESCRIPTORS",
                        descriptors,
                    )
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "DELETE FROM execution_approval_authorities WHERE id=$1",
                        approval_id,
                    )
                receipt_first = await invoke()
            assert (applied.result, replayed.result) == (
                FixedResult.APPLIED,
                FixedResult.REPLAYED,
            ), "authority mutation lost exact replay"
            assert conflicting.result is FixedResult.CONFLICT_OPERATION, (
                "authority mutation accepted a changed same-operation binding"
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


_POSTGRES_P1C_TERMINAL_V3_ALIASES = (
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

_POSTGRES_P1C_TERMINAL_RESULT_DIGEST = hashlib.sha256(
    b"postgres-p1c-terminal-v3-known-result"
).hexdigest()
_POSTGRES_P1C_LEGACY_TERMINAL_REQUEST_DIGEST = (
    "da5caf4a079873de9cdea7f31a284bcac45bdd3526c602038aaeb66147fc5cb8"
)
_POSTGRES_P1C_LEGACY_TERMINAL_RESULT_DIGEST = (
    "0b15cef8a5886d92669f712e36c80a91e4e10d00a1e0d92d6a479ad1bde08278"
)
_POSTGRES_P1C_LEGACY_OUTBOX_REQUEST_DIGEST = (
    "5dccdba355c4feef9cd6df03d5d6b3c8af06feee7ee618108615a35a545425e7"
)
_POSTGRES_P1C_LEGACY_OUTBOX_RESULT_DIGEST = (
    "7a50d0b26f31239a9fba139b28affd32750988bb7d6dc360c0a570ea8856a0d3"
)
_POSTGRES_P1C_LEGACY_BUDGET_REQUEST_DIGEST = (
    "e0d4a8b6ca4ea2e38967e3158283cd1fa175279a41b1c55490cebbf76b48a9a1"
)
_POSTGRES_P1C_LEGACY_BUDGET_RESULT_DIGEST = (
    "04f8900897528d734dd7f4fd030af712b34e2cd18ddf929f247b20494f5ddcad"
)
_POSTGRES_P1C_TERMINAL_NODE_COUNT = 41
_POSTGRES_P1C_TERMINAL_NODE_ID_SHA256 = (
    "5e3de1839318f51847db713d93210f0104228d03c75501f3c401afa0010d3489"
)


def _postgres_p1c_terminal_inventory_digest() -> str:
    encoded = bytearray(b"ares.p1c-terminal-v3-postgres-test-inventory.v1\x00")
    for alias in _POSTGRES_P1C_TERMINAL_V3_ALIASES:
        node_id = (
            "tests/integration/test_postgres_execution_lifecycle.py::"
            f"test_postgres_p1c_terminal_v3_seam[{alias}]"
        ).encode()
        encoded.extend(struct.pack(">I", len(node_id)))
        encoded.extend(node_id)
    return hashlib.sha256(encoded).hexdigest()


assert len(_POSTGRES_P1C_TERMINAL_V3_ALIASES) == _POSTGRES_P1C_TERMINAL_NODE_COUNT
assert len(set(_POSTGRES_P1C_TERMINAL_V3_ALIASES)) == _POSTGRES_P1C_TERMINAL_NODE_COUNT
assert _postgres_p1c_terminal_inventory_digest() == _POSTGRES_P1C_TERMINAL_NODE_ID_SHA256


def _postgres_p1c_terminal_binding_digest(
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
        assert name not in seen, "PostgreSQL terminal oracle contains a duplicate field"
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
        else:  # pragma: no cover - a broken independent oracle must be loud.
            raise AssertionError("unsupported PostgreSQL terminal oracle value")
    return hashlib.sha256(encoded).hexdigest()


def _postgres_p1c_terminal_operation_id(attempt_id: str) -> str:
    digest = _postgres_p1c_terminal_binding_digest(
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


def _postgres_p1c_terminal_operation_code(outcome: OutcomeCode) -> str:
    return {
        OutcomeCode.CONFIRMED_SUCCESS: "terminal_succeeded",
        OutcomeCode.CONFIRMED_FAILURE: "terminal_failed",
        OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT: "cancellation_acknowledgement",
        OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED: "timeout",
    }[outcome]


def _postgres_p1c_terminal_request_digest(intent: TerminalCommitIntentV3) -> str:
    operation_id = _postgres_p1c_terminal_operation_id(intent.attempt_id)
    operation_code = _postgres_p1c_terminal_operation_code(intent.outcome_code)
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
    return _postgres_p1c_terminal_binding_digest(
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


def _postgres_p1c_terminal_derived_uuid(operation_id: str, label: str) -> str:
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


def _postgres_p1c_terminal_result_digest(intent: TerminalCommitIntentV3) -> str:
    operation_id = _postgres_p1c_terminal_operation_id(intent.attempt_id)
    operation_code = _postgres_p1c_terminal_operation_code(intent.outcome_code)
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
    outbox_id = _postgres_p1c_terminal_derived_uuid(operation_id, "terminal-outbox")
    publication_key = _postgres_p1c_terminal_derived_uuid(
        operation_id,
        "terminal-publication",
    )
    return _postgres_p1c_terminal_binding_digest(
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
            ("finding_count", 0),
            ("credential_count", 0),
            ("host_count", 0),
            ("artifact_count", 0),
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


async def _postgres_p1c_terminal_case(
    database: PostgresDatabase,
    *,
    predecessor: AttemptState = AttemptState.RUNNING,
) -> tuple[ExecutionLifecycleStore, _PostgresConnectionAdapter, Any, int]:
    store, adapter, connection = await _postgres_transition_case(database, AttemptState.ACCEPTED)
    if predecessor is AttemptState.ACCEPTED:
        return store, adapter, connection, 0
    dispatched = await _nonterminal_transition(store, adapter, AttemptState.DISPATCHING, 20_100)
    assert dispatched.result is FixedResult.APPLIED, "terminal fixture dispatch failed"
    running = await _nonterminal_transition(store, adapter, AttemptState.RUNNING, 20_101)
    assert running.result is FixedResult.APPLIED, "terminal fixture start failed"
    if predecessor is AttemptState.CANCELLING:
        cancelling = await _nonterminal_transition(store, adapter, AttemptState.CANCELLING, 20_102)
        assert cancelling.result is FixedResult.APPLIED, "terminal fixture cancel failed"
        return store, adapter, connection, 3
    assert predecessor is AttemptState.RUNNING, "unsupported terminal fixture predecessor"
    return store, adapter, connection, 2


def _postgres_p1c_terminal_intent(
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
            else _POSTGRES_P1C_TERMINAL_RESULT_DIGEST
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


async def _postgres_p1c_terminal_receipt(
    connection: Any,
    attempt_id: str = _uuid(210),
) -> Any:
    return await connection.fetchrow(
        "SELECT operation_id,operation_code,campaign_id,primary_target_id,"
        "secondary_target_id,principal_kind,principal_subject_ref,principal_user_id,"
        "principal_authority_revision_present,principal_authority_revision,"
        "binding_contract_version,request_binding_digest,result_code,exact_replay_code,"
        "result_binding_digest,result_identity,result_revision,secondary_result_identity,"
        "secondary_result_revision FROM execution_operation_receipts WHERE operation_id=$1",
        _postgres_p1c_terminal_operation_id(attempt_id),
    )


async def _postgres_p1c_terminal_state(connection: Any) -> Any:
    return await connection.fetchrow(
        "SELECT state,revision,outcome_code,settlement_state,settlement_proof_code,"
        "termination_confirmed,closes_logical,retry_disposition,terminal_operation_id,"
        "cancellation_ack_operation_id,timeout_operation_id "
        "FROM execution_attempts WHERE id=$1",
        _uuid(210),
    )


async def _postgres_p1c_terminal_receipt_snapshot(
    connection: Any,
) -> tuple[tuple[object, ...], ...]:
    rows = await connection.fetch(
        "SELECT * FROM execution_operation_receipts WHERE campaign_id=$1 ORDER BY operation_id",
        _uuid(201),
    )
    return tuple(tuple(row) for row in rows)


async def _postgres_p1c_terminal_snapshot(
    connection: Any,
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
        rows = await connection.fetch(
            f"SELECT * FROM {table} ORDER BY 1"  # noqa: S608 - fixed tuple.
        )
        observed.append((table, tuple(tuple(row) for row in rows)))
    return tuple(observed)


def _postgres_p1c_legacy_terminal_request(
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


class _PostgresP1CTerminalPoolProbe:
    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self.acquire_count = 0
        self.release_count = 0
        self.connection_identities: set[int] = set()

    async def acquire(self) -> Any:
        connection = await self._pool.acquire()
        self.acquire_count += 1
        self.connection_identities.add(id(connection))
        return connection

    async def release(self, connection: Any) -> None:
        self.release_count += 1
        await self._pool.release(connection)


class _PostgresP1CTerminalTraceStore(ExecutionLifecycleStore):
    def __init__(
        self,
        backend: Any,
        *,
        receipt_only: bool = False,
        ledger_mutation: str | None = None,
        fail_at: str | None = None,
        cancel_at: str | None = None,
        duplicate_terminal_returning: bool = False,
    ) -> None:
        super().__init__(backend, "postgresql")
        self.receipt_only = receipt_only
        self.ledger_mutation = ledger_mutation
        self.fail_at = fail_at
        self.cancel_at = cancel_at
        self.duplicate_terminal_returning = duplicate_terminal_returning
        self.transaction_entries = 0
        self.connection_identities: set[int] = set()
        self.read_events: list[str] = []
        self.lock_events: list[tuple[str, str | None]] = []
        self.budget_writes = 0
        self.budget_lock_ids: list[str] = []
        self.output_insert_order: list[str] = []

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        self.transaction_entries += 1
        async with super()._transaction() as connection:
            self.connection_identities.add(id(connection))
            yield connection

    async def _fetchrow(self, connection: Any, sql: str, params: Any) -> Any:
        self.connection_identities.add(id(connection))
        if "execution_operation_receipts" in sql:
            self.read_events.append("receipt")
        elif "pg_advisory_xact_lock" not in sql:
            self.read_events.append("mutable")
        if "FROM execution_attempts WHERE id=" in sql:
            assert sql.endswith(" FOR UPDATE"), "terminal attempt read was not locked"
            self.lock_events.append(("attempt", str(params[0])))
        if self.receipt_only and not (
            "execution_operation_receipts" in sql or "pg_advisory_xact_lock" in sql
        ):
            raise AssertionError("exact terminal replay read a mutable target")
        if "FROM campaign_execution_budgets WHERE id=" in sql:
            assert sql.endswith(" FOR UPDATE"), "terminal budget read was not locked"
            self.budget_lock_ids.append(str(params[0]))
            self.lock_events.append(("budget", str(params[0])))
        if "FROM logical_executions WHERE id=" in sql:
            assert sql.endswith(" FOR UPDATE"), "terminal logical read was not locked"
            self.lock_events.append(("logical", str(params[0])))
        return await super()._fetchrow(connection, sql, params)

    async def _fetchall(self, connection: Any, sql: str, params: Any) -> Any:
        self.connection_identities.add(id(connection))
        self.read_events.append("mutable")
        if self.receipt_only:
            raise AssertionError("exact terminal replay read a mutable target set")
        rows = tuple(await super()._fetchall(connection, sql, params))
        if "FROM campaign_execution_budget_ledger" not in sql or not rows:
            return rows
        assert sql.endswith(" FOR UPDATE"), "terminal ledger set was not locked"
        self.lock_events.append(("ledgers", str(params[0])))
        if self.ledger_mutation == "duplicate":
            return rows + (rows[0],)
        if self.ledger_mutation is None:
            return rows
        changed = [dict(row) for row in rows]
        if self.ledger_mutation == "wrong-kind":
            changed[0]["budget_kind"] = "artifact"
        elif self.ledger_mutation == "wrong-campaign":
            changed[0]["campaign_id"] = _uuid(20_300)
        elif self.ledger_mutation == "wrong-attempt":
            changed[0]["attempt_id"] = _uuid(20_301)
        elif self.ledger_mutation == "non-held":
            changed[0]["disposition"] = "released"
        else:  # pragma: no cover - constructor/dispatcher drift must be loud.
            raise AssertionError(f"unknown PostgreSQL ledger mutation: {self.ledger_mutation}")
        return tuple(changed)

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

    async def cas_update_one(
        self,
        connection: Any,
        sql: str,
        params: Any,
        **kwargs: Any,
    ) -> Any:
        row = await super().cas_update_one(connection, sql, params, **kwargs)
        if "UPDATE campaign_execution_budgets" in sql:
            self.budget_writes += 1
            if self.fail_at == "budget" and self.budget_writes == 2:
                raise RuntimeError("fixed-postgres-terminal-budget-write-failure")
        if self.fail_at == "terminal" and "UPDATE execution_attempts SET state=" in sql:
            raise RuntimeError("fixed-postgres-terminal-attempt-write-failure")
        if self.fail_at == "logical" and "UPDATE logical_executions SET closure" in sql:
            raise RuntimeError("fixed-postgres-terminal-logical-write-failure")
        return row

    async def _insert_output_links(self, *args: Any, **kwargs: Any) -> Any:
        counts = await super()._insert_output_links(*args, **kwargs)
        if self.fail_at == "output":
            raise RuntimeError("fixed-postgres-terminal-output-write-failure")
        if self.fail_at == "exception":
            raise RuntimeError("fixed-postgres-terminal-exception")
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
            raise RuntimeError("fixed-postgres-terminal-outbox-write-failure")
        return result

    async def _insert_terminal_v3_receipt(self, *args: Any, **kwargs: Any) -> Any:
        result = await super()._insert_terminal_v3_receipt(*args, **kwargs)
        if self.fail_at == "receipt":
            raise RuntimeError("fixed-postgres-terminal-receipt-write-failure")
        return result


async def _postgres_p1c_assert_terminal_rollback(
    connection: Any,
    store: ExecutionLifecycleStore,
    intent: TerminalCommitIntentV3,
    *,
    expected_result: FixedResult | None = None,
    expected_exception: type[BaseException] | None = None,
) -> OperationResult | None:
    before = await _postgres_p1c_terminal_snapshot(connection)
    if expected_exception is None:
        result = await store.commit_terminal_attempt_v3(intent)
        assert result.result is expected_result, "terminal rollback result changed"
    else:
        with pytest.raises(expected_exception):
            await store.commit_terminal_attempt_v3(intent)
        result = None
    after = await _postgres_p1c_terminal_snapshot(connection)
    assert after == before, "PostgreSQL terminal failure committed partial state"
    return result


@pytest.mark.parametrize(
    "case_alias",
    _POSTGRES_P1C_TERMINAL_V3_ALIASES,
    ids=_POSTGRES_P1C_TERMINAL_V3_ALIASES,
)
@pytest.mark.asyncio
async def test_postgres_p1c_terminal_v3_seam(  # noqa: C901, PLR0912, PLR0915
    case_alias: str,
    postgres_lifecycle_template: _MigrationHarness,
) -> None:
    if case_alias == "public-intent-excludes-derived-fields":
        declared_fields = fields(TerminalCommitIntentV3)
        public_fields = tuple(item.name for item in declared_fields)
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
        }, "terminal public annotations changed"
        assert all(item.default is MISSING for item in declared_fields[:-1])
        assert declared_fields[-1].default == ()
        params = TerminalCommitIntentV3.__dataclass_params__
        assert is_dataclass(TerminalCommitIntentV3)
        assert (
            params.init,
            params.repr,
            params.eq,
            params.order,
            params.unsafe_hash,
            params.frozen,
        ) == (True, False, False, False, False, True)
        assert tuple(TerminalCommitIntentV3.__slots__) == public_fields
        assert TerminalCommitIntentV3.__hash__ is None
        baseline = _postgres_p1c_terminal_intent(2)
        assert not hasattr(baseline, "__dict__"), "terminal intent lost its slot boundary"
        with pytest.raises(FrozenInstanceError):
            baseline.campaign_id = _uuid(20_299)
        values = {item.name: getattr(baseline, item.name) for item in fields(baseline)}
        for name in sorted(forbidden):
            with pytest.raises(TypeError):
                TerminalCommitIntentV3(**values, **{name: "caller-controlled"})
        return

    if case_alias == "missing-attempt-not-found-or-purged":
        async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
            database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
            await database.connect()
            try:
                intent = _postgres_p1c_terminal_intent(0)
                result = await ExecutionLifecycleStore(
                    database._pool, "postgresql"
                ).commit_terminal_attempt_v3(intent)
                async with database._pool.acquire() as observer:
                    receipt = await _postgres_p1c_terminal_receipt(observer)
            finally:
                await database.close()
        assert (result.result, result.revision) == (
            FixedResult.NOT_FOUND_OR_PURGED,
            None,
        )
        assert receipt is None, "missing PostgreSQL attempt created a receipt"
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
        for outcome, predecessor, operation_code in cases:
            async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
                database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
                await database.connect()
                setup_connection = None
                try:
                    store, _adapter, setup_connection, revision = await _postgres_p1c_terminal_case(
                        database,
                        predecessor=predecessor,
                    )
                    intent = _postgres_p1c_terminal_intent(revision, outcome=outcome)
                    result = await store.commit_terminal_attempt_v3(intent)
                    receipt = await _postgres_p1c_terminal_receipt(setup_connection)
                finally:
                    if setup_connection is not None:
                        await database._pool.release(setup_connection)
                    await database.close()
            assert result.result is FixedResult.APPLIED, "terminal binding case failed"
            assert receipt["operation_id"] == _postgres_p1c_terminal_operation_id(intent.attempt_id)
            assert receipt["operation_code"] == operation_code
            assert receipt["binding_contract_version"] == 2
            assert receipt["request_binding_digest"] == _postgres_p1c_terminal_request_digest(
                intent
            )
            assert receipt["result_binding_digest"] == _postgres_p1c_terminal_result_digest(intent)
            assert receipt["result_binding_digest"] != intent.execution_result_digest, (
                "terminal receipt result binding conflated the execution-result digest"
            )
        return

    if case_alias == "legacy-v3-crossing-conflict-operation":
        for first in ("legacy", "v3"):
            async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
                database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
                await database.connect()
                setup_connection = None
                try:
                    store, _adapter, setup_connection, revision = await _postgres_p1c_terminal_case(
                        database
                    )
                    intent = _postgres_p1c_terminal_intent(revision)
                    operation_id = _postgres_p1c_terminal_operation_id(intent.attempt_id)
                    legacy = _postgres_p1c_legacy_terminal_request(operation_id, revision)
                    if first == "legacy":
                        applied = await store.commit_terminal_attempt(legacy)
                        crossed = await store.commit_terminal_attempt_v3(intent)
                    else:
                        applied = await store.commit_terminal_attempt_v3(intent)
                        crossed = await store.commit_terminal_attempt(legacy)
                finally:
                    if setup_connection is not None:
                        await database._pool.release(setup_connection)
                    await database.close()
            assert (applied.result, crossed.result) == (
                FixedResult.APPLIED,
                FixedResult.CONFLICT_OPERATION,
            ), f"legacy/V3 {first}-first receipt crossing was reinterpreted"
        return

    if case_alias == "derived-revision-overflow-invariant-failure-rollback":
        for target in ("budget", "logical", "actual-max"):
            async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
                database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
                await database.connect()
                setup_connection = None
                try:
                    store, _adapter, setup_connection, revision = await _postgres_p1c_terminal_case(
                        database
                    )
                    intent = _postgres_p1c_terminal_intent(revision)
                    if target == "budget":
                        await setup_connection.execute(
                            "UPDATE campaign_execution_budgets SET revision=$1,"
                            "latest_operation_base_revision=$2 "
                            "WHERE campaign_id=$3 AND budget_kind='noise'",
                            MAX_I53,
                            MAX_I53 - 1,
                            _uuid(201),
                        )
                    elif target == "logical":
                        await setup_connection.execute(
                            "UPDATE logical_executions SET revision=$1 WHERE id=$2",
                            MAX_I53,
                            _uuid(208),
                        )
                    else:
                        await setup_connection.execute(
                            "UPDATE campaign_execution_budgets SET capacity_units=$1,"
                            "reserved_units=$1,consumed_units=0 "
                            "WHERE campaign_id=$2 AND budget_kind='noise'",
                            MAX_I53,
                            _uuid(201),
                        )
                        await setup_connection.execute(
                            "UPDATE campaign_execution_budget_ledger SET reservation_units=$1 "
                            "WHERE attempt_id=$2 AND budget_kind='noise'",
                            MAX_I53,
                            _uuid(210),
                        )
                        budget_revision = await setup_connection.fetchval(
                            "SELECT revision FROM campaign_execution_budgets "
                            "WHERE campaign_id=$1 AND budget_kind='noise'",
                            _uuid(201),
                        )
                        intent = replace(intent, noise_actual=MAX_I53)
                    if target in {"budget", "logical"}:
                        await _postgres_p1c_assert_terminal_rollback(
                            setup_connection,
                            store,
                            intent,
                            expected_result=FixedResult.INVARIANT_FAILURE,
                        )
                    else:
                        applied = await store.commit_terminal_attempt_v3(intent)
                        budget = await setup_connection.fetchrow(
                            "SELECT capacity_units,reserved_units,consumed_units,revision "
                            "FROM campaign_execution_budgets "
                            "WHERE campaign_id=$1 AND budget_kind='noise'",
                            _uuid(201),
                        )
                        ledger = await setup_connection.fetchrow(
                            "SELECT reservation_units,consumed_units,disposition "
                            "FROM campaign_execution_budget_ledger "
                            "WHERE attempt_id=$1 AND budget_kind='noise'",
                            _uuid(210),
                        )
                        assert applied.result is FixedResult.APPLIED
                        assert tuple(budget[:3]) == (MAX_I53, 0, MAX_I53)
                        assert budget["revision"] == budget_revision + 1
                        assert tuple(ledger) == (MAX_I53, MAX_I53, "consumed")
                finally:
                    if setup_connection is not None:
                        await database._pool.release(setup_connection)
                    await database.close()
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
    async with _cloned_postgres_harness(postgres_lifecycle_template) as harness:
        database = PostgresDatabase(_migration_url(harness.config, harness.database_name))
        await database.connect()
        setup_connection = None
        try:
            base_store, _adapter, setup_connection, revision = await _postgres_p1c_terminal_case(
                database, predecessor=predecessor
            )
            store: ExecutionLifecycleStore = base_store
            intent = _postgres_p1c_terminal_intent(revision)

            if case_alias == "invalid-contract-before-receipt":
                trace = _PostgresP1CTerminalTraceStore(database._pool)
                output = OutputObservation(_uuid(20_610), OutputKind.HOST, _uuid(260))
                duplicate_link = OutputObservation(
                    output.link_id,
                    OutputKind.HOST,
                    _uuid(20_611),
                )
                duplicate_target = OutputObservation(
                    _uuid(20_612),
                    OutputKind.HOST,
                    output.target_id,
                )
                too_many_outputs = tuple(
                    OutputObservation(
                        _uuid(21_000 + index),
                        OutputKind.HOST,
                        _uuid(22_000 + index),
                    )
                    for index in range(257)
                )
                invalids = (
                    replace(intent, expected_attempt_revision=MAX_I53),
                    replace(intent, expected_attempt_revision=True),
                    replace(intent, expected_attempt_revision=-1),
                    replace(intent, expected_attempt_revision=MAX_I53 + 1),
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
                        execution_result_digest=_POSTGRES_P1C_TERMINAL_RESULT_DIGEST.upper(),
                    ),
                    replace(intent, execution_result_digest="a" * 63),
                    replace(intent, outputs=(output, output)),
                    replace(intent, outputs=(output, duplicate_link)),
                    replace(intent, outputs=(output, duplicate_target)),
                    replace(intent, outputs=[output]),  # type: ignore[arg-type]
                    replace(intent, outputs=too_many_outputs),
                    replace(
                        intent,
                        outcome_code=OutcomeCode.CONFIRMED_FAILURE,
                        outputs=(output,),
                    ),
                )
                before = await _postgres_p1c_terminal_snapshot(setup_connection)
                results = tuple([await trace.commit_terminal_attempt_v3(item) for item in invalids])
                assert all(item.result is FixedResult.INVALID_CONTRACT for item in results)
                assert trace.transaction_entries == 0, "invalid intent entered a transaction"
                assert await _postgres_p1c_terminal_snapshot(setup_connection) == before
            elif case_alias == "receipt-replay-after-target-deletion":
                applied = await store.commit_terminal_attempt_v3(intent)
                receipt_before = await _postgres_p1c_terminal_receipt(setup_connection)
                deleted = await database.delete_campaign_lifecycle(
                    _uuid(201), lifecycle_operation_id=_uuid(20_303)
                )
                absence = await setup_connection.fetchrow(
                    "SELECT "
                    "(SELECT COUNT(*) FROM campaigns WHERE id=$1),"
                    "(SELECT COUNT(*) FROM logical_executions WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM execution_attempts WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM campaign_execution_budgets WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM campaign_execution_budget_ledger WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM execution_output_links WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM execution_publication_outbox WHERE campaign_id=$1),"
                    "(SELECT COUNT(*) FROM campaign_execution_authority_revisions "
                    "WHERE campaign_id=$1)",
                    _uuid(201),
                )
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    receipt_only=True,
                )
                replayed = await trace.commit_terminal_attempt_v3(intent)
                receipt_after = await _postgres_p1c_terminal_receipt(setup_connection)
                assert deleted.result is FixedResult.APPLIED
                assert (applied.result, replayed.result, replayed.revision) == (
                    FixedResult.APPLIED,
                    FixedResult.REPLAYED,
                    revision + 1,
                )
                assert tuple(absence) == (0, 0, 0, 0, 0, 0, 0, 0), (
                    "terminal replay retained a mutable lifecycle target"
                )
                assert tuple(receipt_before) == tuple(receipt_after), (
                    "terminal replay receipt changed after mutable-target deletion"
                )
                assert trace.transaction_entries == 1
            elif case_alias == "receipt-replay-zero-mutable-reads":
                applied = await store.commit_terminal_attempt_v3(intent)
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    receipt_only=True,
                )
                replayed = await trace.commit_terminal_attempt_v3(intent)
                assert (applied.result, replayed.result) == (
                    FixedResult.APPLIED,
                    FixedResult.REPLAYED,
                )
                assert trace.transaction_entries == 1
            elif case_alias == "changed-intent-conflict-operation":
                applied = await store.commit_terminal_attempt_v3(intent)
                receipt_only = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    receipt_only=True,
                )
                usage_changed = await receipt_only.commit_terminal_attempt_v3(
                    replace(intent, noise_actual=0)
                )
                output_changed = await receipt_only.commit_terminal_attempt_v3(
                    replace(
                        intent,
                        outputs=(
                            OutputObservation(
                                _uuid(20_613),
                                OutputKind.HOST,
                                _uuid(260),
                            ),
                        ),
                    )
                )
                assert (applied.result, usage_changed.result, output_changed.result) == (
                    FixedResult.APPLIED,
                    FixedResult.CONFLICT_OPERATION,
                    FixedResult.CONFLICT_OPERATION,
                )
                assert receipt_only.transaction_entries == 2
            elif case_alias in {
                "known-success-atomic",
                "known-failure-atomic",
                "acknowledged-cancellation-atomic",
                "acknowledged-timeout-atomic",
            }:
                outcome, state, proof, event_code = {
                    "known-success-atomic": (
                        OutcomeCode.CONFIRMED_SUCCESS,
                        AttemptState.SUCCEEDED,
                        "local_completion",
                        "execution_succeeded",
                    ),
                    "known-failure-atomic": (
                        OutcomeCode.CONFIRMED_FAILURE,
                        AttemptState.FAILED,
                        "local_completion",
                        "execution_failed",
                    ),
                    "acknowledged-cancellation-atomic": (
                        OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
                        AttemptState.CANCELLED,
                        "cancellation_no_result_ack",
                        "execution_cancelled",
                    ),
                    "acknowledged-timeout-atomic": (
                        OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
                        AttemptState.TIMED_OUT,
                        "timeout_termination_ack",
                        "execution_timed_out",
                    ),
                }[case_alias]
                intent = _postgres_p1c_terminal_intent(revision, outcome=outcome)
                result = await store.commit_terminal_attempt_v3(intent)
                operation_id = _postgres_p1c_terminal_operation_id(intent.attempt_id)
                outbox_id = _postgres_p1c_terminal_derived_uuid(
                    operation_id,
                    "terminal-outbox",
                )
                publication_key = _postgres_p1c_terminal_derived_uuid(
                    operation_id,
                    "terminal-publication",
                )
                attempt = await _postgres_p1c_terminal_state(setup_connection)
                logical = await setup_connection.fetchrow(
                    "SELECT closure_operation_id,closing_attempt_id,revision "
                    "FROM logical_executions WHERE id=$1",
                    _uuid(208),
                )
                receipt = await _postgres_p1c_terminal_receipt(setup_connection)
                outbox = await setup_connection.fetchrow(
                    "SELECT id,publication_key,attempt_id,campaign_id,event_code,"
                    "is_attempt_terminal,finding_count,credential_count,host_count,"
                    "artifact_count,latest_operation_id,latest_operation_code,"
                    "latest_operation_base_revision "
                    "FROM execution_publication_outbox WHERE attempt_id=$1",
                    _uuid(210),
                )
                settled_ledgers = await setup_connection.fetchval(
                    "SELECT COUNT(*) FROM campaign_execution_budget_ledger "
                    "WHERE attempt_id=$1 AND disposition IN ('consumed','released') "
                    "AND budget_revision_settled IS NOT NULL",
                    _uuid(210),
                )
                assert (result.result, result.revision) == (
                    FixedResult.APPLIED,
                    revision + 1,
                )
                assert tuple(attempt) == (
                    state.value,
                    revision + 1,
                    outcome.value,
                    "settled",
                    proof,
                    True,
                    True,
                    "closed_without_retry",
                    operation_id
                    if outcome in {OutcomeCode.CONFIRMED_SUCCESS, OutcomeCode.CONFIRMED_FAILURE}
                    else None,
                    operation_id if outcome is OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT else None,
                    operation_id if outcome is OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED else None,
                ), "known PostgreSQL terminal settlement changed"
                assert tuple(logical) == (operation_id, _uuid(210), 1), (
                    "known terminal outcome did not close its logical execution exactly"
                )
                assert tuple(receipt) == (
                    operation_id,
                    _postgres_p1c_terminal_operation_code(outcome),
                    _uuid(201),
                    _uuid(210),
                    _uuid(208),
                    "system",
                    SYSTEM_PRINCIPAL_SUBJECT_REF,
                    None,
                    False,
                    None,
                    2,
                    _postgres_p1c_terminal_request_digest(intent),
                    FixedResult.APPLIED.value,
                    FixedResult.REPLAYED.value,
                    _postgres_p1c_terminal_result_digest(intent),
                    _uuid(210),
                    revision + 1,
                    _uuid(208),
                    1,
                ), "known terminal receipt facts changed"
                assert tuple(outbox) == (
                    outbox_id,
                    publication_key,
                    _uuid(210),
                    _uuid(201),
                    event_code,
                    True,
                    0,
                    0,
                    0,
                    0,
                    publication_key,
                    "insert",
                    0,
                ), "known terminal outcome emitted the wrong publication"
                assert int(settled_ledgers) == 3, (
                    "known PostgreSQL terminal budget settlement was incomplete"
                )
            elif case_alias == "uncertain-outcome-invalid-contract":
                uncertain = replace(
                    intent,
                    outcome_code=OutcomeCode.UNKNOWN_AFTER_RECOVERY,
                    execution_result_digest=None,
                )
                trace = _PostgresP1CTerminalTraceStore(database._pool)
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    uncertain,
                    expected_result=FixedResult.INVALID_CONTRACT,
                )
                assert trace.transaction_entries == 0, (
                    "uncertain outcome reached receipt or mutable storage"
                )
            elif case_alias == "single-transaction-zero-nested-acquire":
                pool_probe = _PostgresP1CTerminalPoolProbe(database._pool)
                trace = _PostgresP1CTerminalTraceStore(pool_probe)
                applied = await trace.commit_terminal_attempt_v3(intent)
                assert applied.result is FixedResult.APPLIED
                assert trace.transaction_entries == 1
                assert (pool_probe.acquire_count, pool_probe.release_count) == (1, 1)
                assert len(pool_probe.connection_identities) == 1
                assert trace.connection_identities == pool_probe.connection_identities
                assert trace.read_events[0] == "receipt", (
                    "terminal apply read mutable state before receipt classification"
                )
            elif case_alias == "derive-exact-three-held-ledgers":
                applied = await store.commit_terminal_attempt_v3(intent)
                ledgers = await setup_connection.fetch(
                    "SELECT budget_kind,disposition,consumed_units "
                    "FROM campaign_execution_budget_ledger WHERE attempt_id=$1 "
                    "ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                    "WHEN 'exfiltration' THEN 2 ELSE 3 END",
                    _uuid(210),
                )
                assert applied.result is FixedResult.APPLIED
                assert tuple(tuple(row) for row in ledgers) == (
                    ("noise", "consumed", 1),
                    ("exfiltration", "consumed", 2),
                    ("concurrency", "released", 0),
                )
            elif case_alias == "missing-ledger-inconsistent-set-rollback":
                await setup_connection.execute(
                    "DELETE FROM campaign_execution_budget_ledger "
                    "WHERE attempt_id=$1 AND budget_kind='noise'",
                    _uuid(210),
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    store,
                    intent,
                    expected_result=FixedResult.INCONSISTENT_BUDGET_SET,
                )
            elif case_alias in {
                "duplicate-extra-ledger-inconsistent-set-rollback",
                "wrong-kind-ledger-inconsistent-set-rollback",
                "wrong-campaign-attempt-ledger-inconsistent-set-rollback",
                "non-held-ledger-conflict-operation-rollback",
            }:
                mutations, expected = {
                    "duplicate-extra-ledger-inconsistent-set-rollback": (
                        ("duplicate",),
                        FixedResult.INCONSISTENT_BUDGET_SET,
                    ),
                    "wrong-kind-ledger-inconsistent-set-rollback": (
                        ("wrong-kind",),
                        FixedResult.INCONSISTENT_BUDGET_SET,
                    ),
                    "wrong-campaign-attempt-ledger-inconsistent-set-rollback": (
                        ("wrong-campaign", "wrong-attempt"),
                        FixedResult.INCONSISTENT_BUDGET_SET,
                    ),
                    "non-held-ledger-conflict-operation-rollback": (
                        ("non-held",),
                        FixedResult.CONFLICT_OPERATION,
                    ),
                }[case_alias]
                for mutation in mutations:
                    trace = _PostgresP1CTerminalTraceStore(
                        database._pool,
                        ledger_mutation=mutation,
                    )
                    await _postgres_p1c_assert_terminal_rollback(
                        setup_connection,
                        trace,
                        intent,
                        expected_result=expected,
                    )
            elif case_alias == "current-budget-lock-no-toctou":
                for index, kind in enumerate(("noise", "exfiltration", "concurrency")):
                    await setup_connection.execute(
                        "UPDATE campaign_execution_budgets SET revision=2,"
                        "latest_operation_id=$1,latest_operation_base_revision=1,"
                        "latest_operation_code='configure' "
                        "WHERE campaign_id=$2 AND budget_kind=$3",
                        _uuid(20_310 + index),
                        _uuid(201),
                        kind,
                    )
                expected_budget_ids = tuple(
                    str(row["budget_id"])
                    for row in await setup_connection.fetch(
                        "SELECT budget_id FROM campaign_execution_budget_ledger "
                        "WHERE attempt_id=$1 ORDER BY CASE budget_kind "
                        "WHEN 'noise' THEN 1 WHEN 'exfiltration' THEN 2 ELSE 3 END",
                        _uuid(210),
                    )
                )
                trace = _PostgresP1CTerminalTraceStore(database._pool)
                applied = await trace.commit_terminal_attempt_v3(intent)
                revisions = await setup_connection.fetch(
                    "SELECT revision FROM campaign_execution_budgets WHERE campaign_id=$1 "
                    "ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                    "WHEN 'exfiltration' THEN 2 ELSE 3 END",
                    _uuid(201),
                )
                assert applied.result is FixedResult.APPLIED
                assert tuple(trace.budget_lock_ids) == expected_budget_ids
                assert tuple(trace.lock_events) == (
                    ("attempt", _uuid(210)),
                    ("ledgers", _uuid(210)),
                    *(("budget", budget_id) for budget_id in expected_budget_ids),
                    ("logical", _uuid(208)),
                ), "PostgreSQL terminal row-lock order or cardinality changed"
                assert tuple(int(row["revision"]) for row in revisions) == (3, 3, 3)
            elif case_alias == "budget-capacity-inconsistent-set-rollback":
                await setup_connection.execute(
                    "UPDATE campaign_execution_budgets SET reserved_units=0 "
                    "WHERE campaign_id=$1 AND budget_kind='noise'",
                    _uuid(201),
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
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
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    fail_at=fail_at,
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    intent,
                    expected_exception=RuntimeError,
                )
            elif case_alias == "non-running-attempt-conflict-state":
                result = await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    store,
                    replace(intent, expected_attempt_revision=revision + 1),
                    expected_result=FixedResult.CONFLICT_STATE,
                )
                assert result is not None
                assert result.revision == revision, (
                    "attempt-state precedence did not dominate stale revision"
                )
            elif case_alias == "stale-attempt-revision-conflict":
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    store,
                    replace(intent, expected_attempt_revision=revision - 1),
                    expected_result=FixedResult.CONFLICT_REVISION,
                )
            elif case_alias == "invariant-failure-rollback":
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    duplicate_terminal_returning=True,
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    intent,
                    expected_result=FixedResult.INVARIANT_FAILURE,
                )
            elif case_alias == "cancellation-rollback-and-reuse":
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    cancel_at="output",
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    intent,
                    expected_exception=asyncio.CancelledError,
                )
                reused = await base_store.commit_terminal_attempt_v3(intent)
                assert reused.result is FixedResult.APPLIED
            elif case_alias == "exception-rollback-and-reuse":
                trace = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    fail_at="exception",
                )
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    intent,
                    expected_exception=RuntimeError,
                )
                reused = await base_store.commit_terminal_attempt_v3(intent)
                assert reused.result is FixedResult.APPLIED
            elif case_alias == "legacy-terminal-apply-replay-bytes-unchanged":
                operation_id = _uuid(20_400)
                legacy = _postgres_p1c_legacy_terminal_request(operation_id, revision)
                applied = await store.commit_terminal_attempt(legacy)
                receipt_snapshot_before = await _postgres_p1c_terminal_receipt_snapshot(
                    setup_connection
                )
                receipt_before = await setup_connection.fetchrow(
                    "SELECT * FROM execution_operation_receipts WHERE operation_id=$1",
                    operation_id,
                )
                protected_vectors = await setup_connection.fetch(
                    "SELECT operation_id,operation_code,binding_contract_version,"
                    "request_binding_digest,result_binding_digest "
                    "FROM execution_operation_receipts WHERE operation_id=ANY($1::text[]) "
                    "ORDER BY operation_id",
                    [_uuid(20_200), _uuid(20_202), operation_id],
                )
                replayed = await store.commit_terminal_attempt(legacy)
                receipt_snapshot_after = await _postgres_p1c_terminal_receipt_snapshot(
                    setup_connection
                )
                receipt_after = await setup_connection.fetchrow(
                    "SELECT * FROM execution_operation_receipts WHERE operation_id=$1",
                    operation_id,
                )
                assert (applied.result, replayed.result) == (
                    FixedResult.APPLIED,
                    FixedResult.REPLAYED,
                )
                assert receipt_snapshot_after == receipt_snapshot_before, (
                    "legacy replay changed a top or subordinate receipt"
                )
                assert tuple(receipt_before) == tuple(receipt_after)
                assert receipt_before["operation_code"] == "terminal_succeeded"
                assert receipt_before["binding_contract_version"] == 2
                assert (
                    receipt_before["request_binding_digest"]
                    == _POSTGRES_P1C_LEGACY_TERMINAL_REQUEST_DIGEST
                ), "legacy terminal request binding bytes drifted"
                assert (
                    receipt_before["result_binding_digest"]
                    == _POSTGRES_P1C_LEGACY_TERMINAL_RESULT_DIGEST
                ), "legacy terminal result binding bytes drifted"
                assert {str(row["operation_id"]): tuple(row)[1:] for row in protected_vectors} == {
                    _uuid(20_200): (
                        "outbox_insert",
                        2,
                        _POSTGRES_P1C_LEGACY_OUTBOX_REQUEST_DIGEST,
                        _POSTGRES_P1C_LEGACY_OUTBOX_RESULT_DIGEST,
                    ),
                    _uuid(20_202): (
                        "budget_settle",
                        2,
                        _POSTGRES_P1C_LEGACY_BUDGET_REQUEST_DIGEST,
                        _POSTGRES_P1C_LEGACY_BUDGET_RESULT_DIGEST,
                    ),
                    operation_id: (
                        "terminal_succeeded",
                        2,
                        _POSTGRES_P1C_LEGACY_TERMINAL_REQUEST_DIGEST,
                        _POSTGRES_P1C_LEGACY_TERMINAL_RESULT_DIGEST,
                    ),
                }, "legacy top/budget/outbox receipt vectors drifted"
            elif case_alias == "changed-outcome-conflict-operation":
                applied = await store.commit_terminal_attempt_v3(intent)
                receipt_only = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    receipt_only=True,
                )
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
                receipt_only = _PostgresP1CTerminalTraceStore(
                    database._pool,
                    receipt_only=True,
                )
                changed = await receipt_only.commit_terminal_attempt_v3(
                    replace(
                        intent,
                        execution_result_digest=hashlib.sha256(b"changed-result").hexdigest(),
                    )
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
                invalid = _postgres_p1c_terminal_intent(
                    revision,
                    outcome=outcome,
                    execution_result_digest=_POSTGRES_P1C_TERMINAL_RESULT_DIGEST,
                )
                trace = _PostgresP1CTerminalTraceStore(database._pool)
                await _postgres_p1c_assert_terminal_rollback(
                    setup_connection,
                    trace,
                    invalid,
                    expected_result=FixedResult.INVALID_CONTRACT,
                )
                assert trace.transaction_entries == 0, (
                    "non-result outcome reached receipt or mutable storage"
                )
            elif case_alias == "canonical-output-order-exact-replay":
                await setup_connection.execute(
                    "INSERT INTO hosts(id,campaign_id,ip_address) VALUES($1,$2,$3)",
                    _uuid(20_500),
                    _uuid(201),
                    "192.0.2.2",
                )
                await setup_connection.execute(
                    "INSERT INTO loot(id,campaign_id,host_id,loot_type,name) "
                    "VALUES($1,$2,$3,$4,$5)",
                    _uuid(20_503),
                    _uuid(201),
                    _uuid(260),
                    "artifact",
                    "fixed-output",
                )
                outputs = (
                    OutputObservation(_uuid(20_502), OutputKind.HOST, _uuid(20_500)),
                    OutputObservation(_uuid(20_503), OutputKind.ARTIFACT, _uuid(20_503)),
                    OutputObservation(_uuid(20_501), OutputKind.HOST, _uuid(260)),
                )
                forward = replace(intent, outputs=outputs)
                reversed_intent = replace(intent, outputs=tuple(reversed(outputs)))
                trace = _PostgresP1CTerminalTraceStore(database._pool)
                applied = await trace.commit_terminal_attempt_v3(forward)
                replayed = await trace.commit_terminal_attempt_v3(reversed_intent)
                rows = await setup_connection.fetch(
                    "SELECT id,host_id,loot_id FROM execution_output_links "
                    "WHERE attempt_id=$1 ORDER BY "
                    "CASE WHEN loot_id IS NOT NULL THEN 0 ELSE 1 END,host_id,id",
                    _uuid(210),
                )
                assert (applied.result, replayed.result) == (
                    FixedResult.APPLIED,
                    FixedResult.REPLAYED,
                )
                assert _postgres_p1c_terminal_request_digest(
                    forward
                ) == _postgres_p1c_terminal_request_digest(reversed_intent)
                assert tuple(trace.output_insert_order) == (
                    _uuid(20_503),
                    _uuid(20_501),
                    _uuid(20_502),
                ), "PostgreSQL output persistence did not use canonical semantic order"
                assert tuple(tuple(row) for row in rows) == (
                    (_uuid(20_503), None, _uuid(20_503)),
                    (_uuid(20_501), _uuid(260), None),
                    (_uuid(20_502), _uuid(20_500), None),
                )
            elif case_alias == "terminal-operation-and-system-principal-namespace":
                applied = await store.commit_terminal_attempt_v3(intent)
                receipt = await _postgres_p1c_terminal_receipt(setup_connection)
                actor = await setup_connection.fetchrow(
                    "SELECT actor_subject_ref,actor_user_id FROM execution_attempts WHERE id=$1",
                    _uuid(210),
                )
                assert applied.result is FixedResult.APPLIED
                assert tuple(receipt[:11]) == (
                    _postgres_p1c_terminal_operation_id(_uuid(210)),
                    "terminal_succeeded",
                    _uuid(201),
                    _uuid(210),
                    _uuid(208),
                    "system",
                    SYSTEM_PRINCIPAL_SUBJECT_REF,
                    None,
                    False,
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
                )
            else:  # pragma: no cover - tuple/dispatcher drift must be loud.
                raise AssertionError(f"unhandled PostgreSQL terminal alias: {case_alias}")
        finally:
            if setup_connection is not None:
                await database._pool.release(setup_connection)
            await database.close()
