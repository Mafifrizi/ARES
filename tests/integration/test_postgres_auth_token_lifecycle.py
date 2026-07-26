"""Real PostgreSQL contracts for authentication-token lifecycle behavior."""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock
from urllib.parse import quote
from uuid import uuid4

import pytest

from ares.db import postgres as postgres_module
from ares.db.postgres import (
    PostgresDatabase,
    _acquire_refresh_token_user_lock,
    _refresh_token_user_lock_key,
)

_POSTGRES_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_SAFE_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]+$")


@dataclass(frozen=True)
class _PostgresHarness:
    database: PostgresDatabase
    dsn: str


def _postgres_test_config() -> dict[str, str | int]:
    values = {name: os.environ.get(name) for name in _POSTGRES_ENV}
    configured = [name for name, value in values.items() if value]
    if not configured:
        pytest.skip("real PostgreSQL test environment is not configured")

    missing = [name for name, value in values.items() if not value]
    if missing:
        pytest.fail(
            "Incomplete PostgreSQL test environment; missing: " + ", ".join(missing)
        )

    try:
        port = int(values["ARES_TEST_POSTGRES_PORT"] or "")
    except ValueError:
        pytest.fail("ARES_TEST_POSTGRES_PORT must be an integer")
    if not 1 <= port <= 65535:
        pytest.fail("ARES_TEST_POSTGRES_PORT must be between 1 and 65535")

    return {
        "host": values["ARES_TEST_POSTGRES_HOST"] or "",
        "port": port,
        "user": values["ARES_TEST_POSTGRES_USER"] or "",
        "database": values["ARES_TEST_POSTGRES_DB"] or "",
    }


def _runtime_dsn(config: dict[str, str | int], database: str) -> str:
    host = str(config["host"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return (
        "postgresql://"
        f"{quote(str(config['user']), safe='')}@"
        f"{host}:{config['port']}/"
        f"{quote(database, safe='')}"
    )


def _sanitized_setup_failure(action: str, exc: Exception) -> RuntimeError:
    return RuntimeError(
        f"PostgreSQL token-test setup failed [{action}: {type(exc).__name__}]"
    )


async def _attempt_cleanup(
    action: str,
    cleanup: Callable[[], Awaitable[object]],
    failures: list[str],
) -> None:
    try:
        await cleanup()
    except Exception as exc:
        failures.append(f"{action}: {type(exc).__name__}")


@asynccontextmanager
async def _postgres_harness() -> AsyncIterator[_PostgresHarness]:
    config = _postgres_test_config()
    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg must be installed when the PostgreSQL test environment is configured"
        )

    from ares.core.logger import setup_logger

    setup_logger(level="WARNING")
    test_database = f"ares_token_{uuid4().hex}"
    assert _SAFE_DATABASE_NAME.fullmatch(test_database)
    if test_database == config["database"]:
        pytest.fail("Generated PostgreSQL test database name collision")

    admin = None
    database = None
    creation_attempted = False
    cleanup_failures: list[str] = []
    try:
        try:
            admin = await asyncpg.connect(
                host=config["host"],
                port=config["port"],
                user=config["user"],
                database=config["database"],
            )
        except Exception as exc:
            raise _sanitized_setup_failure("admin-connect", exc) from None

        creation_attempted = True
        try:
            await admin.execute(f'CREATE DATABASE "{test_database}"')
        except Exception as exc:
            raise _sanitized_setup_failure("database-create", exc) from None

        dsn = _runtime_dsn(config, test_database)
        database = PostgresDatabase(dsn, pool_min=1, pool_max=12)
        try:
            await database.connect()
        except Exception as exc:
            raise _sanitized_setup_failure("runtime-initialize", exc) from None

        yield _PostgresHarness(database=database, dsn=dsn)
    finally:
        primary_failure = sys.exception()

        if database is not None:
            await _attempt_cleanup(
                "close-runtime-pool", database.close, cleanup_failures
            )

        if creation_attempted and admin is not None:

            async def _drop_test_database() -> None:
                await admin.execute(
                    f'DROP DATABASE IF EXISTS "{test_database}" WITH (FORCE)'
                )

            await _attempt_cleanup(
                "drop-test-database", _drop_test_database, cleanup_failures
            )

        if admin is not None:
            await _attempt_cleanup(
                "close-admin-connection", admin.close, cleanup_failures
            )

        if cleanup_failures:
            if primary_failure is not None:
                for failure in cleanup_failures:
                    primary_failure.add_note(
                        f"PostgreSQL token-test cleanup failure [{failure}]"
                    )
            else:
                raise RuntimeError(
                    "PostgreSQL token-test cleanup failed: "
                    + "; ".join(cleanup_failures)
                ) from None


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


async def _insert_user(database: PostgresDatabase) -> str:
    user_id = f"token-user-{uuid4().hex}"
    async with database._pool.acquire() as connection:
        await connection.execute(
            """
            INSERT INTO users(id, username, hashed_password, role, created_by)
            VALUES($1, $2, $3, $4, $5)
            """,
            user_id,
            f"token_{uuid4().hex}",
            "not-used-by-token-tests",
            "operator",
            "postgres-token-test",
        )
    return user_id


async def _active_refresh_count(
    database: PostgresDatabase,
    user_id: str,
) -> int:
    async with database._pool.acquire() as connection:
        return int(
            await connection.fetchval(
                """
                SELECT COUNT(*)
                FROM refresh_tokens
                WHERE user_id=$1 AND is_revoked=0 AND expires_at > now()
                """,
                user_id,
            )
        )


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


class _TransactionExitBarrier:
    def __init__(
        self,
        transaction: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
    ) -> None:
        self._transaction = transaction
        self._exit_reached = exit_reached
        self._release_exit = release_exit

    async def __aenter__(self) -> Any:
        return await self._transaction.__aenter__()

    async def __aexit__(self, *exc_info: object) -> bool | None:
        self._exit_reached.set()
        try:
            await asyncio.wait_for(self._release_exit.wait(), timeout=10)
        except TimeoutError:
            pytest.fail("transaction-exit barrier was not released", pytrace=False)
        return await self._transaction.__aexit__(*exc_info)


class _BarrierConnection:
    def __init__(
        self,
        connection: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
    ) -> None:
        self._connection = connection
        self._exit_reached = exit_reached
        self._release_exit = release_exit

    def transaction(self, *args: object, **kwargs: object) -> _TransactionExitBarrier:
        return _TransactionExitBarrier(
            self._connection.transaction(*args, **kwargs),
            self._exit_reached,
            self._release_exit,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _BarrierAcquireContext:
    def __init__(
        self,
        acquire_context: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
    ) -> None:
        self._acquire_context = acquire_context
        self._exit_reached = exit_reached
        self._release_exit = release_exit

    async def __aenter__(self) -> _BarrierConnection:
        connection = await self._acquire_context.__aenter__()
        return _BarrierConnection(
            connection,
            self._exit_reached,
            self._release_exit,
        )

    async def __aexit__(self, *exc_info: object) -> bool | None:
        return await self._acquire_context.__aexit__(*exc_info)


class _BarrierPool:
    def __init__(
        self,
        pool: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
    ) -> None:
        self._pool = pool
        self._exit_reached = exit_reached
        self._release_exit = release_exit

    def acquire(self, *args: object, **kwargs: object) -> _BarrierAcquireContext:
        return _BarrierAcquireContext(
            self._pool.acquire(*args, **kwargs),
            self._exit_reached,
            self._release_exit,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool, name)


async def _wait_for_blocked_backend_sessions(
    database: PostgresDatabase,
    holder_pid: int,
    operations: list[asyncio.Task[Any]],
    minimum_waiters: int,
) -> None:
    deadline = time.monotonic() + 10
    try:
        async with asyncio.timeout(10):
            async with database._pool.acquire() as observer:
                while time.monotonic() < deadline:
                    if any(operation.done() for operation in operations):
                        pytest.fail(
                            "concurrent rotation bypassed the held advisory lock",
                            pytrace=False,
                        )
                    waiter_count = int(
                        await observer.fetchval(
                            """
                            SELECT COUNT(DISTINCT activity.pid)
                            FROM pg_stat_activity AS activity
                            JOIN pg_locks AS waiting
                              ON waiting.pid=activity.pid
                             AND waiting.locktype='advisory'
                             AND waiting.granted=false
                            JOIN pg_locks AS holding
                              ON holding.pid=$1::INTEGER
                             AND holding.locktype='advisory'
                             AND holding.granted=true
                             AND holding.classid=waiting.classid
                             AND holding.objid=waiting.objid
                             AND holding.objsubid=waiting.objsubid
                             AND holding.database IS NOT DISTINCT FROM waiting.database
                            WHERE activity.datname=current_database()
                              AND $1::INTEGER = ANY(pg_blocking_pids(activity.pid))
                            """,
                            holder_pid,
                        )
                        or 0
                    )
                    if waiter_count >= minimum_waiters:
                        return
                    await asyncio.sleep(0.01)
    except TimeoutError:
        pytest.fail(
            "distinct PostgreSQL backend sessions did not overlap on the advisory lock",
            pytrace=False,
        )
    pytest.fail(
        "distinct PostgreSQL backend sessions did not overlap on the advisory lock",
        pytrace=False,
    )


async def _wait_for_advisory_wait(
    database: PostgresDatabase,
    operation: asyncio.Task[Any],
) -> None:
    try:
        async with asyncio.timeout(10):
            async with database._pool.acquire() as monitor:
                while True:
                    if operation.done():
                        pytest.fail(
                            "refresh-token writer bypassed the per-user advisory lock",
                            pytrace=False,
                        )
                    waiting = await monitor.fetchval(
                        """
                        SELECT EXISTS(
                            SELECT 1
                            FROM pg_stat_activity
                            WHERE datname=current_database()
                              AND pid <> pg_backend_pid()
                              AND wait_event_type='Lock'
                              AND wait_event='advisory'
                              AND query ILIKE 'SELECT pg_advisory_xact_lock%'
                        )
                        """
                    )
                    if waiting:
                        return
                    await asyncio.sleep(0)
    except TimeoutError:
        pytest.fail(
            "refresh-token writer did not reach the held advisory lock",
            pytrace=False,
        )


async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
    if task is None:
        return
    if not task.done():
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def _run_with_leader_paused_after_lock(
    monkeypatch: pytest.MonkeyPatch,
    database: PostgresDatabase,
    leader_name: str,
    leader_factory: Callable[[], Coroutine[Any, Any, Any]],
    follower_factory: Callable[[], Coroutine[Any, Any, Any]],
) -> tuple[Any, Any]:
    original_lock = _acquire_refresh_token_user_lock
    leader_has_lock = asyncio.Event()
    release_leader = asyncio.Event()

    async def _gated_lock(connection: Any, user_id: str) -> None:
        await original_lock(connection, user_id)
        task = asyncio.current_task()
        if task is not None and task.get_name() == leader_name:
            leader_has_lock.set()
            try:
                await asyncio.wait_for(release_leader.wait(), timeout=10)
            except TimeoutError:
                pytest.fail(
                    "ordered refresh writer barrier was not released",
                    pytrace=False,
                )

    leader: asyncio.Task[Any] | None = None
    follower: asyncio.Task[Any] | None = None
    with monkeypatch.context() as patch:
        patch.setattr(
            postgres_module,
            "_acquire_refresh_token_user_lock",
            _gated_lock,
        )
        try:
            leader = asyncio.create_task(leader_factory(), name=leader_name)
            try:
                await asyncio.wait_for(leader_has_lock.wait(), timeout=10)
            except TimeoutError:
                pytest.fail(
                    "ordered refresh writer did not acquire its advisory lock",
                    pytrace=False,
                )
            follower = asyncio.create_task(follower_factory())
            await _wait_for_advisory_wait(database, follower)
            release_leader.set()
            try:
                return await asyncio.wait_for(
                    asyncio.gather(leader, follower),
                    timeout=10,
                )
            except TimeoutError:
                pytest.fail(
                    "ordered refresh writers did not finish after lock release",
                    pytrace=False,
                )
        finally:
            release_leader.set()
            await _cancel_task(leader)
            await _cancel_task(follower)


@pytest.mark.asyncio
async def test_postgres_api_key_expiry_contract() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)

        null_id, null_key = await database.create_api_key(
            user_id, "non-expiring", expires_days=None
        )
        null_verification = await database.verify_api_key(null_key)
        _require_fixed(
            null_verification is not None,
            "non-expiring API key verification failed",
        )

        future_id, future_key = await database.create_api_key(
            user_id, "future", expires_days=1
        )
        future_verification = await database.verify_api_key(future_key)
        _require_fixed(
            future_verification is not None,
            "future API key verification failed",
        )

        exact_id, exact_key = await database.create_api_key(
            user_id, "exact", expires_days=1
        )
        past_id, past_key = await database.create_api_key(
            user_id, "past", expires_days=1
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET expires_at=now() WHERE id=$1",
                exact_id,
            )
            await connection.execute(
                "UPDATE api_keys SET expires_at=now() - interval '1 second' WHERE id=$1",
                past_id,
            )
            stored = await connection.fetch(
                "SELECT id, expires_at FROM api_keys WHERE id=ANY($1::text[])",
                [null_id, future_id],
            )

        assert {row["id"] for row in stored} == {null_id, future_id}
        assert next(row for row in stored if row["id"] == null_id)["expires_at"] is None
        future_expiry = next(
            row for row in stored if row["id"] == future_id
        )["expires_at"]
        assert isinstance(future_expiry, datetime)
        assert future_expiry.tzinfo is not None
        exact_verification = await database.verify_api_key(exact_key)
        _require_fixed(
            exact_verification is None,
            "exact-now API key verification unexpectedly succeeded",
        )
        past_verification = await database.verify_api_key(past_key)
        _require_fixed(
            past_verification is None,
            "expired API key verification unexpectedly succeeded",
        )


@pytest.mark.asyncio
async def test_postgres_refresh_expiry_contract() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        future_raw = await database.create_refresh_token(user_id)
        exact_raw = await database.create_refresh_token(user_id)
        past_raw = await database.create_refresh_token(user_id)

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE refresh_tokens SET expires_at=now() WHERE id=$1",
                _token_hash(exact_raw),
            )
            await connection.execute(
                """
                UPDATE refresh_tokens
                SET expires_at=now() - interval '1 second'
                WHERE id=$1
                """,
                _token_hash(past_raw),
            )

        _require_fixed(
            await database.rotate_refresh_token(exact_raw) == (None, None),
            "exact-now refresh token unexpectedly rotated",
        )
        _require_fixed(
            await database.rotate_refresh_token(past_raw) == (None, None),
            "expired refresh token unexpectedly rotated",
        )
        async with database._pool.acquire() as connection:
            assert (
                await connection.fetchval("SELECT COUNT(*) FROM refresh_tokens")
                == 3
            )

        user, successor = await database.rotate_refresh_token(future_raw)
        assert user is not None
        assert set(user) == {"id", "username", "role"}
        assert user["id"] == user_id
        assert successor is not None
        assert await _active_refresh_count(database, user_id) == 1


@pytest.mark.asyncio
async def test_postgres_access_token_timestamp_adapter_round_trip() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        naive_expiry = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).replace(microsecond=0)
        aware_expiry = naive_expiry.astimezone(
            timezone(timedelta(hours=5, minutes=30))
        )
        naive_jti = f"naive-{uuid4().hex}"
        aware_jti = f"aware-{uuid4().hex}"

        await database.revoke_access_token(
            naive_jti,
            user_id,
            naive_expiry.strftime("%Y-%m-%d %H:%M:%S"),
        )
        await database.revoke_access_token(
            aware_jti,
            user_id,
            aware_expiry.isoformat(),
        )

        async with database._pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT jti, expires_at
                FROM revoked_access_tokens
                WHERE jti=ANY($1::text[])
                """,
                [naive_jti, aware_jti],
            )
        assert {row["jti"] for row in rows} == {naive_jti, aware_jti}
        assert all(row["expires_at"] == naive_expiry for row in rows)


@pytest.mark.asyncio
async def test_postgres_refresh_purge_grace_boundaries() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        row_ids = {
            name: _token_hash(f"{name}-{uuid4().hex}")
            for name in ("revoked", "six-days", "eight-days", "future")
        }
        async with database._pool.acquire() as connection:
            await connection.executemany(
                """
                INSERT INTO refresh_tokens(id, user_id, is_revoked, expires_at)
                VALUES($1, $2, $3, $4)
                """,
                [
                    (
                        row_ids["revoked"],
                        user_id,
                        1,
                        datetime.now(timezone.utc) + timedelta(days=1),
                    ),
                    (
                        row_ids["six-days"],
                        user_id,
                        0,
                        datetime.now(timezone.utc) - timedelta(days=6),
                    ),
                    (
                        row_ids["eight-days"],
                        user_id,
                        0,
                        datetime.now(timezone.utc) - timedelta(days=8),
                    ),
                    (
                        row_ids["future"],
                        user_id,
                        0,
                        datetime.now(timezone.utc) + timedelta(days=1),
                    ),
                ],
            )

        assert await database.purge_expired_tokens() == 2
        async with database._pool.acquire() as connection:
            remaining = {
                row["id"]
                for row in await connection.fetch(
                    "SELECT id FROM refresh_tokens WHERE user_id=$1",
                    user_id,
                )
            }
        _require_fixed(
            remaining == {row_ids["six-days"], row_ids["future"]},
            "refresh-token purge retained or removed the wrong rows",
        )


@pytest.mark.asyncio
async def test_eight_concurrent_rotations_have_one_successor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        predecessor = await database.create_refresh_token(user_id)
        captured_logger = Mock()
        monkeypatch.setattr(postgres_module, "logger", captured_logger)
        operations: list[asyncio.Task[Any]] = []
        overlap_proven = False
        async with database._pool.acquire() as holder:
            holder_pid = int(await holder.fetchval("SELECT pg_backend_pid()"))
            async with holder.transaction():
                await holder.execute(
                    "SELECT pg_advisory_xact_lock($1::BIGINT)",
                    _refresh_token_user_lock_key(user_id),
                )
                operations = [
                    asyncio.create_task(database.rotate_refresh_token(predecessor))
                    for _ in range(8)
                ]
                try:
                    await _wait_for_blocked_backend_sessions(
                        database,
                        holder_pid,
                        operations,
                        minimum_waiters=3,
                    )
                    overlap_proven = True
                finally:
                    if not overlap_proven:
                        for operation in operations:
                            await _cancel_task(operation)

        try:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*operations),
                    timeout=10,
                )
            except TimeoutError:
                pytest.fail(
                    "concurrent rotations did not finish after lock release",
                    pytrace=False,
                )
        finally:
            for operation in operations:
                await _cancel_task(operation)

        winners = [result for result in results if result != (None, None)]
        losers = [result for result in results if result == (None, None)]
        _require_fixed(
            len(winners) == 1,
            "concurrent rotation did not produce exactly one winner",
        )
        _require_fixed(
            len(losers) == 7,
            "concurrent rotation did not produce exactly seven normal losers",
        )

        winner_user, successor = winners[0]
        assert winner_user is not None
        assert winner_user["id"] == user_id
        assert successor is not None
        successor_hash = _token_hash(successor)
        async with database._pool.acquire() as connection:
            predecessor_row = await connection.fetchrow(
                "SELECT is_revoked, used_at FROM refresh_tokens WHERE id=$1",
                _token_hash(predecessor),
            )
            active_ids = {
                row["id"]
                for row in await connection.fetch(
                    """
                    SELECT id FROM refresh_tokens
                    WHERE user_id=$1 AND is_revoked=0 AND expires_at > now()
                    """,
                    user_id,
                )
            }
        assert predecessor_row["is_revoked"] == 1
        assert predecessor_row["used_at"] is not None
        _require_fixed(
            active_ids == {successor_hash},
            "persisted successor state did not match the committed rotation",
        )
        _require_fixed(
            successor not in active_ids and predecessor not in active_ids,
            "sensitive token material reached persistence",
        )
        logged = repr(captured_logger.mock_calls)
        _require_fixed(
            successor not in logged and predecessor not in logged,
            "sensitive token material reached logs",
        )


@pytest.mark.asyncio
async def test_two_pools_rotate_one_predecessor_once() -> None:
    async with _postgres_harness() as harness:
        first = harness.database
        second = PostgresDatabase(harness.dsn, pool_min=1, pool_max=4)
        await second.connect()
        try:
            user_id = await _insert_user(first)
            predecessor = await first.create_refresh_token(user_id)
            results = await asyncio.gather(
                first.rotate_refresh_token(predecessor),
                second.rotate_refresh_token(predecessor),
            )
            winners = [result for result in results if result != (None, None)]
            _require_fixed(
                len(winners) == 1,
                "cross-pool rotation did not produce exactly one winner",
            )
            _require_fixed(
                results.count((None, None)) == 1,
                "cross-pool rotation did not produce exactly one normal loser",
            )
            successor = winners[0][1]
            assert successor is not None

            async with second._pool.acquire() as connection:
                predecessor_row = await connection.fetchrow(
                    "SELECT is_revoked, used_at FROM refresh_tokens WHERE id=$1",
                    _token_hash(predecessor),
                )
                active_ids = {
                    row["id"]
                    for row in await connection.fetch(
                        """
                        SELECT id FROM refresh_tokens
                        WHERE user_id=$1 AND is_revoked=0 AND expires_at > now()
                        """,
                        user_id,
                    )
                }
            assert predecessor_row["is_revoked"] == 1
            assert predecessor_row["used_at"] is not None
            _require_fixed(
                active_ids == {_token_hash(successor)},
                "cross-pool persisted successor state was inconsistent",
            )
        finally:
            await second.close()


@pytest.mark.asyncio
async def test_rotation_result_waits_for_real_transaction_exit() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        predecessor = await database.create_refresh_token(user_id)
        predecessor_hash = _token_hash(predecessor)
        transaction_exit_reached = asyncio.Event()
        release_transaction_exit = asyncio.Event()
        real_pool = database._pool
        rotation: asyncio.Task[Any] | None = None
        result: tuple[dict | None, str | None] | None = None

        try:
            database._pool = _BarrierPool(
                real_pool,
                transaction_exit_reached,
                release_transaction_exit,
            )
            rotation = asyncio.create_task(
                database.rotate_refresh_token(predecessor)
            )
            try:
                await asyncio.wait_for(transaction_exit_reached.wait(), timeout=10)
            except TimeoutError:
                pytest.fail(
                    "rotation did not reach the real transaction-exit barrier",
                    pytrace=False,
                )

            _require_fixed(
                not rotation.done(),
                "rotation returned a successor before transaction exit",
            )
            async with real_pool.acquire() as observer:
                predecessor_before_commit = await observer.fetchrow(
                    """
                    SELECT is_revoked, used_at
                    FROM refresh_tokens
                    WHERE id=$1
                    """,
                    predecessor_hash,
                )
                visible_rows_before_commit = int(
                    await observer.fetchval(
                        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id=$1",
                        user_id,
                    )
                )
            _require_fixed(
                predecessor_before_commit is not None
                and predecessor_before_commit["is_revoked"] == 0
                and predecessor_before_commit["used_at"] is None,
                "predecessor state became visible before transaction commit",
            )
            _require_fixed(
                visible_rows_before_commit == 1,
                "uncommitted successor became visible before transaction commit",
            )

            release_transaction_exit.set()
            try:
                result = await asyncio.wait_for(rotation, timeout=10)
            except TimeoutError:
                pytest.fail(
                    "rotation did not finish after transaction-exit release",
                    pytrace=False,
                )
        finally:
            release_transaction_exit.set()
            database._pool = real_pool
            await _cancel_task(rotation)

        _require_fixed(
            result is not None and result != (None, None),
            "rotation did not return its committed successor",
        )
        user, successor = result
        assert user is not None
        assert successor is not None
        successor_hash = _token_hash(successor)
        async with real_pool.acquire() as observer:
            predecessor_after_commit = await observer.fetchrow(
                """
                SELECT is_revoked, used_at
                FROM refresh_tokens
                WHERE id=$1
                """,
                predecessor_hash,
            )
            hashed_successor_count = int(
                await observer.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE id=$1",
                    successor_hash,
                )
            )
            raw_successor_count = int(
                await observer.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE id=$1",
                    successor,
                )
            )
        _require_fixed(
            predecessor_after_commit is not None
            and predecessor_after_commit["is_revoked"] == 1
            and predecessor_after_commit["used_at"] is not None,
            "predecessor state was not committed with the rotation",
        )
        _require_fixed(
            hashed_successor_count == 1,
            "hashed successor was not persisted after transaction commit",
        )
        _require_fixed(
            raw_successor_count == 0,
            "sensitive token material reached persistence",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("operation_name", ["create", "rotate", "logout"])
async def test_refresh_writers_use_expected_transaction_lock(
    operation_name: str,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id = await _insert_user(database)
        predecessor = await database.create_refresh_token(user_id)
        lock_key = _refresh_token_user_lock_key(user_id)
        task: asyncio.Task[Any] | None = None

        async with database._pool.acquire() as holder:
            async with holder.transaction():
                await holder.execute(
                    "SELECT pg_advisory_xact_lock($1::BIGINT)",
                    lock_key,
                )
                if operation_name == "create":
                    operation = database.create_refresh_token(user_id)
                elif operation_name == "rotate":
                    operation = database.rotate_refresh_token(predecessor)
                else:
                    operation = database.revoke_all_refresh_tokens(user_id)
                task = asyncio.create_task(operation)
                wait_proven = False
                try:
                    await _wait_for_advisory_wait(database, task)
                    _require_fixed(
                        not task.done(),
                        "refresh-token writer completed while its advisory lock was held",
                    )
                    wait_proven = True
                finally:
                    if not wait_proven:
                        await _cancel_task(task)

        assert task is not None
        try:
            await asyncio.wait_for(task, timeout=10)
        except TimeoutError:
            pytest.fail(
                "refresh-token writer did not finish after advisory-lock release",
                pytrace=False,
            )


@pytest.mark.asyncio
async def test_successor_collision_rolls_back_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as harness:
        import asyncpg

        database = harness.database
        user_id = await _insert_user(database)
        predecessor = await database.create_refresh_token(user_id)
        with monkeypatch.context() as patch:
            patch.setattr(
                postgres_module.secrets,
                "token_urlsafe",
                lambda _: predecessor,
            )
            try:
                await database.rotate_refresh_token(predecessor)
            except asyncpg.UniqueViolationError:
                pass
            except Exception as exc:
                pytest.fail(
                    "unexpected successor-collision failure "
                    f"[{type(exc).__name__}]",
                    pytrace=False,
                )
            else:
                pytest.fail(
                    "successor collision did not propagate a unique violation",
                    pytrace=False,
                )

        async with database._pool.acquire() as connection:
            predecessor_row = await connection.fetchrow(
                "SELECT is_revoked, used_at FROM refresh_tokens WHERE id=$1",
                _token_hash(predecessor),
            )
            assert await connection.fetchval("SELECT 1") == 1
        assert predecessor_row["is_revoked"] == 0
        assert predecessor_row["used_at"] is None

        user, successor = await database.rotate_refresh_token(predecessor)
        assert user is not None
        assert successor is not None


@pytest.mark.asyncio
async def test_rotation_and_logout_have_both_linearization_orders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database

        rotation_first_user = await _insert_user(database)
        rotation_first_token = await database.create_refresh_token(
            rotation_first_user
        )
        rotation_result, logout_result = await _run_with_leader_paused_after_lock(
            monkeypatch,
            database,
            "rotation-first",
            lambda: database.rotate_refresh_token(rotation_first_token),
            lambda: database.revoke_all_refresh_tokens(rotation_first_user),
        )
        assert rotation_result != (None, None)
        assert logout_result is None
        assert await _active_refresh_count(database, rotation_first_user) == 0

        logout_first_user = await _insert_user(database)
        logout_first_token = await database.create_refresh_token(logout_first_user)
        logout_result, rotation_result = await _run_with_leader_paused_after_lock(
            monkeypatch,
            database,
            "logout-first",
            lambda: database.revoke_all_refresh_tokens(logout_first_user),
            lambda: database.rotate_refresh_token(logout_first_token),
        )
        assert logout_result is None
        _require_fixed(
            rotation_result == (None, None),
            "logout-first rotation unexpectedly produced a successor",
        )
        assert await _active_refresh_count(database, logout_first_user) == 0


@pytest.mark.asyncio
async def test_create_and_logout_follow_lock_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database

        create_first_user = await _insert_user(database)
        created_token, logout_result = await _run_with_leader_paused_after_lock(
            monkeypatch,
            database,
            "create-first",
            lambda: database.create_refresh_token(create_first_user),
            lambda: database.revoke_all_refresh_tokens(create_first_user),
        )
        assert created_token
        assert logout_result is None
        assert await _active_refresh_count(database, create_first_user) == 0

        logout_first_user = await _insert_user(database)
        await database.revoke_all_refresh_tokens(logout_first_user)
        later_token = await database.create_refresh_token(logout_first_user)
        assert later_token
        assert await _active_refresh_count(database, logout_first_user) == 1
