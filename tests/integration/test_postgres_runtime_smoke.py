"""Real PostgreSQL runtime smoke test for the optional database backend."""
from __future__ import annotations

import os
import re
import sys
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from uuid import uuid4

import pytest

_POSTGRES_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_SAFE_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]+$")


class _RollbackProbe(RuntimeError):
    """Intentional exception used to verify a real transaction rollback."""


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
    return RuntimeError(f"PostgreSQL smoke setup failed [{action}: {type(exc).__name__}]")


async def _attempt_cleanup(
    action: str,
    cleanup: Callable[[], Awaitable[object]],
    failures: list[str],
) -> None:
    try:
        await cleanup()
    except Exception as exc:
        failures.append(f"{action}: {type(exc).__name__}")


@pytest.mark.asyncio
async def test_postgres_runtime_schema_and_transaction_smoke() -> None:
    config = _postgres_test_config()

    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg must be installed when the PostgreSQL test environment is configured"
        )

    from ares.core.logger import setup_logger
    from ares.db.postgres import PostgresDatabase

    # The production adapter currently logs a DSN fragment at INFO. Keep this
    # isolated test at WARNING so no connection string is emitted to CI logs.
    setup_logger(level="WARNING")

    test_database = f"ares_smoke_{uuid4().hex}"
    assert _SAFE_DATABASE_NAME.fullmatch(test_database)
    if test_database == config["database"]:
        pytest.fail("Generated PostgreSQL smoke database collided with maintenance database")
    user_id = f"smoke-user-{uuid4().hex}"
    rollback_user_id = f"rollback-user-{uuid4().hex}"
    refresh_row_id = f"smoke-refresh-{uuid4().hex}"
    admin = None
    database = None
    creation_attempted = False
    runtime_connected = False
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

        database = PostgresDatabase(
            _runtime_dsn(config, test_database),
            pool_min=1,
            pool_max=2,
        )
        try:
            await database.connect()
        except Exception as exc:
            raise _sanitized_setup_failure("runtime-initialize", exc) from None
        runtime_connected = True

        async with database._pool.acquire() as connection:
            table_rows = await connection.fetch(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = ANY($1::text[])
                """,
                ["api_keys", "refresh_tokens", "revoked_access_tokens"],
            )
            assert {row["table_name"] for row in table_rows} == {
                "api_keys",
                "refresh_tokens",
                "revoked_access_tokens",
            }

            column_rows = await connection.fetch(
                """
                SELECT table_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND column_name = 'expires_at'
                  AND table_name = ANY($1::text[])
                """,
                ["api_keys", "refresh_tokens"],
            )
            columns = {
                row["table_name"]: (row["data_type"], row["is_nullable"])
                for row in column_rows
            }
            assert columns == {
                "api_keys": ("timestamp with time zone", "YES"),
                "refresh_tokens": ("timestamp with time zone", "NO"),
            }

            index_rows = await connection.fetch(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND tablename = ANY($1::text[])
                """,
                ["api_keys", "refresh_tokens", "revoked_access_tokens"],
            )
            indexes = {row["indexname"] for row in index_rows}
            assert {
                "idx_pg_apikeys_user",
                "idx_pg_apikeys_prefix",
                "idx_pg_refresh_user",
                "idx_pg_refresh_exp",
                "idx_pg_rat_expires",
            } <= indexes

            await connection.execute(
                """
                INSERT INTO users(id, username, hashed_password, role, created_by)
                VALUES($1, $2, $3, $4, $5)
                """,
                user_id,
                f"smoke_{uuid4().hex}",
                "not-used-by-smoke-test",
                "reporter",
                "postgres-smoke",
            )
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            await connection.execute(
                """
                INSERT INTO refresh_tokens(id, user_id, expires_at)
                VALUES($1, $2, $3)
                """,
                refresh_row_id,
                user_id,
                expires_at,
            )
            round_trip = await connection.fetchval(
                "SELECT expires_at FROM refresh_tokens WHERE id=$1",
                refresh_row_id,
            )
            assert isinstance(round_trip, datetime)
            assert round_trip == expires_at

            with pytest.raises(_RollbackProbe):
                async with connection.transaction():
                    insert_result = await connection.execute(
                        """
                        INSERT INTO users(
                            id, username, hashed_password, role, created_by
                        )
                        VALUES($1, $2, $3, $4, $5)
                        """,
                        rollback_user_id,
                        f"rollback_{uuid4().hex}",
                        "not-used-by-smoke-test",
                        "reporter",
                        "postgres-smoke",
                    )
                    assert insert_result == "INSERT 0 1"
                    assert (
                        await connection.fetchval(
                            "SELECT 1 FROM users WHERE id=$1", rollback_user_id
                        )
                        == 1
                    )
                    raise _RollbackProbe

            assert (
                await connection.fetchval(
                    "SELECT 1 FROM users WHERE id=$1", rollback_user_id
                )
                is None
            )
            assert await connection.fetchval("SELECT 1") == 1

        async with database._pool.acquire() as reusable_connection:
            assert await reusable_connection.fetchval("SELECT 1") == 1
    finally:
        primary_failure = sys.exception()

        if runtime_connected and database is not None:

            async def _delete_test_rows() -> None:
                async with database._pool.acquire() as connection:
                    await connection.execute(
                        "DELETE FROM users WHERE id = ANY($1::text[])",
                        [user_id, rollback_user_id],
                    )

            await _attempt_cleanup(
                "delete-test-rows", _delete_test_rows, cleanup_failures
            )

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
                        f"PostgreSQL smoke cleanup failure [{failure}]"
                    )
            else:
                pytest.fail(
                    "PostgreSQL smoke cleanup failed: "
                    + "; ".join(cleanup_failures)
                )
