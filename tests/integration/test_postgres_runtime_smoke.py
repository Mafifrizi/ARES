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


class PostgresError(RuntimeError):
    """Synthetic database-category error for diagnostic-only tests."""


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _canonical_ticket_relation_metadata() -> dict[str, object]:
    return {
        "relkind": "r",
        "relpersistence": "p",
        "relispartition": False,
        "parent_count": 0,
        "child_count": 0,
        "relrowsecurity": False,
        "relforcerowsecurity": False,
        "policy_count": 0,
        "user_trigger_count": 0,
        "user_rule_count": 0,
    }


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
    from ares.db.postgres import _postgres_operational_category

    if action == "runtime-initialize":
        from ares.db.postgres import _postgres_startup_diagnostic_label

        diagnostic = _postgres_startup_diagnostic_label(exc)
        return RuntimeError(
            "PostgreSQL smoke setup failed "
            f"[runtime-initialize:{diagnostic}]"
        )
    category = _postgres_operational_category(exc)
    return RuntimeError(
        f"PostgreSQL smoke setup failed [{action}:{category}]"
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


def test_postgres_startup_diagnostic_statement_contract() -> None:
    from ares.db.postgres import (
        _POSTGRES_FALLBACK_DDL_CODES,
        _POSTGRES_FALLBACK_STATEMENT_SPANS,
        _postgres_fallback_failure_invariant,
    )

    codes_are_unique = (
        len(_POSTGRES_FALLBACK_DDL_CODES)
        == len(set(_POSTGRES_FALLBACK_DDL_CODES))
        == len(_POSTGRES_FALLBACK_STATEMENT_SPANS)
    )
    _require_fixed(
        codes_are_unique,
        "Fallback statements require unique diagnostic identifiers",
    )
    every_statement_maps = True
    spans_are_ordered = True
    previous_end = 0
    for code, start, end in _POSTGRES_FALLBACK_STATEMENT_SPANS:
        failure = PostgresError("diagnostic canary")
        failure.position = start + ((end - start) // 2)
        every_statement_maps = (
            every_statement_maps
            and _postgres_fallback_failure_invariant(failure) == code
        )
        spans_are_ordered = (
            spans_are_ordered
            and start > previous_end
            and end >= start
        )
        previous_end = end
    _require_fixed(
        every_statement_maps,
        "Every fallback statement must map to its fixed identifier",
    )
    _require_fixed(
        spans_are_ordered,
        "Fallback diagnostic statement spans must be ordered",
    )


def test_postgres_ticket_relation_diagnostic_property_contract() -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_RELATION_PROPERTY_BITS,
        _POSTGRES_TICKET_RELATION_PROPERTY_MASK,
        _postgres_ticket_relation_diagnostic_masks,
        _postgres_ticket_relation_is_canonical,
    )

    expected_fields = frozenset(_canonical_ticket_relation_metadata())
    bits = tuple(_POSTGRES_TICKET_RELATION_PROPERTY_BITS.values())
    property_contract_is_exact = (
        frozenset(_POSTGRES_TICKET_RELATION_PROPERTY_BITS)
        == expected_fields
        and len(bits) == len(set(bits)) == 10
        and sum(bits) == _POSTGRES_TICKET_RELATION_PROPERTY_MASK == 0x3FF
        and all(bit > 0 and bit & (bit - 1) == 0 for bit in bits)
    )
    _require_fixed(
        property_contract_is_exact,
        "Relation diagnostic properties require unique bounded bits",
    )

    canonical = _canonical_ticket_relation_metadata()
    canonical_masks = _postgres_ticket_relation_diagnostic_masks(
        canonical
    )
    _require_fixed(
        _postgres_ticket_relation_is_canonical(canonical)
        and canonical_masks == (0, 0, 0, 0),
        "Canonical relation metadata must produce zero masks",
    )


@pytest.mark.parametrize(
    ("field", "violating_value"),
    [
        pytest.param("relkind", "v", id="kind"),
        pytest.param("relpersistence", "u", id="persistence"),
        pytest.param("relispartition", True, id="partition"),
        pytest.param("parent_count", 1, id="parent"),
        pytest.param("child_count", 1, id="child"),
        pytest.param("relrowsecurity", True, id="rls"),
        pytest.param("relforcerowsecurity", True, id="forced-rls"),
        pytest.param("policy_count", 1, id="policy"),
        pytest.param("user_trigger_count", 1, id="user-trigger"),
        pytest.param("user_rule_count", 1, id="user-rule"),
    ],
)
def test_postgres_ticket_relation_single_property_masks(
    field: str,
    violating_value: object,
) -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_RELATION_PROPERTY_BITS,
        _postgres_ticket_relation_diagnostic_masks,
        _postgres_ticket_relation_is_canonical,
    )

    relation = _canonical_ticket_relation_metadata()
    relation[field] = violating_value
    masks = _postgres_ticket_relation_diagnostic_masks(relation)
    expected_bit = _POSTGRES_TICKET_RELATION_PROPERTY_BITS[field]
    _require_fixed(
        masks == (expected_bit, 0, 0, 0)
        and not _postgres_ticket_relation_is_canonical(relation),
        "A relation mutation must set only its assigned mismatch bit",
    )


def test_postgres_ticket_relation_combined_and_alternate_masks() -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_RELATION_AGGREGATE_ONLY,
        _postgres_ticket_relation_diagnostic_invariant,
        _postgres_ticket_relation_diagnostic_masks,
        _postgres_ticket_relation_is_canonical,
    )

    combined = {
        field: (
            "v"
            if field == "relkind"
            else "u"
            if field == "relpersistence"
            else True
            if field in {
                "relispartition",
                "relrowsecurity",
                "relforcerowsecurity",
            }
            else 1
        )
        for field in _canonical_ticket_relation_metadata()
    }
    combined_masks = _postgres_ticket_relation_diagnostic_masks(
        combined
    )
    _require_fixed(
        combined_masks == (0x3FF, 0, 0, 0)
        and not _postgres_ticket_relation_is_canonical(combined),
        "Combined relation mutations must not short-circuit",
    )

    alternate = _canonical_ticket_relation_metadata()
    alternate["relkind"] = b"r"
    alternate["relpersistence"] = b"p"
    alternate_masks = _postgres_ticket_relation_diagnostic_masks(
        alternate
    )
    alternate_invariant = _postgres_ticket_relation_diagnostic_invariant(
        alternate_masks
    )
    _require_fixed(
        alternate_masks == (0x003, 0x003, 0, 0)
        and alternate_invariant
        == "ticket-relation-metadata:m=003;a=003;x=000;n=000"
        and not _postgres_ticket_relation_is_canonical(alternate),
        "Alternate internal-character representations need exact masks",
    )

    wrong_internal = _canonical_ticket_relation_metadata()
    wrong_internal["relkind"] = b"v"
    wrong_internal["relpersistence"] = b"u"
    _require_fixed(
        _postgres_ticket_relation_diagnostic_masks(wrong_internal)
        == (0x003, 0, 0, 0),
        "Wrong internal-character values must not be alternate matches",
    )
    _require_fixed(
        _postgres_ticket_relation_diagnostic_invariant((0, 0, 0, 0))
        == _POSTGRES_TICKET_RELATION_AGGREGATE_ONLY,
        "Zero masks after rejection require the aggregate-only tripwire",
    )


def test_postgres_ticket_relation_missing_and_unexpected_masks() -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_RELATION_PROPERTY_BITS,
        _postgres_ticket_relation_diagnostic_masks,
        _postgres_ticket_relation_is_canonical,
    )

    missing_cases_are_exact = True
    unexpected_cases_are_exact = True
    for field in _canonical_ticket_relation_metadata():
        bit = _POSTGRES_TICKET_RELATION_PROPERTY_BITS[field]

        missing = _canonical_ticket_relation_metadata()
        missing.pop(field)
        missing_cases_are_exact = (
            missing_cases_are_exact
            and _postgres_ticket_relation_diagnostic_masks(missing)
            == (0, 0, 0, bit)
            and not _postgres_ticket_relation_is_canonical(missing)
        )

        unexpected = _canonical_ticket_relation_metadata()
        unexpected[field] = object()
        unexpected_cases_are_exact = (
            unexpected_cases_are_exact
            and _postgres_ticket_relation_diagnostic_masks(unexpected)
            == (0, 0, bit, 0)
            and not _postgres_ticket_relation_is_canonical(unexpected)
        )

    _require_fixed(
        missing_cases_are_exact,
        "Missing relation properties must set only missing bits",
    )
    _require_fixed(
        unexpected_cases_are_exact,
        "Unexpected relation property types must set only type bits",
    )


def test_postgres_ticket_relation_diagnostic_rendering_is_closed() -> None:
    from ares.db.postgres import (
        _is_postgres_ticket_relation_diagnostic,
        _postgres_startup_diagnostic_label,
        _postgres_ticket_relation_diagnostic_invariant,
        _PostgresStartupDiagnosticError,
    )

    canary = "relation-diagnostic-canary-not-for-output"
    high_bit_result = _postgres_ticket_relation_diagnostic_invariant(
        (0x400, 0, 0, 0)
    )
    overlap_result = _postgres_ticket_relation_diagnostic_invariant(
        (0x001, 0, 0x001, 0)
    )
    valid_invariant = _postgres_ticket_relation_diagnostic_invariant(
        (0x003, 0x003, 0, 0)
    )
    invalid_error = _PostgresStartupDiagnosticError(
        "Incompatible WebSocket ticket schema",
        diagnostic_stage="fallback-validation",
        diagnostic_invariant=canary,
    )
    valid_error = _PostgresStartupDiagnosticError(
        "Incompatible WebSocket ticket schema",
        diagnostic_stage="fallback-validation",
        diagnostic_invariant=valid_invariant,
    )
    valid_label = _postgres_startup_diagnostic_label(valid_error)
    invalid_label = _postgres_startup_diagnostic_label(invalid_error)
    closed_rendering = (
        high_bit_result == "ticket-validation-unclassified"
        and overlap_result == "ticket-validation-unclassified"
        and _is_postgres_ticket_relation_diagnostic(valid_invariant)
        and not _is_postgres_ticket_relation_diagnostic(
            "ticket-relation-metadata:m=400;a=000;x=000;n=000"
        )
        and valid_label
        == (
            "fallback-validation:"
            "ticket-relation-metadata:m=003;a=003;x=000;n=000:none"
        )
        and invalid_label == "unclassified"
    )
    _require_fixed(
        closed_rendering,
        "Relation diagnostic rendering must reject unknown masks",
    )
    rendered = " ".join(
        (
            high_bit_result,
            overlap_result,
            valid_invariant,
            valid_label,
            invalid_label,
            str(valid_error),
            repr(valid_error),
            str(invalid_error),
            repr(invalid_error),
        )
    )
    _require_fixed(
        canary not in rendered,
        "Relation diagnostics must not expose source values",
    )


@pytest.mark.asyncio
async def test_postgres_startup_diagnostics_are_distinct_and_sanitized() -> None:
    from ares.db.postgres import (
        PostgresDatabase,
        _postgres_restage_startup_error,
        _postgres_startup_diagnostic_label,
        _postgres_startup_error,
        _postgres_ticket_schema_error,
    )

    canary = "diagnostic-canary-not-for-output"

    class _OwnershipFailureConnection:
        async def fetch(self, *_args: object) -> object:
            raise PostgresError(canary)

    class _RelationQueryFailureConnection:
        async def fetchrow(self, *_args: object) -> object:
            raise PostgresError(canary)

    try:
        await PostgresDatabase._managed_schema_revision(
            _OwnershipFailureConnection()
        )
    except Exception as exc:
        ownership_failure: BaseException = exc
    else:
        pytest.fail("Ownership failure must be diagnosed", pytrace=False)

    try:
        await PostgresDatabase._validate_websocket_ticket_schema(
            _RelationQueryFailureConnection()
        )
    except Exception as exc:
        relation_query_failure: BaseException = exc
    else:
        pytest.fail("Relation query failure must be diagnosed", pytrace=False)

    ddl_cause = PostgresError(canary)
    ddl_failure = _postgres_startup_error(
        "PostgreSQL schema validation failed",
        stage="fallback-ddl",
        invariant="campaigns-table",
        cause=ddl_cause,
    )
    validation_failure = _postgres_restage_startup_error(
        _postgres_ticket_schema_error("ticket-columns"),
        "fallback-validation",
    )
    typed_unknown_failure = _postgres_startup_error(
        "PostgreSQL schema validation failed",
        stage="fallback-validation",
        invariant="ticket-validation-unclassified",
        cause=RuntimeError(canary),
    )
    unknown_failure = RuntimeError(canary)

    labels = (
        _postgres_startup_diagnostic_label(ownership_failure),
        _postgres_startup_diagnostic_label(ddl_failure),
        _postgres_startup_diagnostic_label(validation_failure),
        _postgres_startup_diagnostic_label(typed_unknown_failure),
        _postgres_startup_diagnostic_label(unknown_failure),
        _postgres_startup_diagnostic_label(relation_query_failure),
    )
    labels_are_exact = labels == (
        "ownership:ownership-relation-query:database",
        "fallback-ddl:campaigns-table:database",
        "fallback-validation:ticket-columns:none",
        "unclassified",
        "unclassified",
        "managed-validation:ticket-relation-query:database",
    )
    _require_fixed(
        labels_are_exact,
        "Startup diagnostic stages must remain distinct and fixed",
    )
    public_messages_are_generic = (
        str(ownership_failure) == "PostgreSQL schema validation failed"
        and str(ddl_failure) == "PostgreSQL schema validation failed"
        and str(validation_failure)
        == "Incompatible WebSocket ticket schema"
    )
    _require_fixed(
        public_messages_are_generic,
        "Startup diagnostics must preserve generic public messages",
    )
    rendered = " ".join(
        (
            *labels,
            str(ownership_failure),
            repr(ownership_failure),
            str(ddl_failure),
            repr(ddl_failure),
            str(validation_failure),
            repr(validation_failure),
            str(relation_query_failure),
            repr(relation_query_failure),
        )
    )
    _require_fixed(
        canary not in rendered,
        "Startup diagnostics must not expose source content",
    )


@pytest.mark.asyncio
async def test_postgres_startup_cleanup_preserves_primary_diagnostic() -> None:
    from ares.db.postgres import (
        PostgresDatabase,
        _postgres_startup_diagnostic_label,
        _postgres_startup_error,
    )

    canary = "cleanup-canary-not-for-output"

    class _FailingPool:
        async def close(self) -> None:
            raise RuntimeError(canary)

    database = PostgresDatabase("synthetic")
    pool = _FailingPool()
    database._pool = pool
    primary = _postgres_startup_error(
        "PostgreSQL schema validation failed",
        stage="fallback-validation",
        invariant="ticket-index-inventory",
    )
    await database._close_failed_startup_pool(pool, primary)

    primary_is_preserved = (
        _postgres_startup_diagnostic_label(primary)
        == "fallback-validation:ticket-index-inventory:none"
    )
    _require_fixed(
        primary_is_preserved,
        "Cleanup failure must not replace the primary diagnostic",
    )
    notes = tuple(getattr(primary, "__notes__", ()))
    notes_are_sanitized = (
        len(notes) == 1
        and notes[0]
        == "PostgreSQL startup cleanup failure [pool-close: runtime]"
        and canary not in " ".join(notes)
    )
    _require_fixed(
        notes_are_sanitized,
        "Cleanup diagnostics must remain fixed and sanitized",
    )
    _require_fixed(
        database._pool is None,
        "Failed startup cleanup must clear the candidate pool",
    )


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

        target_probe = None
        try:
            target_probe = await asyncpg.connect(
                host=config["host"],
                port=config["port"],
                user=config["user"],
                database=test_database,
            )
            initial_application_count = int(
                await target_probe.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM information_schema.tables
                    WHERE table_schema=current_schema()
                    """
                )
            )
            initial_version_relation = bool(
                await target_probe.fetchval(
                    """
                    SELECT EXISTS(
                        SELECT 1
                        FROM pg_class AS rel
                        JOIN pg_namespace AS nsp
                          ON nsp.oid=rel.relnamespace
                        WHERE nsp.nspname=current_schema()
                          AND rel.relname='alembic_version'
                    )
                    """
                )
            )
        except Exception as exc:
            raise _sanitized_setup_failure(
                "empty-catalog-probe",
                exc,
            ) from None
        finally:
            if target_probe is not None:
                try:
                    await target_probe.close()
                except Exception as exc:
                    raise _sanitized_setup_failure(
                        "empty-catalog-probe-close",
                        exc,
                    ) from None

        _require_fixed(
            initial_application_count == 0,
            "Runtime smoke database must begin without application tables",
        )
        _require_fixed(
            not initial_version_relation,
            "Runtime smoke database must begin without Alembic ownership",
        )

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
        initial_trace_is_exact = tuple(database._startup_trace) == (
            "fallback-entered",
            "fallback-ddl-complete",
            "startup-ready",
        )
        _require_fixed(
            initial_trace_is_exact,
            "Unversioned runtime startup must complete the fallback path",
        )

        async with database._pool.acquire() as connection:
            version_relation_exists = bool(
                await connection.fetchval(
                    """
                    SELECT EXISTS(
                        SELECT 1
                        FROM pg_class AS rel
                        JOIN pg_namespace AS nsp
                          ON nsp.oid=rel.relnamespace
                        WHERE nsp.nspname=current_schema()
                          AND rel.relname='alembic_version'
                    )
                    """
                )
            )
            _require_fixed(
                not version_relation_exists,
                "Runtime fallback must not stamp Alembic ownership",
            )
            relation_metadata = await connection.fetchrow(
                """
                SELECT rel.relkind::text AS relkind,
                       rel.relpersistence::text AS relpersistence,
                       rel.relispartition,
                       rel.relrowsecurity,
                       rel.relforcerowsecurity,
                       (
                           SELECT COUNT(*)
                           FROM pg_inherits
                           WHERE inhrelid=rel.oid
                       ) AS parent_count,
                       (
                           SELECT COUNT(*)
                           FROM pg_inherits
                           WHERE inhparent=rel.oid
                       ) AS child_count,
                       (
                           SELECT COUNT(*)
                           FROM pg_policy
                           WHERE polrelid=rel.oid
                       ) AS policy_count,
                       (
                           SELECT COUNT(*)
                           FROM pg_trigger
                           WHERE tgrelid=rel.oid
                             AND NOT tgisinternal
                       ) AS user_trigger_count,
                       (
                           SELECT COUNT(*)
                           FROM pg_rewrite
                           WHERE ev_class=rel.oid
                             AND rulename <> '_RETURN'
                       ) AS user_rule_count
                FROM pg_class AS rel
                JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                WHERE nsp.nspname=current_schema()
                  AND rel.relname='websocket_tickets'
                """
            )
            relation_metadata_is_canonical = (
                relation_metadata is not None
                and type(relation_metadata["relkind"]) is str
                and relation_metadata["relkind"] == "r"
                and type(relation_metadata["relpersistence"]) is str
                and relation_metadata["relpersistence"] == "p"
                and relation_metadata["relispartition"] is False
                and relation_metadata["relrowsecurity"] is False
                and relation_metadata["relforcerowsecurity"] is False
                and relation_metadata["parent_count"] == 0
                and relation_metadata["child_count"] == 0
                and relation_metadata["policy_count"] == 0
                and relation_metadata["user_trigger_count"] == 0
                and relation_metadata["user_rule_count"] == 0
            )
            _require_fixed(
                relation_metadata_is_canonical,
                "Runtime ticket relation metadata must be canonical",
            )
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

        await database.close()
        runtime_connected = False
        database = PostgresDatabase(
            _runtime_dsn(config, test_database),
            pool_min=1,
            pool_max=2,
        )
        try:
            await database.connect()
        except Exception as exc:
            raise _sanitized_setup_failure(
                "runtime-reconnect",
                exc,
            ) from None
        runtime_connected = True
        reconnect_trace_is_exact = tuple(database._startup_trace) == (
            "fallback-entered",
            "fallback-ddl-complete",
            "startup-ready",
        )
        _require_fixed(
            reconnect_trace_is_exact,
            "Unversioned runtime reconnect must complete the fallback path",
        )
        async with database._pool.acquire() as reusable_connection:
            reusable_after_reconnect = (
                await reusable_connection.fetchval("SELECT 1") == 1
            )
        _require_fixed(
            reusable_after_reconnect,
            "Runtime pool must remain reusable after reconnect",
        )
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
