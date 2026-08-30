"""Real PostgreSQL runtime smoke test for the optional database backend."""
from __future__ import annotations

import asyncio
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


def _canonical_ticket_columns() -> list[dict[str, object]]:
    definitions = (
        ("ticket_hash", "text", True),
        ("campaign_id", "text", True),
        ("user_id", "text", True),
        ("credential_kind", "text", True),
        ("bearer_subject", "text", False),
        ("bearer_jti", "text", False),
        ("bearer_expires_at", "timestamp with time zone", False),
        ("api_key_id", "text", False),
        ("required_scope", "text", False),
        ("created_at", "timestamp with time zone", True),
        ("expires_at", "timestamp with time zone", True),
        ("consumed_at", "timestamp with time zone", False),
        ("bearer_family_id", "text", False),
        ("bearer_auth_epoch", "bigint", False),
    )
    return [
        {
            "column_name": name,
            "data_type": data_type,
            "attnotnull": not_null,
            "attidentity": "",
            "attgenerated": "",
            "collation_is_default": True,
            "column_default": None,
        }
        for name, data_type, not_null in definitions
    ]


def _expected_ticket_column_contract() -> list[
    tuple[str, str, bool, str, str, bool, str | None]
]:
    return [
        (
            str(row["column_name"]),
            str(row["data_type"]),
            bool(row["attnotnull"]),
            "",
            "",
            True,
            None,
        )
        for row in _canonical_ticket_columns()
    ]


def _canonical_ticket_constraints() -> list[dict[str, object]]:
    checks = {
        "ck_ws_ticket_hash": "CHECK (ticket_hash ~ '^[0-9a-f]{64}$'::text)",
        "ck_ws_ticket_kind": (
            "CHECK (credential_kind = ANY "
            "(ARRAY['bearer'::text, 'api_key'::text]))"
        ),
        "ck_ws_ticket_created_at": "CHECK (created_at < expires_at)",
        "ck_ws_ticket_expires_at": "CHECK (expires_at > created_at)",
        "ck_ws_ticket_consumed_at": (
            "CHECK (consumed_at IS NULL OR consumed_at < expires_at)"
        ),
        "ck_ws_ticket_bearer_expires_finite": (
            "CHECK (bearer_expires_at IS NULL OR isfinite(bearer_expires_at))"
        ),
        "ck_ws_ticket_created_finite": "CHECK (isfinite(created_at))",
        "ck_ws_ticket_expires_finite": "CHECK (isfinite(expires_at))",
        "ck_ws_ticket_consumed_finite": (
            "CHECK (consumed_at IS NULL OR isfinite(consumed_at))"
        ),
        "ck_ws_ticket_time_order": (
            "CHECK (expires_at > created_at AND "
            "(consumed_at IS NULL OR consumed_at < expires_at))"
        ),
        "ck_ws_ticket_source_shape": (
            "CHECK (credential_kind = 'bearer'::text "
            "AND bearer_subject IS NOT NULL "
            "AND length(btrim(bearer_subject)) > 0 "
            "AND bearer_subject = btrim(bearer_subject) "
            "AND bearer_jti IS NOT NULL "
            "AND length(btrim(bearer_jti)) > 0 "
            "AND bearer_jti = btrim(bearer_jti) "
            "AND bearer_expires_at IS NOT NULL "
            "AND bearer_family_id IS NOT NULL "
            "AND bearer_auth_epoch IS NOT NULL "
            "AND bearer_auth_epoch >= 1 "
            "AND api_key_id IS NULL AND required_scope IS NULL "
            "OR credential_kind = 'api_key'::text "
            "AND bearer_subject IS NULL AND bearer_jti IS NULL "
            "AND bearer_expires_at IS NULL "
            "AND bearer_family_id IS NULL "
            "AND bearer_auth_epoch IS NULL "
            "AND api_key_id IS NOT NULL "
            "AND length(btrim(api_key_id)) > 0 "
            "AND api_key_id = btrim(api_key_id) "
            "AND required_scope = 'read'::text)"
        ),
    }
    rows: list[dict[str, object]] = []
    for name, definition in checks.items():
        rows.append(
            {
                "conname": name,
                "contype": b"c",
                "table_oid": 1,
                "referenced_oid": 0,
                "constraint_index_oid": 0,
                "convalidated": True,
                "condeferrable": False,
                "condeferred": False,
                "definition": definition,
                "referenced_schema_oid": None,
                "referenced_schema": None,
                "referenced_table": None,
                "local_columns": [],
                "remote_columns": [],
                "confupdtype": b"a",
                "confdeltype": b"a",
            }
        )
    references = (
        (
            "fk_ws_ticket_api_key",
            "api_key_id",
            "api_keys",
            201,
            "FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE",
        ),
        (
            "fk_ws_ticket_campaign",
            "campaign_id",
            "campaigns",
            202,
            "FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE",
        ),
        (
            "fk_ws_ticket_user",
            "user_id",
            "users",
            203,
            "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
        ),
        (
            "fk_ws_ticket_bearer_family",
            ("bearer_family_id", "user_id"),
            "refresh_token_families",
            204,
            "FOREIGN KEY (bearer_family_id, user_id) "
            "REFERENCES refresh_token_families(id, user_id) ON DELETE CASCADE",
        ),
    )
    for name, column, table, referenced_oid, definition in references:
        local_columns = [column] if isinstance(column, str) else list(column)
        remote_columns = ["id"] if isinstance(column, str) else ["id", "user_id"]
        rows.append(
            {
                "conname": name,
                "contype": b"f",
                "table_oid": 1,
                "referenced_oid": referenced_oid,
                "constraint_index_oid": 0,
                "convalidated": True,
                "condeferrable": False,
                "condeferred": False,
                "definition": definition,
                "referenced_schema_oid": 2,
                "referenced_schema": "public",
                "referenced_table": table,
                "local_columns": local_columns,
                "remote_columns": remote_columns,
                "confupdtype": b"a",
                "confdeltype": b"c",
            }
        )
    rows.append(
        {
            "conname": "websocket_tickets_pkey",
            "contype": b"p",
            "table_oid": 1,
            "referenced_oid": 0,
            "constraint_index_oid": 106,
            "convalidated": True,
            "condeferrable": False,
            "condeferred": False,
            "definition": "PRIMARY KEY (ticket_hash)",
            "referenced_schema_oid": None,
            "referenced_schema": None,
            "referenced_table": None,
            "local_columns": ["ticket_hash"],
            "remote_columns": [],
            "confupdtype": b"a",
            "confdeltype": b"a",
        }
    )
    return sorted(rows, key=lambda row: str(row["conname"]))


def _canonical_ticket_indexes() -> list[dict[str, object]]:
    definitions = (
        ("idx_ws_tickets_api_key", "api_key_id", "text_ops", 11, False),
        ("idx_ws_tickets_bearer_family", "bearer_family_id", "text_ops", 11, False),
        ("idx_ws_tickets_campaign", "campaign_id", "text_ops", 11, False),
        (
            "idx_ws_tickets_expires",
            "expires_at",
            "timestamptz_ops",
            12,
            False,
        ),
        ("idx_ws_tickets_user", "user_id", "text_ops", 11, False),
        ("websocket_tickets_pkey", "ticket_hash", "text_ops", 11, True),
    )
    rows: list[dict[str, object]] = []
    for ordinal, (name, column, opclass, opclass_oid, primary) in enumerate(
        definitions,
        start=101,
    ):
        rows.append(
            {
                "table_oid": 1,
                "index_oid": 106 if primary else ordinal,
                "index_schema_oid": 2,
                "index_schema": "public",
                "index_name": name,
                "index_relkind": b"i",
                "index_relpersistence": b"p",
                "index_is_partition": False,
                "access_method": "btree",
                "indisunique": primary,
                "indisprimary": primary,
                "indisvalid": True,
                "indisready": True,
                "indislive": True,
                "indnkeyatts": 1,
                "indnatts": 1,
                "columns": [column],
                "column_options": [0],
                "operator_classes": [opclass],
                "operator_class_oids": [opclass_oid],
                "operator_class_namespaces": ["pg_catalog"],
                "column_collations_match": [True],
                "expressions": None,
                "predicate": None,
                "definition": "closed-source-defined-index",
            }
        )
    return rows


class _CompleteTicketCensusConnection:
    async def fetchrow(self, query: str, *_args: object) -> object:
        if "FROM pg_class AS rel" not in query:
            raise RuntimeError("closed-test-query")
        return {
            "table_oid": 1,
            "schema_oid": 2,
            "schema_name": "public",
            **_canonical_ticket_relation_metadata(),
        }

    async def fetch(self, query: str, *_args: object) -> object:
        if "FROM pg_attribute AS att" in query:
            rows = _canonical_ticket_columns()
            for row in rows:
                row["attidentity"] = b"\x00"
                row["attgenerated"] = b"\x00"
            return rows
        if "FROM pg_constraint AS con" in query:
            return _canonical_ticket_constraints()
        if "FROM pg_index AS ind" in query:
            return _canonical_ticket_indexes()
        if "FROM pg_opclass AS opc" in query:
            return [
                {"opcname": "text_ops", "opclass_oid": 11},
                {"opcname": "timestamptz_ops", "opclass_oid": 12},
            ]
        if "SELECT rel.relname" in query:
            return [
                {"relname": "api_keys", "relation_oid": 201},
                {"relname": "campaigns", "relation_oid": 202},
                {"relname": "users", "relation_oid": 203},
                {"relname": "refresh_token_families", "relation_oid": 204},
            ]
        raise RuntimeError("closed-test-query")

    async def fetchval(self, query: str, *_args: object) -> object:
        if "current_schema" in query:
            return "public"
        raise RuntimeError("closed-test-query")


class _NoopDiagnosticTransaction:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_exc_info: object) -> None:
        return None


class _Q78ServerProbeError(PostgresError):
    sqlstate = "42883"

    def __init__(self, canary: str) -> None:
        super().__init__(canary)
        self.detail = canary
        self.hint = canary
        self.context = canary


class _Q78FailureConnection(_CompleteTicketCensusConnection):
    def __init__(self, canary: str) -> None:
        self._canary = canary
        self.queries_are_read_only = True

    def transaction(self) -> _NoopDiagnosticTransaction:
        return _NoopDiagnosticTransaction()

    async def fetch(self, query: str, *args: object) -> object:
        normalized = " ".join(query.split()).upper()
        self.queries_are_read_only = (
            self.queries_are_read_only
            and normalized.startswith("SELECT ")
            and not any(
                token in normalized
                for token in (
                    " INSERT ",
                    " UPDATE ",
                    " DELETE ",
                    " CREATE ",
                    " ALTER ",
                    " DROP ",
                    " ALEMBIC_VERSION ",
                )
            )
        )
        if (
            "FROM PG_INDEX AS IND" in normalized
            and "IND.INDKEY::SMALLINT[]" not in normalized
        ):
            raise _Q78ServerProbeError(self._canary)
        return await super().fetch(query, *args)


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


async def _initialize_managed_schema(dsn: str) -> None:
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(
        dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    )

    def upgrade(connection: object) -> None:
        config = Config()
        config.set_main_option("script_location", "migrations")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    try:
        async with engine.connect() as connection:
            await connection.run_sync(upgrade)
    finally:
        await engine.dispose()


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


def test_postgres_ticket_census_covers_every_rejection_predicate() -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_CENSUS_REJECTION_FIELDS,
        _POSTGRES_TICKET_INVARIANTS,
    )

    covered_once = (
        set(_POSTGRES_TICKET_CENSUS_REJECTION_FIELDS)
        == set(_POSTGRES_TICKET_INVARIANTS)
        and len(_POSTGRES_TICKET_CENSUS_REJECTION_FIELDS)
        == len(_POSTGRES_TICKET_INVARIANTS)
        and all(
            isinstance(field, str) and field
            for field in _POSTGRES_TICKET_CENSUS_REJECTION_FIELDS.values()
        )
    )
    _require_fixed(
        covered_once,
        "Every ticket-schema rejection requires one closed census field",
    )


def test_postgres_ticket_census_all_zero_and_closed_rendering() -> None:
    from ares.db.postgres import (
        _POSTGRES_TICKET_CENSUS_FIELDS,
        _is_postgres_ticket_schema_census,
        _new_postgres_ticket_schema_census,
        _postgres_startup_diagnostic_label,
        _postgres_ticket_schema_census_invariant,
        _PostgresStartupDiagnosticError,
    )

    census = _new_postgres_ticket_schema_census()
    invariant = _postgres_ticket_schema_census_invariant(census)
    all_sections_present = all(
        f"{section}=" in invariant
        for section, _fields in _POSTGRES_TICKET_CENSUS_FIELDS
    )
    error = _PostgresStartupDiagnosticError(
        "Incompatible WebSocket ticket schema",
        diagnostic_stage="fallback-validation",
        diagnostic_invariant=invariant,
    )
    label = _postgres_startup_diagnostic_label(error)
    _require_fixed(
        all_sections_present
        and _is_postgres_ticket_schema_census(invariant)
        and label == f"fallback-validation:{invariant}:none",
        "The canonical census requires every deterministic zero section",
    )

    malformed = (
        invariant.replace("r=m000", "r=m400", 1),
        invariant + ";extra=q00",
        invariant.replace(";c=", ";canary=", 1),
        invariant.replace("g0", "g2", 1),
    )
    _require_fixed(
        not any(_is_postgres_ticket_schema_census(item) for item in malformed),
        "Unknown census values must not enter startup diagnostics",
    )


def test_postgres_q78_operation_and_failure_contract_is_closed() -> None:
    import inspect

    from ares.db.postgres import (
        _POSTGRES_Q78_OPERATION_BITS,
        _POSTGRES_Q78_SPLIT_INDEX_QUERY,
        _POSTGRES_Q78_SUBPHASES,
        PostgresDatabase,
        _is_postgres_q78_failure,
        _postgres_q78_failure,
    )

    operation_map_is_exact = _POSTGRES_Q78_OPERATION_BITS == {
        "index-catalog": 0x08,
        "canonical-opclasses": 0x10,
        "current-schema": 0x20,
        "referenced-relations": 0x40,
    } and sum(_POSTGRES_Q78_OPERATION_BITS.values()) == 0x78
    _require_fixed(
        operation_map_is_exact,
        "q78 must map exactly to its four source operations",
    )
    production_source = inspect.getsource(
        PostgresDatabase._validate_websocket_ticket_schema
    )
    managed_revision_source = inspect.getsource(
        PostgresDatabase._managed_schema_revision
    )
    managed_schema_source = inspect.getsource(
        PostgresDatabase._validate_managed_schema
    )
    managed_constraints_source = inspect.getsource(
        PostgresDatabase._validate_managed_constraints
    )
    managed_serials_source = inspect.getsource(
        PostgresDatabase._validate_managed_serials
    )
    managed_source = "\n".join(
        (
            managed_revision_source,
            managed_schema_source,
            managed_constraints_source,
            managed_serials_source,
        )
    )
    syntax_is_portable = (
        "item(collation, ordinality)" not in _POSTGRES_Q78_SPLIT_INDEX_QUERY
        and "item(collation, ordinality)" not in production_source
        and "item(collation_oid, ordinality)"
        in _POSTGRES_Q78_SPLIT_INDEX_QUERY
        and "item(collation_oid, ordinality)" in production_source
    )
    _require_fixed(
        syntax_is_portable,
        "q78 index queries must not use a reserved alias",
    )
    managed_syntax_is_portable = (
        "item(collation, position)" not in managed_source
        and managed_source.count("item(collation_oid, position)") == 3
    )
    _require_fixed(
        managed_syntax_is_portable,
        "Managed index queries must not use a reserved alias",
    )
    catalog_codecs_are_explicit = (
        "idx.relkind::text AS index_relkind"
        in _POSTGRES_Q78_SPLIT_INDEX_QUERY
        and "idx.relpersistence::text AS index_relpersistence"
        in _POSTGRES_Q78_SPLIT_INDEX_QUERY
        and "idx.relkind::text AS index_relkind" in production_source
        and "idx.relpersistence::text AS index_relpersistence"
        in production_source
        and "att.attidentity::text AS attidentity" in production_source
        and "att.attgenerated::text AS attgenerated" in production_source
        and "con.contype::text AS contype" in production_source
        and "con.confupdtype::text AS confupdtype" in production_source
        and "con.confdeltype::text AS confdeltype" in production_source
    )
    _require_fixed(
        catalog_codecs_are_explicit,
        "PostgreSQL internal catalog codes require explicit text projections",
    )
    managed_catalog_codecs_are_explicit = all(
        projection in managed_source
        for projection in (
            "rel.relkind::text AS relkind",
            "rel.relpersistence::text AS relpersistence",
            "index_rel.relkind::text AS index_relkind",
            "index_rel.relpersistence::text AS index_relpersistence",
            "con.contype::text AS contype",
            "con.confupdtype::text AS confupdtype",
            "con.confdeltype::text AS confdeltype",
            "sequence_rel.relkind::text AS relkind",
            "sequence_rel.relpersistence::text AS relpersistence",
            "owner_att.attidentity::text AS attidentity",
            "owner_att.attgenerated::text AS attgenerated",
        )
    )
    _require_fixed(
        managed_catalog_codecs_are_explicit,
        "Managed catalog codes require explicit text projections",
    )
    subphases_are_distinct = True
    for subphase in _POSTGRES_Q78_SUBPHASES:
        rendered = _postgres_q78_failure(
            RuntimeError("closed-client-probe"),
            subphase=subphase,
        )
        subphases_are_distinct = (
            subphases_are_distinct
            and _is_postgres_q78_failure(rendered)
            and rendered.startswith(f"q78:{subphase}:")
            and "none" not in rendered
        )
    _require_fixed(
        subphases_are_distinct,
        "Every q78 subphase requires a distinct closed rendering",
    )


@pytest.mark.parametrize(
    ("sqlstate", "category"),
    [
        pytest.param("42601", "syntax", id="syntax"),
        pytest.param("42P01", "undefined-table", id="undefined-table"),
        pytest.param("42703", "undefined-column", id="undefined-column"),
        pytest.param("42704", "undefined-object", id="undefined-object"),
        pytest.param(
            "42883",
            "undefined-function-or-operator",
            id="undefined-function",
        ),
        pytest.param("42804", "datatype-mismatch", id="datatype"),
        pytest.param("21000", "cardinality", id="cardinality"),
        pytest.param("42501", "permission", id="permission"),
        pytest.param("25P02", "transaction", id="transaction"),
        pytest.param("08006", "connection", id="connection"),
        pytest.param("XX000", "other-postgres", id="other"),
    ],
)
def test_postgres_q78_sqlstate_categories_are_allowlisted(
    sqlstate: str,
    category: str,
) -> None:
    from ares.db.postgres import (
        _is_postgres_q78_failure,
        _postgres_q78_failure,
    )

    error = PostgresError("closed-server-probe")
    error.sqlstate = sqlstate
    rendered = _postgres_q78_failure(error, subphase="server-execute")
    _require_fixed(
        _is_postgres_q78_failure(rendered)
        and rendered
        == f"q78:server-execute:state={sqlstate}:category={category}",
        "PostgreSQL q78 failures require fixed SQLSTATE categories",
    )


@pytest.mark.asyncio
async def test_postgres_q78_failure_retains_complete_split_observation() -> None:
    from ares.db.postgres import (
        PostgresDatabase,
        _is_postgres_q78_failure,
        _is_postgres_q78_split,
        _postgres_startup_diagnostic_label,
        _PostgresStartupDiagnosticError,
    )

    canary = "q78-diagnostic-canary-not-for-output"
    connection = _Q78FailureConnection(canary)
    try:
        await PostgresDatabase._validate_websocket_ticket_schema(connection)
    except _PostgresStartupDiagnosticError as exc:
        failure = exc.q78_failure
        split = exc.q78_split
        label = _postgres_startup_diagnostic_label(exc)
        invariant = exc.diagnostic_invariant
        public_message = str(exc)
    else:
        pytest.fail("The unchanged q78 operation must remain rejecting", pytrace=False)

    split_is_complete = (
        _is_postgres_q78_split(split)
        and "i=m00,e0,o00,b00,u00,p00,v00,r00,l00,k00,n00,c00,d00,a00,j00,s00,t00,y00,h3f,x00,g0"
        in split
        and ";p=i0;o=m0,e0,x0;s=m0,x0;f=m0,e0,oc,b0,x0;z=q0"
        in split
    )
    q78_is_exact = (
        failure
        == (
            "q78:server-execute:state=42883:"
            "category=undefined-function-or-operator"
        )
        and _is_postgres_q78_failure(failure)
        and ";z=q08,x00" in invariant
        and ";o=m0,e0,x0,g0" in invariant
    )
    rendered = " ".join((failure, split, label, invariant, public_message))
    _require_fixed(
        q78_is_exact and split_is_complete,
        "q78 failure must retain a complete independent semantic split",
    )
    _require_fixed(
        connection.queries_are_read_only,
        "q78 split probes must remain read-only and unstamped",
    )
    _require_fixed(
        canary not in rendered and "none" not in label,
        "q78 diagnostics must not expose server content or none",
    )


@pytest.mark.asyncio
async def test_postgres_q78_cancellation_propagates() -> None:
    from ares.db.postgres import PostgresDatabase

    class _CancelledQ78Connection(_Q78FailureConnection):
        async def fetch(self, query: str, *args: object) -> object:
            normalized = " ".join(query.split()).upper()
            if (
                "FROM PG_INDEX AS IND" in normalized
                and "IND.INDKEY::SMALLINT[]" not in normalized
            ):
                raise asyncio.CancelledError
            return await super().fetch(query, *args)

    propagated = False
    try:
        await PostgresDatabase._validate_websocket_ticket_schema(
            _CancelledQ78Connection("closed-cancellation-probe")
        )
    except asyncio.CancelledError:
        propagated = True
    _require_fixed(
        propagated,
        "q78 cancellation must propagate without classification",
    )


def test_postgres_managed_constraint_identifier_normalization() -> None:
    from ares.db.postgres import _postgres_constraint_definition

    unquoted = _postgres_constraint_definition(
        "CHECK (isfinite(timestamp))"
    )
    quoted_lowercase = _postgres_constraint_definition(
        'CHECK (isfinite("timestamp"))'
    )
    quoted_case_sensitive = _postgres_constraint_definition(
        'CHECK (isfinite("Timestamp"))'
    )

    _require_fixed(
        quoted_lowercase == unquoted,
        "managed constraint lowercase identifier normalization changed",
    )
    _require_fixed(
        quoted_case_sensitive != unquoted,
        "managed constraint case-sensitive identifier was weakened",
    )


def test_postgres_ticket_column_census_distinguishes_every_dimension() -> None:
    from ares.db.postgres import _postgres_ticket_column_census

    expected = _expected_ticket_column_contract()
    canonical = _canonical_ticket_columns()
    zero = _postgres_ticket_column_census(canonical, expected)
    _require_fixed(
        not any(zero.values()),
        "Canonical ticket columns must produce a zero census",
    )

    codec = [dict(row) for row in canonical]
    for row in codec:
        row["attidentity"] = b"\x00"
        row["attgenerated"] = b"\x00"
    codec_result = _postgres_ticket_column_census(codec, expected)
    _require_fixed(
        codec_result["a"] == 0x3FFF
        and sum(codec_result.values()) == 0x3FFF,
        "Known internal-character codecs require only alternate bits",
    )

    mutations: tuple[tuple[str, object, str], ...] = (
        ("data_type", "integer", "t"),
        ("attnotnull", False, "u"),
        ("column_default", "now()", "d"),
        ("collation_is_default", False, "l"),
        ("attidentity", "d", "i"),
    )
    dimensions_are_distinct = True
    for source_field, value, census_field in mutations:
        rows = [dict(row) for row in canonical]
        rows[0][source_field] = value
        result = _postgres_ticket_column_census(rows, expected)
        dimensions_are_distinct = (
            dimensions_are_distinct
            and result[census_field] == 0x001
            and sum(result.values()) == 0x001
        )
    _require_fixed(
        dimensions_are_distinct,
        "Column mutations require distinct bounded census dimensions",
    )

    missing = _postgres_ticket_column_census(canonical[1:], expected)
    extra_rows = [dict(row) for row in canonical]
    extra = dict(canonical[-1])
    extra["column_name"] = "closed-test-extra"
    extra_rows.append(extra)
    extra_result = _postgres_ticket_column_census(extra_rows, expected)
    reordered_rows = [dict(row) for row in canonical]
    reordered_rows[0], reordered_rows[1] = reordered_rows[1], reordered_rows[0]
    reordered = _postgres_ticket_column_census(reordered_rows, expected)
    unexpected_rows = [dict(row) for row in canonical]
    unexpected_rows[0]["attidentity"] = object()
    unexpected = _postgres_ticket_column_census(unexpected_rows, expected)
    _require_fixed(
        missing["m"] == 0x001
        and missing["o"] != 0
        and extra_result["e"] == 1
        and reordered["o"] == 0x003
        and unexpected["x"] == 0x001,
        "Missing, extra, order, and shape failures require distinct fields",
    )


def test_postgres_ticket_census_reports_cross_group_mutations_together() -> None:
    from ares.db.postgres import (
        _new_postgres_ticket_schema_census,
        _postgres_ticket_schema_census_invariant,
    )

    census = _new_postgres_ticket_schema_census()
    census["c"]["t"] = 0x001
    census["q"]["s"] = 0x0002
    census["f"]["d"] = 0x4
    census["i"]["a"] = 0x08
    invariant = _postgres_ticket_schema_census_invariant(census)
    all_mutations_survive = all(
        fragment in invariant
        for fragment in ("t0001", "s0002", "d4", "a08")
    )
    _require_fixed(
        all_mutations_survive,
        "Independent later-group mutations must survive one census payload",
    )


@pytest.mark.asyncio
async def test_postgres_ticket_validator_censuses_all_later_groups() -> None:
    from ares.db.postgres import (
        PostgresDatabase,
        _is_postgres_ticket_schema_census,
        _PostgresStartupDiagnosticError,
    )

    try:
        await PostgresDatabase._validate_websocket_ticket_schema(
            _CompleteTicketCensusConnection()
        )
    except _PostgresStartupDiagnosticError as exc:
        invariant = exc.diagnostic_invariant
    else:
        pytest.fail("Alternate catalog codecs must remain rejected", pytrace=False)

    complete = (
        _is_postgres_ticket_schema_census(invariant)
        and "c=m0000,e0,o0000,t0000,u0000,d0000,l0000,i0000,a3fff,x0000,g0"
        in invariant
        and "q=m0000,e0,t0000,v0000,f0000,d0000,s0000,b0000,affff,x0000,g0"
        in invariant
        and "h=t000,v000,f000,d000,s000,a7ff,x000,g0" in invariant
        and "f=l0,s0,t0,r0,u0,d0,i0,af,x0,g0" in invariant
        and "i=m00,e0,o00,b00,u00,p00,v00,r00,l00,k00,n00,c00,d00,a00,j00,s00,t00,y00,h3f,x00,g0"
        in invariant
        and ";o=m0,e0,x0,g0;z=q00,x00" in invariant
    )
    _require_fixed(
        complete,
        "A column rejection must retain canonical and alternate later groups",
    )


@pytest.mark.asyncio
async def test_postgres_startup_diagnostics_are_distinct_and_sanitized() -> None:
    from ares.db.postgres import (
        PostgresDatabase,
        _is_postgres_ticket_schema_census,
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
    relation_invariant = getattr(
        relation_query_failure,
        "diagnostic_invariant",
        "",
    )
    relation_q78_failure = getattr(
        relation_query_failure,
        "q78_failure",
        "",
    )
    relation_q78_split = getattr(
        relation_query_failure,
        "q78_split",
        "",
    )
    labels_are_exact = labels[:5] == (
        "ownership:ownership-relation-query:database",
        "fallback-ddl:campaigns-table:database",
        "fallback-validation:ticket-columns:none",
        "unclassified",
        "unclassified",
    ) and _is_postgres_ticket_schema_census(relation_invariant)
    complete_query_failure = (
        ";z=q7f,x00" in relation_invariant
        and "r=m000,a000,x000,n3ff,g0" in relation_invariant
        and relation_q78_failure
        == "q78:asyncpg-codec:state=-----:category=attribute"
        and relation_q78_split.endswith(";z=qf")
        and "none" not in labels[5]
    )
    _require_fixed(
        labels_are_exact and complete_query_failure,
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

        dsn = _runtime_dsn(config, test_database)
        try:
            await _initialize_managed_schema(dsn)
        except Exception as exc:
            raise _sanitized_setup_failure("alembic-upgrade", exc) from None
        database = PostgresDatabase(
            dsn,
            pool_min=1,
            pool_max=2,
        )
        try:
            await database.connect()
        except Exception as exc:
            raise _sanitized_setup_failure("runtime-initialize", exc) from None
        runtime_connected = True
        initial_trace_is_exact = tuple(database._startup_trace) == ("startup-ready",)
        _require_fixed(
            initial_trace_is_exact,
            "Managed runtime startup must validate without fallback DDL",
        )

        async with database._pool.acquire() as connection:
            managed_revision_is_current = bool(
                await connection.fetchval(
                    """
                    SELECT EXISTS(
                        SELECT 1 FROM alembic_version
                        WHERE version_num='0011'
                    )
                    """
                )
            )
            _require_fixed(
                managed_revision_is_current,
                "Runtime smoke must use exact managed revision 0011",
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
                [
                    "api_keys",
                    "refresh_tokens",
                    "refresh_token_families",
                    "revoked_access_tokens",
                ],
            )
            assert {row["table_name"] for row in table_rows} == {
                "api_keys",
                "refresh_tokens",
                "refresh_token_families",
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
                "idx_apikeys_user",
                "idx_apikeys_prefix",
                "idx_refresh_user",
                "idx_refresh_exp",
                "idx_rat_expires",
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
            from ares.core.token_sessions import (
                generate_family_id,
                generate_refresh_token,
                hash_refresh_token,
            )

            created_at = datetime.now(timezone.utc)
            expires_at = created_at + timedelta(days=30)
            retain_until = expires_at + timedelta(days=30)
            family_id = generate_family_id()
            refresh_row_id = hash_refresh_token(generate_refresh_token())
            await connection.execute(
                """
                INSERT INTO refresh_token_families(
                    id,user_id,auth_epoch,state,created_at,
                    absolute_expires_at,retain_until
                ) VALUES($1,$2,1,'active',$3,$4,$5)
                """,
                family_id,
                user_id,
                created_at,
                expires_at,
                retain_until,
            )
            await connection.execute(
                """
                INSERT INTO refresh_tokens(
                    id,user_id,is_revoked,expires_at,created_at,family_id,
                    parent_id,generation,state,revoked_at
                ) VALUES($1,$2,0,$3,$4,$5,NULL,0,'active',NULL)
                """,
                refresh_row_id,
                user_id,
                expires_at,
                created_at,
                family_id,
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
            "startup-ready",
        )
        _require_fixed(
            reconnect_trace_is_exact,
            "Managed runtime reconnect must not execute fallback DDL",
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
