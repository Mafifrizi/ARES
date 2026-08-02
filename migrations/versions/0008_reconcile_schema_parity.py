"""Reconcile audited historical and runtime schema variants.

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-31 00:00:00

Revision 0008 is deliberately forward-only.  It accepts only the audited
revision-0007 catalog variants, validates all data needed by stronger
constraints before changing the catalog, and converges them on the repaired
Alembic contract.  Unknown or unsafe catalogs fail without mutation.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None


_CATALOG_ERROR = "Incompatible catalog for migration 0008"
_DATA_ERROR = "Unsafe data for migration 0008"
_DOWNGRADE_ERROR = "Migration 0008 is forward-only"
_DIALECT_ERROR = "Unsupported migration dialect"
_TEMP_PREFIX = "__ares_m0008_"

_Column = tuple[str, str, bool, str | None, int]
_ForeignKey = tuple[str, str, str, str, str]


def _column(
    name: str,
    kind: str,
    nullable: bool,
    default: str | None = None,
    primary_key: int = 0,
) -> _Column:
    return name, kind, nullable, default, primary_key


_SQLITE_COLUMNS: dict[str, tuple[_Column, ...]] = {
    "schema_version": (
        _column("version", "INTEGER", False, primary_key=1),
        _column("applied_at", "TEXT", False, "datetime('now')"),
    ),
    "campaigns": (
        _column("id", "TEXT", False, primary_key=1),
        _column("name", "TEXT", False),
        _column("client", "TEXT", False, "Internal"),
        _column("operator", "TEXT", False, "unknown"),
        _column("noise_profile", "TEXT", False, "stealth"),
        _column("status", "TEXT", False, "created"),
        _column("scope_json", "TEXT", False, "[]"),
        _column("targets_json", "TEXT", False, "[]"),
        _column("notes", "TEXT", True, ""),
        _column("created_at", "TEXT", False, "datetime('now')"),
        _column("updated_at", "TEXT", False, "datetime('now')"),
    ),
    "module_runs": (
        _column("id", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("module_id", "TEXT", False),
        _column("outcome", "TEXT", False),
        _column("success", "INTEGER", False, "0"),
        _column("duration_ms", "FLOAT", False, "0.0"),
        _column("completed_at", "TEXT", False, "datetime('now')"),
    ),
    "findings": (
        _column("id", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("module_id", "TEXT", False),
        _column("title", "TEXT", False),
        _column("description", "TEXT", False),
        _column("severity", "TEXT", False),
        _column("confidence", "FLOAT", False, "1.0"),
        _column("mitre_technique", "TEXT", True),
        _column("mitre_tactic", "TEXT", True),
        _column("cvss_score", "FLOAT", False, "0.0"),
        _column("cvss_vector", "TEXT", False, ""),
        _column("evidence_json", "TEXT", False, "{}"),
        _column("remediation", "TEXT", True, ""),
        _column("host", "TEXT", True),
        _column("validated", "INTEGER", False, "0"),
        _column("false_positive", "INTEGER", False, "0"),
        _column("discovered_at", "TEXT", False, "datetime('now')"),
        _column("trace_id", "TEXT", False, ""),
    ),
    "hosts": (
        _column("id", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("ip_address", "TEXT", False),
        _column("hostname", "TEXT", True),
        _column("fqdn", "TEXT", True),
        _column("os", "TEXT", True),
        _column("os_version", "TEXT", True),
        _column("domain", "TEXT", True),
        _column("is_dc", "INTEGER", False, "0"),
        _column("open_ports_json", "TEXT", False, "[]"),
        _column("tags_json", "TEXT", False, "[]"),
        _column("first_seen", "TEXT", False, "datetime('now')"),
        _column("last_seen", "TEXT", False, "datetime('now')"),
    ),
    "credentials": (
        _column("id", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("host_id", "TEXT", True),
        _column("username", "TEXT", False),
        _column("secret_enc", "TEXT", True),
        _column("cred_type", "TEXT", False),
        _column("domain", "TEXT", True),
        _column("source_module", "TEXT", True),
        _column("notes", "TEXT", True, ""),
        _column("cracked", "INTEGER", False, "0"),
        _column("cracked_value_enc", "TEXT", True),
        _column("captured_at", "TEXT", False, "datetime('now')"),
    ),
    "loot": (
        _column("id", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("host_id", "TEXT", True),
        _column("loot_type", "TEXT", False),
        _column("name", "TEXT", False),
        _column("description", "TEXT", True, ""),
        _column("content_enc", "TEXT", True),
        _column("size_bytes", "INTEGER", True, "0"),
        _column("path_on_target", "TEXT", True),
        _column("source_module", "TEXT", True),
        _column("tags_json", "TEXT", False, "[]"),
        _column("captured_at", "TEXT", False, "datetime('now')"),
    ),
    "audit_log": (
        _column("id", "INTEGER", False, primary_key=1),
        _column("campaign_id", "TEXT", True),
        _column("actor", "TEXT", False, "system"),
        _column("action", "TEXT", False),
        _column("detail", "TEXT", True, ""),
        _column("module_id", "TEXT", True),
        _column("timestamp", "TEXT", False, "datetime('now')"),
    ),
    "users": (
        _column("id", "TEXT", False, primary_key=1),
        _column("username", "TEXT", False),
        _column("hashed_password", "TEXT", False),
        _column("role", "TEXT", False, "reporter"),
        _column("is_active", "INTEGER", False, "1"),
        _column("created_by", "TEXT", False, "system"),
        _column("created_at", "TEXT", False, "datetime('now')"),
        _column("last_login", "TEXT", True),
    ),
    "api_keys": (
        _column("id", "TEXT", False, primary_key=1),
        _column("user_id", "TEXT", False),
        _column("name", "TEXT", False),
        _column("key_hash", "TEXT", False),
        _column("key_prefix", "TEXT", False),
        _column("scopes", "TEXT", False, "read"),
        _column("is_active", "INTEGER", False, "1"),
        _column("last_used", "TEXT", True),
        _column("expires_at", "TEXT", True),
        _column("created_at", "TEXT", False, "datetime('now')"),
    ),
    "refresh_tokens": (
        _column("id", "TEXT", False, primary_key=1),
        _column("user_id", "TEXT", False),
        _column("is_revoked", "INTEGER", False, "0"),
        _column("expires_at", "TEXT", False),
        _column("created_at", "TEXT", False, "datetime('now')"),
        _column("used_at", "TEXT", True),
    ),
    "rate_limit_events": (
        _column("id", "INTEGER", False, primary_key=1),
        _column("ip_address", "TEXT", False),
        _column("bucket", "TEXT", False),
        _column("username", "TEXT", True),
        _column("blocked", "INTEGER", False, "0"),
        _column("timestamp", "TEXT", False, "datetime('now')"),
    ),
    "revoked_access_tokens": (
        _column("jti", "TEXT", False, primary_key=1),
        _column("user_id", "TEXT", False),
        _column("revoked_at", "TEXT", False, "datetime('now')"),
        _column("expires_at", "TEXT", False),
    ),
    "websocket_tickets": (
        _column("ticket_hash", "TEXT", False, primary_key=1),
        _column("campaign_id", "TEXT", False),
        _column("user_id", "TEXT", False),
        _column("credential_kind", "TEXT", False),
        _column("bearer_subject", "TEXT", True),
        _column("bearer_jti", "TEXT", True),
        _column("bearer_expires_at", "TEXT", True),
        _column("api_key_id", "TEXT", True),
        _column("required_scope", "TEXT", True),
        _column("created_at", "TEXT", False),
        _column("expires_at", "TEXT", False),
        _column("consumed_at", "TEXT", True),
    ),
}

_SQLITE_FOREIGN_KEYS: dict[str, frozenset[_ForeignKey]] = {
    "module_runs": frozenset(
        {("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE")}
    ),
    "findings": frozenset(
        {("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE")}
    ),
    "hosts": frozenset(
        {("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE")}
    ),
    "credentials": frozenset(
        {
            ("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE"),
            ("host_id", "hosts", "id", "NO ACTION", "SET NULL"),
        }
    ),
    "loot": frozenset(
        {
            ("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE"),
            ("host_id", "hosts", "id", "NO ACTION", "SET NULL"),
        }
    ),
    "audit_log": frozenset(
        {("campaign_id", "campaigns", "id", "NO ACTION", "SET NULL")}
    ),
    "api_keys": frozenset(
        {("user_id", "users", "id", "NO ACTION", "CASCADE")}
    ),
    "refresh_tokens": frozenset(
        {("user_id", "users", "id", "NO ACTION", "CASCADE")}
    ),
    "websocket_tickets": frozenset(
        {
            ("campaign_id", "campaigns", "id", "NO ACTION", "CASCADE"),
            ("user_id", "users", "id", "NO ACTION", "CASCADE"),
            ("api_key_id", "api_keys", "id", "NO ACTION", "CASCADE"),
        }
    ),
}

_SQLITE_INDEXES: dict[str, dict[str, tuple[str, ...]]] = {
    "module_runs": {
        "idx_module_runs_campaign": ("campaign_id",),
        "idx_module_runs_completed": ("completed_at",),
    },
    "findings": {
        "idx_findings_campaign": ("campaign_id",),
        "idx_findings_severity": ("severity",),
        "idx_findings_fp": ("false_positive",),
        "idx_findings_mitre": ("mitre_technique",),
        "idx_findings_cvss": ("cvss_score",),
    },
    "hosts": {
        "idx_hosts_campaign": ("campaign_id",),
        "idx_hosts_ip": ("ip_address",),
        "idx_hosts_domain": ("domain",),
    },
    "credentials": {
        "idx_creds_campaign": ("campaign_id",),
        "idx_creds_username": ("username",),
        "idx_creds_type": ("cred_type",),
    },
    "loot": {
        "idx_loot_campaign": ("campaign_id",),
        "idx_loot_type": ("loot_type",),
    },
    "audit_log": {
        "idx_audit_campaign": ("campaign_id",),
        "idx_audit_actor": ("actor",),
        "idx_audit_action": ("action",),
    },
    "users": {
        "idx_users_username": ("username",),
        "idx_users_role": ("role",),
    },
    "api_keys": {
        "idx_apikeys_user": ("user_id",),
        "idx_apikeys_prefix": ("key_prefix",),
    },
    "refresh_tokens": {
        "idx_refresh_user": ("user_id",),
        "idx_refresh_exp": ("expires_at",),
    },
    "rate_limit_events": {
        "idx_rle_ip": ("ip_address",),
        "idx_rle_timestamp": ("timestamp",),
        "idx_rle_blocked": ("blocked",),
    },
    "revoked_access_tokens": {
        "idx_rat_expires": ("expires_at",),
    },
    "websocket_tickets": {
        "idx_ws_tickets_expires": ("expires_at",),
        "idx_ws_tickets_user": ("user_id",),
        "idx_ws_tickets_campaign": ("campaign_id",),
        "idx_ws_tickets_api_key": ("api_key_id",),
    },
}

_REBUILD_ORDER = (
    "schema_version",
    "campaigns",
    "users",
    "revoked_access_tokens",
    "hosts",
    "module_runs",
    "findings",
    "credentials",
    "loot",
    "audit_log",
    "api_keys",
    "refresh_tokens",
    "rate_limit_events",
    "websocket_tickets",
)
_DROP_ORDER = (
    "websocket_tickets",
    "credentials",
    "loot",
    "module_runs",
    "findings",
    "hosts",
    "refresh_tokens",
    "api_keys",
    "audit_log",
    "rate_limit_events",
    "revoked_access_tokens",
    "users",
    "campaigns",
    "schema_version",
)

_SQLITE_TIMESTAMPS: dict[str, tuple[str, ...]] = {
    "schema_version": ("applied_at",),
    "campaigns": ("created_at", "updated_at"),
    "module_runs": ("completed_at",),
    "findings": ("discovered_at",),
    "hosts": ("first_seen", "last_seen"),
    "credentials": ("captured_at",),
    "loot": ("captured_at",),
    "audit_log": ("timestamp",),
    "users": ("created_at", "last_login"),
    "api_keys": ("last_used", "expires_at", "created_at"),
    "refresh_tokens": ("expires_at", "created_at", "used_at"),
    "rate_limit_events": ("timestamp",),
    "revoked_access_tokens": ("revoked_at", "expires_at"),
    "websocket_tickets": (
        "bearer_expires_at",
        "created_at",
        "expires_at",
        "consumed_at",
    ),
}

_BOOLEAN_INTEGER_COLUMNS = (
    ("module_runs", "success"),
    ("findings", "validated"),
    ("findings", "false_positive"),
    ("hosts", "is_dc"),
    ("credentials", "cracked"),
    ("users", "is_active"),
    ("api_keys", "is_active"),
    ("refresh_tokens", "is_revoked"),
    ("rate_limit_events", "blocked"),
)

_SQLITE_TEXT_PRIMARY_KEYS = {
    "alembic_version": "version_num",
    "campaigns": "id",
    "module_runs": "id",
    "findings": "id",
    "hosts": "id",
    "credentials": "id",
    "loot": "id",
    "users": "id",
    "api_keys": "id",
    "refresh_tokens": "id",
    "revoked_access_tokens": "jti",
    "websocket_tickets": "ticket_hash",
}

_SQLITE_INTEGER_PRIMARY_KEYS = frozenset(
    {"schema_version", "audit_log", "rate_limit_events"}
)

_SQLITE_RESERVED_INDEX_OWNERS = {
    name: table
    for table, indexes in _SQLITE_INDEXES.items()
    for name in indexes
}
_SQLITE_RESERVED_INDEX_OWNERS["idx_findings_validated"] = "findings"


def _normalize_default(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    while (
        len(normalized) >= 2
        and normalized[0] == "("
        and normalized[-1] == ")"
    ):
        normalized = normalized[1:-1].strip()
    normalized = re.sub(r"::(?:text|double precision|integer)$", "", normalized)
    if (
        len(normalized) >= 2
        and normalized[0] == "'"
        and normalized[-1] == "'"
    ):
        normalized = normalized[1:-1].replace("''", "'")
    return " ".join(normalized.split())


def _pg_defaults_match(
    actual: str | None,
    expected: str | None,
    data_type: str,
) -> bool:
    if actual == expected:
        return True
    if data_type != "double precision" or actual is None or expected is None:
        return False
    try:
        actual_number = Decimal(actual)
        expected_number = Decimal(expected)
    except InvalidOperation:
        return False
    return (
        actual_number.is_finite()
        and expected_number.is_finite()
        and actual_number == expected_number
    )


def _sqlite_columns(bind: Any, table: str) -> tuple[_Column, ...]:
    rows = bind.exec_driver_sql(f'PRAGMA table_info("{table}")').fetchall()
    return tuple(
        (
            str(row[1]),
            str(row[2]).upper(),
            not bool(row[3]),
            _normalize_default(row[4]),
            int(row[5]),
        )
        for row in rows
    )


def _sqlite_foreign_keys(bind: Any, table: str) -> tuple[_ForeignKey, ...]:
    rows = bind.exec_driver_sql(
        f'PRAGMA foreign_key_list("{table}")'
    ).fetchall()
    return tuple(
        sorted(
            (
                str(row[3]),
                str(row[2]),
                str(row[4]),
                str(row[5]).upper(),
                str(row[6]).upper(),
            )
            for row in rows
        )
    )


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _require_sqlite_primary_key_index(bind: Any, table: str) -> None:
    rows = bind.exec_driver_sql(
        f'PRAGMA index_list({_quote_sqlite_identifier(table)})'
    ).fetchall()
    primary_rows = [row for row in rows if str(row[3]) == "pk"]
    expected_column = _SQLITE_TEXT_PRIMARY_KEYS.get(table)
    if expected_column is None:
        if table not in _SQLITE_INTEGER_PRIMARY_KEYS or primary_rows:
            raise RuntimeError(_CATALOG_ERROR)
        return
    if (
        len(primary_rows) != 1
        or not bool(primary_rows[0][2])
        or bool(primary_rows[0][4])
    ):
        raise RuntimeError(_CATALOG_ERROR)
    opaque_name = str(primary_rows[0][1])
    schema_rows = bind.execute(
        sa.text(
            "SELECT type, tbl_name, sql FROM sqlite_schema "
            "WHERE name=:name"
        ),
        {"name": opaque_name},
    ).fetchall()
    if (
        len(schema_rows) != 1
        or str(schema_rows[0][0]) != "index"
        or str(schema_rows[0][1]) != table
        or schema_rows[0][2] is not None
    ):
        raise RuntimeError(_CATALOG_ERROR)
    details = bind.exec_driver_sql(
        f'PRAGMA index_xinfo({_quote_sqlite_identifier(opaque_name)})'
    ).fetchall()
    if len(details) != 2:
        raise RuntimeError(_CATALOG_ERROR)
    key_rows = [row for row in details if bool(row[5])]
    auxiliary_rows = [row for row in details if not bool(row[5])]
    if (
        len(key_rows) != 1
        or int(key_rows[0][0]) != 0
        or int(key_rows[0][1]) < 0
        or str(key_rows[0][2]) != expected_column
        or bool(key_rows[0][3])
        or str(key_rows[0][4]).upper() != "BINARY"
        or len(auxiliary_rows) != 1
        or int(auxiliary_rows[0][0]) != 1
        or int(auxiliary_rows[0][1]) != -1
        or auxiliary_rows[0][2] is not None
        or bool(auxiliary_rows[0][3])
        or str(auxiliary_rows[0][4]).upper() != "BINARY"
    ):
        raise RuntimeError(_CATALOG_ERROR)


def _require_sqlite_reserved_index_ownership(bind: Any) -> None:
    rows = bind.execute(
        sa.text("SELECT type, name, tbl_name FROM sqlite_schema")
    ).fetchall()
    for row in rows:
        name = str(row[1])
        owner = _SQLITE_RESERVED_INDEX_OWNERS.get(name)
        if owner is None:
            continue
        if str(row[0]) != "index" or str(row[2]) != owner:
            raise RuntimeError(_CATALOG_ERROR)


def _require_sqlite_managed_name_ownership(bind: Any) -> None:
    managed_tables = set(_REBUILD_ORDER) | {"alembic_version"}
    rows = bind.execute(
        sa.text("SELECT type, name, tbl_name FROM sqlite_schema")
    ).fetchall()
    for row in rows:
        name = str(row[1])
        if name in managed_tables and (
            str(row[0]) != "table" or str(row[2]) != name
        ):
            raise RuntimeError(_CATALOG_ERROR)


def _require_no_sqlite_temp_shadows(bind: Any) -> None:
    managed_tables = set(_REBUILD_ORDER) | {"alembic_version"}
    reserved_indexes = set(_SQLITE_RESERVED_INDEX_OWNERS)
    rows = bind.execute(
        sa.text("SELECT type, name, tbl_name FROM sqlite_temp_master")
    ).fetchall()
    for row in rows:
        object_type = str(row[0])
        name = str(row[1])
        owner = str(row[2])
        if (
            name in managed_tables
            or name in reserved_indexes
            or name.startswith(_TEMP_PREFIX)
            or (object_type == "trigger" and owner in managed_tables)
        ):
            raise RuntimeError(_CATALOG_ERROR)


def _require_sqlite_alembic_version_relation(bind: Any) -> None:
    rows = bind.execute(
        sa.text(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name='alembic_version' OR tbl_name='alembic_version'"
        )
    ).fetchall()
    if (
        len(rows) != 2
        or sum(
            1
            for row in rows
            if str(row[0]) == "table"
            and str(row[1]) == "alembic_version"
            and str(row[2]) == "alembic_version"
            and isinstance(row[3], str)
        )
        != 1
        or sum(
            1
            for row in rows
            if str(row[0]) == "index"
            and str(row[2]) == "alembic_version"
            and row[3] is None
        )
        != 1
    ):
        raise RuntimeError(_CATALOG_ERROR)
    if _sqlite_columns(bind, "alembic_version") != (
        _column("version_num", "VARCHAR(32)", False, primary_key=1),
    ):
        raise RuntimeError(_CATALOG_ERROR)
    physical_columns = bind.exec_driver_sql(
        'PRAGMA table_xinfo("alembic_version")'
    ).fetchall()
    if (
        len(physical_columns) != 1
        or int(physical_columns[0][0]) != 0
        or str(physical_columns[0][1]) != "version_num"
        or str(physical_columns[0][2]).upper() != "VARCHAR(32)"
        or not bool(physical_columns[0][3])
        or physical_columns[0][4] is not None
        or int(physical_columns[0][5]) != 1
        or int(physical_columns[0][6]) != 0
    ):
        raise RuntimeError(_CATALOG_ERROR)
    normalized_sql = _sqlite_table_sql(bind, "alembic_version")
    if normalized_sql != (
        "createtablealembic_version("
        "version_numvarchar(32)notnull,"
        "constraintalembic_version_pkcprimarykey(version_num))"
    ):
        raise RuntimeError(_CATALOG_ERROR)
    _require_sqlite_primary_key_index(bind, "alembic_version")
    values = tuple(
        str(row[0])
        for row in bind.exec_driver_sql(
            "SELECT version_num FROM main.alembic_version"
        ).fetchall()
    )
    if values != ("0007",):
        raise RuntimeError(_CATALOG_ERROR)


def _require_sqlite_table_shape_metadata(bind: Any, table: str) -> None:
    rows = bind.exec_driver_sql(
        f'PRAGMA table_xinfo({_quote_sqlite_identifier(table)})'
    ).fetchall()
    if (
        len(rows) != len(_sqlite_columns(bind, table))
        or any(int(row[6]) != 0 for row in rows)
    ):
        raise RuntimeError(_CATALOG_ERROR)
    raw_sql = _sqlite_raw_table_sql(bind, table)
    if table in {
        "audit_log",
        "rate_limit_events",
        "websocket_tickets",
    } and ("--" in raw_sql or "/*" in raw_sql or "*/" in raw_sql):
        raise RuntimeError(_CATALOG_ERROR)
    if any(
        re.search(pattern, raw_sql, re.IGNORECASE)
        for pattern in (
            r"\bCOLLATE\b",
            r"\bWITHOUT\s+ROWID\b",
            r"\bSTRICT\b",
            r"\bON\s+CONFLICT\b",
            r"\bGENERATED\b",
            r"\bDEFERRABLE\b",
            r"\bINITIALLY\s+(?:DEFERRED|IMMEDIATE)\b",
            r"\bMATCH\s+\w+\b",
        )
    ):
        raise RuntimeError(_CATALOG_ERROR)


def _sqlite_unique_contracts(
    bind: Any,
    table: str,
) -> tuple[tuple[str, ...], ...]:
    contracts: list[tuple[str, ...]] = []
    rows = bind.exec_driver_sql(f'PRAGMA index_list("{table}")').fetchall()
    for row in rows:
        if str(row[3]) != "u":
            continue
        if not bool(row[2]) or bool(row[4]):
            raise RuntimeError(_CATALOG_ERROR)
        name = str(row[1])
        schema_rows = bind.execute(
            sa.text(
                "SELECT type, tbl_name, sql FROM sqlite_schema "
                "WHERE name=:name"
            ),
            {"name": name},
        ).fetchall()
        if (
            len(schema_rows) != 1
            or str(schema_rows[0][0]) != "index"
            or str(schema_rows[0][1]) != table
            or schema_rows[0][2] is not None
        ):
            raise RuntimeError(_CATALOG_ERROR)
        details = bind.exec_driver_sql(
            f'PRAGMA index_xinfo({_quote_sqlite_identifier(name)})'
        ).fetchall()
        key_columns = [column for column in details if bool(column[5])]
        auxiliary_columns = [
            column for column in details if not bool(column[5])
        ]
        if (
            not key_columns
            or tuple(int(column[0]) for column in key_columns)
            != tuple(range(len(key_columns)))
            or any(
                int(column[1]) < 0
                or column[2] is None
                or bool(column[3])
                or str(column[4]).upper() != "BINARY"
                for column in key_columns
            )
            or len(auxiliary_columns) != 1
            or int(auxiliary_columns[0][0]) != len(key_columns)
            or int(auxiliary_columns[0][1]) != -1
            or auxiliary_columns[0][2] is not None
            or bool(auxiliary_columns[0][3])
            or str(auxiliary_columns[0][4]).upper() != "BINARY"
        ):
            raise RuntimeError(_CATALOG_ERROR)
        contracts.append(
            tuple(str(column[2]) for column in key_columns)
        )
    return tuple(sorted(contracts))


def _sqlite_indexes(bind: Any, table: str) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    rows = bind.exec_driver_sql(f'PRAGMA index_list("{table}")').fetchall()
    for row in rows:
        name = str(row[1])
        origin = str(row[3])
        partial = bool(row[4])
        if origin != "c":
            continue
        if bool(row[2]) or partial:
            raise RuntimeError(_CATALOG_ERROR)
        details = bind.exec_driver_sql(
            f'PRAGMA index_xinfo({_quote_sqlite_identifier(name)})'
        ).fetchall()
        key_columns = [column for column in details if bool(column[5])]
        auxiliary_columns = [
            column for column in details if not bool(column[5])
        ]
        if (
            not key_columns
            or tuple(int(column[0]) for column in key_columns)
            != tuple(range(len(key_columns)))
            or any(
                int(column[1]) < 0
                or column[2] is None
                or bool(column[3])
                or str(column[4]).upper() != "BINARY"
                for column in key_columns
            )
            or len(auxiliary_columns) != 1
            or int(auxiliary_columns[0][0]) != len(key_columns)
            or int(auxiliary_columns[0][1]) != -1
            or auxiliary_columns[0][2] is not None
            or bool(auxiliary_columns[0][3])
            or str(auxiliary_columns[0][4]).upper() != "BINARY"
        ):
            raise RuntimeError(_CATALOG_ERROR)
        schema_rows = bind.execute(
            sa.text(
                "SELECT type, tbl_name, sql FROM sqlite_schema "
                "WHERE name=:name"
            ),
            {"name": name},
        ).fetchall()
        if (
            len(schema_rows) != 1
            or str(schema_rows[0][0]) != "index"
            or str(schema_rows[0][1]) != table
            or not isinstance(schema_rows[0][2], str)
        ):
            raise RuntimeError(_CATALOG_ERROR)
        normalized_sql = re.sub(
            r"\s+",
            "",
            str(schema_rows[0][2]),
        ).lower().replace('"', "")
        expected_sql = (
            f"createindex{name.lower()}on{table.lower()}("
            + ",".join(str(column[2]).lower() for column in key_columns)
            + ")"
        )
        if normalized_sql != expected_sql:
            raise RuntimeError(_CATALOG_ERROR)
        result[name] = tuple(str(column[2]) for column in key_columns)
    return result


def _sqlite_raw_table_sql(bind: Any, table: str) -> str:
    row = bind.execute(
        sa.text(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name=:name"
        ),
        {"name": table},
    ).scalar_one_or_none()
    if not isinstance(row, str):
        raise RuntimeError(_CATALOG_ERROR)
    return row


def _normalize_sql_syntax(
    value: object,
    *,
    strip_postgres_casts: bool = False,
) -> str:
    text = str(value)
    chunks: list[str] = []
    position = 0
    unquoted_start = 0

    def append_unquoted(segment: str) -> None:
        normalized = segment.lower().replace('"', "")
        if strip_postgres_casts:
            normalized = re.sub(
                r"::(?:text|double precision|integer|character varying)",
                "",
                normalized,
            )
        chunks.append(re.sub(r"\s+", "", normalized))

    while position < len(text):
        if text[position] != "'":
            position += 1
            continue
        append_unquoted(text[unquoted_start:position])
        literal_start = position
        position += 1
        while position < len(text):
            if text[position] != "'":
                position += 1
                continue
            if position + 1 < len(text) and text[position + 1] == "'":
                position += 2
                continue
            position += 1
            break
        else:
            raise RuntimeError(_CATALOG_ERROR)
        chunks.append(text[literal_start:position])
        unquoted_start = position
    append_unquoted(text[unquoted_start:])
    return "".join(chunks)


def _sqlite_table_sql(bind: Any, table: str) -> str:
    return _normalize_sql_syntax(_sqlite_raw_table_sql(bind, table))


def _sqlite_ticket_snapshot(bind: Any) -> tuple[object, ...]:
    rows = bind.execute(
        sa.text(
            "SELECT ticket_hash, campaign_id, user_id, credential_kind, "
            "bearer_subject, bearer_jti, bearer_expires_at, api_key_id, "
            "required_scope, created_at, expires_at, consumed_at "
            "FROM websocket_tickets ORDER BY ticket_hash"
        )
    ).fetchall()
    return tuple(
        tuple(value for value in row)
        for row in rows
    )


def _columns_compatible(
    table: str,
    actual: tuple[_Column, ...],
) -> bool:
    expected = _SQLITE_COLUMNS[table]
    actual_names = tuple(column[0] for column in actual)
    expected_names = tuple(column[0] for column in expected)
    allowed_orders = {expected_names}
    if table == "findings":
        runtime = list(expected_names)
        runtime.remove("trace_id")
        runtime.insert(runtime.index("evidence_json"), "trace_id")
        historical = (
            "id",
            "campaign_id",
            "module_id",
            "title",
            "description",
            "severity",
            "cvss_score",
            "cvss_vector",
            "confidence",
            "mitre_technique",
            "mitre_tactic",
            "evidence_json",
            "remediation",
            "host",
            "validated",
            "false_positive",
            "discovered_at",
            "trace_id",
        )
        allowed_orders.update({tuple(runtime), historical})
    elif table == "credentials":
        historical = list(expected_names)
        historical.remove("cracked_value_enc")
        historical.append("cracked_value_enc")
        allowed_orders.add(tuple(historical))
        source_only = tuple(
            "cracked_value" if name == "cracked_value_enc" else name
            for name in expected_names
        )
        historical_source_only = tuple(
            "cracked_value" if name == "cracked_value_enc" else name
            for name in historical
        )
        allowed_orders.update({source_only, historical_source_only})
    if actual_names not in allowed_orders:
        return False

    by_name = {column[0]: column for column in actual}
    for expected_column in expected:
        name, expected_type, expected_nullable, default, primary_key = (
            expected_column
        )
        source_name = (
            "cracked_value"
            if table == "credentials"
            and name == "cracked_value_enc"
            and name not in by_name
            else name
        )
        current = by_name[source_name]
        current_type = current[1]
        if (
            table in {"module_runs", "findings"}
            and name in {"duration_ms", "confidence", "cvss_score"}
        ):
            type_matches = current_type in {"FLOAT", "REAL"}
        else:
            type_matches = current_type == expected_type
        if not type_matches or current[3:] != (default, primary_key):
            return False
        if current[2] != expected_nullable:
            if not (
                table == "findings"
                and name in {"cvss_score", "cvss_vector", "trace_id"}
                and current[2]
                and not expected_nullable
            ) and not (
                primary_key == 1
                and current[2]
                and not expected_nullable
            ):
                return False
    return True


def _require_not_null_data(bind: Any, table: str) -> None:
    columns = [
        name
        for name, _kind, nullable, _default, _primary_key
        in _SQLITE_COLUMNS[table]
        if not nullable
    ]
    predicate = " OR ".join(f'"{name}" IS NULL' for name in columns)
    statement = (  # noqa: S608
        f'SELECT 1 FROM "{table}" WHERE {predicate} LIMIT 1'  # noqa: S608
    )
    if predicate and bind.exec_driver_sql(  # noqa: S608
        statement
    ).first():
        raise RuntimeError(_DATA_ERROR)


def _require_no_orphans(bind: Any) -> None:
    checks = (
        ("module_runs", "campaign_id", "campaigns", "id", False),
        ("findings", "campaign_id", "campaigns", "id", False),
        ("hosts", "campaign_id", "campaigns", "id", False),
        ("credentials", "campaign_id", "campaigns", "id", False),
        ("credentials", "host_id", "hosts", "id", True),
        ("loot", "campaign_id", "campaigns", "id", False),
        ("loot", "host_id", "hosts", "id", True),
        ("audit_log", "campaign_id", "campaigns", "id", True),
        ("api_keys", "user_id", "users", "id", False),
        ("refresh_tokens", "user_id", "users", "id", False),
        (
            "websocket_tickets",
            "campaign_id",
            "campaigns",
            "id",
            False,
        ),
        ("websocket_tickets", "user_id", "users", "id", False),
        (
            "websocket_tickets",
            "api_key_id",
            "api_keys",
            "id",
            True,
        ),
    )
    tables = set(sa.inspect(bind).get_table_names())
    for child, local, parent, remote, nullable in checks:
        if child not in tables:
            continue
        nullable_guard = f'child."{local}" IS NOT NULL AND ' if nullable else ""
        statement = (  # noqa: S608
            f'SELECT 1 FROM "{child}" AS child '  # noqa: S608
            f'LEFT JOIN "{parent}" AS parent '
            f'ON child."{local}"=parent."{remote}" '
            f'WHERE {nullable_guard}parent."{remote}" IS NULL LIMIT 1'
        )
        if bind.exec_driver_sql(statement).first():  # noqa: S608
            raise RuntimeError(_DATA_ERROR)


def _require_boolean_integer_data(
    bind: Any,
    tables: set[str],
) -> None:
    for table, column in _BOOLEAN_INTEGER_COLUMNS:
        if table not in tables:
            continue
        statement = (  # noqa: S608
            f'SELECT 1 FROM "{table}" '  # noqa: S608
            f'WHERE "{column}" NOT IN (0, 1) LIMIT 1'
        )
        if bind.exec_driver_sql(statement).first():
            raise RuntimeError(_DATA_ERROR)


def _require_valid_sqlite_timestamps(
    bind: Any,
    tables: set[str],
) -> None:
    for table, columns in _SQLITE_TIMESTAMPS.items():
        if table not in tables:
            continue
        for column in columns:
            statement = (  # noqa: S608
                f'SELECT 1 FROM "{table}" '  # noqa: S608
                f'WHERE "{column}" IS NOT NULL '
                f'AND julianday("{column}") IS NULL LIMIT 1'
            )
            if bind.exec_driver_sql(statement).first():
                raise RuntimeError(_DATA_ERROR)


def _require_valid_sqlite_ticket_data(
    bind: Any,
    tables: set[str],
) -> None:
    if "websocket_tickets" not in tables:
        return
    timestamp_format = "%Y-%m-%dT%H:%M:%fZ"
    statement = """
        SELECT 1
        FROM websocket_tickets
        WHERE COALESCE(
            (
                length(ticket_hash)=64
                AND ticket_hash NOT GLOB '*[^0-9a-f]*'
                AND credential_kind IN ('bearer', 'api_key')
                AND strftime(:timestamp_format, created_at) IS NOT NULL
                AND strftime(:timestamp_format, created_at)=created_at
                AND strftime(:timestamp_format, expires_at) IS NOT NULL
                AND strftime(:timestamp_format, expires_at)=expires_at
                AND (
                    consumed_at IS NULL
                    OR (
                        strftime(
                            :timestamp_format,
                            consumed_at
                        ) IS NOT NULL
                        AND strftime(
                            :timestamp_format,
                            consumed_at
                        )=consumed_at
                    )
                )
                AND julianday(expires_at) > julianday(created_at)
                AND (
                    consumed_at IS NULL
                    OR julianday(consumed_at) < julianday(expires_at)
                )
                AND (
                    (
                        credential_kind='bearer'
                        AND bearer_subject IS NOT NULL
                        AND length(trim(bearer_subject)) > 0
                        AND bearer_subject=trim(bearer_subject)
                        AND bearer_jti IS NOT NULL
                        AND length(trim(bearer_jti)) > 0
                        AND bearer_jti=trim(bearer_jti)
                        AND bearer_expires_at IS NOT NULL
                        AND strftime(
                            :timestamp_format,
                            bearer_expires_at
                        ) IS NOT NULL
                        AND strftime(
                            :timestamp_format,
                            bearer_expires_at
                        )=bearer_expires_at
                        AND api_key_id IS NULL
                        AND required_scope IS NULL
                    )
                    OR (
                        credential_kind='api_key'
                        AND bearer_subject IS NULL
                        AND bearer_jti IS NULL
                        AND bearer_expires_at IS NULL
                        AND api_key_id IS NOT NULL
                        AND length(trim(api_key_id)) > 0
                        AND api_key_id=trim(api_key_id)
                        AND required_scope='read'
                    )
                )
            ),
            0
        ) != 1
        LIMIT 1
    """
    if bind.execute(
        sa.text(statement),
        {"timestamp_format": timestamp_format},
    ).first():
        raise RuntimeError(_DATA_ERROR)


def _require_no_external_references(
    bind: Any,
    tables: set[str],
) -> None:
    rebuilt = set(_REBUILD_ORDER)
    for child in tables - rebuilt:
        for row in bind.exec_driver_sql(
            f'PRAGMA foreign_key_list("{child}")'  # noqa: S608
        ).fetchall():
            if str(row[2]) in rebuilt:
                raise RuntimeError(_CATALOG_ERROR)


def _require_ticket_contract(bind: Any) -> None:
    if _sqlite_columns(bind, "websocket_tickets") != _SQLITE_COLUMNS[
        "websocket_tickets"
    ]:
        raise RuntimeError(_CATALOG_ERROR)
    foreign_key_rows = bind.exec_driver_sql(
        'PRAGMA foreign_key_list("websocket_tickets")'
    ).fetchall()
    foreign_key_contracts = tuple(
        sorted(
            (
                str(row[3]),
                str(row[2]),
                str(row[4]),
                str(row[5]).upper(),
                str(row[6]).upper(),
                str(row[7]).upper(),
            )
            for row in foreign_key_rows
        )
    )
    expected_foreign_keys = tuple(
        sorted(
            (*contract, "NONE")
            for contract in _SQLITE_FOREIGN_KEYS["websocket_tickets"]
        )
    )
    if (
        len(foreign_key_rows) != len(expected_foreign_keys)
        or {int(row[0]) for row in foreign_key_rows}
        != set(range(len(expected_foreign_keys)))
        or any(int(row[1]) != 0 for row in foreign_key_rows)
        or foreign_key_contracts != expected_foreign_keys
    ):
        raise RuntimeError(_CATALOG_ERROR)
    if _sqlite_indexes(bind, "websocket_tickets") != _SQLITE_INDEXES[
        "websocket_tickets"
    ]:
        raise RuntimeError(_CATALOG_ERROR)
    raw_sql = _sqlite_raw_table_sql(bind, "websocket_tickets")
    if "--" in raw_sql or "/*" in raw_sql or "*/" in raw_sql:
        raise RuntimeError(_CATALOG_ERROR)
    sql = _sqlite_table_sql(bind, "websocket_tickets")
    required = (
        "constraintck_ws_ticket_hashcheck("
        "length(ticket_hash)=64andticket_hashnotglob'*[^0-9a-f]*')",
        "constraintck_ws_ticket_kindcheck("
        "credential_kindin('bearer','api_key'))",
        "constraintck_ws_ticket_created_atcheck("
        "strftime('%Y-%m-%dT%H:%M:%fZ',created_at)isnotnulland"
        "strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)",
        "constraintck_ws_ticket_expires_atcheck("
        "strftime('%Y-%m-%dT%H:%M:%fZ',expires_at)isnotnulland"
        "strftime('%Y-%m-%dT%H:%M:%fZ',expires_at)=expires_at)",
        "constraintck_ws_ticket_consumed_atcheck("
        "consumed_atisnullor(strftime('%Y-%m-%dT%H:%M:%fZ',"
        "consumed_at)isnotnullandstrftime('%Y-%m-%dT%H:%M:%fZ',"
        "consumed_at)=consumed_at))",
        "constraintck_ws_ticket_time_ordercheck("
        "julianday(expires_at)>julianday(created_at)and("
        "consumed_atisnullorjulianday(consumed_at)<"
        "julianday(expires_at)))",
        "constraintck_ws_ticket_source_shapecheck("
        "(credential_kind='bearer'andbearer_subjectisnotnulland"
        "length(trim(bearer_subject))>0and"
        "bearer_subject=trim(bearer_subject)andbearer_jtiisnotnulland"
        "length(trim(bearer_jti))>0andbearer_jti=trim(bearer_jti)and"
        "bearer_expires_atisnotnulland"
        "strftime('%Y-%m-%dT%H:%M:%fZ',bearer_expires_at)isnotnulland"
        "strftime('%Y-%m-%dT%H:%M:%fZ',bearer_expires_at)="
        "bearer_expires_atandapi_key_idisnullandrequired_scopeisnull)"
        "or(credential_kind='api_key'andbearer_subjectisnulland"
        "bearer_jtiisnullandbearer_expires_atisnulland"
        "api_key_idisnotnullandlength(trim(api_key_id))>0and"
        "api_key_id=trim(api_key_id)andrequired_scope='read'))",
    )
    foreign_key_names = (
        "constraintfk_ws_ticket_campaign",
        "constraintfk_ws_ticket_user",
        "constraintfk_ws_ticket_api_key",
    )
    table_level_foreign_keys = (
        "constraintfk_ws_ticket_campaignforeignkey(campaign_id)"
        "referencescampaigns(id)ondeletecascade",
        "constraintfk_ws_ticket_userforeignkey(user_id)"
        "referencesusers(id)ondeletecascade",
        "constraintfk_ws_ticket_api_keyforeignkey(api_key_id)"
        "referencesapi_keys(id)ondeletecascade",
    )
    inline_foreign_keys = (
        "campaign_idtextnotnullconstraintfk_ws_ticket_campaign"
        "referencescampaigns(id)ondeletecascade",
        "user_idtextnotnullconstraintfk_ws_ticket_user"
        "referencesusers(id)ondeletecascade",
        "api_key_idtextconstraintfk_ws_ticket_api_key"
        "referencesapi_keys(id)ondeletecascade",
    )
    table_level = all(
        fragment in sql for fragment in table_level_foreign_keys
    )
    inline = all(fragment in sql for fragment in inline_foreign_keys)
    if (
        sql.count("check(") != 7
        or (table_level == inline)
        or sql.count("foreignkey(") != (3 if table_level else 0)
        or any(sql.count(name) != 1 for name in foreign_key_names)
        or any(
            forbidden in sql
            for forbidden in (
                "deferrable",
                "initiallydeferred",
                "initiallyimmediate",
                "match",
            )
        )
        or any(fragment not in sql for fragment in required)
    ):
        raise RuntimeError(_CATALOG_ERROR)


def _sqlite_preflight(bind: Any) -> bool:
    _require_no_sqlite_temp_shadows(bind)
    _require_sqlite_managed_name_ownership(bind)
    _require_sqlite_alembic_version_relation(bind)
    tables = set(sa.inspect(bind).get_table_names())
    required = {
        "campaigns",
        "findings",
        "hosts",
        "credentials",
        "loot",
        "audit_log",
        "users",
        "api_keys",
        "refresh_tokens",
        "revoked_access_tokens",
        "websocket_tickets",
    }
    if not required.issubset(tables):
        raise RuntimeError(_CATALOG_ERROR)
    if any(table.startswith(_TEMP_PREFIX) for table in tables):
        raise RuntimeError(_CATALOG_ERROR)
    _require_sqlite_reserved_index_ownership(bind)
    triggers = bind.execute(
        sa.text(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name IN ("
            "'alembic_version','schema_version','campaigns','users',"
            "'revoked_access_tokens','hosts','module_runs','findings',"
            "'credentials','loot','audit_log','api_keys',"
            "'refresh_tokens','rate_limit_events',"
            "'websocket_tickets') LIMIT 1"
        )
    ).first()
    if triggers:
        raise RuntimeError(_CATALOG_ERROR)

    optional = {"schema_version", "module_runs", "rate_limit_events"}
    for table in required | (optional & tables):
        if not _columns_compatible(table, _sqlite_columns(bind, table)):
            raise RuntimeError(_CATALOG_ERROR)
        _require_sqlite_table_shape_metadata(bind, table)
        _require_sqlite_primary_key_index(bind, table)
        _require_not_null_data(bind, table)

    _require_ticket_contract(bind)
    _require_no_orphans(bind)
    _require_boolean_integer_data(bind, tables)
    _require_valid_sqlite_timestamps(bind, tables)
    _require_valid_sqlite_ticket_data(bind, tables)
    _require_no_external_references(bind, tables)

    expected_unique = {
        "hosts": {("campaign_id", "ip_address")},
        "users": {("username",)},
    }
    unique_exact = True
    managed = required | (optional & tables)
    for table in managed:
        expected = tuple(sorted(expected_unique.get(table, set())))
        unique = _sqlite_unique_contracts(bind, table)
        raw_table_sql = _sqlite_raw_table_sql(bind, table)
        unique_declarations = len(
            re.findall(r"\bUNIQUE\b", raw_table_sql, re.IGNORECASE)
        )
        if (
            unique_declarations != len(unique)
            or re.search(
                r"\bON\s+CONFLICT\b",
                raw_table_sql,
                re.IGNORECASE,
            )
        ):
            raise RuntimeError(_CATALOG_ERROR)
        if unique not in ((), expected):
            raise RuntimeError(_CATALOG_ERROR)
        if expected and not unique:
            columns = expected[0]
            grouped = ", ".join(f'"{column}"' for column in columns)
            statement = (  # noqa: S608
                f'SELECT 1 FROM "{table}" GROUP BY {grouped} '  # noqa: S608
                "HAVING count(*) > 1 LIMIT 1"
            )
            if bind.exec_driver_sql(statement).first():
                raise RuntimeError(_DATA_ERROR)
            unique_exact = False
        sql = _sqlite_table_sql(bind, table)
        if table not in {"rate_limit_events", "websocket_tickets"} and (
            "check(" in sql
        ):
            raise RuntimeError(_CATALOG_ERROR)

    exact = optional.issubset(tables) and unique_exact
    for table in _SQLITE_COLUMNS:
        if table not in tables:
            continue
        expected_columns = _SQLITE_COLUMNS[table]
        actual_columns = _sqlite_columns(bind, table)
        exact_columns = actual_columns == expected_columns
        exact = exact and exact_columns

        expected_fks = _SQLITE_FOREIGN_KEYS.get(table, frozenset())
        actual_fks = _sqlite_foreign_keys(bind, table)
        if (
            len(actual_fks) != len(set(actual_fks))
            or not set(actual_fks).issubset(expected_fks)
        ):
            raise RuntimeError(_CATALOG_ERROR)
        exact = exact and actual_fks == tuple(sorted(expected_fks))

        expected_indexes = _SQLITE_INDEXES.get(table, {})
        actual_indexes = _sqlite_indexes(bind, table)
        allowed_indexes = dict(expected_indexes)
        if table == "findings":
            allowed_indexes["idx_findings_validated"] = ("validated",)
        if any(
            name not in allowed_indexes
            or allowed_indexes[name] != columns
            for name, columns in actual_indexes.items()
        ):
            raise RuntimeError(_CATALOG_ERROR)
        exact = exact and actual_indexes == expected_indexes

    for table in ("audit_log", "rate_limit_events"):
        if table in tables:
            has_autoincrement = "autoincrement" in _sqlite_table_sql(
                bind, table
            )
            exact = exact and has_autoincrement
    if "rate_limit_events" in tables:
        sql = _sqlite_table_sql(bind, "rate_limit_events")
        has_check = (
            "constraintck_rate_limit_events_blocked_bool"
            "check(blockedin(0,1))"
        ) in sql
        if sql.count("check(") not in {0, 1} or (
            "check(" in sql and not has_check
        ):
            raise RuntimeError(_CATALOG_ERROR)
        exact = exact and has_check
    return exact


def _create_sqlite_table(table: str) -> None:
    if table == "schema_version":
        op.create_table(
            table,
            sa.Column("version", sa.Integer(), primary_key=True),
            sa.Column(
                "applied_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "campaigns":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column(
                "client",
                sa.Text(),
                nullable=False,
                server_default="Internal",
            ),
            sa.Column(
                "operator",
                sa.Text(),
                nullable=False,
                server_default="unknown",
            ),
            sa.Column(
                "noise_profile",
                sa.Text(),
                nullable=False,
                server_default="stealth",
            ),
            sa.Column(
                "status",
                sa.Text(),
                nullable=False,
                server_default="created",
            ),
            sa.Column(
                "scope_json",
                sa.Text(),
                nullable=False,
                server_default="[]",
            ),
            sa.Column(
                "targets_json",
                sa.Text(),
                nullable=False,
                server_default="[]",
            ),
            sa.Column("notes", sa.Text(), server_default=""),
            sa.Column(
                "created_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column(
                "updated_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "users":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("username", sa.Text(), nullable=False),
            sa.Column("hashed_password", sa.Text(), nullable=False),
            sa.Column(
                "role", sa.Text(), nullable=False, server_default="reporter"
            ),
            sa.Column(
                "is_active",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
            sa.Column(
                "created_by",
                sa.Text(),
                nullable=False,
                server_default="system",
            ),
            sa.Column(
                "created_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column("last_login", sa.Text()),
            sa.UniqueConstraint("username", name="uq_users_username"),
        )
    elif table == "revoked_access_tokens":
        op.create_table(
            table,
            sa.Column("jti", sa.Text(), primary_key=True),
            sa.Column("user_id", sa.Text(), nullable=False),
            sa.Column(
                "revoked_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column("expires_at", sa.Text(), nullable=False),
        )
    elif table == "hosts":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_hosts_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column("ip_address", sa.Text(), nullable=False),
            sa.Column("hostname", sa.Text()),
            sa.Column("fqdn", sa.Text()),
            sa.Column("os", sa.Text()),
            sa.Column("os_version", sa.Text()),
            sa.Column("domain", sa.Text()),
            sa.Column(
                "is_dc", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "open_ports_json",
                sa.Text(),
                nullable=False,
                server_default="[]",
            ),
            sa.Column(
                "tags_json", sa.Text(), nullable=False, server_default="[]"
            ),
            sa.Column(
                "first_seen",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column(
                "last_seen",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.UniqueConstraint(
                "campaign_id", "ip_address", name="uq_hosts_campaign_ip"
            ),
        )
    elif table == "module_runs":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_module_runs_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column("module_id", sa.Text(), nullable=False),
            sa.Column("outcome", sa.Text(), nullable=False),
            sa.Column(
                "success", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "duration_ms",
                sa.Float(),
                nullable=False,
                server_default="0.0",
            ),
            sa.Column(
                "completed_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "findings":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_findings_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column("module_id", sa.Text(), nullable=False),
            sa.Column("title", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("severity", sa.Text(), nullable=False),
            sa.Column(
                "confidence",
                sa.Float(),
                nullable=False,
                server_default="1.0",
            ),
            sa.Column("mitre_technique", sa.Text()),
            sa.Column("mitre_tactic", sa.Text()),
            sa.Column(
                "cvss_score",
                sa.Float(),
                nullable=False,
                server_default="0.0",
            ),
            sa.Column(
                "cvss_vector",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "evidence_json",
                sa.Text(),
                nullable=False,
                server_default="{}",
            ),
            sa.Column("remediation", sa.Text(), server_default=""),
            sa.Column("host", sa.Text()),
            sa.Column(
                "validated",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "false_positive",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "discovered_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column(
                "trace_id",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
        )
    elif table == "credentials":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_credentials_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column(
                "host_id",
                sa.Text(),
                sa.ForeignKey(
                    "hosts.id",
                    name="fk_credentials_host",
                    ondelete="SET NULL",
                ),
            ),
            sa.Column("username", sa.Text(), nullable=False),
            sa.Column("secret_enc", sa.Text()),
            sa.Column("cred_type", sa.Text(), nullable=False),
            sa.Column("domain", sa.Text()),
            sa.Column("source_module", sa.Text()),
            sa.Column("notes", sa.Text(), server_default=""),
            sa.Column(
                "cracked", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("cracked_value_enc", sa.Text()),
            sa.Column(
                "captured_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "loot":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_loot_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column(
                "host_id",
                sa.Text(),
                sa.ForeignKey(
                    "hosts.id",
                    name="fk_loot_host",
                    ondelete="SET NULL",
                ),
            ),
            sa.Column("loot_type", sa.Text(), nullable=False),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), server_default=""),
            sa.Column("content_enc", sa.Text()),
            sa.Column("size_bytes", sa.Integer(), server_default="0"),
            sa.Column("path_on_target", sa.Text()),
            sa.Column("source_module", sa.Text()),
            sa.Column(
                "tags_json", sa.Text(), nullable=False, server_default="[]"
            ),
            sa.Column(
                "captured_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "audit_log":
        op.create_table(
            table,
            sa.Column(
                "id", sa.Integer(), primary_key=True, autoincrement=True
            ),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_audit_campaign",
                    ondelete="SET NULL",
                ),
            ),
            sa.Column(
                "actor", sa.Text(), nullable=False, server_default="system"
            ),
            sa.Column("action", sa.Text(), nullable=False),
            sa.Column("detail", sa.Text(), server_default=""),
            sa.Column("module_id", sa.Text()),
            sa.Column(
                "timestamp",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sqlite_autoincrement=True,
        )
    elif table == "api_keys":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Text(),
                sa.ForeignKey(
                    "users.id",
                    name="fk_api_keys_user",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("key_hash", sa.Text(), nullable=False),
            sa.Column("key_prefix", sa.Text(), nullable=False),
            sa.Column(
                "scopes", sa.Text(), nullable=False, server_default="read"
            ),
            sa.Column(
                "is_active",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
            sa.Column("last_used", sa.Text()),
            sa.Column("expires_at", sa.Text()),
            sa.Column(
                "created_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
        )
    elif table == "refresh_tokens":
        op.create_table(
            table,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Text(),
                sa.ForeignKey(
                    "users.id",
                    name="fk_refresh_tokens_user",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column(
                "is_revoked",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column("expires_at", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.Column("used_at", sa.Text()),
        )
    elif table == "rate_limit_events":
        op.create_table(
            table,
            sa.Column(
                "id", sa.Integer(), primary_key=True, autoincrement=True
            ),
            sa.Column("ip_address", sa.Text(), nullable=False),
            sa.Column("bucket", sa.Text(), nullable=False),
            sa.Column("username", sa.Text()),
            sa.Column(
                "blocked", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "timestamp",
                sa.Text(),
                nullable=False,
                server_default=sa.text("datetime('now')"),
            ),
            sa.CheckConstraint(
                "blocked IN (0, 1)",
                name="ck_rate_limit_events_blocked_bool",
            ),
            sqlite_autoincrement=True,
        )
    elif table == "websocket_tickets":
        _create_sqlite_websocket_tickets()
    else:
        raise RuntimeError(_CATALOG_ERROR)


def _create_sqlite_websocket_tickets() -> None:
    timestamp_format = "%Y-%m-%dT%H:%M:%fZ"
    op.create_table(
        "websocket_tickets",
        sa.Column("ticket_hash", sa.Text(), primary_key=True, nullable=False),
        sa.Column(
            "campaign_id",
            sa.Text(),
            sa.ForeignKey(
                "campaigns.id",
                name="fk_ws_ticket_campaign",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey(
                "users.id",
                name="fk_ws_ticket_user",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("credential_kind", sa.Text(), nullable=False),
        sa.Column("bearer_subject", sa.Text()),
        sa.Column("bearer_jti", sa.Text()),
        sa.Column("bearer_expires_at", sa.Text()),
        sa.Column(
            "api_key_id",
            sa.Text(),
            sa.ForeignKey(
                "api_keys.id",
                name="fk_ws_ticket_api_key",
                ondelete="CASCADE",
            ),
        ),
        sa.Column("required_scope", sa.Text()),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("consumed_at", sa.Text()),
        sa.CheckConstraint(
            "length(ticket_hash)=64 "
            "AND ticket_hash NOT GLOB '*[^0-9a-f]*'",
            name="ck_ws_ticket_hash",
        ),
        sa.CheckConstraint(
            "credential_kind IN ('bearer', 'api_key')",
            name="ck_ws_ticket_kind",
        ),
        sa.CheckConstraint(
            f"strftime('{timestamp_format}', created_at) IS NOT NULL "
            f"AND strftime('{timestamp_format}', created_at)=created_at",
            name="ck_ws_ticket_created_at",
        ),
        sa.CheckConstraint(
            f"strftime('{timestamp_format}', expires_at) IS NOT NULL "
            f"AND strftime('{timestamp_format}', expires_at)=expires_at",
            name="ck_ws_ticket_expires_at",
        ),
        sa.CheckConstraint(
            "consumed_at IS NULL OR ("
            f"strftime('{timestamp_format}', consumed_at) IS NOT NULL "
            f"AND strftime('{timestamp_format}', consumed_at)=consumed_at)",
            name="ck_ws_ticket_consumed_at",
        ),
        sa.CheckConstraint(
            "julianday(expires_at) > julianday(created_at) "
            "AND (consumed_at IS NULL "
            "OR julianday(consumed_at) < julianday(expires_at))",
            name="ck_ws_ticket_time_order",
        ),
        sa.CheckConstraint(
            """
            (
                credential_kind='bearer'
                AND bearer_subject IS NOT NULL
                AND length(trim(bearer_subject)) > 0
                AND bearer_subject=trim(bearer_subject)
                AND bearer_jti IS NOT NULL
                AND length(trim(bearer_jti)) > 0
                AND bearer_jti=trim(bearer_jti)
                AND bearer_expires_at IS NOT NULL
                AND strftime(
                    '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
                ) IS NOT NULL
                AND strftime(
                    '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
                )=bearer_expires_at
                AND api_key_id IS NULL
                AND required_scope IS NULL
            )
            OR
            (
                credential_kind='api_key'
                AND bearer_subject IS NULL
                AND bearer_jti IS NULL
                AND bearer_expires_at IS NULL
                AND api_key_id IS NOT NULL
                AND length(trim(api_key_id)) > 0
                AND api_key_id=trim(api_key_id)
                AND required_scope='read'
            )
            """,
            name="ck_ws_ticket_source_shape",
        ),
    )


def _create_sqlite_indexes(table: str) -> None:
    for name, columns in _SQLITE_INDEXES.get(table, {}).items():
        op.create_index(name, table, list(columns))


def _copy_columns(bind: Any, table: str, source: str) -> None:
    names = [column[0] for column in _SQLITE_COLUMNS[table]]
    quoted = ", ".join(f'"{name}"' for name in names)
    selected = quoted
    if table == "credentials":
        source_columns = {
            str(row[1])
            for row in bind.exec_driver_sql(
                f'PRAGMA table_info("{source}")'  # noqa: S608
            ).fetchall()
        }
        if (
            "cracked_value_enc" not in source_columns
            and "cracked_value" in source_columns
        ):
            selected = ", ".join(
                (
                    '"cracked_value"'
                    if name == "cracked_value_enc"
                    else f'"{name}"'
                )
                for name in names
            )
    bind.exec_driver_sql(  # noqa: S608
        f'INSERT INTO "{table}" ({quoted}) '  # noqa: S608
        f'SELECT {selected} FROM "{source}"'
    )


def _sequence_values(bind: Any) -> dict[str, int]:
    exists = bind.execute(
        sa.text(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='sqlite_sequence'"
        )
    ).first()
    if not exists:
        return {}
    rows = bind.execute(
        sa.text(
            "SELECT name, seq FROM sqlite_sequence "
            "WHERE name IN ('audit_log', 'rate_limit_events')"
        )
    ).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def _restore_sequences(bind: Any, sequences: dict[str, int]) -> None:
    for table, sequence in sequences.items():
        result = bind.execute(
            sa.text(
                "UPDATE sqlite_sequence SET seq=:sequence "
                "WHERE name=:name AND seq < :sequence"
            ),
            {"name": table, "sequence": sequence},
        )
        if result.rowcount == 0:
            current = bind.execute(
                sa.text(
                    "SELECT seq FROM sqlite_sequence WHERE name=:name"
                ),
                {"name": table},
            ).scalar_one_or_none()
            if current is None:
                bind.execute(
                    sa.text(
                        "INSERT INTO sqlite_sequence(name, seq) "
                        "VALUES(:name, :sequence)"
                    ),
                    {"name": table, "sequence": sequence},
                )


def _sqlite_upgrade(bind: Any) -> None:
    # Alembic's SQLite implementation uses a logical per-revision
    # transaction, but SQLite does not emit BEGIN for DDL.  An explicit
    # write transaction makes the reconciliation and Alembic's subsequent
    # version-row update one atomic unit.  Alembic owns commit/rollback.
    bind.exec_driver_sql("BEGIN IMMEDIATE")
    exact = _sqlite_preflight(bind)
    if exact:
        return

    tables = set(sa.inspect(bind).get_table_names())
    ticket_before = _sqlite_ticket_snapshot(bind)
    sequences = _sequence_values(bind)
    row_counts = {
        table: int(
            bind.exec_driver_sql(  # noqa: S608
                f'SELECT count(*) FROM "{table}"'  # noqa: S608
            ).scalar_one()
        )
        for table in _REBUILD_ORDER
        if table in tables
    }

    bind.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    deferred = bind.exec_driver_sql(
        "PRAGMA defer_foreign_keys"
    ).scalar_one()
    if int(deferred) != 1:
        raise RuntimeError(_CATALOG_ERROR)

    existing = [table for table in _REBUILD_ORDER if table in tables]
    for table in existing:
        backup = f"{_TEMP_PREFIX}{table}"
        bind.exec_driver_sql(  # noqa: S608
            f'CREATE TEMP TABLE "{backup}" AS SELECT * FROM "{table}"'  # noqa: S608
        )
    for table in _DROP_ORDER:
        if table in existing:
            op.drop_table(table)

    for table in _REBUILD_ORDER:
        _create_sqlite_table(table)
        if table in existing:
            _copy_columns(bind, table, f"{_TEMP_PREFIX}{table}")
        _create_sqlite_indexes(table)

    _restore_sequences(bind, sequences)
    for table in existing:
        bind.exec_driver_sql(f'DROP TABLE "{_TEMP_PREFIX}{table}"')

    for table, expected_count in row_counts.items():
        current = int(
            bind.exec_driver_sql(  # noqa: S608
                f'SELECT count(*) FROM "{table}"'  # noqa: S608
            ).scalar_one()
        )
        if current != expected_count:
            raise RuntimeError(_DATA_ERROR)
    if _sqlite_ticket_snapshot(bind) != ticket_before:
        raise RuntimeError(_DATA_ERROR)
    if bind.exec_driver_sql("PRAGMA foreign_key_check").first():
        raise RuntimeError(_DATA_ERROR)
    if not _sqlite_preflight(bind):
        raise RuntimeError(_CATALOG_ERROR)


_PG_FINITE_CHECKS: dict[str, dict[str, bool]] = {
    "campaigns": {"created_at": False, "updated_at": False},
    "module_runs": {"completed_at": False},
    "findings": {"discovered_at": False},
    "hosts": {"first_seen": False, "last_seen": False},
    "credentials": {"captured_at": False},
    "loot": {"captured_at": False},
    "audit_log": {"timestamp": False},
    "users": {"created_at": False, "last_login": True},
    "api_keys": {
        "last_used": True,
        "expires_at": True,
        "created_at": False,
    },
    "refresh_tokens": {
        "expires_at": False,
        "created_at": False,
        "used_at": True,
    },
    "rate_limit_events": {"timestamp": False},
    "revoked_access_tokens": {
        "revoked_at": False,
        "expires_at": False,
    },
}

_PG_FOREIGN_KEYS: dict[
    str,
    tuple[str, str, str, str, str],
] = {
    "fk_module_runs_campaign": (
        "module_runs",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_findings_campaign": (
        "findings",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_hosts_campaign": (
        "hosts",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_credentials_campaign": (
        "credentials",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_credentials_host": (
        "credentials",
        "host_id",
        "hosts",
        "id",
        "SET NULL",
    ),
    "fk_loot_campaign": (
        "loot",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_loot_host": ("loot", "host_id", "hosts", "id", "SET NULL"),
    "fk_audit_campaign": (
        "audit_log",
        "campaign_id",
        "campaigns",
        "id",
        "SET NULL",
    ),
    "fk_api_keys_user": (
        "api_keys",
        "user_id",
        "users",
        "id",
        "CASCADE",
    ),
    "fk_refresh_tokens_user": (
        "refresh_tokens",
        "user_id",
        "users",
        "id",
        "CASCADE",
    ),
    "fk_ws_ticket_campaign": (
        "websocket_tickets",
        "campaign_id",
        "campaigns",
        "id",
        "CASCADE",
    ),
    "fk_ws_ticket_user": (
        "websocket_tickets",
        "user_id",
        "users",
        "id",
        "CASCADE",
    ),
    "fk_ws_ticket_api_key": (
        "websocket_tickets",
        "api_key_id",
        "api_keys",
        "id",
        "CASCADE",
    ),
}

_PG_UNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "uq_hosts_campaign_ip": ("hosts", ("campaign_id", "ip_address")),
    "uq_users_username": ("users", ("username",)),
}

_PG_PRIMARY_KEYS: dict[str, tuple[str, ...]] = {
    "campaigns": ("id",),
    "module_runs": ("id",),
    "findings": ("id",),
    "hosts": ("id",),
    "credentials": ("id",),
    "loot": ("id",),
    "audit_log": ("id",),
    "users": ("id",),
    "api_keys": ("id",),
    "refresh_tokens": ("id",),
    "rate_limit_events": ("id",),
    "revoked_access_tokens": ("jti",),
    "websocket_tickets": ("ticket_hash",),
}

_PG_RUNTIME_ALIASES: dict[str, tuple[str, str]] = {
    "idx_pg_module_runs_campaign": (
        "module_runs",
        "idx_module_runs_campaign",
    ),
    "idx_pg_module_runs_completed": (
        "module_runs",
        "idx_module_runs_completed",
    ),
    "idx_pg_findings_campaign": ("findings", "idx_findings_campaign"),
    "idx_pg_findings_severity": ("findings", "idx_findings_severity"),
    "idx_pg_findings_fp": ("findings", "idx_findings_fp"),
    "idx_pg_hosts_campaign": ("hosts", "idx_hosts_campaign"),
    "idx_pg_hosts_ip": ("hosts", "idx_hosts_ip"),
    "idx_pg_creds_campaign": ("credentials", "idx_creds_campaign"),
    "idx_pg_audit_campaign": ("audit_log", "idx_audit_campaign"),
    "idx_pg_users_username": ("users", "idx_users_username"),
    "idx_pg_apikeys_user": ("api_keys", "idx_apikeys_user"),
    "idx_pg_apikeys_prefix": ("api_keys", "idx_apikeys_prefix"),
    "idx_pg_refresh_user": ("refresh_tokens", "idx_refresh_user"),
    "idx_pg_refresh_exp": ("refresh_tokens", "idx_refresh_exp"),
    "idx_pg_rat_expires": (
        "revoked_access_tokens",
        "idx_rat_expires",
    ),
}

_PG_TICKET_CHECKS: dict[str, str] = {
    "ck_ws_ticket_bearer_expires_finite": (
        "CHECK (bearer_expires_at IS NULL "
        "OR isfinite(bearer_expires_at))"
    ),
    "ck_ws_ticket_consumed_at": (
        "CHECK (consumed_at IS NULL OR consumed_at < expires_at)"
    ),
    "ck_ws_ticket_consumed_finite": (
        "CHECK (consumed_at IS NULL OR isfinite(consumed_at))"
    ),
    "ck_ws_ticket_created_at": "CHECK (created_at < expires_at)",
    "ck_ws_ticket_created_finite": "CHECK (isfinite(created_at))",
    "ck_ws_ticket_expires_at": "CHECK (expires_at > created_at)",
    "ck_ws_ticket_expires_finite": "CHECK (isfinite(expires_at))",
    "ck_ws_ticket_hash": (
        "CHECK (ticket_hash ~ '^[0-9a-f]{64}$'::text)"
    ),
    "ck_ws_ticket_kind": (
        "CHECK (credential_kind = ANY "
        "(ARRAY['bearer'::text, 'api_key'::text]))"
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
        "AND api_key_id IS NULL "
        "AND required_scope IS NULL "
        "OR credential_kind = 'api_key'::text "
        "AND bearer_subject IS NULL "
        "AND bearer_jti IS NULL "
        "AND bearer_expires_at IS NULL "
        "AND api_key_id IS NOT NULL "
        "AND length(btrim(api_key_id)) > 0 "
        "AND api_key_id = btrim(api_key_id) "
        "AND required_scope = 'read'::text)"
    ),
    "ck_ws_ticket_time_order": (
        "CHECK (expires_at > created_at AND "
        "(consumed_at IS NULL OR consumed_at < expires_at))"
    ),
}

_PG_TICKET_TIMESTAMPS = frozenset(
    {
        "bearer_expires_at",
        "created_at",
        "expires_at",
        "consumed_at",
    }
)

_PG_FINDINGS_RUNTIME_ORDER = (
    "id",
    "campaign_id",
    "module_id",
    "title",
    "description",
    "severity",
    "confidence",
    "mitre_technique",
    "mitre_tactic",
    "cvss_score",
    "cvss_vector",
    "trace_id",
    "evidence_json",
    "remediation",
    "host",
    "validated",
    "false_positive",
    "discovered_at",
)

_PG_SERIAL_DEFAULTS = {
    ("audit_log", "id"): "nextval('audit_log_id_seq'::regclass)",
    (
        "rate_limit_events",
        "id",
    ): "nextval('rate_limit_events_id_seq'::regclass)",
}

_PG_AUDITED_FAST_DEFAULTS = {
    ("findings", "cvss_score"): "{0}",
    ("findings", "cvss_vector"): '{""}',
    ("findings", "trace_id"): '{""}',
}

_PG_REQUIRED_TABLES = frozenset(
    {
        "campaigns",
        "findings",
        "hosts",
        "credentials",
        "loot",
        "audit_log",
        "users",
        "api_keys",
        "refresh_tokens",
        "revoked_access_tokens",
        "websocket_tickets",
    }
)

_PG_OPTIONAL_TABLES = frozenset({"module_runs", "rate_limit_events"})


def _pg_check_name(table: str, column: str) -> str:
    if table == "rate_limit_events":
        return "ck_rate_limit_events_timestamp_finite"
    if table == "revoked_access_tokens":
        return f"ck_revoked_access_tokens_{column}_finite"
    if table == "audit_log":
        return "ck_audit_log_timestamp_finite"
    if table == "module_runs":
        return "ck_module_runs_completed_at_finite"
    return f"ck_{table}_{column}_finite"


def _pg_validate_alembic_version_relation(bind: Any) -> None:
    relation_rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    relation.oid::bigint AS relation_oid,
                    namespace.nspname AS relation_schema,
                    relation_type.oid::bigint AS type_oid,
                    type_namespace.nspname AS type_schema,
                    relation_type.typname AS type_name,
                    relation_type.typtype::text AS typtype,
                    relation_type.typrelid::bigint AS type_relation_oid,
                    relation.relkind::text AS relkind,
                    relation.relpersistence::text AS relpersistence,
                    relation.relispartition,
                    relation.relrowsecurity,
                    relation.relforcerowsecurity,
                    (
                        SELECT count(*)
                        FROM pg_inherits
                        WHERE inhrelid=relation.oid
                    ) AS parent_count,
                    (
                        SELECT count(*)
                        FROM pg_inherits
                        WHERE inhparent=relation.oid
                    ) AS child_count,
                    (
                        SELECT count(*)
                        FROM pg_policy
                        WHERE polrelid=relation.oid
                    ) AS policy_count,
                    (
                        SELECT count(*)
                        FROM pg_trigger
                        WHERE tgrelid=relation.oid
                          AND NOT tgisinternal
                    ) AS user_trigger_count,
                    (
                        SELECT count(*)
                        FROM pg_rewrite
                        WHERE ev_class=relation.oid
                    ) AS user_rule_count
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                LEFT JOIN pg_type AS relation_type
                  ON relation_type.oid=relation.reltype
                LEFT JOIN pg_namespace AS type_namespace
                  ON type_namespace.oid=relation_type.typnamespace
                WHERE namespace.nspname=current_schema()
                  AND relation.relname='alembic_version'
                """
            )
        ).mappings()
    )
    if len(relation_rows) != 1:
        raise RuntimeError(_CATALOG_ERROR)
    relation = relation_rows[0]
    try:
        relation_oid = int(relation["relation_oid"])
        type_oid = int(relation["type_oid"])
        schema = relation["relation_schema"]
        type_contract = (
            relation["type_schema"],
            relation["type_name"],
            str(relation["typtype"]),
            int(relation["type_relation_oid"]),
        )
        relation_contract = (
            str(relation["relkind"]),
            str(relation["relpersistence"]),
            bool(relation["relispartition"]),
            bool(relation["relrowsecurity"]),
            bool(relation["relforcerowsecurity"]),
            int(relation["parent_count"]),
            int(relation["child_count"]),
            int(relation["policy_count"]),
            int(relation["user_trigger_count"]),
            int(relation["user_rule_count"]),
        )
    except (KeyError, TypeError, ValueError):
        raise RuntimeError(_CATALOG_ERROR) from None
    if (
        relation_oid <= 0
        or type_oid <= 0
        or not isinstance(schema, str)
        or not schema
        or type_contract != (schema, "alembic_version", "c", relation_oid)
        or relation_contract
        != ("r", "p", False, False, False, 0, 0, 0, 0, 0)
    ):
        raise RuntimeError(_CATALOG_ERROR)

    column_rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    attribute.attnum,
                    attribute.attname AS column_name,
                    pg_catalog.format_type(
                        attribute.atttypid,
                        attribute.atttypmod
                    ) AS data_type,
                    attribute.attnotnull,
                    attribute.attidentity::text AS attidentity,
                    attribute.attgenerated::text AS attgenerated,
                    attribute.attisdropped,
                    attribute.attinhcount,
                    attribute.attislocal,
                    attribute.atthasmissing,
                    attribute.attmissingval::text AS missing_value,
                    attribute.attcollation=type_record.typcollation
                        AS collation_is_default,
                    pg_get_expr(
                        default_record.adbin,
                        default_record.adrelid
                    ) AS column_default
                FROM pg_attribute AS attribute
                LEFT JOIN pg_type AS type_record
                  ON type_record.oid=attribute.atttypid
                LEFT JOIN pg_attrdef AS default_record
                  ON default_record.adrelid=attribute.attrelid
                 AND default_record.adnum=attribute.attnum
                WHERE attribute.attrelid=:relation_oid
                  AND attribute.attnum > 0
                ORDER BY attribute.attnum
                """
            ),
            {"relation_oid": relation_oid},
        ).mappings()
    )
    try:
        column_contract = tuple(
            (
                int(row["attnum"]),
                str(row["column_name"]),
                str(row["data_type"]),
                bool(row["attnotnull"]),
                str(row["attidentity"]),
                str(row["attgenerated"]),
                bool(row["attisdropped"]),
                int(row["attinhcount"]),
                bool(row["attislocal"]),
                bool(row["atthasmissing"]),
                row["missing_value"],
                bool(row["collation_is_default"]),
                row["column_default"],
            )
            for row in column_rows
        )
    except (KeyError, TypeError, ValueError):
        raise RuntimeError(_CATALOG_ERROR) from None
    if column_contract != (
        (
            1,
            "version_num",
            "character varying(32)",
            True,
            "",
            "",
            False,
            0,
            True,
            False,
            None,
            True,
            None,
        ),
    ):
        raise RuntimeError(_CATALOG_ERROR)

    constraint_rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    constraint_record.oid::bigint AS constraint_oid,
                    constraint_record.conname AS constraint_name,
                    constraint_record.contype::text AS contype,
                    constraint_record.convalidated,
                    constraint_record.condeferrable,
                    constraint_record.condeferred,
                    constraint_record.conindid::bigint AS index_oid,
                    ARRAY(
                        SELECT attribute.attname
                        FROM unnest(constraint_record.conkey)
                             WITH ORDINALITY AS key(attnum, position)
                        JOIN pg_attribute AS attribute
                          ON attribute.attrelid=constraint_record.conrelid
                         AND attribute.attnum=key.attnum
                        ORDER BY key.position
                    ) AS columns
                FROM pg_constraint AS constraint_record
                WHERE constraint_record.conrelid=:relation_oid
                ORDER BY constraint_record.conname
                """
            ),
            {"relation_oid": relation_oid},
        ).mappings()
    )
    try:
        constraint_contract = tuple(
            (
                int(row["constraint_oid"]),
                str(row["constraint_name"]),
                str(row["contype"]),
                bool(row["convalidated"]),
                bool(row["condeferrable"]),
                bool(row["condeferred"]),
                int(row["index_oid"]),
                tuple(str(column) for column in row["columns"]),
            )
            for row in constraint_rows
        )
    except (KeyError, TypeError, ValueError):
        raise RuntimeError(_CATALOG_ERROR) from None
    if (
        len(constraint_contract) != 1
        or constraint_contract[0][0] <= 0
        or constraint_contract[0][6] <= 0
        or constraint_contract[0][1:]
        != (
            "alembic_version_pkc",
            "p",
            True,
            False,
            False,
            constraint_contract[0][6],
            ("version_num",),
        )
    ):
        raise RuntimeError(_CATALOG_ERROR)
    primary_constraint_oid = constraint_contract[0][0]
    primary_index_oid = constraint_contract[0][6]

    index_rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    index_record.oid::bigint AS index_oid,
                    index_record.relname AS index_name,
                    index_namespace.nspname AS index_schema,
                    index_record.relkind::text AS index_relkind,
                    index_record.relpersistence::text AS index_relpersistence,
                    index_record.relispartition AS index_is_partition,
                    access_method.amname AS access_method,
                    index_definition.indrelid::bigint AS table_oid,
                    index_definition.indisunique,
                    index_definition.indisprimary,
                    index_definition.indisvalid,
                    index_definition.indisready,
                    index_definition.indislive,
                    index_definition.indnkeyatts,
                    index_definition.indnatts,
                    constraint_record.oid::bigint AS constraint_oid,
                    constraint_record.conname AS constraint_name,
                    constraint_record.contype::text AS contype,
                    ARRAY(
                        SELECT attribute.attname
                        FROM unnest(index_definition.indkey)
                             WITH ORDINALITY AS key(attnum, position)
                        LEFT JOIN pg_attribute AS attribute
                          ON attribute.attrelid=index_definition.indrelid
                         AND attribute.attnum=key.attnum
                        ORDER BY key.position
                    ) AS columns,
                    ARRAY(
                        SELECT option
                        FROM unnest(index_definition.indoption)
                             WITH ORDINALITY AS item(option, position)
                        ORDER BY item.position
                    ) AS column_options,
                    ARRAY(
                        SELECT operator_class.opcname
                        FROM unnest(index_definition.indclass)
                             WITH ORDINALITY AS item(opclass, position)
                        JOIN pg_opclass AS operator_class
                          ON operator_class.oid=item.opclass
                        ORDER BY item.position
                    ) AS operator_classes,
                    ARRAY(
                        SELECT operator_namespace.nspname
                        FROM unnest(index_definition.indclass)
                             WITH ORDINALITY AS item(opclass, position)
                        JOIN pg_opclass AS operator_class
                          ON operator_class.oid=item.opclass
                        JOIN pg_namespace AS operator_namespace
                          ON operator_namespace.oid=
                             operator_class.opcnamespace
                        ORDER BY item.position
                    ) AS operator_class_namespaces,
                    ARRAY(
                        SELECT item.collation_oid=attribute.attcollation
                        FROM unnest(index_definition.indcollation)
                             WITH ORDINALITY AS item(collation_oid, position)
                        JOIN unnest(index_definition.indkey)
                             WITH ORDINALITY AS key(attnum, position)
                          ON key.position=item.position
                        LEFT JOIN pg_attribute AS attribute
                          ON attribute.attrelid=index_definition.indrelid
                         AND attribute.attnum=key.attnum
                        ORDER BY item.position
                    ) AS column_collations_match,
                    pg_get_expr(
                        index_definition.indexprs,
                        index_definition.indrelid
                    ) AS expressions,
                    pg_get_expr(
                        index_definition.indpred,
                        index_definition.indrelid
                    ) AS predicate
                FROM pg_index AS index_definition
                JOIN pg_class AS index_record
                  ON index_record.oid=index_definition.indexrelid
                JOIN pg_namespace AS index_namespace
                  ON index_namespace.oid=index_record.relnamespace
                JOIN pg_am AS access_method
                  ON access_method.oid=index_record.relam
                LEFT JOIN pg_constraint AS constraint_record
                  ON constraint_record.conindid=index_definition.indexrelid
                 AND constraint_record.conrelid=index_definition.indrelid
                WHERE index_definition.indrelid=:relation_oid
                ORDER BY index_record.relname
                """
            ),
            {"relation_oid": relation_oid},
        ).mappings()
    )
    try:
        index_contract = tuple(
            (
                int(row["index_oid"]),
                str(row["index_name"]),
                row["index_schema"],
                str(row["index_relkind"]),
                str(row["index_relpersistence"]),
                bool(row["index_is_partition"]),
                str(row["access_method"]),
                int(row["table_oid"]),
                bool(row["indisunique"]),
                bool(row["indisprimary"]),
                bool(row["indisvalid"]),
                bool(row["indisready"]),
                bool(row["indislive"]),
                int(row["indnkeyatts"]),
                int(row["indnatts"]),
                int(row["constraint_oid"]),
                row["constraint_name"],
                row["contype"],
                tuple(str(column) for column in row["columns"]),
                tuple(int(option) for option in row["column_options"]),
                tuple(str(value) for value in row["operator_classes"]),
                tuple(
                    str(value)
                    for value in row["operator_class_namespaces"]
                ),
                tuple(
                    bool(value)
                    for value in row["column_collations_match"]
                ),
                row["expressions"],
                row["predicate"],
            )
            for row in index_rows
        )
    except (KeyError, TypeError, ValueError):
        raise RuntimeError(_CATALOG_ERROR) from None
    if index_contract != (
        (
            primary_index_oid,
            "alembic_version_pkc",
            schema,
            "i",
            "p",
            False,
            "btree",
            relation_oid,
            True,
            True,
            True,
            True,
            True,
            1,
            1,
            primary_constraint_oid,
            "alembic_version_pkc",
            "p",
            ("version_num",),
            (0,),
            ("text_ops",),
            ("pg_catalog",),
            (True,),
            None,
            None,
        ),
    ):
        raise RuntimeError(_CATALOG_ERROR)
    quoted_schema = '"' + schema.replace('"', '""') + '"'
    values = tuple(
        str(row[0])
        for row in bind.exec_driver_sql(
            f'SELECT version_num FROM {quoted_schema}."alembic_version"'  # noqa: S608
        ).fetchall()
    )
    if values != ("0007",):
        raise RuntimeError(_CATALOG_ERROR)


def _pg_relation_rows(bind: Any) -> list[dict[str, object]]:
    return list(
        bind.execute(
            sa.text(
                """
                SELECT
                    relation.oid::bigint AS relation_oid,
                    relation.relname AS table_name,
                    relation.relkind::text AS relkind,
                    relation.relpersistence::text AS relpersistence,
                    relation.relispartition,
                    relation.relrowsecurity,
                    relation.relforcerowsecurity,
                    (
                        SELECT count(*)
                        FROM pg_inherits
                        WHERE inhrelid=relation.oid
                    ) AS parent_count,
                    (
                        SELECT count(*)
                        FROM pg_inherits
                        WHERE inhparent=relation.oid
                    ) AS child_count,
                    (
                        SELECT count(*)
                        FROM pg_policy
                        WHERE polrelid=relation.oid
                    ) AS policy_count,
                    (
                        SELECT count(*)
                        FROM pg_trigger
                        WHERE tgrelid=relation.oid
                          AND NOT tgisinternal
                    ) AS user_trigger_count,
                    (
                        SELECT count(*)
                        FROM pg_rewrite
                        WHERE ev_class=relation.oid
                    ) AS user_rule_count
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname=current_schema()
                  AND relation.relname IN (
                      'campaigns',
                      'module_runs',
                      'findings',
                      'hosts',
                      'credentials',
                      'loot',
                      'audit_log',
                      'users',
                      'api_keys',
                      'refresh_tokens',
                      'rate_limit_events',
                      'revoked_access_tokens',
                      'websocket_tickets'
                  )
                """
            )
        ).mappings()
    )


def _pg_validate_relation_shapes(bind: Any) -> set[str]:
    rows = _pg_relation_rows(bind)
    relations = {
        str(row["table_name"]): row
        for row in rows
    }
    if len(relations) != len(rows):
        raise RuntimeError(_CATALOG_ERROR)
    tables = set(relations)
    if not _PG_REQUIRED_TABLES.issubset(tables):
        raise RuntimeError(_CATALOG_ERROR)
    if not tables.issubset(_PG_REQUIRED_TABLES | _PG_OPTIONAL_TABLES):
        raise RuntimeError(_CATALOG_ERROR)
    expected = ("r", "p", False, False, False, 0, 0, 0, 0, 0)
    for row in relations.values():
        actual = (
            str(row["relkind"]),
            str(row["relpersistence"]),
            bool(row["relispartition"]),
            bool(row["relrowsecurity"]),
            bool(row["relforcerowsecurity"]),
            int(row["parent_count"]),
            int(row["child_count"]),
            int(row["policy_count"]),
            int(row["user_trigger_count"]),
            int(row["user_rule_count"]),
        )
        if actual != expected:
            raise RuntimeError(_CATALOG_ERROR)

    type_rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    type_record.typname AS type_name,
                    type_record.typtype::text AS typtype,
                    type_record.typrelid::bigint AS type_relation_oid,
                    namespace.nspname AS type_schema
                FROM pg_type AS type_record
                JOIN pg_namespace AS namespace
                  ON namespace.oid=type_record.typnamespace
                WHERE namespace.nspname=current_schema()
                  AND type_record.typname IN (
                      'campaigns',
                      'module_runs',
                      'findings',
                      'hosts',
                      'credentials',
                      'loot',
                      'audit_log',
                      'users',
                      'api_keys',
                      'refresh_tokens',
                      'rate_limit_events',
                      'revoked_access_tokens',
                      'websocket_tickets'
                  )
                ORDER BY type_record.typname
                """
            )
        ).mappings()
    )
    type_contracts = {
        str(row["type_name"]): row
        for row in type_rows
    }
    if len(type_contracts) != len(type_rows) or set(type_contracts) != tables:
        raise RuntimeError(_CATALOG_ERROR)
    for table, relation in relations.items():
        type_row = type_contracts[table]
        if (
            str(type_row["typtype"]) != "c"
            or int(type_row["type_relation_oid"])
            != int(relation["relation_oid"])
            or not isinstance(type_row["type_schema"], str)
            or not type_row["type_schema"]
        ):
            raise RuntimeError(_CATALOG_ERROR)
    return tables


def _pg_column_rows(bind: Any) -> list[dict[str, object]]:
    return list(
        bind.execute(
            sa.text(
                """
                SELECT
                    relation.relname AS table_name,
                    attribute.attnum,
                    attribute.attname AS column_name,
                    format_type(
                        attribute.atttypid,
                        attribute.atttypmod
                    ) AS data_type,
                    attribute.attnotnull,
                    attribute.attidentity::text AS attidentity,
                    attribute.attgenerated::text AS attgenerated,
                    attribute.attisdropped,
                    attribute.attinhcount,
                    attribute.attislocal,
                    attribute.atthasmissing,
                    attribute.attmissingval::text AS missing_value,
                    (
                        attribute.attcollation=
                        type_record.typcollation
                    ) AS collation_is_default,
                    pg_get_expr(
                        default_record.adbin,
                        default_record.adrelid
                    ) AS column_default
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                JOIN pg_attribute AS attribute
                  ON attribute.attrelid=relation.oid
                JOIN pg_type AS type_record
                  ON type_record.oid=attribute.atttypid
                LEFT JOIN pg_attrdef AS default_record
                  ON default_record.adrelid=relation.oid
                 AND default_record.adnum=attribute.attnum
                WHERE namespace.nspname=current_schema()
                  AND relation.relname IN (
                      'campaigns',
                      'module_runs',
                      'findings',
                      'hosts',
                      'credentials',
                      'loot',
                      'audit_log',
                      'users',
                      'api_keys',
                      'refresh_tokens',
                      'rate_limit_events',
                      'revoked_access_tokens',
                      'websocket_tickets'
                  )
                  AND attribute.attnum > 0
                ORDER BY relation.relname, attribute.attnum
                """
            )
        ).mappings()
    )


def _pg_column_type(table: str, column: _Column) -> str:
    name, kind, _nullable, _default, _primary_key = column
    if (
        name in _PG_FINITE_CHECKS.get(table, {})
        or (
            table == "websocket_tickets"
            and name in _PG_TICKET_TIMESTAMPS
        )
    ):
        return "timestamp with time zone"
    if kind == "TEXT":
        return "text"
    if kind == "INTEGER":
        return "integer"
    if kind == "FLOAT":
        return "double precision"
    raise RuntimeError(_CATALOG_ERROR)


def _pg_column_default(
    table: str,
    column: _Column,
) -> str | None:
    name, _kind, _nullable, default, _primary_key = column
    serial_default = _PG_SERIAL_DEFAULTS.get((table, name))
    if serial_default is not None:
        return serial_default
    if default == "datetime('now')":
        return "now()"
    return default


def _pg_expected_columns(
    table: str,
    *,
    source_credentials: bool = False,
) -> tuple[_Column, ...]:
    columns = _SQLITE_COLUMNS[table]
    if not source_credentials:
        return columns
    return tuple(
        (
            "cracked_value" if column[0] == "cracked_value_enc" else column[0],
            *column[1:],
        )
        for column in columns
    )


def _pg_validate_column_metadata(
    table: str,
    rows: list[dict[str, object]],
    expected: tuple[_Column, ...],
) -> list[tuple[str, sa.types.TypeEngine, str]]:
    if len(rows) != len(expected):
        raise RuntimeError(_CATALOG_ERROR)
    alterations: list[tuple[str, sa.types.TypeEngine, str]] = []
    for position, (row, column) in enumerate(
        zip(rows, expected, strict=True),
        start=1,
    ):
        name, _kind, nullable, _default, _primary_key = column
        actual_nullable = not bool(row["attnotnull"])
        nullable_matches = actual_nullable == nullable
        if (
            table == "findings"
            and name in {"cvss_score", "cvss_vector", "trace_id"}
            and actual_nullable
            and not nullable
        ):
            nullable_matches = True
            kind: sa.types.TypeEngine
            default: str
            if name == "cvss_score":
                kind = sa.Float()
                default = "0.0"
            else:
                kind = sa.Text()
                default = ""
            alterations.append((name, kind, default))
        actual_default = _normalize_default(row["column_default"])
        expected_default = _normalize_default(
            _pg_column_default(table, column)
        )
        has_missing = bool(row["atthasmissing"])
        missing_value = row["missing_value"]
        expected_missing = _PG_AUDITED_FAST_DEFAULTS.get((table, name))
        missing_metadata_matches = (
            (
                has_missing
                and expected_missing is not None
                and str(missing_value) == expected_missing
            )
            or (not has_missing and missing_value is None)
        )
        if (
            int(row["attnum"]) != position
            or str(row["column_name"]) != name
            or str(row["data_type"]).lower()
            != _pg_column_type(table, column)
            or not nullable_matches
            or not _pg_defaults_match(
                actual_default,
                expected_default,
                str(row["data_type"]).lower(),
            )
            or str(row["attidentity"])
            or str(row["attgenerated"])
            or bool(row["attisdropped"])
            or int(row["attinhcount"]) != 0
            or not bool(row["attislocal"])
            or not missing_metadata_matches
            or not bool(row["collation_is_default"])
        ):
            raise RuntimeError(_CATALOG_ERROR)
    return alterations


def _pg_validate_columns(
    bind: Any,
    tables: set[str],
) -> tuple[
    list[tuple[str, sa.types.TypeEngine, str]],
    bool,
]:
    by_table: dict[str, list[dict[str, object]]] = {}
    for row in _pg_column_rows(bind):
        by_table.setdefault(str(row["table_name"]), []).append(row)
    if set(by_table) != tables:
        raise RuntimeError(_CATALOG_ERROR)

    findings_alterations: list[
        tuple[str, sa.types.TypeEngine, str]
    ] = []
    rename_credentials = False
    for table in tables:
        rows = by_table[table]
        names = tuple(str(row["column_name"]) for row in rows)
        expected = _pg_expected_columns(table)
        expected_names = tuple(column[0] for column in expected)
        if table == "findings":
            if names not in {
                expected_names,
                _PG_FINDINGS_RUNTIME_ORDER,
            }:
                raise RuntimeError(_CATALOG_ERROR)
            by_name = {column[0]: column for column in expected}
            expected = tuple(by_name[name] for name in names)
        elif table == "credentials":
            source_expected = _pg_expected_columns(
                table,
                source_credentials=True,
            )
            source_names = tuple(column[0] for column in source_expected)
            if names == source_names:
                expected = source_expected
                rename_credentials = True
            elif names != expected_names:
                raise RuntimeError(_CATALOG_ERROR)
        elif names != expected_names:
            raise RuntimeError(_CATALOG_ERROR)

        alterations = _pg_validate_column_metadata(
            table,
            rows,
            expected,
        )
        if table == "findings":
            findings_alterations = alterations
        elif alterations:
            raise RuntimeError(_CATALOG_ERROR)
    return findings_alterations, rename_credentials


def _pg_validate_serial_sequences(
    bind: Any,
    tables: set[str],
) -> None:
    rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    namespace.nspname AS sequence_schema,
                    sequence_record.relname AS sequence_name,
                    sequence_record.relkind::text AS relkind,
                    sequence_record.relpersistence::text AS relpersistence,
                    format_type(
                        sequence_definition.seqtypid,
                        NULL
                    ) AS data_type,
                    sequence_definition.seqstart,
                    sequence_definition.seqincrement,
                    sequence_definition.seqmax,
                    sequence_definition.seqmin,
                    sequence_definition.seqcache,
                    sequence_definition.seqcycle,
                    owner_namespace.nspname AS owner_schema,
                    owner_table.relname AS owner_table,
                    owner_column.attname AS owner_column,
                    dependency.deptype::text AS deptype
                FROM pg_class AS sequence_record
                JOIN pg_namespace AS namespace
                  ON namespace.oid=sequence_record.relnamespace
                JOIN pg_sequence AS sequence_definition
                  ON sequence_definition.seqrelid=sequence_record.oid
                LEFT JOIN pg_depend AS dependency
                  ON dependency.classid='pg_class'::regclass
                 AND dependency.objid=sequence_record.oid
                 AND dependency.objsubid=0
                 AND dependency.refclassid='pg_class'::regclass
                 AND dependency.deptype IN ('a', 'i')
                LEFT JOIN pg_class AS owner_table
                  ON owner_table.oid=dependency.refobjid
                LEFT JOIN pg_namespace AS owner_namespace
                  ON owner_namespace.oid=owner_table.relnamespace
                LEFT JOIN pg_attribute AS owner_column
                  ON owner_column.attrelid=dependency.refobjid
                 AND owner_column.attnum=dependency.refobjsubid
                WHERE namespace.nspname=current_schema()
                  AND sequence_record.relname IN (
                      'audit_log_id_seq',
                      'rate_limit_events_id_seq'
                  )
                ORDER BY sequence_record.relname
                """
            )
        ).mappings()
    )
    expected = {
        "audit_log_id_seq": ("audit_log", "id"),
    }
    if "rate_limit_events" in tables:
        expected["rate_limit_events_id_seq"] = (
            "rate_limit_events",
            "id",
        )
    if len(rows) != len(expected):
        raise RuntimeError(_CATALOG_ERROR)
    seen: set[str] = set()
    for row in rows:
        name = str(row["sequence_name"])
        owner = expected.get(name)
        if (
            owner is None
            or name in seen
            or (
                str(row["relkind"]),
                str(row["relpersistence"]),
                str(row["data_type"]),
                int(row["seqstart"]),
                int(row["seqincrement"]),
                int(row["seqmax"]),
                int(row["seqmin"]),
                int(row["seqcache"]),
                bool(row["seqcycle"]),
                str(row["owner_schema"]),
                str(row["owner_table"]),
                str(row["owner_column"]),
                str(row["deptype"]),
            )
            != (
                "S",
                "p",
                "integer",
                1,
                1,
                2147483647,
                1,
                1,
                False,
                str(row["sequence_schema"]),
                owner[0],
                owner[1],
                "a",
            )
        ):
            raise RuntimeError(_CATALOG_ERROR)
        seen.add(name)


def _pg_constraint_rows(bind: Any) -> list[dict[str, object]]:
    return list(
        bind.execute(
            sa.text(
                """
                SELECT
                    relation.relname AS table_name,
                    constraint_record.conname AS constraint_name,
                    constraint_record.contype::text AS constraint_type,
                    constraint_record.convalidated AS is_validated,
                    constraint_record.condeferrable AS is_deferrable,
                    constraint_record.condeferred AS is_deferred,
                    pg_get_constraintdef(
                        constraint_record.oid,
                        true
                    ) AS definition
                FROM pg_constraint AS constraint_record
                JOIN pg_class AS relation
                  ON relation.oid=constraint_record.conrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname=current_schema()
                """
            )
        ).mappings()
    )


def _pg_index_rows(bind: Any) -> list[dict[str, object]]:
    return list(
        bind.execute(
            sa.text(
                """
                SELECT
                    table_record.relname AS table_name,
                    index_record.relname AS index_name,
                    index_record.relkind::text AS index_relkind,
                    index_record.relpersistence::text AS index_relpersistence,
                    index_record.relispartition AS index_is_partition,
                    access_method.amname AS access_method,
                    index_definition.indisunique AS is_unique,
                    index_definition.indisprimary AS is_primary,
                    index_definition.indisvalid AS is_valid,
                    index_definition.indisready AS is_ready,
                    index_definition.indislive AS is_live,
                    index_definition.indnkeyatts,
                    index_definition.indnatts,
                    ARRAY(
                        SELECT attribute.attname
                        FROM unnest(index_definition.indkey)
                             WITH ORDINALITY AS key(attnum, position)
                        LEFT JOIN pg_attribute AS attribute
                          ON attribute.attrelid=index_definition.indrelid
                         AND attribute.attnum=key.attnum
                        ORDER BY key.position
                    ) AS columns,
                    ARRAY(
                        SELECT option
                        FROM unnest(index_definition.indoption)
                             WITH ORDINALITY AS item(option, position)
                        ORDER BY item.position
                    ) AS column_options,
                    ARRAY(
                        SELECT operator_class.opcname
                        FROM unnest(index_definition.indclass)
                             WITH ORDINALITY AS item(opclass, position)
                        JOIN pg_opclass AS operator_class
                          ON operator_class.oid=item.opclass
                        ORDER BY item.position
                    ) AS operator_classes,
                    ARRAY(
                        SELECT namespace_record.nspname
                        FROM unnest(index_definition.indclass)
                             WITH ORDINALITY AS item(opclass, position)
                        JOIN pg_opclass AS operator_class
                          ON operator_class.oid=item.opclass
                        JOIN pg_namespace AS namespace_record
                          ON namespace_record.oid=
                             operator_class.opcnamespace
                        ORDER BY item.position
                    ) AS operator_class_namespaces,
                    ARRAY(
                        SELECT item.collation_oid=attribute.attcollation
                        FROM unnest(index_definition.indcollation)
                             WITH ORDINALITY AS item(collation_oid, position)
                        JOIN unnest(index_definition.indkey)
                             WITH ORDINALITY AS key(attnum, position)
                          ON key.position=item.position
                        LEFT JOIN pg_attribute AS attribute
                          ON attribute.attrelid=index_definition.indrelid
                         AND attribute.attnum=key.attnum
                        ORDER BY item.position
                    ) AS column_collations_match,
                    pg_get_expr(
                        index_definition.indexprs,
                        index_definition.indrelid
                    ) AS expressions,
                    pg_get_expr(
                        index_definition.indpred,
                        index_definition.indrelid
                    ) AS predicate
                FROM pg_index AS index_definition
                JOIN pg_class AS table_record
                  ON table_record.oid=index_definition.indrelid
                JOIN pg_class AS index_record
                  ON index_record.oid=index_definition.indexrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=table_record.relnamespace
                JOIN pg_am AS access_method
                  ON access_method.oid=index_record.relam
                LEFT JOIN pg_constraint AS constraint_record
                  ON constraint_record.conindid=index_definition.indexrelid
                WHERE namespace.nspname=current_schema()
                  AND constraint_record.oid IS NULL
                """
            )
        ).mappings()
    )


def _pg_reject_reserved_index_collisions(
    bind: Any,
    tables: set[str],
) -> None:
    rows = list(
        bind.execute(
            sa.text(
                """
                SELECT
                    named_record.relname AS reserved_name,
                    namespace.nspname AS reserved_schema,
                    named_record.relkind::text AS relkind,
                    index_definition.indexrelid IS NOT NULL AS is_index,
                    table_namespace.nspname AS table_schema,
                    table_record.relname AS table_name,
                    ARRAY(
                        SELECT constraint_record.contype::text
                        FROM pg_constraint AS constraint_record
                        WHERE constraint_record.conindid=named_record.oid
                          AND constraint_record.conrelid=table_record.oid
                        ORDER BY constraint_record.oid
                    ) AS owner_constraint_types
                FROM pg_class AS named_record
                JOIN pg_namespace AS namespace
                  ON namespace.oid=named_record.relnamespace
                LEFT JOIN pg_index AS index_definition
                  ON index_definition.indexrelid=named_record.oid
                LEFT JOIN pg_class AS table_record
                  ON table_record.oid=index_definition.indrelid
                LEFT JOIN pg_namespace AS table_namespace
                  ON table_namespace.oid=table_record.relnamespace
                WHERE namespace.nspname=current_schema()
                ORDER BY named_record.relname
                """
            )
        ).mappings()
    )
    canonical = {
        name: table
        for table, indexes in _SQLITE_INDEXES.items()
        if table != "schema_version"
        for name in indexes
    }
    aliases = {
        alias: table
        for alias, (table, _canonical) in _PG_RUNTIME_ALIASES.items()
    }
    plain_indexes = canonical | aliases
    plain_indexes["idx_findings_validated"] = "findings"
    primary_indexes = {
        f"{table}_pkey": table
        for table in _PG_PRIMARY_KEYS
    }
    unique_indexes = {
        name: table
        for name, (table, _columns) in _PG_UNIQUES.items()
    }
    sequences = {
        "audit_log_id_seq": "audit_log",
        "rate_limit_events_id_seq": "rate_limit_events",
    }
    for row in rows:
        name = str(row["reserved_name"])
        relation_contract = (
            str(row["relkind"]),
            bool(row["is_index"]),
            row["table_schema"],
            row["table_name"],
            tuple(
                str(value)
                for value in (row["owner_constraint_types"] or ())
            ),
        )
        if name in plain_indexes:
            expected_table = plain_indexes[name]
            if relation_contract != (
                "i",
                True,
                str(row["reserved_schema"]),
                expected_table,
                (),
            ):
                raise RuntimeError(_CATALOG_ERROR)
        elif name in primary_indexes:
            expected_table = primary_indexes[name]
            if expected_table not in tables or relation_contract != (
                "i",
                True,
                str(row["reserved_schema"]),
                expected_table,
                ("p",),
            ):
                raise RuntimeError(_CATALOG_ERROR)
        elif name in unique_indexes:
            expected_table = unique_indexes[name]
            if expected_table not in tables or relation_contract != (
                "i",
                True,
                str(row["reserved_schema"]),
                expected_table,
                ("u",),
            ):
                raise RuntimeError(_CATALOG_ERROR)
        elif name in sequences:
            expected_table = sequences[name]
            if expected_table not in tables or relation_contract != (
                "S",
                False,
                None,
                None,
                (),
            ):
                raise RuntimeError(_CATALOG_ERROR)


def _pg_index_opclass(table: str, column: str) -> str:
    if (table, column) in {
        ("findings", "cvss_score"),
    }:
        return "float8_ops"
    if (table, column) in {
        ("findings", "false_positive"),
        ("findings", "validated"),
        ("rate_limit_events", "blocked"),
    }:
        return "int4_ops"
    if (table, column) in {
        ("module_runs", "completed_at"),
        ("rate_limit_events", "timestamp"),
        ("refresh_tokens", "expires_at"),
        ("revoked_access_tokens", "expires_at"),
        ("websocket_tickets", "expires_at"),
    }:
        return "timestamptz_ops"
    return "text_ops"


def _pg_index_contract(
    row: dict[str, object],
) -> tuple[object, ...]:
    columns = tuple(str(value) for value in (row["columns"] or ()))
    return (
        str(row["index_relkind"]),
        str(row["index_relpersistence"]),
        bool(row["index_is_partition"]),
        str(row["access_method"]),
        bool(row["is_unique"]),
        bool(row["is_primary"]),
        bool(row["is_valid"]),
        bool(row["is_ready"]),
        bool(row["is_live"]),
        int(row["indnkeyatts"]),
        int(row["indnatts"]),
        columns,
        tuple(int(value) for value in (row["column_options"] or ())),
        tuple(str(value) for value in (row["operator_classes"] or ())),
        tuple(
            str(value)
            for value in (row["operator_class_namespaces"] or ())
        ),
        tuple(
            bool(value)
            for value in (row["column_collations_match"] or ())
        ),
        row["expressions"],
        row["predicate"],
    )


def _expected_pg_index(
    table: str,
    columns: tuple[str, ...],
) -> tuple[object, ...]:
    count = len(columns)
    return (
        "i",
        "p",
        False,
        "btree",
        False,
        False,
        True,
        True,
        True,
        count,
        count,
        columns,
        (0,) * count,
        tuple(_pg_index_opclass(table, column) for column in columns),
        ("pg_catalog",) * count,
        (True,) * count,
        None,
        None,
    )


def _pg_require_safe_data(bind: Any, tables: set[str]) -> None:
    for table, columns in _PG_FINITE_CHECKS.items():
        if table not in tables:
            continue
        for column, nullable in columns.items():
            invalid_statement = (  # noqa: S608
                f'SELECT 1 FROM "{table}" '  # noqa: S608
                f'WHERE "{column}" IS NOT NULL '
                f'AND NOT isfinite("{column}") LIMIT 1'
            )
            invalid = bind.exec_driver_sql(  # noqa: S608
                invalid_statement
            ).first()
            if invalid:
                raise RuntimeError(_DATA_ERROR)
            null_statement = (  # noqa: S608
                f'SELECT 1 FROM "{table}" '  # noqa: S608
                f'WHERE "{column}" IS NULL LIMIT 1'
            )
            if not nullable and bind.exec_driver_sql(  # noqa: S608
                null_statement
            ).first():
                raise RuntimeError(_DATA_ERROR)
    for column in ("cvss_score", "cvss_vector", "trace_id"):
        statement = (  # noqa: S608
            f'SELECT 1 FROM findings '  # noqa: S608
            f'WHERE "{column}" IS NULL LIMIT 1'
        )
        if bind.exec_driver_sql(statement).first():  # noqa: S608
            raise RuntimeError(_DATA_ERROR)
    _require_no_orphans(bind)
    _require_boolean_integer_data(bind, tables)
    duplicate_checks = (
        ("hosts", ("campaign_id", "ip_address")),
        ("users", ("username",)),
    )
    for table, columns in duplicate_checks:
        grouped = ", ".join(f'"{column}"' for column in columns)
        statement = (  # noqa: S608
            f'SELECT 1 FROM "{table}" GROUP BY {grouped} '  # noqa: S608
            "HAVING count(*) > 1 LIMIT 1"
        )
        if bind.exec_driver_sql(statement).first():
            raise RuntimeError(_DATA_ERROR)


def _normalize_pg_definition(value: object) -> str:
    return _normalize_sql_syntax(
        value,
        strip_postgres_casts=True,
    )


def _expected_pg_fk(
    local: str,
    parent: str,
    remote: str,
    on_delete: str,
) -> str:
    return _normalize_pg_definition(
        f"FOREIGN KEY ({local}) REFERENCES {parent}({remote}) "
        f"ON DELETE {on_delete}"
    )


def _expected_pg_unique(columns: tuple[str, ...]) -> str:
    return _normalize_pg_definition(
        f"UNIQUE ({', '.join(columns)})"
    )


def _expected_pg_primary(columns: tuple[str, ...]) -> str:
    return _normalize_pg_definition(
        f"PRIMARY KEY ({', '.join(columns)})"
    )


def _pg_constraint_plan(
    bind: Any,
    tables: set[str],
) -> tuple[
    list[tuple[str, str, str]],
    list[tuple[str, str, str, str, str]],
    list[tuple[str, str, str]],
    list[tuple[str, str, tuple[str, ...]]],
    list[tuple[str, str, str]],
]:
    rows = _pg_constraint_rows(bind)
    drop: list[tuple[str, str, str]] = []
    add_fks: list[tuple[str, str, str, str, str]] = []
    add_checks: list[tuple[str, str, str]] = []
    add_uniques: list[tuple[str, str, tuple[str, ...]]] = []
    rename_uniques: list[tuple[str, str, str]] = []

    by_table_type: dict[tuple[str, str], list[dict[str, object]]] = {}
    for row in rows:
        table = str(row["table_name"])
        kind = str(row["constraint_type"])
        by_table_type.setdefault((table, kind), []).append(row)
        if table in _PG_PRIMARY_KEYS and (
            not bool(row["is_validated"])
            or bool(row["is_deferrable"])
            or bool(row["is_deferred"])
        ):
            raise RuntimeError(_CATALOG_ERROR)

    for table, columns in _PG_PRIMARY_KEYS.items():
        if table not in tables:
            continue
        rows_for_table = by_table_type.get((table, "p"), [])
        expected_name = f"{table}_pkey"
        expected = _expected_pg_primary(columns)
        if len(rows_for_table) != 1:
            raise RuntimeError(_CATALOG_ERROR)
        row = rows_for_table[0]
        if (
            str(row["constraint_name"]) != expected_name
            or _normalize_pg_definition(row["definition"]) != expected
        ):
            raise RuntimeError(_CATALOG_ERROR)

    expected_fks_by_table: dict[str, set[str]] = {
        table: set()
        for table in (set(_PG_PRIMARY_KEYS) & tables)
    }
    for (
        _canonical,
        (table, local, parent, remote, on_delete),
    ) in _PG_FOREIGN_KEYS.items():
        if table in tables:
            expected_fks_by_table[table].add(
                _expected_pg_fk(local, parent, remote, on_delete)
            )
    for table, expected_definitions in expected_fks_by_table.items():
        foreign_rows = by_table_type.get((table, "f"), [])
        actual_definitions = tuple(
            _normalize_pg_definition(row["definition"])
            for row in foreign_rows
        )
        if (
            len(actual_definitions) != len(set(actual_definitions))
            or not set(actual_definitions).issubset(expected_definitions)
        ):
            raise RuntimeError(_CATALOG_ERROR)

    for canonical, (
        table,
        local,
        parent,
        remote,
        on_delete,
    ) in _PG_FOREIGN_KEYS.items():
        if table not in tables:
            continue
        expected = _expected_pg_fk(local, parent, remote, on_delete)
        candidates = [
            row
            for row in by_table_type.get((table, "f"), [])
            if _normalize_pg_definition(row["definition"]) == expected
        ]
        if len(candidates) > 1:
            raise RuntimeError(_CATALOG_ERROR)
        canonical_row = next(
            (
                row
                for row in by_table_type.get((table, "f"), [])
                if str(row["constraint_name"]) == canonical
            ),
            None,
        )
        if canonical_row is not None and _normalize_pg_definition(
            canonical_row["definition"]
        ) != expected:
            raise RuntimeError(_CATALOG_ERROR)
        if not candidates:
            if table == "websocket_tickets":
                raise RuntimeError(_CATALOG_ERROR)
            add_fks.append((canonical, table, local, parent, remote))
        elif str(candidates[0]["constraint_name"]) != canonical:
            if table == "websocket_tickets":
                raise RuntimeError(_CATALOG_ERROR)
            drop.append(
                (table, str(candidates[0]["constraint_name"]), "foreignkey")
            )
            add_fks.append((canonical, table, local, parent, remote))

    for canonical, (table, columns) in _PG_UNIQUES.items():
        expected = _expected_pg_unique(columns)
        candidates = [
            row
            for row in by_table_type.get((table, "u"), [])
            if _normalize_pg_definition(row["definition"]) == expected
        ]
        if any(
            _normalize_pg_definition(row["definition"]) != expected
            for row in by_table_type.get((table, "u"), [])
        ) or len(candidates) > 1:
            raise RuntimeError(_CATALOG_ERROR)
        canonical_row = next(
            (
                row
                for row in by_table_type.get((table, "u"), [])
                if str(row["constraint_name"]) == canonical
            ),
            None,
        )
        if canonical_row is not None and _normalize_pg_definition(
            canonical_row["definition"]
        ) != expected:
            raise RuntimeError(_CATALOG_ERROR)
        if not candidates:
            add_uniques.append((canonical, table, columns))
        elif str(candidates[0]["constraint_name"]) != canonical:
            drop.append(
                (table, str(candidates[0]["constraint_name"]), "unique")
            )
            add_uniques.append((canonical, table, columns))

    expected_checks: dict[tuple[str, str], str] = {}
    for table, columns in _PG_FINITE_CHECKS.items():
        if table not in tables:
            continue
        for column, nullable in columns.items():
            name = _pg_check_name(table, column)
            expression = (
                f"{column} IS NULL OR isfinite({column})"
                if nullable
                else f"isfinite({column})"
            )
            expected_checks[(table, name)] = _normalize_pg_definition(
                f"CHECK ({expression})"
            )
    if "rate_limit_events" in tables:
        expected_checks[
            ("rate_limit_events", "ck_rate_limit_events_blocked_bool")
        ] = _normalize_pg_definition(
            "CHECK (blocked = ANY (ARRAY[0, 1]))"
        )
    for name, definition in _PG_TICKET_CHECKS.items():
        expected_checks[("websocket_tickets", name)] = (
            _normalize_pg_definition(definition)
        )

    for (table, name), expected in expected_checks.items():
        row = next(
            (
                item
                for item in by_table_type.get((table, "c"), [])
                if str(item["constraint_name"]) == name
            ),
            None,
        )
        if row is None:
            if table == "websocket_tickets":
                raise RuntimeError(_CATALOG_ERROR)
            expression = expected
            if name == "ck_rate_limit_events_blocked_bool":
                expression = "blocked IN (0, 1)"
            else:
                column = next(
                    column_name
                    for column_name in _PG_FINITE_CHECKS[table]
                    if _pg_check_name(table, column_name) == name
                )
                nullable = _PG_FINITE_CHECKS[table][column]
                expression = (
                    f"{column} IS NULL OR isfinite({column})"
                    if nullable
                    else f"isfinite({column})"
                )
            add_checks.append((name, table, expression))
        elif _normalize_pg_definition(row["definition"]) != expected:
            raise RuntimeError(_CATALOG_ERROR)

    expected_check_names: dict[str, set[str]] = {}
    for table, name in expected_checks:
        expected_check_names.setdefault(table, set()).add(name)
    expected_unique_tables = {
        table for table, _columns in _PG_UNIQUES.values()
    }
    managed_tables = set(_PG_PRIMARY_KEYS) & tables
    for (table, kind), constraint_rows in by_table_type.items():
        if table not in managed_tables:
            continue
        if kind == "c" and any(
            str(row["constraint_name"])
            not in expected_check_names.get(table, set())
            for row in constraint_rows
        ):
            raise RuntimeError(_CATALOG_ERROR)
        if kind == "u" and table not in expected_unique_tables:
            raise RuntimeError(_CATALOG_ERROR)
        if kind == "f":
            actual_definitions = tuple(
                _normalize_pg_definition(row["definition"])
                for row in constraint_rows
            )
            if (
                len(actual_definitions) != len(set(actual_definitions))
                or not set(actual_definitions).issubset(
                    expected_fks_by_table.get(table, set())
                )
            ):
                raise RuntimeError(_CATALOG_ERROR)
        if kind not in {"p", "f", "u", "c"}:
            raise RuntimeError(_CATALOG_ERROR)

    return drop, add_fks, add_checks, add_uniques, rename_uniques


def _postgresql_upgrade(bind: Any) -> None:
    _pg_validate_alembic_version_relation(bind)
    tables = _pg_validate_relation_shapes(bind)
    create_module_runs = "module_runs" not in tables
    create_rate_limit = "rate_limit_events" not in tables

    # The complete plan is read-only through this point.  An unsafe value,
    # conflicting constraint, or non-equivalent alias therefore fails before
    # any application DDL.
    findings_alterations, rename_credentials = _pg_validate_columns(
        bind,
        tables,
    )
    _pg_validate_serial_sequences(bind, tables)
    _pg_require_safe_data(bind, tables)
    (
        drop_constraints,
        add_fks,
        add_checks,
        add_uniques,
        rename_uniques,
    ) = _pg_constraint_plan(bind, tables)

    canonical_indexes = {
        table: indexes
        for table, indexes in _SQLITE_INDEXES.items()
        if table != "schema_version"
    }
    _pg_reject_reserved_index_collisions(bind, tables)
    index_rows = _pg_index_rows(bind)
    indexes = {
        (str(row["table_name"]), str(row["index_name"])): row
        for row in index_rows
    }
    known_indexes = {
        (table, name)
        for table, values in canonical_indexes.items()
        for name in values
    }
    known_indexes.update(
        (table, alias)
        for alias, (table, _canonical) in _PG_RUNTIME_ALIASES.items()
    )
    known_indexes.add(("findings", "idx_findings_validated"))
    managed_tables = _PG_REQUIRED_TABLES | _PG_OPTIONAL_TABLES
    if any(
        key[0] in managed_tables and key not in known_indexes
        for key in indexes
    ):
        raise RuntimeError(_CATALOG_ERROR)

    create_indexes: list[tuple[str, str, tuple[str, ...]]] = []
    drop_indexes: list[tuple[str, str]] = []
    for table, expected_indexes in canonical_indexes.items():
        if table not in tables:
            continue
        for name, expected_columns in expected_indexes.items():
            row = indexes.get((table, name))
            if row is None:
                if table == "websocket_tickets":
                    raise RuntimeError(_CATALOG_ERROR)
                create_indexes.append((name, table, expected_columns))
            elif _pg_index_contract(row) != _expected_pg_index(
                table, expected_columns
            ):
                raise RuntimeError(_CATALOG_ERROR)

    for alias, (table, canonical) in _PG_RUNTIME_ALIASES.items():
        row = indexes.get((table, alias))
        if row is None:
            continue
        expected_columns = canonical_indexes[table][canonical]
        if _pg_index_contract(row) != _expected_pg_index(
            table, expected_columns
        ):
            raise RuntimeError(_CATALOG_ERROR)
        drop_indexes.append((alias, table))

    obsolete = indexes.get(("findings", "idx_findings_validated"))
    if obsolete is not None:
        if _pg_index_contract(obsolete) != _expected_pg_index(
            "findings", ("validated",)
        ):
            raise RuntimeError(_CATALOG_ERROR)
        drop_indexes.append(("idx_findings_validated", "findings"))

    if rename_credentials:
        op.alter_column(
            "credentials",
            "cracked_value",
            new_column_name="cracked_value_enc",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
    if create_module_runs:
        timestamp = sa.DateTime(timezone=True)
        op.create_table(
            "module_runs",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "campaign_id",
                sa.Text(),
                sa.ForeignKey(
                    "campaigns.id",
                    name="fk_module_runs_campaign",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            sa.Column("module_id", sa.Text(), nullable=False),
            sa.Column("outcome", sa.Text(), nullable=False),
            sa.Column(
                "success", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "duration_ms",
                sa.Float(),
                nullable=False,
                server_default="0.0",
            ),
            sa.Column(
                "completed_at",
                timestamp,
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.CheckConstraint(
                "isfinite(completed_at)",
                name="ck_module_runs_completed_at_finite",
            ),
        )
        op.create_index(
            "idx_module_runs_campaign", "module_runs", ["campaign_id"]
        )
        op.create_index(
            "idx_module_runs_completed", "module_runs", ["completed_at"]
        )
    if create_rate_limit:
        op.create_table(
            "rate_limit_events",
            sa.Column(
                "id", sa.Integer(), primary_key=True, autoincrement=True
            ),
            sa.Column("ip_address", sa.Text(), nullable=False),
            sa.Column("bucket", sa.Text(), nullable=False),
            sa.Column("username", sa.Text()),
            sa.Column(
                "blocked", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "timestamp",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.CheckConstraint(
                "blocked IN (0, 1)",
                name="ck_rate_limit_events_blocked_bool",
            ),
            sa.CheckConstraint(
                "isfinite(timestamp)",
                name="ck_rate_limit_events_timestamp_finite",
            ),
        )
        op.create_index("idx_rle_ip", "rate_limit_events", ["ip_address"])
        op.create_index(
            "idx_rle_timestamp", "rate_limit_events", ["timestamp"]
        )
        op.create_index(
            "idx_rle_blocked", "rate_limit_events", ["blocked"]
        )

    for table, name, constraint_type in drop_constraints:
        op.drop_constraint(name, table, type_=constraint_type)
    if rename_uniques:
        raise RuntimeError(_CATALOG_ERROR)
    for name, table, columns in add_uniques:
        op.create_unique_constraint(name, table, list(columns))
    for name, table, local, parent, remote in add_fks:
        on_delete = _PG_FOREIGN_KEYS[name][4]
        op.create_foreign_key(
            name,
            table,
            parent,
            [local],
            [remote],
            ondelete=on_delete,
        )
    for name, table, expression in add_checks:
        op.create_check_constraint(name, table, expression)
    for name, kind, default in findings_alterations:
        op.alter_column(
            "findings",
            name,
            existing_type=kind,
            nullable=False,
            server_default=default,
        )
    for name, table, columns in create_indexes:
        op.create_index(name, table, list(columns))
    for name, table in drop_indexes:
        op.drop_index(name, table_name=table)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "sqlite":
        _sqlite_upgrade(bind)
        return
    if dialect == "postgresql":
        _postgresql_upgrade(bind)
        return
    raise RuntimeError(_DIALECT_ERROR)


def downgrade() -> None:
    raise RuntimeError(_DOWNGRADE_ERROR)
