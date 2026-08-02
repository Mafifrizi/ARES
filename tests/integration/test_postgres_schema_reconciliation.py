"""PostgreSQL runtime ownership checks for the reconciled Alembic schema."""
from __future__ import annotations

import importlib
import os
import sys
from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ares.db.postgres import PostgresDatabase, _classify_postgres_revision

_POSTGRES_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_MIGRATION_REQUIRED = "PostgreSQL schema migration required"
_INCOMPATIBLE_SCHEMA = "Incompatible managed PostgreSQL schema"
_VALIDATION_FAILED = "PostgreSQL schema validation failed"

_EXPECTED_TABLES = (
    "api_keys",
    "audit_log",
    "campaigns",
    "credentials",
    "findings",
    "hosts",
    "loot",
    "module_runs",
    "rate_limit_events",
    "refresh_token_families",
    "refresh_tokens",
    "revoked_access_tokens",
    "users",
    "websocket_tickets",
)
_EXPECTED_INDEXES = (
    ("api_keys", "idx_apikeys_prefix", ("key_prefix",), "text_ops"),
    ("api_keys", "idx_apikeys_user", ("user_id",), "text_ops"),
    ("audit_log", "idx_audit_action", ("action",), "text_ops"),
    ("audit_log", "idx_audit_actor", ("actor",), "text_ops"),
    ("audit_log", "idx_audit_campaign", ("campaign_id",), "text_ops"),
    ("credentials", "idx_creds_campaign", ("campaign_id",), "text_ops"),
    ("credentials", "idx_creds_type", ("cred_type",), "text_ops"),
    ("credentials", "idx_creds_username", ("username",), "text_ops"),
    ("findings", "idx_findings_campaign", ("campaign_id",), "text_ops"),
    ("findings", "idx_findings_cvss", ("cvss_score",), "float8_ops"),
    (
        "findings",
        "idx_findings_fp",
        ("false_positive",),
        "int4_ops",
    ),
    ("findings", "idx_findings_mitre", ("mitre_technique",), "text_ops"),
    ("findings", "idx_findings_severity", ("severity",), "text_ops"),
    ("hosts", "idx_hosts_campaign", ("campaign_id",), "text_ops"),
    ("hosts", "idx_hosts_domain", ("domain",), "text_ops"),
    ("hosts", "idx_hosts_ip", ("ip_address",), "text_ops"),
    ("loot", "idx_loot_campaign", ("campaign_id",), "text_ops"),
    ("loot", "idx_loot_type", ("loot_type",), "text_ops"),
    (
        "module_runs",
        "idx_module_runs_campaign",
        ("campaign_id",),
        "text_ops",
    ),
    (
        "module_runs",
        "idx_module_runs_completed",
        ("completed_at",),
        "timestamptz_ops",
    ),
    (
        "rate_limit_events",
        "idx_rle_blocked",
        ("blocked",),
        "int4_ops",
    ),
    (
        "rate_limit_events",
        "idx_rle_ip",
        ("ip_address",),
        "text_ops",
    ),
    (
        "rate_limit_events",
        "idx_rle_timestamp",
        ("timestamp",),
        "timestamptz_ops",
    ),
    (
        "refresh_tokens",
        "idx_refresh_exp",
        ("expires_at",),
        "timestamptz_ops",
    ),
    (
        "refresh_token_families",
        "idx_refresh_family_retain",
        ("retain_until",),
        "timestamptz_ops",
    ),
    (
        "refresh_token_families",
        "idx_refresh_family_user_state_exp",
        ("user_id", "state", "absolute_expires_at"),
        ("text_ops", "text_ops", "timestamptz_ops"),
    ),
    (
        "refresh_tokens",
        "idx_refresh_family_generation",
        ("family_id", "generation"),
        ("text_ops", "int8_ops"),
    ),
    ("refresh_tokens", "idx_refresh_user", ("user_id",), "text_ops"),
    (
        "refresh_tokens",
        "uq_refresh_token_one_active",
        ("family_id",),
        "text_ops",
    ),
    (
        "revoked_access_tokens",
        "idx_rat_expires",
        ("expires_at",),
        "timestamptz_ops",
    ),
    ("users", "idx_users_role", ("role",), "text_ops"),
    ("users", "idx_users_username", ("username",), "text_ops"),
)
_EXPECTED_PRIMARY_KEYS = (
    ("api_keys", "api_keys_pkey", ("id",)),
    ("audit_log", "audit_log_pkey", ("id",)),
    ("campaigns", "campaigns_pkey", ("id",)),
    ("credentials", "credentials_pkey", ("id",)),
    ("findings", "findings_pkey", ("id",)),
    ("hosts", "hosts_pkey", ("id",)),
    ("loot", "loot_pkey", ("id",)),
    ("module_runs", "module_runs_pkey", ("id",)),
    ("rate_limit_events", "rate_limit_events_pkey", ("id",)),
    (
        "refresh_token_families",
        "refresh_token_families_pkey",
        ("id",),
    ),
    ("refresh_tokens", "refresh_tokens_pkey", ("id",)),
    (
        "revoked_access_tokens",
        "revoked_access_tokens_pkey",
        ("jti",),
    ),
    ("users", "users_pkey", ("id",)),
)

_EXPECTED_FOREIGN_KEYS = (
    (
        "api_keys",
        "fk_api_keys_user",
        ("user_id",),
        "users",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "audit_log",
        "fk_audit_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "credentials",
        "fk_credentials_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "credentials",
        "fk_credentials_host",
        ("host_id",),
        "hosts",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "findings",
        "fk_findings_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "hosts",
        "fk_hosts_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "loot",
        "fk_loot_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "loot",
        "fk_loot_host",
        ("host_id",),
        "hosts",
        ("id",),
        "SET NULL",
        "n",
    ),
    (
        "module_runs",
        "fk_module_runs_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "refresh_token_families",
        "fk_refresh_family_user",
        ("user_id",),
        "users",
        ("id",),
        "CASCADE",
        "c",
    ),
    (
        "refresh_tokens",
        "fk_refresh_token_family_owner",
        ("family_id", "user_id"),
        "refresh_token_families",
        ("id", "user_id"),
        "CASCADE",
        "c",
    ),
    (
        "refresh_tokens",
        "fk_refresh_token_parent",
        ("family_id", "parent_id"),
        "refresh_tokens",
        ("family_id", "id"),
        "CASCADE",
        "c",
    ),
    (
        "refresh_tokens",
        "fk_refresh_tokens_user",
        ("user_id",),
        "users",
        ("id",),
        "CASCADE",
        "c",
    ),
)

_EXPECTED_UNIQUES = (
    ("hosts", "uq_hosts_campaign_ip", ("campaign_id", "ip_address")),
    (
        "refresh_token_families",
        "uq_refresh_family_owner",
        ("id", "user_id"),
    ),
    (
        "refresh_tokens",
        "uq_refresh_token_family_generation",
        ("family_id", "generation"),
    ),
    (
        "refresh_tokens",
        "uq_refresh_token_family_hash",
        ("family_id", "id"),
    ),
    ("refresh_tokens", "uq_refresh_token_parent", ("parent_id",)),
    ("users", "uq_users_username", ("username",)),
)

_EXPECTED_FINITE_CHECKS = (
    ("api_keys", "created_at", False),
    ("api_keys", "expires_at", True),
    ("api_keys", "last_used", True),
    ("audit_log", "timestamp", False),
    ("campaigns", "created_at", False),
    ("campaigns", "updated_at", False),
    ("credentials", "captured_at", False),
    ("findings", "discovered_at", False),
    ("hosts", "first_seen", False),
    ("hosts", "last_seen", False),
    ("loot", "captured_at", False),
    ("module_runs", "completed_at", False),
    ("rate_limit_events", "timestamp", False),
    ("refresh_token_families", "absolute_expires_at", False),
    ("refresh_token_families", "created_at", False),
    ("refresh_token_families", "retain_until", False),
    ("refresh_token_families", "revoked_at", True),
    ("refresh_tokens", "created_at", False),
    ("refresh_tokens", "expires_at", False),
    ("refresh_tokens", "revoked_at", True),
    ("refresh_tokens", "used_at", True),
    ("revoked_access_tokens", "expires_at", False),
    ("revoked_access_tokens", "revoked_at", False),
    ("users", "created_at", False),
    ("users", "last_login", True),
)

_EXPECTED_TOKEN_CHECKS = (
    ("users", "ck_users_auth_epoch", "auth_epoch", "CHECK (auth_epoch >= 1)"),
    (
        "refresh_token_families",
        "ck_refresh_family_id",
        "id",
        "CHECK (id ~ '^[A-Za-z0-9_-]{43}$'::text)",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_epoch",
        "auth_epoch",
        "CHECK (auth_epoch >= 1)",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_state",
        "state",
        "CHECK (state = ANY (ARRAY['active'::text, 'revoked'::text]))",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_revocation_shape",
        "state",
        "CHECK (state = 'active'::text AND revoked_at IS NULL "
        "AND revoke_reason IS NULL OR state = 'revoked'::text "
        "AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_reason",
        "revoke_reason",
        "CHECK (revoke_reason IS NULL OR (revoke_reason = ANY "
        "(ARRAY['expired'::text, 'logout_all'::text, "
        "'logout_current'::text, 'operator_revoke'::text, "
        "'password_change'::text, 'password_reset'::text, "
        "'replay'::text, 'role_change'::text, "
        "'rollout_reset'::text, 'user_status_change'::text])))",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_expiry_order",
        "absolute_expires_at",
        "CHECK (absolute_expires_at > created_at)",
    ),
    (
        "refresh_token_families",
        "ck_refresh_family_retention_order",
        "retain_until",
        "CHECK (retain_until > absolute_expires_at AND "
        "(revoked_at IS NULL OR retain_until > revoked_at))",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_hash",
        "id",
        "CHECK (id ~ '^[0-9a-f]{64}$'::text)",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_generation",
        "generation",
        "CHECK (generation >= 0)",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_parent_shape",
        "generation",
        "CHECK (generation = 0 AND parent_id IS NULL "
        "OR generation > 0 AND parent_id IS NOT NULL)",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_state",
        "state",
        "CHECK (state = ANY (ARRAY['active'::text, "
        "'consumed'::text, 'retired'::text]))",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_state_shape",
        "state",
        "CHECK (state = 'active'::text AND is_revoked = 0 "
        "AND used_at IS NULL AND revoked_at IS NULL "
        "OR state = 'consumed'::text AND is_revoked = 1 "
        "AND used_at IS NOT NULL AND revoked_at IS NULL "
        "OR state = 'retired'::text AND is_revoked = 1 "
        "AND revoked_at IS NOT NULL)",
    ),
    (
        "refresh_tokens",
        "ck_refresh_token_expiry_order",
        "expires_at",
        "CHECK (expires_at > created_at)",
    ),
)

_CURRENT_EXPECTED_TABLES = _EXPECTED_TABLES
_CURRENT_EXPECTED_INDEXES = _EXPECTED_INDEXES
_CURRENT_EXPECTED_PRIMARY_KEYS = _EXPECTED_PRIMARY_KEYS
_CURRENT_EXPECTED_FOREIGN_KEYS = _EXPECTED_FOREIGN_KEYS
_CURRENT_EXPECTED_UNIQUES = _EXPECTED_UNIQUES
_CURRENT_EXPECTED_FINITE_CHECKS = _EXPECTED_FINITE_CHECKS

_EXPECTED_TABLES = tuple(
    table for table in _EXPECTED_TABLES if table != "refresh_token_families"
)
_EXPECTED_INDEXES = tuple(
    item
    for item in _EXPECTED_INDEXES
    if item[1]
    not in {
        "idx_refresh_family_retain",
        "idx_refresh_family_user_state_exp",
        "idx_refresh_family_generation",
        "uq_refresh_token_one_active",
    }
)
_EXPECTED_PRIMARY_KEYS = tuple(
    item
    for item in _EXPECTED_PRIMARY_KEYS
    if item[0] != "refresh_token_families"
)
_EXPECTED_FOREIGN_KEYS = tuple(
    item
    for item in _EXPECTED_FOREIGN_KEYS
    if item[1]
    not in {
        "fk_refresh_family_user",
        "fk_refresh_token_family_owner",
        "fk_refresh_token_parent",
    }
)
_EXPECTED_UNIQUES = tuple(
    item
    for item in _EXPECTED_UNIQUES
    if item[1]
    not in {
        "uq_refresh_family_owner",
        "uq_refresh_token_family_generation",
        "uq_refresh_token_family_hash",
        "uq_refresh_token_parent",
    }
)
_EXPECTED_FINITE_CHECKS = tuple(
    item
    for item in _EXPECTED_FINITE_CHECKS
    if item[0] != "refresh_token_families"
    and not (item[0] == "refresh_tokens" and item[1] == "revoked_at")
)


def _finite_check_name(table: str, column: str) -> str:
    if table == "module_runs":
        return "ck_module_runs_completed_at_finite"
    if table == "audit_log":
        return "ck_audit_log_timestamp_finite"
    if table == "rate_limit_events":
        return "ck_rate_limit_events_timestamp_finite"
    if table == "refresh_tokens" and column == "revoked_at":
        return "ck_refresh_token_revoked_finite"
    if table == "refresh_token_families":
        return {
            "created_at": "ck_refresh_family_created_finite",
            "absolute_expires_at": "ck_refresh_family_expires_finite",
            "revoked_at": "ck_refresh_family_revoked_finite",
            "retain_until": "ck_refresh_family_retain_finite",
        }[column]
    return f"ck_{table}_{column}_finite"


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _postgres_test_config() -> tuple[str, int, str, str]:
    present = {name for name in _POSTGRES_ENV if name in os.environ}
    if not present:
        pytest.skip("real PostgreSQL test environment is not configured")
    if present != set(_POSTGRES_ENV):
        pytest.fail("Incomplete PostgreSQL test environment", pytrace=False)
    values = {name: os.environ[name] for name in _POSTGRES_ENV}
    if any(not value or value != value.strip() for value in values.values()):
        pytest.fail("Invalid PostgreSQL test environment", pytrace=False)
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if (
        not raw_port.isascii()
        or not raw_port.isdecimal()
        or str(int(raw_port)) != raw_port
    ):
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    port = int(raw_port)
    if not 1 <= port <= 65535:
        pytest.fail(
            "PostgreSQL test port is outside its valid range",
            pytrace=False,
        )
    return (
        values["ARES_TEST_POSTGRES_HOST"],
        port,
        values["ARES_TEST_POSTGRES_USER"],
        values["ARES_TEST_POSTGRES_DB"],
    )


class _AsyncBoundary:
    async def __aenter__(self) -> _AsyncBoundary:
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        return None


class _AcquireBoundary:
    def __init__(self, connection: _PureManagedConnection) -> None:
        self._connection = connection

    async def __aenter__(self) -> _PureManagedConnection:
        return self._connection

    async def __aexit__(self, *_exc_info: object) -> None:
        return None


def _table_rows() -> list[dict[str, object]]:
    return [
        {
            "table_oid": position + 100,
            "table_name": table,
            "table_schema": "public",
            "type_oid": position + 500,
            "type_schema": "public",
            "type_name": table,
            "typtype": "c",
            "type_relation_oid": position + 100,
            "relkind": "r",
            "relpersistence": "p",
            "relispartition": False,
            "relrowsecurity": False,
            "relforcerowsecurity": False,
            "parent_count": 0,
            "child_count": 0,
            "policy_count": 0,
            "user_trigger_count": 0,
            "user_rule_count": 0,
        }
        for position, table in enumerate(_CURRENT_EXPECTED_TABLES)
    ]


def _index_rows() -> list[dict[str, object]]:
    return [
        {
            "table_name": table,
            "index_name": name,
            "index_relkind": "i",
            "index_relpersistence": "p",
            "index_is_partition": False,
            "access_method": "btree",
            "indisunique": name == "uq_refresh_token_one_active",
            "indisprimary": False,
            "indisvalid": True,
            "indisready": True,
            "indislive": True,
            "indnkeyatts": len(columns),
            "indnatts": len(columns),
            "columns": list(columns),
            "column_options": [0] * len(columns),
            "operator_classes": (
                list(opclass)
                if isinstance(opclass, tuple)
                else [opclass] * len(columns)
            ),
            "operator_class_namespaces": ["pg_catalog"] * len(columns),
            "column_collations_match": [True] * len(columns),
            "expressions": None,
            "predicate": (
                "(state = 'active'::text)"
                if name == "uq_refresh_token_one_active"
                else None
            ),
        }
        for table, name, columns, opclass in _CURRENT_EXPECTED_INDEXES
    ]


def _primary_rows() -> list[dict[str, object]]:
    return [
        {
            "table_name": table,
            "conname": name,
            "contype": "p",
            "convalidated": True,
            "condeferrable": False,
            "condeferred": False,
            "constraint_index_oid": position + 1000,
            "local_columns": list(columns),
            "index_relkind": "i",
            "index_relpersistence": "p",
            "index_is_partition": False,
            "indisunique": True,
            "indisprimary": True,
            "indisvalid": True,
            "indisready": True,
            "indislive": True,
        }
        for position, (table, name, columns) in enumerate(
            _CURRENT_EXPECTED_PRIMARY_KEYS
        )
    ]


def _managed_constraint_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for position, (
        table,
        name,
        local,
        parent,
        remote,
        on_delete,
        delete_code,
    ) in enumerate(_CURRENT_EXPECTED_FOREIGN_KEYS, start=1):
        reference_index_name = {
            "fk_refresh_token_family_owner": "uq_refresh_family_owner",
            "fk_refresh_token_parent": "uq_refresh_token_family_hash",
        }.get(name, f"{parent}_pkey")
        parent_is_deferred = name == "fk_refresh_token_parent"
        definition = (
            f"FOREIGN KEY ({', '.join(local)}) "
            f"REFERENCES {parent}({', '.join(remote)}) "
            f"ON DELETE {on_delete}"
        )
        if parent_is_deferred:
            definition += " DEFERRABLE INITIALLY DEFERRED"
        rows.append(
            {
                "source_schema": "public",
                "table_name": table,
                "conname": name,
                "contype": "f",
                "convalidated": True,
                "condeferrable": parent_is_deferred,
                "condeferred": parent_is_deferred,
                "constraint_index_oid": 2000 + position,
                "definition": definition,
                "referenced_schema": "public",
                "referenced_table": parent,
                "confupdtype": "a",
                "confdeltype": delete_code,
                "local_columns": list(local),
                "remote_columns": list(remote),
                "index_schema": "public",
                "index_name": reference_index_name,
                "index_relkind": "i",
                "index_relpersistence": "p",
                "index_is_partition": False,
                "access_method": "btree",
                "indisunique": True,
                "indisprimary": reference_index_name.endswith("_pkey"),
                "indisvalid": True,
                "indisready": True,
                "indislive": True,
                "indnkeyatts": len(remote),
                "indnatts": len(remote),
                "index_columns": list(remote),
                "column_options": [0] * len(remote),
                "operator_classes": ["text_ops"] * len(remote),
                "operator_class_namespaces": ["pg_catalog"] * len(remote),
                "column_collations_match": [True] * len(remote),
                "expressions": None,
                "predicate": None,
            }
        )
    for position, (table, name, columns) in enumerate(
        _CURRENT_EXPECTED_UNIQUES,
        start=1,
    ):
        rows.append(
            {
                "source_schema": "public",
                "table_name": table,
                "conname": name,
                "contype": "u",
                "convalidated": True,
                "condeferrable": False,
                "condeferred": False,
                "constraint_index_oid": 3000 + position,
                "definition": f"UNIQUE ({', '.join(columns)})",
                "referenced_schema": None,
                "referenced_table": None,
                "confupdtype": " ",
                "confdeltype": " ",
                "local_columns": list(columns),
                "remote_columns": [],
                "index_schema": "public",
                "index_name": name,
                "index_relkind": "i",
                "index_relpersistence": "p",
                "index_is_partition": False,
                "access_method": "btree",
                "indisunique": True,
                "indisprimary": False,
                "indisvalid": True,
                "indisready": True,
                "indislive": True,
                "indnkeyatts": len(columns),
                "indnatts": len(columns),
                "index_columns": list(columns),
                "column_options": [0] * len(columns),
                "operator_classes": [
                    "int8_ops"
                    if table == "refresh_tokens"
                    and column == "generation"
                    else "text_ops"
                    for column in columns
                ],
                "operator_class_namespaces": ["pg_catalog"] * len(columns),
                "column_collations_match": [True] * len(columns),
                "expressions": None,
                "predicate": None,
            }
        )
    for table, column, nullable in _CURRENT_EXPECTED_FINITE_CHECKS:
        name = _finite_check_name(table, column)
        expression = (
            f"{column} IS NULL OR isfinite({column})"
            if nullable
            else f"isfinite({column})"
        )
        rows.append(
            {
                "source_schema": "public",
                "table_name": table,
                "conname": name,
                "contype": "c",
                "convalidated": True,
                "condeferrable": False,
                "condeferred": False,
                "constraint_index_oid": 0,
                "definition": f"CHECK ({expression})",
                "referenced_schema": None,
                "referenced_table": None,
                "confupdtype": " ",
                "confdeltype": " ",
                "local_columns": [column],
                "remote_columns": [],
                "index_schema": None,
                "index_name": None,
                "index_relkind": None,
                "index_relpersistence": None,
                "index_is_partition": None,
                "access_method": None,
                "indisunique": None,
                "indisprimary": None,
                "indisvalid": None,
                "indisready": None,
                "indislive": None,
                "indnkeyatts": None,
                "indnatts": None,
                "index_columns": [],
                "column_options": [],
                "operator_classes": [],
                "operator_class_namespaces": [],
                "column_collations_match": [],
                "expressions": None,
                "predicate": None,
            }
        )
    blocked = deepcopy(rows[-1])
    blocked.update(
        {
            "table_name": "rate_limit_events",
            "conname": "ck_rate_limit_events_blocked_bool",
            "definition": "CHECK (blocked = ANY (ARRAY[0, 1]))",
            "local_columns": ["blocked"],
        }
    )
    rows.append(blocked)
    for table, name, column, definition in _EXPECTED_TOKEN_CHECKS:
        token_check = deepcopy(blocked)
        token_check.update(
            {
                "table_name": table,
                "conname": name,
                "definition": definition,
                "local_columns": [column],
            }
        )
        rows.append(token_check)
    return rows


def _managed_sequence_rows() -> list[dict[str, object]]:
    return [
        {
            "sequence_schema": "public",
            "sequence_name": name,
            "relkind": "S",
            "relpersistence": "p",
            "data_type": "integer",
            "seqstart": 1,
            "seqincrement": 1,
            "seqmax": 2147483647,
            "seqmin": 1,
            "seqcache": 1,
            "seqcycle": False,
            "owner_schema": "public",
            "owner_table": table,
            "owner_column": "id",
            "deptype": "a",
            "owner_data_type": "integer",
            "attnotnull": True,
            "attidentity": "",
            "attgenerated": "",
            "collation_is_default": True,
            "column_default": f"nextval('{name}'::regclass)",
        }
        for name, table in (
            ("audit_log_id_seq", "audit_log"),
            ("rate_limit_events_id_seq", "rate_limit_events"),
        )
    ]


class _PureManagedConnection:
    def __init__(
        self,
        *,
        revision_present: bool = True,
        revision_values: tuple[object, ...] = ("0009",),
    ) -> None:
        self.revision_present = revision_present
        self.revision_values = revision_values
        self.version_relation = {
            "table_oid": 42,
            "schema_name": "public",
            "type_oid": 84,
            "type_schema": "public",
            "type_name": "alembic_version",
            "typtype": "c",
            "type_relation_oid": 42,
            "relkind": "r",
            "relpersistence": "p",
            "relispartition": False,
            "relrowsecurity": False,
            "relforcerowsecurity": False,
            "parent_count": 0,
            "child_count": 0,
            "policy_count": 0,
            "user_trigger_count": 0,
            "user_rule_count": 0,
        }
        self.version_columns = [
            {
                "attnum": 1,
                "column_name": "version_num",
                "data_type": "character varying(32)",
                "attnotnull": True,
                "attidentity": "",
                "attgenerated": "",
                "attisdropped": False,
                "attinhcount": 0,
                "attislocal": True,
                "atthasmissing": False,
                "missing_value": None,
                "collation_is_default": True,
                "column_default": None,
            }
        ]
        self.version_primary = [
            {
                "conname": "alembic_version_pkc",
                "contype": "p",
                "convalidated": True,
                "condeferrable": False,
                "condeferred": False,
                "columns": ["version_num"],
            }
        ]
        self.version_indexes = [
            {
                "index_name": "alembic_version_pkc",
                "index_relkind": "i",
                "index_relpersistence": "p",
                "index_is_partition": False,
                "access_method": "btree",
                "indisunique": True,
                "indisprimary": True,
                "indisvalid": True,
                "indisready": True,
                "indislive": True,
                "indnkeyatts": 1,
                "indnatts": 1,
                "constraint_name": "alembic_version_pkc",
                "columns": ["version_num"],
                "column_options": [0],
                "operator_classes": ["text_ops"],
                "operator_class_namespaces": ["pg_catalog"],
                "column_collations_match": [True],
                "expressions": None,
                "predicate": None,
            }
        ]
        self.tables = _table_rows()
        self.legacy_indexes: list[dict[str, object]] = []
        self.indexes = _index_rows()
        self.primary_keys = _primary_rows()
        self.constraints = _managed_constraint_rows()
        self.sequences = _managed_sequence_rows()
        self.fallback_count = 0
        self.raise_during_revision: Exception | None = None

    def transaction(self) -> _AsyncBoundary:
        return _AsyncBoundary()

    async def fetch(self, query: str, *_args: object) -> list[dict[str, object]]:
        normalized = " ".join(query.split())
        if (
            "rel.relname='alembic_version'" in normalized
            and "FROM pg_class AS rel" in normalized
        ):
            if self.raise_during_revision is not None:
                raise self.raise_during_revision
            return [deepcopy(self.version_relation)] if self.revision_present else []
        if "WHERE att.attrelid=$1::oid" in normalized:
            return deepcopy(self.version_columns)
        if "WHERE con.conrelid=$1::oid" in normalized:
            return deepcopy(self.version_primary)
        if normalized.startswith("SELECT version_num FROM"):
            return [
                {"version_num": value}
                for value in self.revision_values
            ]
        if (
            "FROM pg_index AS ind" in normalized
            and "WHERE ind.indrelid=$1::oid" in normalized
        ):
            return deepcopy(self.version_indexes)
        if (
            "rel.relname=ANY($1::text[])" in normalized
            and "FROM pg_class AS rel" in normalized
        ):
            return deepcopy(self.tables)
        if (
            "FROM pg_index AS ind" in normalized
            and "left(index_rel.relname, 7)='idx_pg_'" in normalized
        ):
            return deepcopy(self.legacy_indexes)
        if "FROM pg_index AS ind" in normalized:
            return deepcopy(self.indexes)
        if (
            "FROM pg_constraint AS con" in normalized
            and "source.relname=ANY($1::text[])" in normalized
            and "con.contype='p'" in normalized
        ):
            return deepcopy(self.primary_keys)
        if (
            "FROM pg_constraint AS con" in normalized
            and "con.contype <> 'p'" in normalized
        ):
            return deepcopy(self.constraints)
        if "pg_sequence AS sequence_def" in normalized:
            return deepcopy(self.sequences)
        raise AssertionError("unexpected managed-schema catalog operation")

    async def fetchval(self, query: str, *_args: object) -> object:
        normalized = " ".join(query.split())
        if "SELECT EXISTS(" in normalized:
            return False
        raise AssertionError("unexpected managed-schema scalar operation")

    async def execute(self, query: str, *_args: object) -> str:
        if "CREATE TABLE IF NOT EXISTS campaigns" not in query:
            raise AssertionError("unexpected managed-schema mutation")
        self.fallback_count += 1
        return "OK"


class _PurePool:
    def __init__(self, connection: _PureManagedConnection) -> None:
        self.connection = connection
        self.close_count = 0

    def acquire(self) -> _AcquireBoundary:
        return _AcquireBoundary(self.connection)

    async def close(self) -> None:
        self.close_count += 1


class _RealConnectionAudit:
    def __init__(self, connection: Any, pool: _RealPoolAudit) -> None:
        self._connection = connection
        self._pool = pool

    def transaction(self) -> Any:
        return self._connection.transaction()

    async def execute(self, query: str, *args: object) -> object:
        if "CREATE TABLE IF NOT EXISTS campaigns" in query:
            self._pool.fallback_count += 1
        return await self._connection.execute(query, *args)

    async def fetch(self, query: str, *args: object) -> object:
        return await self._connection.fetch(query, *args)

    async def fetchrow(self, query: str, *args: object) -> object:
        return await self._connection.fetchrow(query, *args)

    async def fetchval(self, query: str, *args: object) -> object:
        return await self._connection.fetchval(query, *args)


class _RealAcquireAudit:
    def __init__(self, pool: _RealPoolAudit) -> None:
        self._pool = pool
        self._connection: Any = None

    async def __aenter__(self) -> _RealConnectionAudit:
        self._connection = await self._pool._pool.acquire()
        return _RealConnectionAudit(self._connection, self._pool)

    async def __aexit__(self, *_exc_info: object) -> None:
        if self._connection is not None:
            await self._pool._pool.release(self._connection)
            self._connection = None


class _RealPoolAudit:
    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self.fallback_count = 0
        self.close_count = 0

    def acquire(self) -> _RealAcquireAudit:
        return _RealAcquireAudit(self)

    async def close(self) -> None:
        self.close_count += 1
        await self._pool.close()


def _audit_runtime_pools(
    monkeypatch: pytest.MonkeyPatch,
) -> list[_RealPoolAudit]:
    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg is required for configured PostgreSQL tests",
            pytrace=False,
        )
    original_create_pool = asyncpg.create_pool
    pools: list[_RealPoolAudit] = []

    async def _create_pool(*args: object, **kwargs: object) -> _RealPoolAudit:
        real_pool = await original_create_pool(*args, **kwargs)
        audited_pool = _RealPoolAudit(real_pool)
        pools.append(audited_pool)
        return audited_pool

    monkeypatch.setattr(asyncpg, "create_pool", _create_pool)
    return pools


def _runtime_database(harness: Any) -> PostgresDatabase:
    from tests.integration import test_postgres_migration_portability as support

    return PostgresDatabase(
        support._migration_url(harness.config, harness.database_name),
        pool_min=1,
        pool_max=2,
    )


async def _fixed_connect_result(database: PostgresDatabase) -> str:
    try:
        await database.connect()
    except RuntimeError as exc:
        message = str(exc)
        if message in {
            _MIGRATION_REQUIRED,
            _INCOMPATIBLE_SCHEMA,
            _VALIDATION_FAILED,
        }:
            return message
        return "unexpected"
    return "connected"


async def _run_init(
    monkeypatch: pytest.MonkeyPatch,
    connection: _PureManagedConnection,
) -> int:
    validated = 0

    async def _validate_ticket(
        _database: object,
        _connection: object,
    ) -> None:
        nonlocal validated
        validated += 1

    monkeypatch.setattr(
        PostgresDatabase,
        "_validate_websocket_ticket_schema",
        _validate_ticket,
    )
    database = PostgresDatabase("synthetic")
    database._pool = _PurePool(connection)
    with patch("ares.db.postgres.logger.info", return_value=None):
        await database._init_schema()
    return validated


@pytest.mark.parametrize("revision", ["0001", "0004", "0007", "0008"])
def test_revision_classifier_requires_migration_for_known_older_heads(
    revision: str,
) -> None:
    observed = ""
    try:
        _classify_postgres_revision((revision,))
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _MIGRATION_REQUIRED,
        "known older PostgreSQL revision was not migration-gated",
    )


@pytest.mark.parametrize(
    "values",
    [
        (),
        (None,),
        ("",),
        ("0009", "0009"),
        ("0009", "0008"),
        ("9999",),
        (" 0009",),
    ],
)
def test_revision_classifier_rejects_malformed_or_unknown_state(
    values: tuple[object, ...],
) -> None:
    observed = ""
    try:
        _classify_postgres_revision(values)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _INCOMPATIBLE_SCHEMA,
        "malformed PostgreSQL revision state was accepted",
    )


def test_revision_classifier_accepts_only_exact_managed_head() -> None:
    accepted = _classify_postgres_revision(("0009",)) == "0009"
    _require_fixed(accepted, "managed PostgreSQL revision was rejected")


def test_postgres_constraint_normalization_preserves_literal_case() -> None:
    migration = importlib.import_module(
        "migrations.versions.0008_reconcile_schema_parity"
    )
    scope_expected = migration._normalize_pg_definition(
        "CHECK (required_scope = 'read'::text)"
    )
    scope_changed = migration._normalize_pg_definition(
        "check (required_scope = 'READ'::TEXT)"
    )
    hash_expected = migration._normalize_pg_definition(
        "CHECK (ticket_hash ~ '^[0-9a-f]{64}$'::text)"
    )
    hash_changed = migration._normalize_pg_definition(
        "check (ticket_hash ~ '^[0-9A-F]{64}$'::TEXT)"
    )
    _require_fixed(
        scope_expected != scope_changed and hash_expected != hash_changed,
        "PostgreSQL constraint literal drift was normalized away",
    )


@pytest.mark.asyncio
async def test_unversioned_database_requires_migration_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _PureManagedConnection(revision_present=False)
    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _MIGRATION_REQUIRED and connection.fallback_count == 0,
        "unversioned PostgreSQL startup did not require migration",
    )


@pytest.mark.asyncio
async def test_managed_database_validates_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _PureManagedConnection()
    validated = await _run_init(monkeypatch, connection)
    _require_fixed(
        connection.fallback_count == 0 and validated == 1,
        "managed PostgreSQL schema entered runtime fallback",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-index",
        "invalid-index",
        "wrong-opclass",
        "wrong-collation",
        "wrong-constraint",
        "wrong-column",
    ],
)
@pytest.mark.asyncio
async def test_version_relation_index_metadata_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    connection = _PureManagedConnection()
    if mutation == "extra-index":
        extra = deepcopy(connection.version_indexes[0])
        extra["index_name"] = "unexpected_version_index"
        extra["constraint_name"] = None
        extra["indisunique"] = False
        extra["indisprimary"] = False
        connection.version_indexes.append(extra)
    elif mutation == "invalid-index":
        connection.version_indexes[0]["indisvalid"] = False
    elif mutation == "wrong-opclass":
        connection.version_indexes[0]["operator_classes"] = ["varchar_ops"]
    elif mutation == "wrong-collation":
        connection.version_indexes[0]["column_collations_match"] = [False]
    elif mutation == "wrong-constraint":
        connection.version_indexes[0]["constraint_name"] = None
    elif mutation == "wrong-column":
        connection.version_indexes[0]["columns"] = ["other"]
    else:
        raise AssertionError("unknown version-index mutation")

    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _INCOMPATIBLE_SCHEMA
        and connection.fallback_count == 0,
        "PostgreSQL version index metadata drift was accepted",
    )


@pytest.mark.parametrize(
    "field",
    [
        "parent_count",
        "child_count",
        "policy_count",
        "user_trigger_count",
        "user_rule_count",
        "type_relation_oid",
        "missing-type-binding",
    ],
)
@pytest.mark.asyncio
async def test_version_relation_rejects_attached_metadata(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    connection = _PureManagedConnection()
    if field == "missing-type-binding":
        connection.version_relation["type_oid"] = None
        connection.version_relation["type_schema"] = None
        connection.version_relation["type_name"] = None
        connection.version_relation["typtype"] = None
        connection.version_relation["type_relation_oid"] = None
    else:
        connection.version_relation[field] = 1
    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _INCOMPATIBLE_SCHEMA
        and connection.fallback_count == 0,
        "PostgreSQL version relation metadata drift was accepted",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-attnum",
        "dropped-column",
        "inherited-column",
        "nonlocal-column",
        "missing-value",
        "custom-collation",
    ],
)
@pytest.mark.asyncio
async def test_version_column_physical_metadata_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    connection = _PureManagedConnection()
    column = connection.version_columns[0]
    if mutation == "wrong-attnum":
        column["attnum"] = 2
    elif mutation == "dropped-column":
        dropped = deepcopy(column)
        dropped.update(
            {
                "attnum": 2,
                "column_name": "........pg.dropped.2........",
                "data_type": "-",
                "attnotnull": False,
                "attisdropped": True,
                "collation_is_default": False,
            }
        )
        connection.version_columns.append(dropped)
    elif mutation == "inherited-column":
        column["attinhcount"] = 1
    elif mutation == "nonlocal-column":
        column["attislocal"] = False
    elif mutation == "missing-value":
        column["atthasmissing"] = True
        column["missing_value"] = "{}"
    elif mutation == "custom-collation":
        column["collation_is_default"] = False
    else:
        raise AssertionError("unknown version-column mutation")
    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _INCOMPATIBLE_SCHEMA
        and connection.fallback_count == 0,
        "PostgreSQL version column metadata drift was accepted",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-table",
        "wrong-table-kind",
        "wrong-table-type-binding",
        "missing-index",
        "extra-legacy-index",
        "wrong-index-column",
        "unique-index",
        "partial-index",
        "wrong-opclass",
        "wrong-opclass-namespace",
        "wrong-collation",
        "descending-index",
        "missing-primary-key",
        "wrong-primary-key",
        "invalid-primary-index",
        "relation-rls",
        "relation-forced-rls",
        "relation-inheritance",
        "relation-policy",
        "relation-trigger",
        "relation-rule",
        "missing-foreign-key",
        "wrong-foreign-key-target",
        "wrong-foreign-index",
        "duplicate-foreign-key",
        "extra-root-foreign-key",
        "extra-exclusion-constraint",
        "missing-check",
        "wrong-check-definition",
        "missing-unique",
        "wrong-unique-index",
        "missing-sequence",
        "wrong-sequence-owner",
        "wrong-sequence-owner-schema",
        "wrong-sequence-default",
        "wrong-sequence-options",
        "identity-serial",
        "generated-serial",
    ],
)
@pytest.mark.asyncio
async def test_managed_inventory_rejects_catalog_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    connection = _PureManagedConnection()
    if mutation == "missing-table":
        connection.tables.pop()
    elif mutation == "wrong-table-kind":
        connection.tables[0]["relkind"] = "v"
    elif mutation == "wrong-table-type-binding":
        connection.tables[0]["type_relation_oid"] = 9999
    elif mutation == "missing-index":
        connection.indexes.pop()
    elif mutation == "extra-legacy-index":
        connection.legacy_indexes.append(
            {
                "table_name": "users",
                "index_name": "idx_pg_unexpected",
            }
        )
    elif mutation == "wrong-index-column":
        connection.indexes[0]["columns"] = ["id"]
    elif mutation == "unique-index":
        connection.indexes[0]["indisunique"] = True
    elif mutation == "partial-index":
        connection.indexes[0]["predicate"] = "true"
    elif mutation == "wrong-opclass":
        connection.indexes[0]["operator_classes"] = ["text_pattern_ops"]
    elif mutation == "wrong-opclass-namespace":
        connection.indexes[0]["operator_class_namespaces"] = ["public"]
    elif mutation == "wrong-collation":
        connection.indexes[0]["column_collations_match"] = [False]
    elif mutation == "descending-index":
        connection.indexes[0]["column_options"] = [1]
    elif mutation == "missing-primary-key":
        connection.primary_keys.pop()
    elif mutation == "wrong-primary-key":
        connection.primary_keys[0]["local_columns"] = ["user_id"]
    elif mutation == "invalid-primary-index":
        connection.primary_keys[0]["indisvalid"] = False
    elif mutation == "relation-rls":
        connection.tables[0]["relrowsecurity"] = True
    elif mutation == "relation-forced-rls":
        connection.tables[0]["relforcerowsecurity"] = True
    elif mutation == "relation-inheritance":
        connection.tables[0]["child_count"] = 1
    elif mutation == "relation-policy":
        connection.tables[0]["policy_count"] = 1
    elif mutation == "relation-trigger":
        connection.tables[0]["user_trigger_count"] = 1
    elif mutation == "relation-rule":
        connection.tables[0]["user_rule_count"] = 1
    elif mutation == "missing-foreign-key":
        connection.constraints = [
            row
            for row in connection.constraints
            if row["contype"] != "f"
            or row["conname"] != "fk_api_keys_user"
        ]
    elif mutation == "wrong-foreign-key-target":
        foreign_key = next(
            row
            for row in connection.constraints
            if row["conname"] == "fk_api_keys_user"
        )
        foreign_key["referenced_table"] = "campaigns"
    elif mutation == "wrong-foreign-index":
        foreign_key = next(
            row
            for row in connection.constraints
            if row["conname"] == "fk_api_keys_user"
        )
        foreign_key["index_name"] = "campaigns_pkey"
    elif mutation == "duplicate-foreign-key":
        extra = deepcopy(
            next(
                row
                for row in connection.constraints
                if row["conname"] == "fk_api_keys_user"
            )
        )
        extra["conname"] = "duplicate_api_keys_user"
        connection.constraints.append(extra)
    elif mutation == "extra-root-foreign-key":
        extra = deepcopy(
            next(
                row
                for row in connection.constraints
                if row["conname"] == "fk_api_keys_user"
            )
        )
        extra.update(
            {
                "table_name": "campaigns",
                "conname": "unexpected_campaign_self_fk",
                "definition": (
                    "FOREIGN KEY (id) REFERENCES campaigns(id) "
                    "ON DELETE CASCADE"
                ),
                "referenced_table": "campaigns",
                "local_columns": ["id"],
            }
        )
        connection.constraints.append(extra)
    elif mutation == "extra-exclusion-constraint":
        extra = deepcopy(connection.constraints[-1])
        extra.update(
            {
                "table_name": "campaigns",
                "conname": "unexpected_campaign_exclusion",
                "contype": "x",
                "definition": "EXCLUDE USING btree (id WITH =)",
                "local_columns": ["id"],
            }
        )
        connection.constraints.append(extra)
    elif mutation == "missing-check":
        connection.constraints = [
            row
            for row in connection.constraints
            if row["contype"] != "c"
            or row["conname"] != "ck_users_created_at_finite"
        ]
    elif mutation == "wrong-check-definition":
        check = next(
            row
            for row in connection.constraints
            if row["conname"] == "ck_rate_limit_events_blocked_bool"
        )
        check["definition"] = "CHECK ((blocked = 0) OR (blocked = 1))"
    elif mutation == "missing-unique":
        connection.constraints = [
            row
            for row in connection.constraints
            if row["contype"] != "u"
            or row["conname"] != "uq_users_username"
        ]
    elif mutation == "wrong-unique-index":
        unique = next(
            row
            for row in connection.constraints
            if row["conname"] == "uq_users_username"
        )
        unique["column_collations_match"] = [False]
    elif mutation == "missing-sequence":
        connection.sequences.pop()
    elif mutation == "wrong-sequence-owner":
        connection.sequences[0]["owner_table"] = "campaigns"
    elif mutation == "wrong-sequence-owner-schema":
        connection.sequences[0]["owner_schema"] = "other"
    elif mutation == "wrong-sequence-default":
        connection.sequences[0]["column_default"] = "7"
    elif mutation == "wrong-sequence-options":
        connection.sequences[0]["seqincrement"] = 2
    elif mutation == "identity-serial":
        connection.sequences[0]["attidentity"] = "d"
    elif mutation == "generated-serial":
        connection.sequences[0]["attgenerated"] = "s"
    else:
        raise AssertionError("unknown managed-schema mutation")

    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    _require_fixed(
        observed == _INCOMPATIBLE_SCHEMA
        and connection.fallback_count == 0,
        "managed PostgreSQL catalog drift was not rejected",
    )


@pytest.mark.parametrize(
    "revision_values",
    [("0003",), (), ("unknown",), ("0009", "0008")],
)
@pytest.mark.asyncio
async def test_versioned_failure_never_enters_runtime_fallback(
    monkeypatch: pytest.MonkeyPatch,
    revision_values: tuple[object, ...],
) -> None:
    connection = _PureManagedConnection(revision_values=revision_values)
    observed = ""
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
    expected = (
        _MIGRATION_REQUIRED
        if revision_values == ("0003",)
        else _INCOMPATIBLE_SCHEMA
    )
    _require_fixed(
        observed == expected and connection.fallback_count == 0,
        "versioned PostgreSQL failure entered runtime fallback",
    )


@pytest.mark.asyncio
async def test_catalog_operation_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _PureManagedConnection()
    connection.raise_during_revision = RuntimeError()
    observed = ""
    context_suppressed = False
    try:
        await _run_init(monkeypatch, connection)
    except RuntimeError as exc:
        observed = str(exc)
        context_suppressed = (
            exc.__cause__ is None and exc.__suppress_context__
        )
    _require_fixed(
        observed == _VALIDATION_FAILED
        and context_suppressed
        and connection.fallback_count == 0,
        "PostgreSQL catalog failure was not sanitized",
    )


@pytest.mark.asyncio
async def test_connect_closes_pool_after_migration_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _PureManagedConnection(revision_values=("0007",))
    pool = _PurePool(connection)

    async def _create_pool(*_args: object, **_kwargs: object) -> _PurePool:
        return pool

    monkeypatch.setitem(
        sys.modules,
        "asyncpg",
        SimpleNamespace(create_pool=_create_pool),
    )
    database = PostgresDatabase("synthetic")
    observed = ""
    with patch("ares.db.postgres.logger.info", return_value=None):
        try:
            await database.connect()
        except RuntimeError as exc:
            observed = str(exc)
    _require_fixed(
        observed == _MIGRATION_REQUIRED
        and pool.close_count == 1
        and database._pool is None
        and connection.fallback_count == 0,
        "PostgreSQL migration gate leaked its startup pool",
    )


def test_postgres_config_ignores_noncanonical_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _POSTGRES_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARES_TEST_POSTGRES_DATABASE", "ignored")
    monkeypatch.setenv("ARES_DATABASE_URL", "ignored")
    skipped = False
    try:
        _postgres_test_config()
    except pytest.skip.Exception:
        skipped = True
    _require_fixed(
        skipped,
        "noncanonical PostgreSQL configuration prevented a clean skip",
    )


def test_postgres_config_rejects_partial_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _POSTGRES_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARES_TEST_POSTGRES_HOST", "127.0.0.1")
    failed = False
    try:
        _postgres_test_config()
    except pytest.fail.Exception:
        failed = True
    _require_fixed(failed, "partial PostgreSQL configuration was accepted")


@pytest.mark.parametrize(
    "raw_port",
    ["", " 5432", "05432", "65536"],
    ids=[
        "empty-port",
        "whitespace-port",
        "noncanonical-port",
        "out-of-range-port",
    ],
)
def test_postgres_config_rejects_invalid_port(
    monkeypatch: pytest.MonkeyPatch,
    raw_port: str,
) -> None:
    monkeypatch.setenv("ARES_TEST_POSTGRES_HOST", "127.0.0.1")
    monkeypatch.setenv("ARES_TEST_POSTGRES_PORT", raw_port)
    monkeypatch.setenv("ARES_TEST_POSTGRES_USER", "synthetic")
    monkeypatch.setenv("ARES_TEST_POSTGRES_DB", "synthetic")
    failed = False
    try:
        _postgres_test_config()
    except pytest.fail.Exception:
        failed = True
    _require_fixed(failed, "invalid PostgreSQL port was accepted")


@pytest.mark.asyncio
async def test_real_postgres_managed_startup_preserves_unrelated_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        connection = await harness._connect(target)
        try:
            empty_before = await connection.fetchrow(
                """
                SELECT
                    to_regclass('alembic_version') IS NULL AS no_version,
                    count(*) FILTER (
                        WHERE table_name=ANY($1::text[])
                    )=0 AS no_application_tables
                FROM information_schema.tables
                WHERE table_schema=current_schema()
                """,
                list(_EXPECTED_TABLES),
            )
            initially_empty = (
                empty_before is not None
                and bool(empty_before["no_version"])
                and bool(empty_before["no_application_tables"])
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            at_0007 = bool(
                await connection.fetchval(
                    "SELECT version_num='0007' FROM alembic_version"
                )
            )
        finally:
            await connection.close()
        _require_fixed(
            at_0007,
            "Managed-startup fixture must reach revision 0007 before 0008",
        )
        await harness._alembic(target, "upgrade", "0008")
        await harness._alembic(target, "upgrade", "0009")
        connection = await harness._connect(target)
        try:
            await connection.execute(
                "CREATE TABLE operator_owned_probe(id INTEGER PRIMARY KEY)"
            )
            await connection.execute(
                "CREATE INDEX operator_owned_probe_idx "
                "ON operator_owned_probe(id)"
            )
        finally:
            await connection.close()

        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        try:
            await database.connect()
            async with database._pool.acquire() as runtime_connection:
                state = await runtime_connection.fetchrow(
                    """
                    SELECT
                        (
                            SELECT version_num='0009'
                            FROM alembic_version
                        ) AS managed,
                        (
                            SELECT count(*)=0
                            FROM pg_indexes
                            WHERE schemaname=current_schema()
                              AND indexname LIKE 'idx_pg_%'
                        ) AS no_legacy_indexes,
                        to_regclass('operator_owned_probe') IS NOT NULL
                            AS unrelated_preserved
                    """
                )
                valid = (
                    state is not None
                    and bool(state["managed"])
                    and bool(state["no_legacy_indexes"])
                    and bool(state["unrelated_preserved"])
                )
        finally:
            await database.close()
        no_fallback = (
            len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1
        )
        _require_fixed(
            initially_empty and valid and no_fallback,
            "managed PostgreSQL startup contract failed",
        )


@pytest.mark.asyncio
async def test_real_postgres_older_revision_requires_migration_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0008")
        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        observed = await _fixed_connect_result(database)
        gated = (
            observed == _MIGRATION_REQUIRED
            and database._pool is None
            and len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1
        )

        await harness._alembic(target, "upgrade", "0009")
        try:
            recovered_state = (
                await _fixed_connect_result(database) == "connected"
            )
        finally:
            await database.close()
        _require_fixed(
            gated
            and recovered_state
            and len(pools) == 2
            and pools[1].fallback_count == 0
            and pools[1].close_count == 1,
            "PostgreSQL migration gate did not recover after upgrade",
        )


@pytest.mark.parametrize(
    "revision_state",
    [
        pytest.param("empty", id="empty-revision"),
        pytest.param("multiple", id="multiple-revisions"),
        pytest.param("malformed", id="malformed-revision"),
        pytest.param("unknown", id="unknown-revision"),
    ],
)
@pytest.mark.asyncio
async def test_real_postgres_invalid_revision_state_closes_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
    revision_state: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    operations = {
        "empty": (
            "DELETE FROM alembic_version",
            "INSERT INTO alembic_version(version_num) VALUES('0009')",
        ),
        "multiple": (
            "INSERT INTO alembic_version(version_num) VALUES('0007')",
            "DELETE FROM alembic_version WHERE version_num='0007'",
        ),
        "malformed": (
            "UPDATE alembic_version SET version_num=' 0009'",
            "UPDATE alembic_version SET version_num='0009'",
        ),
        "unknown": (
            "UPDATE alembic_version SET version_num='9999'",
            "UPDATE alembic_version SET version_num='0009'",
        ),
    }
    mutation, repair = operations[revision_state]
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0009")
        connection = await harness._connect(target)
        try:
            await connection.execute(mutation)
        finally:
            await connection.close()

        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        rejected = await _fixed_connect_result(database)
        first_pool_closed = (
            rejected == _INCOMPATIBLE_SCHEMA
            and database._pool is None
            and len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1
        )

        connection = await harness._connect(target)
        try:
            await connection.execute(repair)
        finally:
            await connection.close()
        try:
            recovered = await _fixed_connect_result(database) == "connected"
        finally:
            await database.close()
        _require_fixed(
            bool(revision_state)
            and first_pool_closed
            and recovered
            and len(pools) == 2
            and pools[1].fallback_count == 0
            and pools[1].close_count == 1,
            "invalid PostgreSQL revision state did not fail closed",
        )


@pytest.mark.parametrize(
    "drift",
    [
        pytest.param("missing-table", id="missing-table"),
        pytest.param("missing-index", id="missing-index"),
        pytest.param("plain-idx-pg", id="plain-legacy-index"),
        pytest.param(
            "constraint-owned-idx-pg",
            id="constraint-owned-legacy-index",
        ),
        pytest.param("extra-version-index", id="extra-version-index"),
        pytest.param(
            "version-relation-policy",
            id="version-relation-policy",
        ),
        pytest.param(
            "version-index-relation",
            id="version-index-relation",
        ),
        pytest.param(
            "version-dropped-column",
            id="version-dropped-column",
        ),
        pytest.param(
            "version-custom-collation",
            id="version-custom-collation",
        ),
        pytest.param("relation-rls", id="relation-rls"),
        pytest.param("relation-forced-rls", id="relation-forced-rls"),
        pytest.param("relation-inheritance", id="relation-inheritance"),
        pytest.param("relation-policy", id="relation-policy"),
        pytest.param("relation-trigger", id="relation-trigger"),
        pytest.param("relation-rule", id="relation-rule"),
        pytest.param("missing-foreign-key", id="missing-foreign-key"),
        pytest.param("wrong-foreign-key", id="wrong-foreign-key"),
        pytest.param("duplicate-foreign-key", id="duplicate-foreign-key"),
        pytest.param("extra-root-foreign-key", id="extra-root-foreign-key"),
        pytest.param(
            "extra-exclusion-constraint",
            id="extra-exclusion-constraint",
        ),
        pytest.param("missing-check", id="missing-check"),
        pytest.param("wrong-check", id="wrong-check"),
        pytest.param("missing-unique", id="missing-unique"),
        pytest.param("wrong-unique", id="wrong-unique"),
        pytest.param("missing-sequence", id="missing-sequence"),
        pytest.param("wrong-sequence-owner", id="wrong-sequence-owner"),
        pytest.param(
            "wrong-sequence-owner-schema",
            id="wrong-sequence-owner-schema",
        ),
        pytest.param("wrong-sequence-options", id="wrong-sequence-options"),
        pytest.param("wrong-sequence-default", id="wrong-sequence-default"),
    ],
)
@pytest.mark.asyncio
async def test_real_postgres_managed_catalog_drift_never_falls_back(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    statements = {
        "missing-table": "DROP TABLE rate_limit_events",
        "missing-index": "DROP INDEX idx_users_role",
        "plain-idx-pg": "CREATE INDEX idx_pg_unexpected ON users(role)",
        "constraint-owned-idx-pg": (
            "ALTER TABLE users ADD CONSTRAINT idx_pg_users_role UNIQUE(role)"
        ),
        "extra-version-index": (
            "CREATE INDEX unexpected_version_index "
            "ON alembic_version(version_num)"
        ),
        "version-relation-policy": (
            "CREATE POLICY ares_runtime_version_policy "
            "ON alembic_version USING (true)"
        ),
        "version-index-relation": (
            "DROP TABLE alembic_version; "
            "CREATE INDEX alembic_version ON campaigns(status)"
        ),
        "version-dropped-column": (
            "ALTER TABLE alembic_version "
            "ADD COLUMN unexpected_version_column INTEGER; "
            "ALTER TABLE alembic_version "
            "DROP COLUMN unexpected_version_column"
        ),
        "version-custom-collation": (
            'CREATE COLLATION ares_runtime_version_collation FROM "C"; '
            "ALTER TABLE alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(32) "
            "COLLATE ares_runtime_version_collation"
        ),
        "relation-rls": (
            "ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY"
        ),
        "relation-forced-rls": (
            "ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY; "
            "ALTER TABLE campaigns FORCE ROW LEVEL SECURITY"
        ),
        "relation-inheritance": (
            "CREATE TABLE ares_runtime_campaign_child() "
            "INHERITS (campaigns)"
        ),
        "relation-policy": (
            "CREATE POLICY ares_runtime_policy "
            "ON campaigns USING (true)"
        ),
        "relation-trigger": (
            "CREATE FUNCTION ares_runtime_trigger() "
            "RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN RETURN NEW; END $$; "
            "CREATE TRIGGER ares_runtime_trigger "
            "BEFORE UPDATE ON campaigns FOR EACH ROW "
            "EXECUTE FUNCTION ares_runtime_trigger()"
        ),
        "relation-rule": (
            "CREATE RULE ares_runtime_rule AS "
            "ON UPDATE TO campaigns DO ALSO NOTHING"
        ),
        "missing-foreign-key": (
            "ALTER TABLE api_keys "
            "DROP CONSTRAINT fk_api_keys_user"
        ),
        "wrong-foreign-key": (
            "ALTER TABLE api_keys "
            "DROP CONSTRAINT fk_api_keys_user; "
            "ALTER TABLE api_keys "
            "ADD CONSTRAINT fk_api_keys_user "
            "FOREIGN KEY(user_id) REFERENCES campaigns(id) "
            "ON DELETE CASCADE"
        ),
        "duplicate-foreign-key": (
            "ALTER TABLE api_keys "
            "ADD CONSTRAINT duplicate_api_keys_user "
            "FOREIGN KEY(user_id) REFERENCES users(id) "
            "ON DELETE CASCADE"
        ),
        "extra-root-foreign-key": (
            "ALTER TABLE campaigns "
            "ADD CONSTRAINT unexpected_campaign_self_fk "
            "FOREIGN KEY(id) REFERENCES campaigns(id)"
        ),
        "extra-exclusion-constraint": (
            "ALTER TABLE campaigns "
            "ADD CONSTRAINT unexpected_campaign_exclusion "
            "EXCLUDE USING btree (id WITH =)"
        ),
        "missing-check": (
            "ALTER TABLE users "
            "DROP CONSTRAINT ck_users_created_at_finite"
        ),
        "wrong-check": (
            "ALTER TABLE rate_limit_events "
            "DROP CONSTRAINT ck_rate_limit_events_blocked_bool; "
            "ALTER TABLE rate_limit_events "
            "ADD CONSTRAINT ck_rate_limit_events_blocked_bool "
            "CHECK ((blocked=0) OR (blocked=1))"
        ),
        "missing-unique": (
            "ALTER TABLE users DROP CONSTRAINT uq_users_username"
        ),
        "wrong-unique": (
            "ALTER TABLE users DROP CONSTRAINT uq_users_username; "
            "ALTER TABLE users "
            "ADD CONSTRAINT uq_users_username UNIQUE(role)"
        ),
        "missing-sequence": "DROP SEQUENCE audit_log_id_seq CASCADE",
        "wrong-sequence-owner": (
            "ALTER SEQUENCE audit_log_id_seq OWNED BY NONE"
        ),
        "wrong-sequence-owner-schema": (
            "CREATE SCHEMA ares_runtime_shadow; "
            "CREATE TABLE ares_runtime_shadow.audit_log(id INTEGER NOT NULL); "
            "ALTER SEQUENCE audit_log_id_seq OWNED BY NONE; "
            "ALTER SEQUENCE audit_log_id_seq "
            "SET SCHEMA ares_runtime_shadow; "
            "ALTER SEQUENCE ares_runtime_shadow.audit_log_id_seq "
            "OWNED BY ares_runtime_shadow.audit_log.id"
        ),
        "wrong-sequence-options": (
            "ALTER SEQUENCE audit_log_id_seq INCREMENT BY 2"
        ),
        "wrong-sequence-default": (
            "ALTER TABLE audit_log ALTER COLUMN id SET DEFAULT 7"
        ),
    }
    statement = statements[drift]
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0009")
        connection = await harness._connect(target)
        try:
            await connection.execute(statement)
        finally:
            await connection.close()
        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        rejected = await _fixed_connect_result(database)
        _require_fixed(
            bool(drift)
            and rejected == _INCOMPATIBLE_SCHEMA
            and database._pool is None
            and len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1,
            "managed PostgreSQL catalog drift entered fallback",
        )


@pytest.mark.asyncio
async def test_real_postgres_unversioned_startup_requires_migration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        observed = await _fixed_connect_result(database)
        connection = await harness._connect(target)
        try:
            state = await connection.fetchrow(
                """
                SELECT
                    to_regclass('alembic_version') IS NULL AS unversioned,
                    to_regclass('campaigns') IS NULL AS no_campaigns,
                    to_regclass('websocket_tickets') IS NULL AS no_tickets
                """
            )
        finally:
            await connection.close()
        unchanged = (
            state is not None
            and bool(state["unversioned"])
            and bool(state["no_campaigns"])
            and bool(state["no_tickets"])
        )
        _require_fixed(
            observed == _MIGRATION_REQUIRED
            and unchanged
            and database._pool is None
            and len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1,
            "unversioned PostgreSQL startup did not fail closed",
        )


async def _stamp_runtime_origin_0007(target: Any) -> None:
    from ares.db.postgres import (
        _PG_CREATE_TABLES,
        _POSTGRES_FALLBACK_STATEMENT_SPANS,
    )

    connection = await target_support_connect(target)
    try:
        for _code, start, end in _POSTGRES_FALLBACK_STATEMENT_SPANS:
            await connection.execute(_PG_CREATE_TABLES[start:end])
        await connection.execute(
            """
            CREATE TABLE alembic_version(
                version_num VARCHAR(32) NOT NULL,
                CONSTRAINT alembic_version_pkc PRIMARY KEY(version_num)
            )
            """
        )
        await connection.execute(
            "INSERT INTO alembic_version(version_num) VALUES('0007')"
        )
    finally:
        await connection.close()


async def target_support_connect(target: Any) -> Any:
    from tests.integration import test_postgres_migration_portability as support

    return await support._connect(target)


async def _application_data_digest(
    connection: Any,
    *,
    excluded_tables: frozenset[str] = frozenset(),
) -> tuple[object, ...]:
    values: list[object] = []
    try:
        for table in _EXPECTED_TABLES:
            if table in excluded_tables:
                continue
            table_exists = await connection.fetchval(
                "SELECT to_regclass($1) IS NOT NULL",
                table,
            )
            if not table_exists:
                values.append(None)
                continue
            row = await connection.fetchrow(
                f"""
                SELECT count(*)::bigint AS row_count,
                       md5(
                           coalesce(
                               string_agg(
                                   row_to_json(value)::text,
                                   '' ORDER BY row_to_json(value)::text
                               ),
                               ''
                           )
                       ) AS row_digest
                FROM {table} AS value
                """  # noqa: S608
            )
            values.append(
                (
                    int(row["row_count"]),
                    str(row["row_digest"]),
                )
            )
    except Exception:
        raise RuntimeError("PostgreSQL data fingerprint failed") from None
    return tuple(values)


async def _managed_object_identity_fingerprint(
    connection: Any,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    try:
        relations = tuple(
            (
                int(row["relation_oid"]),
                str(row["relation_name"]),
                str(row["relation_kind"]),
                int(row["relation_file"]),
            )
            for row in await connection.fetch(
                """
                SELECT
                    relation.oid::bigint AS relation_oid,
                    relation.relname AS relation_name,
                    relation.relkind AS relation_kind,
                    relation.relfilenode::bigint AS relation_file
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname=current_schema()
                  AND relation.relkind IN ('r', 'p', 'i', 'S')
                ORDER BY relation.relname, relation.oid
                """
            )
        )
        constraints = tuple(
            (
                int(row["constraint_oid"]),
                str(row["constraint_name"]),
                int(row["relation_oid"]),
                int(row["referenced_relation_oid"]),
                int(row["backing_index_oid"]),
            )
            for row in await connection.fetch(
                """
                SELECT
                    constraint_record.oid::bigint AS constraint_oid,
                    constraint_record.conname AS constraint_name,
                    constraint_record.conrelid::bigint AS relation_oid,
                    constraint_record.confrelid::bigint
                        AS referenced_relation_oid,
                    constraint_record.conindid::bigint AS backing_index_oid
                FROM pg_constraint AS constraint_record
                JOIN pg_class AS relation
                  ON relation.oid=constraint_record.conrelid
                JOIN pg_namespace AS namespace
                  ON namespace.oid=relation.relnamespace
                WHERE namespace.nspname=current_schema()
                ORDER BY relation.relname, constraint_record.conname
                """
            )
        )
    except Exception:
        raise RuntimeError(
            "PostgreSQL identity fingerprint failed"
        ) from None
    return relations, constraints


def _same_catalog_without_revision(before: Any, after: Any) -> bool:
    return (
        before.schemas == after.schemas
        and before.relations == after.relations
        and before.columns == after.columns
        and before.constraints == after.constraints
        and before.indexes == after.indexes
        and before.sequences == after.sequences
    )


@pytest.mark.asyncio
async def test_real_postgres_correct_0007_is_data_preserving_noop() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            fast_default_rows = await connection.fetch(
                """
                SELECT attribute.attname,
                       attribute.atthasmissing,
                       attribute.attmissingval::text AS missing_value
                FROM pg_attribute AS attribute
                WHERE attribute.attrelid='findings'::regclass
                  AND attribute.attname=ANY($1::text[])
                ORDER BY attribute.attname
                """,
                ["cvss_score", "cvss_vector", "trace_id"],
            )
            audited_fast_defaults = tuple(
                (
                    str(row["attname"]),
                    bool(row["atthasmissing"]),
                    (
                        str(row["missing_value"])
                        if row["missing_value"] is not None
                        else None
                    ),
                )
                for row in fast_default_rows
            ) == (
                ("cvss_score", False, None),
                ("cvss_vector", False, None),
                ("trace_id", True, '{""}'),
            )
            before_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            before_data = await _application_data_digest(connection)
            before_identity = await _managed_object_identity_fingerprint(
                connection
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            after_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            after_data = await _application_data_digest(connection)
            after_identity = await _managed_object_identity_fingerprint(
                connection
            )
            revision_current = await connection.fetchval(
                "SELECT version_num='0008' FROM alembic_version"
            )
            after_fast_default_rows = await connection.fetch(
                """
                SELECT attribute.attname,
                       attribute.atthasmissing,
                       attribute.attmissingval::text AS missing_value
                FROM pg_attribute AS attribute
                WHERE attribute.attrelid='findings'::regclass
                  AND attribute.attname=ANY($1::text[])
                ORDER BY attribute.attname
                """,
                ["cvss_score", "cvss_vector", "trace_id"],
            )
            fast_defaults_preserved = tuple(
                (
                    str(row["attname"]),
                    bool(row["atthasmissing"]),
                    (
                        str(row["missing_value"])
                        if row["missing_value"] is not None
                        else None
                    ),
                )
                for row in after_fast_default_rows
            ) == (
                ("cvss_score", False, None),
                ("cvss_vector", False, None),
                ("trace_id", True, '{""}'),
            )
        finally:
            await connection.close()
        identity_preserved = before_identity == after_identity
        _require_fixed(
            audited_fast_defaults
            and _same_catalog_without_revision(before_catalog, after_catalog)
            and before_data == after_data
            and identity_preserved
            and bool(revision_current)
            and bool(fast_defaults_preserved),
            "revision 0008 changed an exact revision 0007 database",
        )


@pytest.mark.asyncio
async def test_real_postgres_version_trigger_cannot_mutate_application_data(
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await connection.execute(
                """
                INSERT INTO campaigns(id, name, status)
                VALUES(
                    'version-trigger-campaign',
                    'synthetic',
                    'created'
                )
                """
            )
            await connection.execute(
                """
                CREATE FUNCTION ares_m0008_version_trigger()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    UPDATE campaigns
                    SET status='trigger-fired'
                    WHERE id='version-trigger-campaign';
                    RETURN NEW;
                END
                $$;
                CREATE TRIGGER ares_m0008_version_trigger
                AFTER UPDATE ON alembic_version
                FOR EACH ROW
                EXECUTE FUNCTION ares_m0008_version_trigger()
                """
            )
            transaction = connection.transaction()
            await transaction.start()
            try:
                await connection.execute(
                    "UPDATE alembic_version SET version_num=version_num"
                )
                replay_capable = bool(
                    await connection.fetchval(
                        """
                        SELECT status='trigger-fired'
                        FROM campaigns
                        WHERE id='version-trigger-campaign'
                        """
                    )
                )
            finally:
                await transaction.rollback()
            before_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()

        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True

        connection = await harness._connect(target)
        try:
            after_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            after_data = await _application_data_digest(connection)
            state = await connection.fetchrow(
                """
                SELECT
                    (
                        SELECT version_num='0007'
                        FROM alembic_version
                    ) AS revision_unchanged,
                    (
                        SELECT status='created'
                        FROM campaigns
                        WHERE id='version-trigger-campaign'
                    ) AS canary_unchanged,
                    EXISTS(
                        SELECT 1
                        FROM pg_trigger AS trigger_record
                        WHERE trigger_record.tgrelid='alembic_version'::regclass
                          AND trigger_record.tgname=
                              'ares_m0008_version_trigger'
                          AND NOT trigger_record.tgisinternal
                    ) AS trigger_preserved
                """
            )
            unchanged = (
                state is not None
                and bool(state["revision_unchanged"])
                and bool(state["canary_unchanged"])
                and bool(state["trigger_preserved"])
                and before_catalog == after_catalog
                and before_data == after_data
            )
            if failed and unchanged:
                await connection.execute(
                    """
                    DROP TRIGGER ares_m0008_version_trigger
                    ON alembic_version;
                    DROP FUNCTION ares_m0008_version_trigger()
                    """
                )
        finally:
            await connection.close()

        recovered = False
        if failed and unchanged:
            await harness._alembic(target, "upgrade", "0008")
            connection = await harness._connect(target)
            try:
                recovered = bool(
                    await connection.fetchval(
                        "SELECT version_num='0008' FROM alembic_version"
                    )
                )
            finally:
                await connection.close()
        _require_fixed(
            replay_capable and failed and unchanged and recovered,
            "PostgreSQL version trigger bypassed migration preflight",
        )


@pytest.mark.parametrize("attachment", ["policy", "rule"])
@pytest.mark.asyncio
async def test_real_postgres_version_relation_attachment_is_atomic(
    attachment: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    mutation = {
        "policy": (
            "CREATE POLICY ares_m0008_version_policy "
            "ON alembic_version USING (true)"
        ),
        "rule": (
            "CREATE RULE ares_m0008_version_rule AS "
            "ON UPDATE TO alembic_version DO ALSO NOTHING"
        ),
    }[attachment]
    repair = {
        "policy": (
            "DROP POLICY ares_m0008_version_policy ON alembic_version"
        ),
        "rule": "DROP RULE ares_m0008_version_rule ON alembic_version",
    }[attachment]

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await connection.execute(mutation)
            before_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()

        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True

        connection = await harness._connect(target)
        try:
            after_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            after_data = await _application_data_digest(connection)
            relation_oid = await connection.fetchval(
                "SELECT 'alembic_version'::regclass::oid"
            )
            attachment_count = (
                await connection.fetchval(
                    """
                    SELECT count(*)
                    FROM pg_policy
                    WHERE polrelid=$1::oid
                    """,
                    relation_oid,
                )
                if attachment == "policy"
                else await connection.fetchval(
                    """
                    SELECT count(*)
                    FROM pg_rewrite
                    WHERE ev_class=$1::oid
                    """,
                    relation_oid,
                )
            )
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
            unchanged = (
                bool(revision_unchanged)
                and int(attachment_count) == 1
                and before_catalog == after_catalog
                and before_data == after_data
            )
            if failed and unchanged:
                await connection.execute(repair)
        finally:
            await connection.close()

        recovered = False
        if failed and unchanged:
            await harness._alembic(target, "upgrade", "0008")
            connection = await harness._connect(target)
            try:
                recovered = bool(
                    await connection.fetchval(
                        "SELECT version_num='0008' FROM alembic_version"
                    )
                )
            finally:
                await connection.close()
        _require_fixed(
            failed and unchanged and recovered,
            "PostgreSQL version attachment bypassed migration preflight",
        )


@pytest.mark.asyncio
async def test_real_postgres_post_ddl_failure_rolls_back_completely() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await connection.execute(
                """
                ALTER TABLE findings
                ALTER COLUMN trace_id DROP NOT NULL
                """
            )
            before_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()

        failed = False
        try:
            await harness._alembic(
                target,
                "upgrade",
                "0008",
                fault="0005-after-alter",
            )
        except RuntimeError:
            failed = True

        connection = await harness._connect(target)
        try:
            after_catalog = await harness._postgres_isolation_fingerprint(
                connection
            )
            after_data = await _application_data_digest(connection)
            state = await connection.fetchrow(
                """
                SELECT
                    (
                        SELECT version_num='0007'
                        FROM alembic_version
                    ) AS revision_unchanged,
                    NOT (
                        SELECT attnotnull
                        FROM pg_attribute
                        WHERE attrelid='findings'::regclass
                          AND attname='trace_id'
                          AND attnum > 0
                          AND NOT attisdropped
                    ) AS alteration_rolled_back,
                    (SELECT 1)=1 AS connection_reusable
                """
            )
            rolled_back = (
                state is not None
                and bool(state["revision_unchanged"])
                and bool(state["alteration_rolled_back"])
                and bool(state["connection_reusable"])
                and before_catalog == after_catalog
                and before_data == after_data
            )
        finally:
            await connection.close()

        recovered = False
        if failed and rolled_back:
            await harness._alembic(target, "upgrade", "0008")
            connection = await harness._connect(target)
            try:
                state = await connection.fetchrow(
                    """
                    SELECT
                        (
                            SELECT version_num='0008'
                            FROM alembic_version
                        ) AS revision_current,
                        (
                            SELECT attnotnull
                            FROM pg_attribute
                            WHERE attrelid='findings'::regclass
                              AND attname='trace_id'
                              AND attnum > 0
                              AND NOT attisdropped
                        ) AS column_hardened
                    """
                )
                recovered = (
                    state is not None
                    and bool(state["revision_current"])
                    and bool(state["column_hardened"])
                )
            finally:
                await connection.close()
        _require_fixed(
            failed and rolled_back and recovered,
            "PostgreSQL migration failure did not roll back real DDL",
        )


@pytest.mark.asyncio
async def test_real_postgres_runtime_origin_converges_without_data_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await _stamp_runtime_origin_0007(target)
        connection = await harness._connect(target)
        try:
            await connection.execute(
                """
                ALTER TABLE findings
                ALTER COLUMN cvss_score DROP NOT NULL;
                ALTER TABLE findings
                ALTER COLUMN cvss_vector DROP NOT NULL;
                ALTER TABLE findings
                ALTER COLUMN trace_id DROP NOT NULL
                """
            )
            await connection.execute(
                """
                INSERT INTO campaigns(id, name)
                VALUES('runtime-campaign', 'synthetic')
                """
            )
            await connection.execute(
                """
                INSERT INTO module_runs(
                    id, campaign_id, module_id, outcome
                )
                VALUES(
                    'runtime-run',
                    'runtime-campaign',
                    'synthetic-module',
                    'synthetic'
                )
                """
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            state = await connection.fetchrow(
                """
                SELECT
                    (
                        SELECT version_num='0008'
                        FROM alembic_version
                    ) AS revision_current,
                    to_regclass('rate_limit_events') IS NOT NULL
                        AS missing_table_reconciled,
                    (
                        SELECT count(*)=0
                        FROM pg_indexes
                        WHERE schemaname=current_schema()
                          AND indexname LIKE 'idx_pg_%'
                    ) AS legacy_indexes_removed,
                    (
                        SELECT count(*)=$1
                        FROM pg_indexes
                        WHERE schemaname=current_schema()
                          AND indexname=ANY($2::text[])
                    ) AS canonical_indexes_present,
                    (
                        SELECT count(*)=1
                        FROM campaigns
                        WHERE id='runtime-campaign'
                    ) AS campaign_preserved,
                    (
                        SELECT count(*)=1
                        FROM module_runs
                        WHERE id='runtime-run'
                    ) AS run_preserved,
                    (
                        SELECT bool_and(attribute.attnotnull)
                        FROM pg_attribute AS attribute
                        WHERE attribute.attrelid='findings'::regclass
                          AND attribute.attname=ANY($3::text[])
                    ) AS findings_hardened,
                    (
                        SELECT array_agg(
                            attribute.attname::text
                            ORDER BY attribute.attnum
                        )=$4::text[]
                        FROM pg_attribute AS attribute
                        WHERE attribute.attrelid='findings'::regclass
                          AND attribute.attnum > 0
                          AND NOT attribute.attisdropped
                    ) AS audited_order_preserved
                """,
                len(_EXPECTED_INDEXES),
                [name for _, name, _, _ in _EXPECTED_INDEXES],
                ["cvss_score", "cvss_vector", "trace_id"],
                [
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
                ],
            )
            converged = (
                state is not None
                and all(bool(value) for value in state.values())
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0009")
        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        try:
            guard_accepted = (
                await _fixed_connect_result(database) == "connected"
            )
        finally:
            await database.close()
        _require_fixed(
            converged
            and guard_accepted
            and len(pools) == 1
            and pools[0].fallback_count == 0,
            "revision 0008 did not reconcile runtime-origin drift",
        )


@pytest.mark.asyncio
async def test_real_postgres_supported_legacy_objects_converge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await connection.execute(
                "UPDATE refresh_tokens SET id=repeat('a', 64)"
            )
            await connection.execute(
                """
                DROP TABLE module_runs;
                CREATE INDEX idx_findings_validated
                ON findings(validated);
                CREATE TABLE ares_m0008_unrelated_probe(
                    id INTEGER PRIMARY KEY,
                    marker TEXT NOT NULL
                );
                INSERT INTO ares_m0008_unrelated_probe(id, marker)
                VALUES(1, 'preserved')
                """
            )
            before_data = await _application_data_digest(
                connection,
                excluded_tables=frozenset({"module_runs"}),
            )
        finally:
            await connection.close()

        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            after_data = await _application_data_digest(
                connection,
                excluded_tables=frozenset({"module_runs"}),
            )
            state = await connection.fetchrow(
                """
                    SELECT
                        (
                            SELECT version_num='0008'
                            FROM alembic_version
                        ) AS revision_current,
                        to_regclass('module_runs') IS NOT NULL
                            AS module_table_present,
                        EXISTS(
                            SELECT 1
                            FROM pg_constraint
                            WHERE conrelid='module_runs'::regclass
                              AND conname='fk_module_runs_campaign'
                              AND contype='f'
                        ) AS module_fk_present,
                        EXISTS(
                            SELECT 1
                            FROM pg_constraint
                            WHERE conrelid='module_runs'::regclass
                              AND conname=
                                  'ck_module_runs_completed_at_finite'
                              AND contype='c'
                        ) AS module_check_present,
                        (
                            SELECT array_agg(indexname ORDER BY indexname)
                            FROM pg_indexes
                            WHERE schemaname=current_schema()
                              AND tablename='module_runs'
                        ) = ARRAY[
                            'idx_module_runs_campaign',
                            'idx_module_runs_completed',
                            'module_runs_pkey'
                        ]::name[] AS module_indexes_exact,
                        to_regclass('idx_findings_validated') IS NULL
                            AS obsolete_index_removed,
                        (
                            SELECT marker='preserved'
                            FROM ares_m0008_unrelated_probe
                            WHERE id=1
                        ) AS unrelated_preserved
                """
            )
            converged = (
                state is not None
                and bool(state["revision_current"])
                and bool(state["module_table_present"])
                and bool(state["module_fk_present"])
                and bool(state["module_check_present"])
                and bool(state["module_indexes_exact"])
                and bool(state["obsolete_index_removed"])
                and bool(state["unrelated_preserved"])
                and before_data == after_data
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0009")
        pools = _audit_runtime_pools(monkeypatch)
        database = _runtime_database(target)
        try:
            connected = await _fixed_connect_result(database) == "connected"
        finally:
            await database.close()
        _require_fixed(
            connected
            and converged
            and len(pools) == 1
            and pools[0].fallback_count == 0
            and pools[0].close_count == 1,
            "supported PostgreSQL legacy objects did not converge safely",
        )


@pytest.mark.asyncio
async def test_real_postgres_non_equivalent_legacy_index_rolls_back() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await connection.execute(
                """
                CREATE INDEX idx_pg_findings_mitre
                ON findings(severity)
                """
            )
            before = await harness._postgres_isolation_fingerprint(connection)
        finally:
            await connection.close()
        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            failed and before == after and bool(revision_unchanged),
            "non-equivalent PostgreSQL legacy index was mutated",
        )


_COLUMN_AND_RELATION_MUTATIONS = (
    pytest.param("missing-column", id="missing-column"),
    pytest.param("extra-column", id="extra-column"),
    pytest.param("wrong-order", id="wrong-order"),
    pytest.param("wrong-type", id="wrong-type"),
    pytest.param("wrong-nullability", id="wrong-nullability"),
    pytest.param("wrong-default", id="wrong-default"),
    pytest.param("identity-column", id="identity-column"),
    pytest.param("generated-column", id="generated-column"),
    pytest.param("custom-collation", id="custom-collation"),
    pytest.param("sequence-default", id="sequence-default"),
    pytest.param("sequence-ownership", id="sequence-ownership"),
    pytest.param("sequence-owner-schema", id="sequence-owner-schema"),
    pytest.param("sequence-options", id="sequence-options"),
    pytest.param(
        "planned-primary-relation",
        id="planned-primary-relation",
    ),
    pytest.param(
        "planned-unique-relation",
        id="planned-unique-relation",
    ),
    pytest.param(
        "planned-sequence-relation",
        id="planned-sequence-relation",
    ),
    pytest.param("optional-type-collision", id="optional-type-collision"),
    pytest.param("root-foreign-key", id="root-foreign-key"),
    pytest.param("duplicate-foreign-key", id="duplicate-foreign-key"),
    pytest.param(
        "extra-exclusion-constraint",
        id="extra-exclusion-constraint",
    ),
    pytest.param("regrouped-check", id="regrouped-check"),
    pytest.param(
        "ticket-scope-literal-case",
        id="ticket-scope-literal-case",
    ),
    pytest.param(
        "ticket-hash-literal-case",
        id="ticket-hash-literal-case",
    ),
    pytest.param(
        "canonical-index-unrelated",
        id="canonical-index-unrelated",
    ),
    pytest.param("alias-index-unrelated", id="alias-index-unrelated"),
    pytest.param(
        "obsolete-index-unrelated",
        id="obsolete-index-unrelated",
    ),
    pytest.param(
        "reserved-constraint-index",
        id="reserved-constraint-index",
    ),
    pytest.param("reserved-alias-relation", id="reserved-alias-relation"),
    pytest.param("relation-rls", id="relation-rls"),
    pytest.param("relation-forced-rls", id="relation-forced-rls"),
    pytest.param("relation-policy", id="relation-policy"),
    pytest.param("relation-trigger", id="relation-trigger"),
    pytest.param("relation-rule", id="relation-rule"),
    pytest.param("relation-inheritance", id="relation-inheritance"),
    pytest.param("relation-view", id="relation-view"),
    pytest.param("relation-partition", id="relation-partition"),
)


async def _apply_column_or_relation_mutation(
    connection: Any,
    mutation: str,
) -> None:
    if mutation == "missing-column":
        await connection.execute(
            "ALTER TABLE campaigns DROP COLUMN notes"
        )
    elif mutation == "extra-column":
        await connection.execute(
            "ALTER TABLE campaigns ADD COLUMN unexpected_column TEXT"
        )
    elif mutation == "wrong-order":
        await connection.execute(
            """
            ALTER TABLE campaigns DROP COLUMN notes;
            ALTER TABLE campaigns
            ADD COLUMN notes TEXT DEFAULT ''
            """
        )
    elif mutation == "wrong-type":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ALTER COLUMN notes TYPE VARCHAR(64)
            """
        )
    elif mutation == "wrong-nullability":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ALTER COLUMN notes SET NOT NULL
            """
        )
    elif mutation == "wrong-default":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ALTER COLUMN status SET DEFAULT 'unexpected'
            """
        )
    elif mutation == "identity-column":
        await connection.execute(
            """
            ALTER TABLE audit_log ALTER COLUMN id DROP DEFAULT;
            ALTER TABLE audit_log
            ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY
            """
        )
    elif mutation == "generated-column":
        await connection.execute(
            """
            ALTER TABLE campaigns DROP COLUMN notes;
            ALTER TABLE campaigns ADD COLUMN notes TEXT
            GENERATED ALWAYS AS (''::text) STORED
            """
        )
    elif mutation == "custom-collation":
        await connection.execute(
            """
            CREATE COLLATION ares_m0008_collation FROM "C";
            ALTER TABLE campaigns
            ALTER COLUMN notes TYPE TEXT
            COLLATE ares_m0008_collation
            """
        )
    elif mutation == "sequence-default":
        await connection.execute(
            """
            ALTER TABLE audit_log
            ALTER COLUMN id SET DEFAULT 7
            """
        )
    elif mutation == "sequence-ownership":
        await connection.execute(
            "ALTER SEQUENCE audit_log_id_seq OWNED BY NONE"
        )
    elif mutation == "sequence-owner-schema":
        await connection.execute(
            """
            CREATE SCHEMA ares_m0008_shadow;
            CREATE TABLE ares_m0008_shadow.audit_log(
                id INTEGER NOT NULL
            );
            ALTER SEQUENCE audit_log_id_seq OWNED BY NONE;
            ALTER SEQUENCE audit_log_id_seq
            SET SCHEMA ares_m0008_shadow;
            ALTER SEQUENCE ares_m0008_shadow.audit_log_id_seq
            OWNED BY ares_m0008_shadow.audit_log.id
            """
        )
    elif mutation == "sequence-options":
        await connection.execute(
            "ALTER SEQUENCE audit_log_id_seq INCREMENT BY 2"
        )
    elif mutation == "planned-primary-relation":
        await connection.execute(
            """
            DROP TABLE module_runs;
            CREATE TABLE module_runs_pkey(value TEXT)
            """
        )
    elif mutation == "planned-unique-relation":
        await connection.execute(
            """
            ALTER TABLE users DROP CONSTRAINT uq_users_username;
            CREATE TABLE uq_users_username(value TEXT)
            """
        )
    elif mutation == "planned-sequence-relation":
        await connection.execute(
            """
            DROP TABLE rate_limit_events;
            CREATE TABLE rate_limit_events_id_seq(value TEXT)
            """
        )
    elif mutation == "optional-type-collision":
        await connection.execute(
            """
            DROP TABLE module_runs;
            CREATE DOMAIN module_runs AS TEXT
            """
        )
    elif mutation == "root-foreign-key":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ADD CONSTRAINT unexpected_campaign_self_fk
            FOREIGN KEY(id) REFERENCES campaigns(id)
            """
        )
    elif mutation == "duplicate-foreign-key":
        await connection.execute(
            """
            ALTER TABLE api_keys
            ADD CONSTRAINT duplicate_api_keys_user
            FOREIGN KEY(user_id) REFERENCES users(id)
            ON DELETE CASCADE
            """
        )
    elif mutation == "extra-exclusion-constraint":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ADD CONSTRAINT unexpected_campaign_exclusion
            EXCLUDE USING btree (id WITH =)
            """
        )
    elif mutation == "regrouped-check":
        await connection.execute(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_time_order;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_time_order
            CHECK (
                (expires_at > created_at AND consumed_at IS NULL)
                OR consumed_at < expires_at
            )
            """
        )
    elif mutation == "ticket-scope-literal-case":
        await connection.execute(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_source_shape;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_source_shape
            CHECK (
                credential_kind = 'bearer'::text
                AND bearer_subject IS NOT NULL
                AND length(btrim(bearer_subject)) > 0
                AND bearer_subject = btrim(bearer_subject)
                AND bearer_jti IS NOT NULL
                AND length(btrim(bearer_jti)) > 0
                AND bearer_jti = btrim(bearer_jti)
                AND bearer_expires_at IS NOT NULL
                AND api_key_id IS NULL
                AND required_scope IS NULL
                OR credential_kind = 'api_key'::text
                AND bearer_subject IS NULL
                AND bearer_jti IS NULL
                AND bearer_expires_at IS NULL
                AND api_key_id IS NOT NULL
                AND length(btrim(api_key_id)) > 0
                AND api_key_id = btrim(api_key_id)
                AND required_scope = 'READ'::text
            )
            """
        )
    elif mutation == "ticket-hash-literal-case":
        await connection.execute(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_hash;
            UPDATE websocket_tickets
            SET ticket_hash=upper(ticket_hash);
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_hash
            CHECK (ticket_hash ~ '^[0-9A-F]{64}$'::text)
            """
        )
    elif mutation == "canonical-index-unrelated":
        await connection.execute(
            """
            DROP INDEX idx_users_role;
            CREATE INDEX idx_users_role ON campaigns(status)
            """
        )
    elif mutation == "alias-index-unrelated":
        await connection.execute(
            """
            CREATE INDEX idx_pg_users_username
            ON campaigns(status)
            """
        )
    elif mutation == "obsolete-index-unrelated":
        await connection.execute(
            """
            CREATE INDEX idx_findings_validated
            ON campaigns(status)
            """
        )
    elif mutation == "reserved-constraint-index":
        await connection.execute(
            """
            ALTER TABLE campaigns
            ADD CONSTRAINT idx_pg_users_username UNIQUE(status)
            """
        )
    elif mutation == "reserved-alias-relation":
        await connection.execute(
            """
            CREATE TABLE idx_pg_users_username(
                value TEXT
            )
            """
        )
    elif mutation == "relation-rls":
        await connection.execute(
            "ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY"
        )
    elif mutation == "relation-forced-rls":
        await connection.execute(
            """
            ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
            ALTER TABLE campaigns FORCE ROW LEVEL SECURITY
            """
        )
    elif mutation == "relation-policy":
        await connection.execute(
            """
            CREATE POLICY ares_m0008_policy
            ON campaigns USING (true)
            """
        )
    elif mutation == "relation-trigger":
        await connection.execute(
            """
            CREATE FUNCTION ares_m0008_trigger()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RETURN NEW;
            END
            $$;
            CREATE TRIGGER ares_m0008_trigger
            BEFORE UPDATE ON campaigns
            FOR EACH ROW
            EXECUTE FUNCTION ares_m0008_trigger()
            """
        )
    elif mutation == "relation-rule":
        await connection.execute(
            """
            CREATE RULE ares_m0008_rule AS
            ON UPDATE TO campaigns DO ALSO NOTHING
            """
        )
    elif mutation == "relation-inheritance":
        await connection.execute(
            """
            CREATE TABLE ares_m0008_campaign_child()
            INHERITS (campaigns)
            """
        )
    elif mutation == "relation-view":
        await connection.execute(
            """
            DROP TABLE module_runs CASCADE;
            CREATE VIEW module_runs AS
            SELECT
                NULL::text AS id,
                NULL::text AS campaign_id,
                NULL::text AS module_id,
                NULL::text AS outcome,
                0::integer AS success,
                0::double precision AS duration_ms,
                now() AS completed_at
            WHERE false
            """
        )
    elif mutation == "relation-partition":
        await connection.execute(
            """
            DROP TABLE rate_limit_events;
            CREATE TABLE rate_limit_events(
                id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                bucket TEXT NOT NULL,
                username TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
            ) PARTITION BY RANGE(id)
            """
        )
    else:
        raise AssertionError("unknown PostgreSQL catalog mutation")


@pytest.mark.parametrize(
    "catalog_mutation",
    _COLUMN_AND_RELATION_MUTATIONS,
)
@pytest.mark.asyncio
async def test_real_postgres_unapproved_column_or_relation_shape_is_atomic(
    catalog_mutation: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await _apply_column_or_relation_mutation(
                connection,
                catalog_mutation,
            )
            before = await harness._postgres_isolation_fingerprint(connection)
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()
        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            after_data = await _application_data_digest(connection)
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            failed
            and before == after
            and before_data == after_data
            and bool(revision_unchanged),
            "unapproved PostgreSQL catalog shape was not atomic",
        )


@pytest.mark.asyncio
async def test_real_postgres_unreserved_idx_pg_name_is_preserved() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await connection.execute(
                """
                CREATE TABLE ares_m0008_unmanaged(value TEXT);
                CREATE INDEX idx_pg_unmanaged_custom
                ON ares_m0008_unmanaged(value)
                """
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            preserved = await connection.fetchval(
                """
                SELECT to_regclass('ares_m0008_unmanaged') IS NOT NULL
                   AND to_regclass('idx_pg_unmanaged_custom') IS NOT NULL
                   AND (
                       SELECT version_num='0008'
                       FROM alembic_version
                   )
                """
            )
        finally:
            await connection.close()
        _require_fixed(
            bool(preserved),
            "unreserved PostgreSQL index metadata was not preserved",
        )


@pytest.mark.asyncio
async def test_real_postgres_source_credential_column_is_renamed_safely(
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            await connection.execute(
                """
                ALTER TABLE credentials
                RENAME COLUMN cracked_value_enc TO cracked_value
                """
            )
            await connection.execute(
                """
                UPDATE credentials
                SET cracked_value='synthetic-protected-marker'
                """
            )
            before_data = await _application_data_digest(
                connection,
                excluded_tables=frozenset({"credentials"}),
            )
            before_credentials = tuple(
                tuple(row.values())
                for row in await connection.fetch(
                    """
                    SELECT
                        id,
                        campaign_id,
                        host_id,
                        username,
                        secret_enc,
                        cred_type,
                        domain,
                        source_module,
                        notes,
                        cracked,
                        cracked_value AS protected_value,
                        captured_at
                    FROM credentials
                    ORDER BY id
                    """
                )
            )
            before_marker_present = bool(before_credentials) and all(
                row[10] is not None and bool(str(row[10]))
                for row in before_credentials
            )
        finally:
            await connection.close()
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            after_data = await _application_data_digest(
                connection,
                excluded_tables=frozenset({"credentials"}),
            )
            after_credentials = tuple(
                tuple(row.values())
                for row in await connection.fetch(
                    """
                    SELECT
                        id,
                        campaign_id,
                        host_id,
                        username,
                        secret_enc,
                        cred_type,
                        domain,
                        source_module,
                        notes,
                        cracked,
                        cracked_value_enc AS protected_value,
                        captured_at
                    FROM credentials
                    ORDER BY id
                    """
                )
            )
            names = tuple(
                str(row["attname"])
                for row in await connection.fetch(
                    """
                    SELECT attribute.attname
                    FROM pg_attribute AS attribute
                    WHERE attribute.attrelid='credentials'::regclass
                      AND attribute.attnum > 0
                      AND NOT attribute.attisdropped
                    ORDER BY attribute.attnum
                    """
                )
            )
            revision_current = await connection.fetchval(
                "SELECT version_num='0008' FROM alembic_version"
            )
            renamed = (
                "cracked_value_enc" in names
                and "cracked_value" not in names
            )
        finally:
            await connection.close()
        credentials_preserved = (
            before_marker_present
            and before_credentials == after_credentials
        )
        _require_fixed(
            before_data == after_data
            and credentials_preserved
            and renamed
            and bool(revision_current),
            "credential column reconciliation changed protected data",
        )


_CREDENTIAL_COLUMN_FAILURES = (
    pytest.param("both", id="both-columns"),
    pytest.param("neither", id="neither-column"),
    pytest.param("wrong-source", id="wrong-source"),
)


@pytest.mark.parametrize(
    "credential_mutation",
    _CREDENTIAL_COLUMN_FAILURES,
)
@pytest.mark.asyncio
async def test_real_postgres_invalid_credential_column_state_is_atomic(
    credential_mutation: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            if credential_mutation == "both":
                await connection.execute(
                    """
                    ALTER TABLE credentials
                    ADD COLUMN cracked_value TEXT
                    """
                )
            elif credential_mutation == "neither":
                await connection.execute(
                    """
                    ALTER TABLE credentials
                    DROP COLUMN cracked_value_enc
                    """
                )
            elif credential_mutation == "wrong-source":
                await connection.execute(
                    """
                    ALTER TABLE credentials
                    RENAME COLUMN cracked_value_enc TO cracked_value;
                    ALTER TABLE credentials
                    ALTER COLUMN cracked_value SET DEFAULT ''
                    """
                )
            else:
                raise AssertionError(
                    "unknown PostgreSQL credential-column mutation"
                )
            before = await harness._postgres_isolation_fingerprint(connection)
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()
        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            after_data = await _application_data_digest(connection)
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            failed
            and before == after
            and before_data == after_data
            and bool(revision_unchanged),
            "invalid PostgreSQL credential-column state was not atomic",
        )


async def _prepare_unsafe_runtime_case(
    connection: Any,
    case: str,
) -> None:
    if case == "orphan":
        await connection.execute(
            """
            ALTER TABLE module_runs
            DROP CONSTRAINT module_runs_campaign_id_fkey
            """
        )
        await connection.execute(
            """
            INSERT INTO module_runs(
                id, campaign_id, module_id, outcome
            )
            VALUES(
                'unsafe-run',
                'missing-campaign',
                'synthetic-module',
                'synthetic'
            )
            """
        )
    elif case == "null":
        await connection.execute(
            "ALTER TABLE findings ALTER COLUMN trace_id DROP NOT NULL"
        )
        await connection.execute(
            """
            INSERT INTO campaigns(id, name)
            VALUES('unsafe-campaign', 'synthetic')
            """
        )
        await connection.execute(
            """
            INSERT INTO findings(
                id, campaign_id, module_id, title, description,
                severity, trace_id
            )
            VALUES(
                'unsafe-finding',
                'unsafe-campaign',
                'synthetic-module',
                'synthetic',
                'synthetic',
                'low',
                NULL
            )
            """
        )
    elif case == "flag":
        await connection.execute(
            """
            CREATE TABLE rate_limit_events(
                id SERIAL PRIMARY KEY,
                ip_address TEXT NOT NULL,
                bucket TEXT NOT NULL,
                username TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await connection.execute(
            """
            INSERT INTO rate_limit_events(ip_address, bucket, blocked)
            VALUES('192.0.2.1', 'synthetic', 2)
            """
        )
    elif case == "infinity":
        await connection.execute(
            """
            INSERT INTO campaigns(id, name, created_at)
            VALUES('unsafe-campaign', 'synthetic', 'infinity')
            """
        )
    else:
        raise AssertionError("unknown unsafe PostgreSQL fixture")


@pytest.mark.parametrize("unsafe_case", ["orphan", "null", "flag", "infinity"])
@pytest.mark.asyncio
async def test_real_postgres_unsafe_runtime_data_rolls_back_atomically(
    unsafe_case: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await _stamp_runtime_origin_0007(target)
        connection = await harness._connect(target)
        try:
            await _prepare_unsafe_runtime_case(connection, unsafe_case)
            before = await harness._postgres_isolation_fingerprint(connection)
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()
        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            after_data = await _application_data_digest(connection)
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            failed
            and before == after
            and before_data == after_data
            and bool(revision_unchanged),
            "unsafe PostgreSQL reconciliation was not atomic",
        )


_BOOLEAN_DATA_MUTATIONS = (
    pytest.param("module-success", id="module-success"),
    pytest.param("finding-validated", id="finding-validated"),
    pytest.param("finding-false-positive", id="finding-false-positive"),
    pytest.param("host-domain-controller", id="host-domain-controller"),
    pytest.param("credential-cracked", id="credential-cracked"),
    pytest.param("user-active", id="user-active"),
    pytest.param("api-key-active", id="api-key-active"),
    pytest.param("refresh-revoked", id="refresh-revoked"),
    pytest.param("rate-blocked", id="rate-blocked"),
)


@pytest.mark.parametrize(
    "boolean_mutation",
    _BOOLEAN_DATA_MUTATIONS,
)
@pytest.mark.asyncio
async def test_real_postgres_invalid_integer_boolean_is_atomic(
    boolean_mutation: str,
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    mutation_targets = {
        "module-success": ("module_runs", "success"),
        "finding-validated": ("findings", "validated"),
        "finding-false-positive": ("findings", "false_positive"),
        "host-domain-controller": ("hosts", "is_dc"),
        "credential-cracked": ("credentials", "cracked"),
        "user-active": ("users", "is_active"),
        "api-key-active": ("api_keys", "is_active"),
        "refresh-revoked": ("refresh_tokens", "is_revoked"),
        "rate-blocked": ("rate_limit_events", "blocked"),
    }
    table, column = mutation_targets[boolean_mutation]
    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0007")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            if boolean_mutation == "rate-blocked":
                await connection.execute(
                    "ALTER TABLE rate_limit_events "
                    "DROP CONSTRAINT ck_rate_limit_events_blocked_bool"
                )
            await connection.execute(
                f'UPDATE "{table}" SET "{column}"=2'  # noqa: S608
            )
            before = await harness._postgres_isolation_fingerprint(connection)
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()
        failed = False
        try:
            await harness._alembic(target, "upgrade", "0008")
        except RuntimeError:
            failed = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            after_data = await _application_data_digest(connection)
            revision_unchanged = await connection.fetchval(
                "SELECT version_num='0007' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            failed
            and before == after
            and before_data == after_data
            and bool(revision_unchanged),
            "unsafe PostgreSQL Boolean data was not atomic",
        )


_FINITE_TIMESTAMPS = (
    ("campaigns", "created_at", "ck_campaigns_created_at_finite", False),
    ("campaigns", "updated_at", "ck_campaigns_updated_at_finite", False),
    (
        "module_runs",
        "completed_at",
        "ck_module_runs_completed_at_finite",
        False,
    ),
    (
        "findings",
        "discovered_at",
        "ck_findings_discovered_at_finite",
        False,
    ),
    ("hosts", "first_seen", "ck_hosts_first_seen_finite", False),
    ("hosts", "last_seen", "ck_hosts_last_seen_finite", False),
    (
        "credentials",
        "captured_at",
        "ck_credentials_captured_at_finite",
        False,
    ),
    ("loot", "captured_at", "ck_loot_captured_at_finite", False),
    ("audit_log", "timestamp", "ck_audit_log_timestamp_finite", False),
    ("users", "created_at", "ck_users_created_at_finite", False),
    ("users", "last_login", "ck_users_last_login_finite", True),
    ("api_keys", "last_used", "ck_api_keys_last_used_finite", True),
    ("api_keys", "expires_at", "ck_api_keys_expires_at_finite", True),
    ("api_keys", "created_at", "ck_api_keys_created_at_finite", False),
    (
        "refresh_tokens",
        "expires_at",
        "ck_refresh_tokens_expires_at_finite",
        False,
    ),
    (
        "refresh_tokens",
        "created_at",
        "ck_refresh_tokens_created_at_finite",
        False,
    ),
    (
        "refresh_tokens",
        "used_at",
        "ck_refresh_tokens_used_at_finite",
        True,
    ),
    (
        "revoked_access_tokens",
        "revoked_at",
        "ck_revoked_access_tokens_revoked_at_finite",
        False,
    ),
    (
        "revoked_access_tokens",
        "expires_at",
        "ck_revoked_access_tokens_expires_at_finite",
        False,
    ),
    (
        "rate_limit_events",
        "timestamp",
        "ck_rate_limit_events_timestamp_finite",
        False,
    ),
)


@pytest.mark.asyncio
async def test_real_postgres_all_managed_timestamps_enforce_finite_values(
) -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await _stamp_runtime_origin_0007(target)
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            enforcement_valid = True
            finite_value = datetime(2099, 1, 1, tzinfo=timezone.utc)
            for table, column, constraint, nullable in _FINITE_TIMESTAMPS:
                catalog = await connection.fetchrow(
                    """
                    SELECT pg_get_constraintdef(con.oid, true) AS definition
                    FROM pg_constraint AS con
                    JOIN pg_class AS rel ON rel.oid=con.conrelid
                    JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                    WHERE nsp.nspname=current_schema()
                      AND rel.relname=$1
                      AND con.conname=$2
                      AND con.contype='c'
                      AND con.convalidated
                    """,
                    table,
                    constraint,
                )
                definition = (
                    str(catalog["definition"]).replace(" ", "").lower()
                    if catalog is not None
                    else ""
                )
                catalog_column = (
                    f'"{column}"' if column == "timestamp" else column
                )
                expected_term = f"isfinite({catalog_column})"
                catalog_valid = expected_term in definition
                if nullable:
                    catalog_valid = (
                        catalog_valid
                        and f"{catalog_column}isnull" in definition
                    )

                finite_update = await connection.execute(
                    (
                        f"UPDATE {table} SET {column}=$1 "  # noqa: S608
                        f"WHERE ctid=(SELECT ctid FROM {table} LIMIT 1)"
                    ),
                    finite_value,
                )
                finite_succeeded = finite_update.startswith("UPDATE 1")
                infinity_rejected = []
                for unsafe in ("infinity", "-infinity"):
                    rejected = False
                    try:
                        await connection.execute(
                            f"UPDATE {table} "  # noqa: S608
                            f"SET {column}='{unsafe}'::timestamptz "
                            f"WHERE ctid=("
                            f"SELECT ctid FROM {table} LIMIT 1)"
                        )
                    except Exception:
                        rejected = True
                    reusable = await connection.fetchval("SELECT true")
                    infinity_rejected.append(rejected and bool(reusable))

                null_rejected = False
                null_accepted = False
                try:
                    null_result = await connection.execute(
                        f"UPDATE {table} SET {column}=NULL "  # noqa: S608
                        f"WHERE ctid=(SELECT ctid FROM {table} LIMIT 1)"
                    )
                    null_accepted = null_result.startswith("UPDATE 1")
                except Exception:
                    null_rejected = True
                reusable = await connection.fetchval("SELECT true")
                null_valid = (
                    null_accepted
                    if nullable
                    else null_rejected
                ) and bool(reusable)
                enforcement_valid = (
                    enforcement_valid
                    and catalog_valid
                    and finite_succeeded
                    and all(infinity_rejected)
                    and null_valid
                )
        finally:
            await connection.close()
        _require_fixed(
            enforcement_valid,
            "PostgreSQL finite timestamp contract diverged",
        )


@pytest.mark.asyncio
async def test_real_postgres_downgrade_refusal_is_non_mutating() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        await harness._alembic(target, "upgrade", "0008")
        connection = await harness._connect(target)
        try:
            await harness._seed_postgres_contract(connection)
            before = await harness._postgres_isolation_fingerprint(connection)
            before_data = await _application_data_digest(connection)
        finally:
            await connection.close()
        refused = False
        try:
            await harness._alembic(target, "downgrade", "0007")
        except RuntimeError:
            refused = True
        connection = await harness._connect(target)
        try:
            after = await harness._postgres_isolation_fingerprint(connection)
            after_data = await _application_data_digest(connection)
            revision_current = await connection.fetchval(
                "SELECT version_num='0008' FROM alembic_version"
            )
        finally:
            await connection.close()
        _require_fixed(
            refused
            and before == after
            and before_data == after_data
            and bool(revision_current),
            "revision 0008 downgrade refusal mutated PostgreSQL state",
        )


@pytest.mark.asyncio
async def test_real_postgres_target_decoy_and_maintenance_are_isolated() -> None:
    _postgres_test_config()
    from tests.integration import test_postgres_migration_portability as harness

    async with harness._postgres_harness() as target:
        async with harness._postgres_harness() as decoy:
            maintenance_before = await harness._database_fingerprint(
                target.config,
                target.config.maintenance_database,
            )
            decoy_before = await harness._database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            await harness._alembic(target, "upgrade", "0008")
            target_after = await harness._database_fingerprint(
                target.config,
                target.database_name,
            )
            decoy_after = await harness._database_fingerprint(
                decoy.config,
                decoy.database_name,
            )
            maintenance_after = await harness._database_fingerprint(
                target.config,
                target.config.maintenance_database,
            )
        isolated = (
            bool(target_after.versions)
            and decoy_before == decoy_after
            and harness._isolation_fingerprint_has_no_ares_state(decoy_after)
            and maintenance_before == maintenance_after
        )
        _require_fixed(
            isolated,
            "PostgreSQL revision 0008 migrated an unselected database",
        )
