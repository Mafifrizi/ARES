# ruff: noqa: E501, S608
"""Add independently persisted execution admission authority.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from importlib import import_module
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

_PREVIOUS = import_module("migrations.versions.0010_execution_lifecycle")
classify_unversioned_catalog = _PREVIOUS.classify_unversioned_catalog
_require_sqlite_alembic_version_relation = _PREVIOUS._require_sqlite_alembic_version_relation
_pg_validate_alembic_version_relation = _PREVIOUS._pg_validate_alembic_version_relation


def _fail() -> None:
    raise RuntimeError("revision-0011 preflight failed")


def _dialect() -> str:
    dialect = op.get_bind().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        _fail()
    return dialect


def _contract() -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    lifecycle = import_module("ares.db.execution_lifecycle")
    return (
        tuple(lifecycle.V11_AUTHORITY_TABLES),
        tuple(lifecycle.SQLITE_ADMISSION_AUTHORITY_V11_DDL),
        tuple(lifecycle.POSTGRES_ADMISSION_AUTHORITY_V11_DDL),
    )


def _preflight() -> str:
    bind = op.get_bind()
    dialect = _dialect()
    # Revision 0011 accepts only the protected, exact revision-0010 catalog.
    # This check precedes owner resolution and every catalog/data mutation.
    _PREVIOUS.verify_managed_catalog(bind)
    tables, _, _ = _contract()
    existing = set(sa.inspect(bind).get_table_names())
    if not set(_PREVIOUS._LIFECYCLE_COLUMNS).issubset(existing):
        _fail()
    if any(table in existing for table in tables):
        _fail()
    return dialect


def _deterministic_uuid(domain: bytes, *values: object) -> str:
    encoded = bytearray(domain + b"\x00")
    for value in values:
        item = str(value).encode("utf-8")
        encoded.extend(len(item).to_bytes(4, "big"))
        encoded.extend(item)
    digest = hashlib.sha256(encoded).hexdigest()
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


def _grant_binding_digest(campaign_id: object, actor_user_id: object) -> str:
    lifecycle = import_module("ares.db.execution_lifecycle")
    return lifecycle.canonical_operation_binding_digest(
        "campaign-actor-grant",
        (
            ("campaign_id", str(campaign_id)),
            ("actor_user_id", str(actor_user_id)),
            ("authority_state", "active"),
        ),
    )


def _canonical_destination_authority(
    scope_json: object, targets_json: object
) -> tuple[int, str, str]:
    try:
        scope = json.loads(str(scope_json))
        targets = json.loads(str(targets_json))
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail()
    if type(scope) is not list or type(targets) is not list:
        _fail()
    normalized: set[str] = set()
    for entry in scope:
        if type(entry) is not dict or set(entry) - {"cidr", "description"}:
            _fail()
        cidr = entry.get("cidr")
        if type(cidr) is not str or not cidr or "\x00" in cidr:
            _fail()
        try:
            canonical = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            _fail()
        normalized.add("scope:" + canonical)
    for entry in targets:
        if type(entry) is not str or not entry or "\x00" in entry:
            _fail()
        value = entry.strip()
        if not value:
            _fail()
        try:
            if "/" in value:
                value = str(ipaddress.ip_network(value, strict=False))
            else:
                value = str(ipaddress.ip_address(value))
        except ValueError:
            value = value.lower().rstrip(".")
            if not value or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,2047}", value) is None:
                _fail()
        normalized.add("target:" + value)
    values = tuple(sorted(normalized))
    lifecycle = import_module("ares.db.execution_lifecycle")
    return lifecycle.ExecutionLifecycleStore._destination_authority_facts(values)


def _credential_binding_digest(row: Any) -> str:
    lifecycle = import_module("ares.db.execution_lifecycle")
    return lifecycle.ExecutionLifecycleStore._credential_authority_binding(row)


def _actor_binding_digest(row: Any) -> str:
    lifecycle = import_module("ares.db.execution_lifecycle")
    return lifecycle.canonical_operation_binding_digest(
        "actor-authority",
        (
            ("user_id", str(row[0])),
            ("username", str(row[1])),
            ("role", str(row[2])),
            ("is_active", bool(row[3])),
            ("auth_epoch", int(row[4])),
        ),
    )


def _campaign_binding_digest(row: Any, destination_binding: str) -> str:
    lifecycle = import_module("ares.db.execution_lifecycle")
    return lifecycle.canonical_operation_binding_digest(
        "campaign-authority",
        (
            ("campaign_id", str(row[0])),
            ("operator", str(row[1])),
            ("status", str(row[2])),
            ("noise_profile", str(row[3])),
            ("destination_binding_digest", destination_binding),
        ),
    )


def _backfill_plan(bind: Any) -> tuple[tuple[tuple[Any, ...], ...], ...]:
    """Resolve and validate every compatibility authority before mutation."""
    campaign_rows = bind.execute(
        sa.text(
            "SELECT c.id,c.operator,c.scope_json,c.targets_json,u.id "
            "FROM campaigns c LEFT JOIN users u ON u.username=c.operator "
            "ORDER BY c.id,u.id"
        )
    ).fetchall()
    grouped: dict[str, list[tuple[Any, ...]]] = {}
    for row in campaign_rows:
        grouped.setdefault(str(row[0]), []).append(tuple(row))
    campaigns: list[tuple[Any, ...]] = []
    for campaign_id in sorted(grouped):
        matches = grouped[campaign_id]
        if len(matches) != 1 or matches[0][4] is None:
            _fail()
        row = matches[0]
        count, destination_digest, destination_binding = _canonical_destination_authority(
            row[2], row[3]
        )
        actor_user_id = str(row[4])
        campaigns.append(
            (
                str(row[0]),
                actor_user_id,
                _grant_binding_digest(row[0], actor_user_id),
                _deterministic_uuid(b"ares.migration-0011.grant", row[0], actor_user_id),
                count,
                destination_digest,
                destination_binding,
                _deterministic_uuid(b"ares.migration-0011.destination", row[0]),
                _campaign_binding_digest(
                    bind.execute(
                        sa.text(
                            "SELECT id,operator,status,noise_profile FROM campaigns WHERE id=:id"
                        ),
                        {"id": row[0]},
                    ).one(),
                    destination_binding,
                ),
            )
        )
    actor_rows = bind.execute(
        sa.text(
            "SELECT a.user_id,u.username,u.role,u.is_active,u.auth_epoch "
            "FROM execution_actor_authority_revisions a JOIN users u ON u.id=a.user_id "
            "ORDER BY a.user_id"
        )
    ).fetchall()
    actors = tuple((str(row[0]), _actor_binding_digest(row)) for row in actor_rows)
    credential_rows = bind.execute(
        sa.text(
            "SELECT id,campaign_id,host_id,username,cred_type,domain,source_module "
            "FROM credentials ORDER BY id"
        )
    ).fetchall()
    credentials = tuple((str(row[0]), _credential_binding_digest(row)) for row in credential_rows)
    return tuple(campaigns), credentials, actors


def _backfill(bind: Any, plan: tuple[tuple[tuple[Any, ...], ...], ...]) -> None:
    campaigns, credentials, actors = plan
    for (
        campaign_id,
        actor_user_id,
        grant_binding,
        grant_operation,
        count,
        destination_digest,
        destination_binding,
        destination_operation,
        campaign_binding,
    ) in campaigns:
        bind.execute(
            sa.text(
                "INSERT INTO campaign_execution_actor_grants("
                "campaign_id,actor_user_id,authority_state,revision,binding_digest,"
                "latest_operation_id,latest_operation_base_revision,latest_operation_code) "
                "VALUES(:campaign,:actor,'active',0,:binding,:operation,0,'put')"
            ),
            {
                "campaign": campaign_id,
                "actor": actor_user_id,
                "binding": grant_binding,
                "operation": grant_operation,
            },
        )
        bind.execute(
            sa.text(
                "UPDATE campaign_execution_authority_revisions "
                "SET authority_binding_digest=:binding WHERE campaign_id=:campaign"
            ),
            {"binding": campaign_binding, "campaign": campaign_id},
        )
        bind.execute(
            sa.text(
                "INSERT INTO campaign_execution_destination_authorities("
                "campaign_id,authority_state,revision,normalization_version,destination_count,"
                "destination_set_digest,binding_digest,latest_operation_id,"
                "latest_operation_base_revision,latest_operation_code) "
                "VALUES(:campaign,'active',0,1,:count,:destination,:binding,:operation,0,'update')"
            ),
            {
                "campaign": campaign_id,
                "count": count,
                "destination": destination_digest,
                "binding": destination_binding,
                "operation": destination_operation,
            },
        )
    for credential_id, binding_digest in credentials:
        bind.execute(
            sa.text(
                "UPDATE credentials SET execution_authority_binding_digest=:digest "
                "WHERE id=:credential"
            ),
            {"digest": binding_digest, "credential": credential_id},
        )
    for actor_user_id, binding_digest in actors:
        bind.execute(
            sa.text(
                "UPDATE execution_actor_authority_revisions "
                "SET authority_binding_digest=:binding WHERE user_id=:actor"
            ),
            {"binding": binding_digest, "actor": actor_user_id},
        )
    # Campaign ownership is resolved to one persisted user before mutation and
    # materialized as an explicit compatibility grant.  Role alone never grants
    # access.  No approval or attempt observation can be inferred historically;
    # historical logical/attempt rows retain their v2 defaults.


_RECEIPT_COLUMNS = (
    "operation_id,operation_code,campaign_id,primary_target_id,secondary_target_id,"
    "principal_kind,principal_subject_ref,principal_user_id,"
    "principal_authority_revision_present,principal_authority_revision,"
    "binding_contract_version,request_binding_digest,expected_revision_present,"
    "expected_revision,secondary_expected_revision_present,secondary_expected_revision,"
    "owner_ref,lease_generation,result_code,exact_replay_code,result_binding_digest,"
    "result_identity,result_revision_present,result_revision,secondary_result_identity,"
    "secondary_result_revision_present,secondary_result_revision,created_at"
)

_V11_ADDED_COLUMNS: dict[str, tuple[str, ...]] = {
    "logical_executions": (
        "immutable_work_digest",
        "immutable_intent_digest",
        "canonical_principal_user_id",
        "admission_authority_contract_version",
    ),
    "execution_attempts": (
        "approval_authority_binding_digest",
        "credential_authority_binding_digest",
        "destination_authority_binding_digest",
        "campaign_actor_grant_revision",
        "gateway_activation_revision",
        "gateway_revision",
        "immutable_work_digest",
        "immutable_intent_digest",
        "trusted_principal_user_id",
        "trusted_principal_subject_ref",
        "authority_contract_version",
    ),
    "execution_actor_authority_revisions": (
        "authority_latest_operation_code",
        "authority_latest_operation_base_revision",
        "authority_latest_operation_id",
        "authority_binding_digest",
        "authority_revision",
        "authority_state",
    ),
    "campaign_execution_authority_revisions": (
        "authority_latest_operation_code",
        "authority_latest_operation_base_revision",
        "authority_latest_operation_id",
        "authority_binding_digest",
        "authority_revision",
        "authority_state",
    ),
    "credentials": (
        "execution_authority_latest_operation_code",
        "execution_authority_latest_operation_base_revision",
        "execution_authority_latest_operation_id",
        "execution_authority_binding_digest",
        "execution_authority_revision",
        "execution_authority_state",
    ),
}


def _count(bind: Any, sql: str, values: dict[str, Any] | None = None) -> int:
    value = bind.execute(sa.text(sql), values or {}).scalar_one()
    return int(value)


def _assert_downgrade_safe(
    bind: Any,
    plan: tuple[tuple[tuple[Any, ...], ...], ...],
) -> None:
    """Reject all v11 mutations and v3 admission data before changing catalog bytes."""
    lifecycle = import_module("ares.db.execution_lifecycle")
    additive_receipts = bind.execute(
        sa.text(
            "SELECT count(*) FROM execution_operation_receipts WHERE operation_code IN :codes"
        ).bindparams(sa.bindparam("codes", expanding=True)),
        {"codes": tuple(lifecycle.V11_ADDITIVE_OPERATION_CODES)},
    ).scalar_one()
    if int(additive_receipts):
        _fail()
    if _count(
        bind,
        "SELECT count(*) FROM logical_executions WHERE "
        "admission_authority_contract_version<>2 OR canonical_principal_user_id IS NOT NULL "
        "OR immutable_intent_digest IS NOT NULL OR immutable_work_digest IS NOT NULL",
    ):
        _fail()
    if _count(
        bind,
        "SELECT count(*) FROM execution_attempts WHERE authority_contract_version<>2 "
        "OR trusted_principal_subject_ref IS NOT NULL OR trusted_principal_user_id IS NOT NULL "
        "OR immutable_intent_digest IS NOT NULL OR immutable_work_digest IS NOT NULL "
        "OR gateway_revision IS NOT NULL "
        "OR gateway_activation_revision IS NOT NULL OR campaign_actor_grant_revision IS NOT NULL "
        "OR destination_authority_binding_digest IS NOT NULL "
        "OR credential_authority_binding_digest IS NOT NULL "
        "OR approval_authority_binding_digest IS NOT NULL",
    ):
        _fail()
    for table in (
        "execution_actor_authority_revisions",
        "campaign_execution_authority_revisions",
    ):
        if _count(
            bind,
            f"SELECT count(*) FROM {table} WHERE authority_state<>'active' "
            "OR authority_revision<>0 OR authority_latest_operation_id IS NOT NULL "
            "OR authority_latest_operation_base_revision IS NOT NULL "
            "OR authority_latest_operation_code IS NOT NULL",
        ):
            _fail()
    for table in (
        "execution_approval_authorities",
        "execution_attempt_destination_observations",
        "execution_attempt_credential_observations",
    ):
        if _count(bind, f"SELECT count(*) FROM {table}"):
            _fail()

    campaigns, credentials, actors = plan
    actual_grants = bind.execute(
        sa.text(
            "SELECT campaign_id,actor_user_id,authority_state,revision,binding_digest,"
            "latest_operation_id,latest_operation_base_revision,latest_operation_code "
            "FROM campaign_execution_actor_grants ORDER BY campaign_id,actor_user_id"
        )
    ).fetchall()
    expected_grants = tuple(
        (row[0], row[1], "active", 0, row[2], row[3], 0, "put") for row in campaigns
    )
    if tuple(tuple(row) for row in actual_grants) != expected_grants:
        _fail()
    actual_destinations = bind.execute(
        sa.text(
            "SELECT campaign_id,authority_state,revision,normalization_version,"
            "destination_count,destination_set_digest,binding_digest,latest_operation_id,"
            "latest_operation_base_revision,latest_operation_code "
            "FROM campaign_execution_destination_authorities ORDER BY campaign_id"
        )
    ).fetchall()
    expected_destinations = tuple(
        (row[0], "active", 0, 1, row[4], row[5], row[6], row[7], 0, "update") for row in campaigns
    )
    if tuple(tuple(row) for row in actual_destinations) != expected_destinations:
        _fail()
    actual_campaign_bindings = bind.execute(
        sa.text(
            "SELECT campaign_id,authority_binding_digest "
            "FROM campaign_execution_authority_revisions ORDER BY campaign_id"
        )
    ).fetchall()
    expected_campaign_bindings = tuple((row[0], row[8]) for row in campaigns)
    if tuple(tuple(row) for row in actual_campaign_bindings) != expected_campaign_bindings:
        _fail()
    actual_credentials = bind.execute(
        sa.text(
            "SELECT id,execution_authority_state,execution_authority_revision,"
            "execution_authority_binding_digest,execution_authority_latest_operation_id,"
            "execution_authority_latest_operation_base_revision,"
            "execution_authority_latest_operation_code FROM credentials ORDER BY id"
        )
    ).fetchall()
    expected_credentials = tuple(
        (credential_id, "active", 0, digest, None, None, None)
        for credential_id, digest in credentials
    )
    if tuple(tuple(row) for row in actual_credentials) != expected_credentials:
        _fail()
    actual_actor_bindings = bind.execute(
        sa.text(
            "SELECT user_id,authority_binding_digest "
            "FROM execution_actor_authority_revisions ORDER BY user_id"
        )
    ).fetchall()
    if tuple(tuple(row) for row in actual_actor_bindings) != actors:
        _fail()


def _v10_receipt_create_statement(dialect: str) -> str:
    lifecycle = import_module("ares.db.execution_lifecycle")
    source = (
        lifecycle.POSTGRES_LIFECYCLE_DDL
        if dialect == "postgresql"
        else lifecycle.SQLITE_LIFECYCLE_DDL
    )
    return next(
        statement
        for statement in source
        if statement.startswith("CREATE TABLE execution_operation_receipts")
    )


def _restore_v10_receipts(bind: Any, dialect: str) -> None:
    statement = _v10_receipt_create_statement(dialect)
    if dialect == "postgresql":
        operation = re.search(
            r"CONSTRAINT ck_eor_operation_code CHECK \((.*?)\),\n", statement, re.S
        )
        shape = re.search(
            r"CONSTRAINT ck_eor_operation_shape CHECK \((.*?)\),\n    CONSTRAINT ck_eor_outbox_owner_shape",
            statement,
            re.S,
        )
        if operation is None or shape is None:
            _fail()
        for sql in (
            "ALTER TABLE execution_operation_receipts DROP CONSTRAINT ck_eor_operation_code",
            "ALTER TABLE execution_operation_receipts ADD CONSTRAINT ck_eor_operation_code CHECK ("
            + operation.group(1)
            + ")",
            "ALTER TABLE execution_operation_receipts DROP CONSTRAINT ck_eor_operation_shape",
            "ALTER TABLE execution_operation_receipts ADD CONSTRAINT ck_eor_operation_shape CHECK ("
            + shape.group(1)
            + ")",
        ):
            bind.execute(sa.text(sql))
        return
    for sql in (
        "DROP TRIGGER trg_eor_immutable_update",
        "DROP TRIGGER trg_eor_immutable_delete",
        "ALTER TABLE execution_operation_receipts RENAME TO execution_operation_receipts_v11",
        statement,
        "INSERT INTO execution_operation_receipts("
        + _RECEIPT_COLUMNS
        + ") SELECT "
        + _RECEIPT_COLUMNS
        + " FROM execution_operation_receipts_v11",
        "DROP TABLE execution_operation_receipts_v11",
        "CREATE TRIGGER trg_eor_immutable_update BEFORE UPDATE ON execution_operation_receipts "
        "BEGIN SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
        "CREATE TRIGGER trg_eor_immutable_delete BEFORE DELETE ON execution_operation_receipts "
        "BEGIN SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
        "CREATE INDEX ix_eor_campaign_created ON execution_operation_receipts(campaign_id,created_at,operation_id)",
        "CREATE INDEX ix_eor_primary_target ON execution_operation_receipts(primary_target_id,operation_code,created_at)",
        "CREATE INDEX ix_eor_principal_created ON execution_operation_receipts(principal_kind,principal_subject_ref,created_at,operation_id)",
    ):
        bind.execute(sa.text(sql))


def _apply_downgrade(bind: Any, dialect: str) -> None:
    bind.execute(sa.text("DROP INDEX ix_credentials_execution_authority"))
    for table in (
        "execution_attempt_credential_observations",
        "execution_attempt_destination_observations",
        "execution_approval_authorities",
        "campaign_execution_destination_authorities",
        "campaign_execution_actor_grants",
    ):
        bind.execute(sa.text(f"DROP TABLE {table}"))
    _restore_v10_receipts(bind, dialect)
    for table, columns in _V11_ADDED_COLUMNS.items():
        for column in columns:
            bind.execute(sa.text(f"ALTER TABLE {table} DROP COLUMN {column}"))


def verify_managed_catalog(connection: Any) -> None:
    lifecycle = import_module("ares.db.execution_lifecycle")
    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())
    if not set(lifecycle.LIFECYCLE_TABLES).issubset(tables):
        _fail()
    if not set(lifecycle.V11_AUTHORITY_TABLES).issubset(tables):
        _fail()
    dialect = connection.dialect.name
    if dialect == "sqlite":
        rows = connection.execute(
            sa.text(
                "SELECT m.name,p.name FROM sqlite_schema AS m "
                "JOIN pragma_table_info(m.name) AS p "
                "WHERE m.type='table' AND m.name IN :names ORDER BY m.name,p.cid"
            ).bindparams(
                sa.bindparam(
                    "names",
                    value=tuple(lifecycle._V11_EXISTING_COLUMNS)
                    + tuple(lifecycle.V11_AUTHORITY_TABLES),
                    expanding=True,
                )
            )
        ).fetchall()
        lifecycle._validate_v11_columns(rows)
        receipt = connection.execute(
            sa.text(
                "SELECT sql FROM sqlite_schema WHERE type='table' "
                "AND name='execution_operation_receipts'"
            )
        ).fetchone()
        if receipt is None or not all(
            code in str(receipt[0]) for code in lifecycle.V11_OPERATION_CODES
        ):
            _fail()
    elif dialect == "postgresql":
        names = list(tuple(lifecycle._V11_EXISTING_COLUMNS) + lifecycle.V11_AUTHORITY_TABLES)
        rows = connection.execute(
            sa.text(
                "SELECT c.relname,a.attname FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped "
                "WHERE n.nspname=current_schema() AND c.relname=ANY(:names) "
                "ORDER BY c.relname,a.attnum"
            ),
            {"names": names},
        ).fetchall()
        lifecycle._validate_v11_columns(rows)
        definitions = connection.execute(
            sa.text(
                "SELECT con.conname,pg_get_constraintdef(con.oid,true) FROM pg_constraint con "
                "JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND c.relname='execution_operation_receipts' "
                "AND con.conname IN ('ck_eor_operation_code','ck_eor_operation_shape')"
            )
        ).fetchall()
        operation = next(
            (str(row[1]) for row in definitions if str(row[0]) == "ck_eor_operation_code"),
            "",
        )
        if len(definitions) != 2 or not all(
            code in operation for code in lifecycle.V11_ADDITIVE_OPERATION_CODES
        ):
            _fail()
    else:
        _fail()


def upgrade() -> None:
    dialect = _preflight()
    bind = op.get_bind()
    plan = _backfill_plan(bind)
    _, sqlite_ddl, postgres_ddl = _contract()
    for statement in sqlite_ddl if dialect == "sqlite" else postgres_ddl:
        bind.execute(sa.text(statement))
    _backfill(bind, plan)
    verify_managed_catalog(bind)


def downgrade() -> None:
    dialect = _dialect()
    bind = op.get_bind()
    plan = _backfill_plan(bind)
    _assert_downgrade_safe(bind, plan)
    _apply_downgrade(bind, dialect)
    _PREVIOUS.verify_managed_catalog(bind)
