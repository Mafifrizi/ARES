"""Real SQLite migration tests for revision 0010."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection

from ares.db.execution_lifecycle import (
    LIFECYCLE_TABLES,
    SQLITE_LIFECYCLE_DDL,
    V11_AUTHORITY_TABLES,
    sqlite_admission_authority_runtime_script,
    validate_sqlite_admission_authority_catalog,
    validate_sqlite_lifecycle_catalog,
)
from ares.db.migrations.adoption import migration_config
from ares.db.schema import CREATE_TABLES

# Independently derived from the handwritten whole-catalog oracle below after
# freezing the revision-0010 P1-B DDL.  This does not call the production
# lifecycle validator or expected-fact builder.
_SQLITE_CATALOG_FINGERPRINT_V1 = "087c437f1fb02a37bcdbe9e9312485410c01d0673d587429dbc6c6d34ad22e12"

_P1B_LOGICAL_EXECUTION_COLUMNS = (
    "id",
    "submission_id",
    "campaign_id",
    "actor_subject_ref",
    "actor_user_id",
    "module_id",
    "ingress_code",
    "admission_operation_id",
    "submission_binding_contract_version",
    "submission_request_binding_digest",
    "submission_result_code",
    "submission_exact_replay_code",
    "submission_result_binding_digest",
    "highest_attempt_ordinal",
    "revision",
    "created_at",
    "closure_operation_id",
    "closure_authority_subject_ref",
    "closure_authority_user_id",
    "closure_authority_revision",
    "closing_attempt_id",
    "closed_at",
)

_P1B_RECEIPT_COLUMNS = (
    "operation_id",
    "operation_code",
    "campaign_id",
    "primary_target_id",
    "secondary_target_id",
    "principal_kind",
    "principal_subject_ref",
    "principal_user_id",
    "principal_authority_revision_present",
    "principal_authority_revision",
    "binding_contract_version",
    "request_binding_digest",
    "expected_revision_present",
    "expected_revision",
    "secondary_expected_revision_present",
    "secondary_expected_revision",
    "owner_ref",
    "lease_generation",
    "result_code",
    "exact_replay_code",
    "result_binding_digest",
    "result_identity",
    "result_revision_present",
    "result_revision",
    "secondary_result_identity",
    "secondary_result_revision_present",
    "secondary_result_revision",
    "created_at",
)

_P1B_SQLITE_RECEIPT_TRIGGERS = (
    (
        "trg_eor_immutable_delete",
        "execution_operation_receipts",
        "CREATE TRIGGER trg_eor_immutable_delete BEFORE DELETE "
        "ON execution_operation_receipts BEGIN "
        "SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
    ),
    (
        "trg_eor_immutable_update",
        "execution_operation_receipts",
        "CREATE TRIGGER trg_eor_immutable_update BEFORE UPDATE "
        "ON execution_operation_receipts BEGIN "
        "SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
    ),
)


def _independent_sqlite_catalog_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    normalized = tuple(
        tuple("" if value is None else re.sub(r"\s+", " ", str(value)).strip() for value in row)
        for row in rows
    )
    payload = json.dumps(normalized, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _run(path: str, operation: str, revision: str) -> None:
    with migration_config() as configured:
        config: Config = configured
        config.cmd_opts = SimpleNamespace(x=[f"db_url=sqlite:///{path}"])
        getattr(command, operation)(config, revision)


def _revision(path: str) -> str:
    connection = sqlite3.connect(path)
    try:
        return str(connection.execute("SELECT version_num FROM alembic_version").fetchone()[0])
    finally:
        connection.close()


def test_empty_database_upgrades_through_exact_head_0010(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        gateway = connection.execute("SELECT mode,revision FROM execution_gateway_state").fetchall()
    finally:
        connection.close()
    assert _revision(path.as_posix()) == "0010", "migration head changed"
    assert set(LIFECYCLE_TABLES).issubset(tables), "lifecycle tables missing"
    assert gateway == [("disabled", 0)], "gateway was enabled by migration"


def test_empty_database_upgrades_through_exact_head_0011(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "head")
    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        gateway = connection.execute("SELECT mode,revision FROM execution_gateway_state").fetchall()
        validate_sqlite_lifecycle_catalog(connection)
        validate_sqlite_admission_authority_catalog(connection)
    finally:
        connection.close()
    assert _revision(path.as_posix()) == "0011", "migration head changed"
    assert set(LIFECYCLE_TABLES).issubset(tables), "lifecycle tables missing"
    assert set(V11_AUTHORITY_TABLES).issubset(tables), "admission-authority tables missing"
    assert gateway == [("disabled", 0)], "gateway was enabled by migration"


def test_sqlite_catalog_matches_independent_literal_fingerprint(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        observed = _independent_sqlite_catalog_fingerprint(connection)
        index_row = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE type='index' AND name='ix_eol_attempt'"
        ).fetchone()
        index_columns = tuple(connection.execute("PRAGMA index_xinfo(ix_eol_attempt)"))
        validate_sqlite_lifecycle_catalog(connection)
    finally:
        connection.close()
    assert observed == _SQLITE_CATALOG_FINGERPRINT_V1, "SQLite whole-catalog fingerprint changed"
    assert tuple(index_row) == (
        "index",
        "ix_eol_attempt",
        "execution_output_links",
        "CREATE INDEX ix_eol_attempt ON execution_output_links(attempt_id)",
    ), "operational attempt index definition changed"
    assert index_columns == (
        (0, 1, "attempt_id", 0, "BINARY", 1),
        (1, -1, None, 0, "BINARY", 0),
    ), "operational attempt index signature changed"


def test_sqlite_validator_rejects_missing_operational_attempt_index() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(CREATE_TABLES)
        connection.execute("DROP INDEX ix_eol_attempt")
        with pytest.raises(RuntimeError, match="Incompatible execution lifecycle schema"):
            validate_sqlite_lifecycle_catalog(connection)
    finally:
        connection.close()


def test_sqlite_validator_rejects_wrong_operational_attempt_index_key() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(CREATE_TABLES)
        connection.execute("DROP INDEX ix_eol_attempt")
        connection.execute("CREATE INDEX ix_eol_attempt ON execution_output_links(campaign_id)")
        with pytest.raises(RuntimeError, match="Incompatible execution lifecycle schema"):
            validate_sqlite_lifecycle_catalog(connection)
    finally:
        connection.close()


@pytest.mark.parametrize("table", LIFECYCLE_TABLES, ids=LIFECYCLE_TABLES)
def test_each_lifecycle_table_is_created_once(tmp_path, table: str) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        count = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?",
            (table,),
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == 1, "lifecycle relation count changed"


def test_attempt_contract_version_columns_are_exact_and_ordered(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute("PRAGMA table_info(execution_attempts)").fetchall()
        table_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='execution_attempts'"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    columns = tuple(str(row[1]) for row in rows)
    assert columns.index("policy_contract_version") == (
        columns.index("policy_evaluation_state") + 1
    ), "policy contract column order changed"
    assert {str(row[1]): (str(row[2]), int(row[3])) for row in rows}[
        "request_contract_version"
    ] == ("INTEGER", 1), "request contract type changed"
    assert "request_contract_version=1" in table_sql, "request version check missing"
    assert "policy_contract_version=1" in table_sql, "policy version check missing"
    assert "descriptor_contract_version='ares.module-descriptor.v2'" in table_sql, (
        "descriptor contract check changed"
    )


def test_p1b_submission_authority_and_receipt_schema_are_exact(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        logical_columns = tuple(
            str(row[1]) for row in connection.execute("PRAGMA table_info(logical_executions)")
        )
        receipt_columns = tuple(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(execution_operation_receipts)")
        )
        receipt_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_schema "
                "WHERE type='table' AND name='execution_operation_receipts'"
            ).fetchone()[0]
        )
        receipt_foreign_keys = tuple(
            connection.execute("PRAGMA foreign_key_list(execution_operation_receipts)")
        )
    finally:
        connection.close()
    assert logical_columns == _P1B_LOGICAL_EXECUTION_COLUMNS, "submission authority columns changed"
    assert receipt_columns == _P1B_RECEIPT_COLUMNS, "receipt-v2 column order changed"
    assert "binding_contract_version=2" in receipt_sql, "receipt-v2 contract check changed"
    assert "principal_kind IN ('actor','resolver')" in receipt_sql, (
        "receipt actor/resolver principal shape changed"
    )
    assert "principal_kind IN ('worker','system')" in receipt_sql, (
        "receipt worker/system principal shape changed"
    )
    assert "expected_revision_present=1" in receipt_sql, (
        "receipt revision-presence contract changed"
    )
    assert "CONSTRAINT ck_eor_operation_shape" in receipt_sql, (
        "receipt operation-specific revision-presence contract missing"
    )
    assert "CONSTRAINT ck_eor_outbox_owner_shape" in receipt_sql, (
        "receipt outbox owner/generation contract missing"
    )
    assert receipt_foreign_keys == (), "historical receipts gained a target foreign key"


def test_p1b_sqlite_receipt_immutability_objects_are_exact(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        rows = connection.execute(
            "SELECT name,tbl_name,sql FROM sqlite_schema "
            "WHERE type='trigger' AND tbl_name='execution_operation_receipts' "
            "ORDER BY name"
        ).fetchall()
    finally:
        connection.close()
    observed = tuple(
        (str(name), str(table), re.sub(r"\s+", " ", str(sql)).strip()) for name, table, sql in rows
    )
    assert observed == _P1B_SQLITE_RECEIPT_TRIGGERS, (
        "SQLite receipt immutability trigger allowlist changed"
    )


def test_sqlite_cyclic_foreign_key_is_inline_and_deferred() -> None:
    logical = SQLITE_LIFECYCLE_DDL[0]
    attempts = SQLITE_LIFECYCLE_DDL[1]
    assert logical.startswith("CREATE TABLE logical_executions"), "logical relation order changed"
    assert attempts.startswith("CREATE TABLE execution_attempts"), "attempt relation order changed"
    assert (
        "FOREIGN KEY (id,closing_attempt_id) "
        "REFERENCES execution_attempts(logical_execution_id,id) "
        "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED"
    ) in logical, "closing foreign key changed"


def test_runtime_and_migration_lifecycle_catalogs_match(tmp_path) -> None:
    migration_path = tmp_path / "migration.db"
    runtime_path = tmp_path / "runtime.db"
    _run(migration_path.as_posix(), "upgrade", "0010")
    runtime = sqlite3.connect(runtime_path)
    try:
        generation_11 = sqlite_admission_authority_runtime_script()
        assert CREATE_TABLES.endswith(generation_11), "runtime generation-11 suffix changed"
        runtime.executescript(CREATE_TABLES[: -len(generation_11)])
    finally:
        runtime.close()

    def catalog(path) -> tuple[tuple[str, str, str], ...]:
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(
                "SELECT type,name,replace(replace(sql,'IF NOT EXISTS ',''),' OR IGNORE','') "
                "FROM sqlite_schema WHERE type IN ('table','index','trigger') "
                "AND (tbl_name IN (?,?,?,?,?,?,?,?,?,?,?) "
                "OR name IN (?,?,?,?,?,?,?,?,?,?,?)) "
                "AND sql IS NOT NULL ORDER BY type,name",
                (*LIFECYCLE_TABLES, *LIFECYCLE_TABLES),
            ).fetchall()
            return tuple((str(row[0]), str(row[1]), str(row[2])) for row in rows)
        finally:
            connection.close()

    assert catalog(migration_path) == catalog(runtime_path), (
        "runtime and migration lifecycle catalogs differ"
    )


_SQLITE_CATALOG_DRIFTS = (
    (
        "logical-type",
        "logical_executions",
        "actor_subject_ref TEXT NOT NULL",
        "actor_subject_ref INTEGER NOT NULL",
    ),
    ("logical-null", "logical_executions", "actor_user_id TEXT,", "actor_user_id TEXT NOT NULL,"),
    (
        "logical-default",
        "logical_executions",
        "revision INTEGER NOT NULL DEFAULT 0",
        "revision INTEGER NOT NULL DEFAULT 1",
    ),
    (
        "logical-unique-order",
        "logical_executions",
        "UNIQUE (campaign_id,id)",
        "UNIQUE (id,campaign_id)",
    ),
    (
        "logical-fk-action",
        "logical_executions",
        "ON UPDATE NO ACTION ON DELETE NO ACTION",
        "ON UPDATE CASCADE ON DELETE NO ACTION",
    ),
    (
        "logical-fk-deferral",
        "logical_executions",
        "DEFERRABLE INITIALLY DEFERRED",
        "DEFERRABLE INITIALLY IMMEDIATE",
    ),
    (
        "attempt-check",
        "execution_attempts",
        "request_contract_version=1",
        "request_contract_version IN (1,2)",
    ),
    (
        "attempt-column-order",
        "execution_attempts",
        "policy_evaluation_state TEXT NOT NULL,\n    policy_contract_version INTEGER NOT NULL",
        "policy_contract_version INTEGER NOT NULL,\n    policy_evaluation_state TEXT NOT NULL",
    ),
    (
        "receipt-contract",
        "execution_operation_receipts",
        "binding_contract_version=2",
        "binding_contract_version IN (1,2)",
    ),
    (
        "submission-contract",
        "logical_executions",
        "submission_binding_contract_version=2",
        "submission_binding_contract_version IN (1,3)",
    ),
    (
        "receipt-trigger-action",
        "trg_eor_immutable_update",
        "BEFORE UPDATE",
        "AFTER UPDATE",
    ),
    (
        "receipt-result-null",
        "execution_operation_receipts",
        "result_binding_digest TEXT NOT NULL",
        "result_binding_digest TEXT",
    ),
    (
        "outbox-count-check",
        "execution_publication_outbox",
        "finding_count BETWEEN 0 AND 9007199254740991",
        "finding_count>=0",
    ),
    ("gateway-mode", "execution_gateway_state", "'emergency_disabled'", "'compatibility_enabled'"),
    (
        "index-order",
        "ix_ea_logical_state",
        "logical_execution_id,state,ordinal",
        "ordinal,state,logical_execution_id",
    ),
    (
        "index-predicate",
        "uq_ea_one_child",
        "WHERE parent_attempt_id IS NOT NULL",
        "WHERE parent_attempt_id IS NULL",
    ),
)


@pytest.mark.parametrize(
    ("_case", "object_name", "old", "new"),
    _SQLITE_CATALOG_DRIFTS,
    ids=tuple(case[0] for case in _SQLITE_CATALOG_DRIFTS),
)
def test_sqlite_validator_rejects_each_literal_catalog_drift(
    _case: str, object_name: str, old: str, new: str
) -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(CREATE_TABLES)
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_schema SET sql=replace(sql,?,?) WHERE name=? AND instr(sql,?)>0",
            (old, new, object_name, old),
        )
        connection.execute("PRAGMA writable_schema=OFF")
        assert cursor.rowcount == 1, "catalog mutation did not apply"
        with pytest.raises(RuntimeError, match="Incompatible execution lifecycle schema"):
            validate_sqlite_lifecycle_catalog(connection)
    finally:
        connection.close()


def test_revision_0010_downgrade_refuses_before_mutation(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        before = tuple(
            connection.execute(
                "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
        )
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="revision-0010 downgrade is not supported"):
        _run(path.as_posix(), "downgrade", "0009")
    connection = sqlite3.connect(path)
    try:
        after = tuple(
            connection.execute(
                "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
        )
    finally:
        connection.close()
    assert before == after, "downgrade refusal mutated the catalog"
    assert _revision(path.as_posix()) == "0010", "downgrade changed revision"


@pytest.mark.parametrize("_case", ["empty", "v2-populated"], ids=("empty", "v2-populated"))
def test_revision_0011_upgrades_supported_0010_catalog(tmp_path, _case: str) -> None:
    path = tmp_path / f"supported-{_case}.db"
    _run(path.as_posix(), "upgrade", "0010")
    actor_id = "00000000-0000-4000-8000-000000001101"
    campaign_id = "00000000-0000-4000-8000-000000001102"
    if _case == "v2-populated":
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(
                "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
                (actor_id, "migration-owner", "fixed", "admin", "fixed"),
            )
            connection.execute(
                "INSERT INTO campaigns(id,name,operator,scope_json,targets_json) VALUES(?,?,?,?,?)",
                (
                    campaign_id,
                    "migration-campaign",
                    "migration-owner",
                    '[{"cidr":"10.11.0.0/24"}]',
                    '["Host.Example."]',
                ),
            )
            connection.execute(
                "INSERT INTO execution_actor_authority_revisions("
                "user_id,latest_operation_id,latest_operation_code) VALUES(?,?,'ensure')",
                (actor_id, "00000000-0000-4000-8000-000000001103"),
            )
            connection.execute(
                "INSERT INTO campaign_execution_authority_revisions("
                "campaign_id,latest_operation_id,latest_operation_code) VALUES(?,?,'ensure')",
                (campaign_id, "00000000-0000-4000-8000-000000001104"),
            )
            connection.execute(
                "INSERT INTO credentials(id,campaign_id,username,cred_type,source_module) "
                "VALUES(?,?,?,?,?)",
                (
                    "00000000-0000-4000-8000-000000001105",
                    campaign_id,
                    "opaque-user",
                    "cleartext",
                    "migration-fixture",
                ),
            )
            connection.commit()
        finally:
            connection.close()

    _run(path.as_posix(), "upgrade", "0011")
    connection = sqlite3.connect(path)
    try:
        validate_sqlite_admission_authority_catalog(connection)
        counts = tuple(
            int(
                connection.execute(
                    f"SELECT count(*) FROM {table}"  # noqa: S608 - frozen table tuple.
                ).fetchone()[0]
            )
            for table in V11_AUTHORITY_TABLES
        )
        if _case == "v2-populated":
            grant = connection.execute(
                "SELECT authority_state,revision FROM campaign_execution_actor_grants "
                "WHERE campaign_id=? AND actor_user_id=?",
                (campaign_id, actor_id),
            ).fetchone()
            destination = connection.execute(
                "SELECT authority_state,revision,normalization_version,destination_count "
                "FROM campaign_execution_destination_authorities WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            credential = connection.execute(
                "SELECT execution_authority_state,execution_authority_revision,"
                "execution_authority_binding_digest FROM credentials WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
    finally:
        connection.close()
    assert _revision(path.as_posix()) == "0011", "supported upgrade missed revision 0011"
    if _case == "empty":
        assert counts == (0,) * len(V11_AUTHORITY_TABLES), "empty upgrade fabricated authority"
    else:
        assert counts == (1, 1, 0, 0, 0), "v2 authority backfill cardinality changed"
        assert tuple(grant) == ("active", 0), "compatibility campaign grant changed"
        assert tuple(destination) == ("active", 0, 1, 2), "destination backfill changed"
        assert tuple(credential[:2]) == ("active", 0), "credential authority backfill changed"
        assert re.fullmatch(r"[0-9a-f]{64}", str(credential[2])), (
            "credential binding backfill changed"
        )


def test_revision_0011_downgrade_refuses_before_mutation(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "head")
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (
                "00000000-0000-4000-8000-000000001111",
                "downgrade-owner",
                "fixed",
                "admin",
                "fixed",
            ),
        )
        connection.execute(
            "INSERT INTO execution_actor_authority_revisions("
            "user_id,latest_operation_id,latest_operation_code,authority_revision) "
            "VALUES(?,?,'ensure',1)",
            (
                "00000000-0000-4000-8000-000000001111",
                "00000000-0000-4000-8000-000000001112",
            ),
        )
        connection.commit()
        before = tuple(
            connection.execute(
                "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
        )
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="revision-0011 preflight failed"):
        _run(path.as_posix(), "downgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        after = tuple(
            connection.execute(
                "SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name"
            ).fetchall()
        )
        validate_sqlite_admission_authority_catalog(connection)
    finally:
        connection.close()
    assert before == after, "revision-0011 downgrade refusal mutated catalog"
    assert _revision(path.as_posix()) == "0011", "revision-0011 downgrade changed revision"


def test_revision_0011_failed_upgrade_rolls_back_and_retry_succeeds(tmp_path, monkeypatch) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    original_execute = Connection.execute

    def fail_after_catalog_mutation(self, statement, *args, **kwargs):
        result = original_execute(self, statement, *args, **kwargs)
        if (
            str(statement)
            .lstrip()
            .startswith("CREATE TABLE execution_attempt_credential_observations")
        ):
            raise RuntimeError("injected revision-0011 failure")
        return result

    monkeypatch.setattr(Connection, "execute", fail_after_catalog_mutation)
    engine = sa.create_engine(f"sqlite:///{path}")
    try:
        with engine.connect() as migration_connection:
            migration_connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            migration_connection.commit()
            migration_connection.exec_driver_sql("BEGIN IMMEDIATE")
            with pytest.raises(RuntimeError, match="injected revision-0011 failure"):
                with migration_config(migration_connection) as config:
                    command.upgrade(config, "0011")
            if migration_connection.in_transaction():
                migration_connection.rollback()
    finally:
        engine.dispose()
    connection = sqlite3.connect(path)
    try:
        tables_after_failure = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        validate_sqlite_lifecycle_catalog(connection)
    finally:
        connection.close()
    assert _revision(path.as_posix()) == "0010", "failed upgrade advanced revision"
    assert set(V11_AUTHORITY_TABLES).isdisjoint(tables_after_failure), (
        "failed upgrade left generation-11 relations"
    )

    monkeypatch.setattr(Connection, "execute", original_execute)
    _run(path.as_posix(), "upgrade", "0011")
    connection = sqlite3.connect(path)
    try:
        validate_sqlite_admission_authority_catalog(connection)
    finally:
        connection.close()
    assert _revision(path.as_posix()) == "0011", "retry did not reach revision 0011"


def test_migration_seeds_no_authority_budget_attempt_or_outbox_rows(tmp_path) -> None:
    path = tmp_path / "managed.db"
    _run(path.as_posix(), "upgrade", "0010")
    connection = sqlite3.connect(path)
    try:
        counts = tuple(
            int(
                connection.execute(
                    f"SELECT count(*) FROM {table}"  # noqa: S608 - fixed names
                ).fetchone()[0]
            )
            for table in LIFECYCLE_TABLES
            if table != "execution_gateway_state"
        )
    finally:
        connection.close()
    assert counts == (0,) * 10, "migration seeded lifecycle authority"
