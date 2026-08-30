"""Real PostgreSQL 16 catalog tests for revision 0010."""

from __future__ import annotations

import hashlib
import json

import pytest

from ares.db.execution_lifecycle import (
    POSTGRES_LIFECYCLE_DDL,
    V11_AUTHORITY_TABLES,
    validate_postgresql_admission_authority_catalog,
    validate_postgresql_lifecycle_catalog,
)
from tests.integration.test_postgres_migration_portability import (
    _alembic,
    _migration_url,
    _postgres_harness,
)

_EXPECTED_LIFECYCLE_TABLES = (
    "campaign_execution_authority_revisions",
    "campaign_execution_budget_ledger",
    "campaign_execution_budgets",
    "execution_actor_authority_revisions",
    "execution_attempt_approvals",
    "execution_attempts",
    "execution_gateway_state",
    "execution_operation_receipts",
    "execution_output_links",
    "execution_publication_outbox",
    "logical_executions",
)
# Independently reproduced from two clean PostgreSQL-16 catalogs using only the
# handwritten catalog queries below after freezing the revision-0010 P1-B DDL.
_POSTGRES_LITERAL_ORACLE_FINGERPRINT_V1 = (
    "94e0e4fd279991da5ed029521cec92810d8738d4b4bc0de1254fc2fd96230ff1"
)

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

_POSTGRES_LITERAL_DRIFT_CASES = (
    ("relation-persistence", "ALTER TABLE execution_gateway_state SET UNLOGGED"),
    ("relation-rls", "ALTER TABLE execution_attempts ENABLE ROW LEVEL SECURITY"),
    ("relation-force-rls", "ALTER TABLE execution_attempts FORCE ROW LEVEL SECURITY"),
    ("column-order-extra", "ALTER TABLE execution_attempts ADD COLUMN catalog_drift BIGINT"),
    ("column-type", "ALTER TABLE execution_attempts ALTER COLUMN state TYPE VARCHAR(64)"),
    ("column-nullability", "ALTER TABLE execution_attempts ALTER COLUMN state DROP NOT NULL"),
    ("column-default", "ALTER TABLE execution_attempts ALTER COLUMN revision SET DEFAULT 1"),
    (
        "column-collation",
        "ALTER TABLE execution_attempts ALTER COLUMN bounded_recovery_proof_code "
        'TYPE TEXT COLLATE "C"',
    ),
    ("check-definition", "ALTER TABLE execution_attempts DROP CONSTRAINT ck_ea_history_dnf"),
    (
        "foreign-key-deferrability",
        "ALTER TABLE execution_attempts ALTER CONSTRAINT fk_ea_logical_campaign NOT DEFERRABLE",
    ),
    (
        "index-key-order",
        "DROP INDEX ix_ea_logical_state; CREATE INDEX ix_ea_logical_state "
        "ON execution_attempts (state, logical_execution_id, ordinal)",
    ),
    (
        "index-predicate",
        "DROP INDEX uq_ea_one_child; CREATE UNIQUE INDEX uq_ea_one_child "
        "ON execution_attempts (logical_execution_id, parent_attempt_id) "
        "WHERE parent_attempt_id IS NULL",
    ),
    (
        "index-method",
        "DROP INDEX ix_eol_attempt; CREATE INDEX ix_eol_attempt "
        "ON execution_output_links USING HASH (attempt_id)",
    ),
    ("unexpected-index", "CREATE INDEX ix_ea_catalog_drift ON execution_attempts (id)"),
    (
        "unexpected-trigger",
        "CREATE FUNCTION lifecycle_catalog_drift() RETURNS trigger LANGUAGE plpgsql "
        "AS 'BEGIN RETURN NEW; END'; CREATE TRIGGER lifecycle_catalog_drift "
        "BEFORE UPDATE ON execution_attempts FOR EACH ROW "
        "EXECUTE FUNCTION lifecycle_catalog_drift()",
    ),
    (
        "unexpected-policy",
        "ALTER TABLE execution_attempts ENABLE ROW LEVEL SECURITY; "
        "CREATE POLICY lifecycle_catalog_drift ON execution_attempts USING (true)",
    ),
    (
        "unexpected-rule",
        "CREATE RULE lifecycle_catalog_drift AS ON UPDATE TO execution_gateway_state "
        "DO ALSO NOTHING",
    ),
)

# Generation-11 catalog authority is intentionally specified here as literal
# mutations rather than by reusing migration or validator constants.  Every
# case receives a fresh database at revision 0011.
_POSTGRES_V11_LITERAL_DRIFT_CASES = (
    (
        "relation-presence",
        "DROP TABLE campaign_execution_actor_grants CASCADE",
    ),
    (
        "relation-kind",
        "DROP TABLE execution_attempt_destination_observations CASCADE; "
        "CREATE VIEW execution_attempt_destination_observations AS SELECT "
        "NULL::text AS attempt_id,NULL::text AS campaign_id,NULL::bigint AS ordinal,"
        "NULL::text AS destination_ref_digest,NULL::bigint AS authority_revision,"
        "NULL::bigint AS normalization_version,NULL::bigint AS observed_at WHERE false",
    ),
    (
        "relation-persistence",
        "ALTER TABLE campaign_execution_actor_grants SET UNLOGGED",
    ),
    (
        "relation-partition",
        "DROP TABLE execution_attempt_destination_observations CASCADE; "
        "CREATE TABLE execution_attempt_destination_observations("
        "attempt_id TEXT NOT NULL,campaign_id TEXT NOT NULL,ordinal BIGINT NOT NULL,"
        "destination_ref_digest TEXT NOT NULL,authority_revision BIGINT NOT NULL,"
        "normalization_version BIGINT NOT NULL,observed_at BIGINT NOT NULL DEFAULT "
        "((EXTRACT(epoch FROM clock_timestamp())*1000)::bigint)) "
        "PARTITION BY RANGE (ordinal)",
    ),
    (
        "relation-rls",
        "ALTER TABLE campaign_execution_actor_grants ENABLE ROW LEVEL SECURITY",
    ),
    (
        "relation-force-rls",
        "ALTER TABLE campaign_execution_actor_grants FORCE ROW LEVEL SECURITY",
    ),
    (
        "column-order-extra",
        "ALTER TABLE campaign_execution_actor_grants ADD COLUMN catalog_drift BIGINT",
    ),
    (
        "column-presence",
        "ALTER TABLE campaign_execution_actor_grants DROP COLUMN binding_digest CASCADE",
    ),
    (
        "column-type",
        "ALTER TABLE campaign_execution_actor_grants ALTER COLUMN authority_state TYPE VARCHAR(64)",
    ),
    (
        "column-nullability",
        "ALTER TABLE campaign_execution_actor_grants ALTER COLUMN authority_state DROP NOT NULL",
    ),
    (
        "column-default",
        "ALTER TABLE campaign_execution_actor_grants ALTER COLUMN revision SET DEFAULT 1",
    ),
    (
        "column-collation",
        'ALTER TABLE execution_approval_authorities ALTER COLUMN module_id TYPE TEXT COLLATE "C"',
    ),
    (
        "primary-key-presence",
        "ALTER TABLE campaign_execution_actor_grants DROP CONSTRAINT pk_ceag",
    ),
    (
        "primary-key-order",
        "ALTER TABLE campaign_execution_actor_grants DROP CONSTRAINT pk_ceag; "
        "ALTER TABLE campaign_execution_actor_grants ADD CONSTRAINT pk_ceag "
        "PRIMARY KEY (actor_user_id,campaign_id)",
    ),
    (
        "unique-presence",
        "ALTER TABLE execution_approval_authorities DROP CONSTRAINT uq_eapa_ref",
    ),
    (
        "unique-key-order",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT uq_eado_attempt_destination; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT uq_eado_attempt_destination "
        "UNIQUE (destination_ref_digest,attempt_id)",
    ),
    (
        "check-presence",
        "ALTER TABLE campaign_execution_actor_grants DROP CONSTRAINT ck_ceag_shape",
    ),
    (
        "check-definition",
        "ALTER TABLE campaign_execution_actor_grants DROP CONSTRAINT ck_ceag_shape; "
        "ALTER TABLE campaign_execution_actor_grants ADD CONSTRAINT ck_ceag_shape "
        "CHECK (revision >= 0)",
    ),
    (
        "foreign-key-presence",
        "ALTER TABLE execution_attempt_destination_observations DROP CONSTRAINT fk_eado_attempt",
    ),
    (
        "foreign-key-local-columns",
        "ALTER TABLE execution_attempt_credential_observations "
        "DROP CONSTRAINT fk_eaco_attempt; "
        "ALTER TABLE execution_attempt_credential_observations "
        "ADD CONSTRAINT fk_eaco_attempt FOREIGN KEY (campaign_id,credential_id) "
        "REFERENCES execution_attempts(campaign_id,id) "
        "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "foreign-key-referenced-relation",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT fk_eado_attempt; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) "
        "REFERENCES logical_executions(campaign_id,id) "
        "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "foreign-key-referenced-columns",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT fk_eado_attempt; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) "
        "REFERENCES execution_attempts(logical_execution_id,id) "
        "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "foreign-key-update-action",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT fk_eado_attempt; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) "
        "REFERENCES execution_attempts(campaign_id,id) "
        "ON UPDATE CASCADE ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "foreign-key-delete-action",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT fk_eado_attempt; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) "
        "REFERENCES execution_attempts(campaign_id,id) "
        "ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED",
    ),
    (
        "foreign-key-deferrability",
        "ALTER TABLE execution_attempt_destination_observations "
        "ALTER CONSTRAINT fk_eado_attempt NOT DEFERRABLE",
    ),
    (
        "foreign-key-initially-deferred",
        "ALTER TABLE execution_attempt_destination_observations "
        "ALTER CONSTRAINT fk_eado_attempt DEFERRABLE INITIALLY IMMEDIATE",
    ),
    (
        "foreign-key-validation",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT fk_eado_attempt; "
        "ALTER TABLE execution_attempt_destination_observations "
        "ADD CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) "
        "REFERENCES execution_attempts(campaign_id,id) "
        "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED NOT VALID",
    ),
    (
        "explicit-index-presence",
        "DROP INDEX ix_ceag_actor_state",
    ),
    (
        "backing-index-presence",
        "ALTER TABLE execution_attempt_destination_observations "
        "DROP CONSTRAINT uq_eado_attempt_destination",
    ),
    (
        "index-key-order",
        "DROP INDEX ix_ceag_actor_state; CREATE INDEX ix_ceag_actor_state "
        "ON campaign_execution_actor_grants(authority_state,actor_user_id,campaign_id)",
    ),
    (
        "index-uniqueness",
        "DROP INDEX ix_ceag_actor_state; CREATE UNIQUE INDEX ix_ceag_actor_state "
        "ON campaign_execution_actor_grants(actor_user_id,authority_state,campaign_id)",
    ),
    (
        "index-method",
        "DROP INDEX ix_ceag_actor_state; CREATE INDEX ix_ceag_actor_state "
        "ON campaign_execution_actor_grants USING HASH(actor_user_id)",
    ),
    (
        "index-predicate",
        "DROP INDEX ix_ceag_actor_state; CREATE INDEX ix_ceag_actor_state "
        "ON campaign_execution_actor_grants(actor_user_id,authority_state,campaign_id) "
        "WHERE authority_state='active'",
    ),
    (
        "index-expression",
        "DROP INDEX ix_ceag_actor_state; CREATE INDEX ix_ceag_actor_state "
        "ON campaign_execution_actor_grants((lower(actor_user_id)),authority_state,campaign_id)",
    ),
    (
        "index-validity",
        "SET allow_system_table_mods=on; "
        "UPDATE pg_catalog.pg_index SET indisvalid=false "
        "WHERE indexrelid='ix_ceag_actor_state'::regclass",
    ),
    (
        "index-readiness",
        "SET allow_system_table_mods=on; "
        "UPDATE pg_catalog.pg_index SET indisready=false "
        "WHERE indexrelid='ix_ceag_actor_state'::regclass",
    ),
    (
        "altered-column-check",
        "ALTER TABLE logical_executions DROP CONSTRAINT "
        "logical_executions_admission_authority_contract_version_check",
    ),
    (
        "credential-authority-check",
        "ALTER TABLE credentials DROP CONSTRAINT credentials_execution_authority_state_check",
    ),
    (
        "additive-receipt-operation-code",
        "ALTER TABLE execution_operation_receipts DROP CONSTRAINT ck_eor_operation_code",
    ),
    (
        "unexpected-relation",
        "CREATE TABLE campaign_execution_unexpected_authority(id TEXT PRIMARY KEY)",
    ),
    (
        "unexpected-constraint",
        "ALTER TABLE campaign_execution_actor_grants ADD CONSTRAINT "
        "ck_ceag_catalog_drift CHECK (true)",
    ),
    (
        "unexpected-index",
        "CREATE INDEX ix_ceag_catalog_drift ON campaign_execution_actor_grants(campaign_id)",
    ),
    (
        "unexpected-trigger",
        "CREATE FUNCTION admission_authority_catalog_drift() RETURNS trigger "
        "LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; "
        "CREATE TRIGGER admission_authority_catalog_drift BEFORE UPDATE "
        "ON campaign_execution_actor_grants FOR EACH ROW "
        "EXECUTE FUNCTION admission_authority_catalog_drift()",
    ),
    (
        "unexpected-policy",
        "CREATE POLICY admission_authority_catalog_drift "
        "ON campaign_execution_actor_grants USING (true)",
    ),
    (
        "unexpected-rule",
        "CREATE RULE admission_authority_catalog_drift AS ON UPDATE "
        "TO campaign_execution_actor_grants DO ALSO NOTHING",
    ),
)

_POSTGRES_V11_LITERAL_DRIFT_COUNT = 45
_POSTGRES_V11_LITERAL_DRIFT_ALIASES_SHA256 = (
    "95c34bebd5d9d0663b08e9604749e083ee67e57b987adee190c23c8c9ed2ddc9"
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_alias", "mutation"),
    _POSTGRES_V11_LITERAL_DRIFT_CASES,
    ids=[case[0] for case in _POSTGRES_V11_LITERAL_DRIFT_CASES],
)
async def test_postgres_generation_11_validator_rejects_literal_catalog_drift(
    case_alias: str,
    mutation: str,
) -> None:
    aliases = tuple(case[0] for case in _POSTGRES_V11_LITERAL_DRIFT_CASES)
    assert len(aliases) == _POSTGRES_V11_LITERAL_DRIFT_COUNT
    assert len(set(aliases)) == _POSTGRES_V11_LITERAL_DRIFT_COUNT
    assert (
        hashlib.sha256(("\n".join(aliases) + "\n").encode()).hexdigest()
        == _POSTGRES_V11_LITERAL_DRIFT_ALIASES_SHA256
    )
    assert case_alias in aliases

    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0011")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(
                harness.config,
                harness.database_name,
                ordinary_driver=True,
            )
        )
        try:
            await connection.execute(mutation)
            with pytest.raises(
                RuntimeError,
                match="Incompatible admission authority schema",
            ):
                await validate_postgresql_admission_authority_catalog(connection)
        finally:
            await connection.close()


async def _independent_postgres_catalog_fingerprint(connection) -> str:
    names = list(_EXPECTED_LIFECYCLE_TABLES)
    facts: list[tuple[object, ...]] = []
    queries = (
        (
            "relation",
            "SELECT c.relname,c.relkind::text,c.relpersistence::text,c.relispartition,"
            "c.relrowsecurity,c.relforcerowsecurity,c.reloptions "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
            "ORDER BY c.relname",
            (names,),
        ),
        (
            "column",
            "SELECT c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),"
            "a.attndims,a.attnotnull,pg_get_expr(d.adbin,d.adrelid,false),"
            "a.attidentity::text,a.attgenerated::text,coalesce(coll.collname,'') "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped "
            "LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
            "LEFT JOIN pg_collation coll ON coll.oid=nullif(a.attcollation,0) "
            "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
            "ORDER BY c.relname,a.attnum",
            (names,),
        ),
        (
            "constraint",
            "SELECT c.relname,con.conname,con.contype::text,"
            "pg_get_constraintdef(con.oid,false),con.conkey::text,"
            "coalesce(rn.nspname,''),coalesce(rr.relname,''),"
            "coalesce(con.confkey::text,''),con.confmatchtype::text,"
            "con.confupdtype::text,con.confdeltype::text,con.condeferrable,"
            "con.condeferred,con.convalidated FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_constraint con ON con.conrelid=c.oid "
            "LEFT JOIN pg_class rr ON rr.oid=con.confrelid "
            "LEFT JOIN pg_namespace rn ON rn.oid=rr.relnamespace "
            "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
            "ORDER BY c.relname,con.conname",
            (names,),
        ),
        (
            "index",
            "SELECT c.relname,idx.relname,i.indisunique,i.indisprimary,i.indisvalid,"
            "i.indisready,am.amname,i.indkey::text,i.indnkeyatts,i.indnatts,"
            "pg_get_expr(i.indexprs,i.indrelid,false),"
            "pg_get_expr(i.indpred,i.indrelid,false),pg_get_indexdef(i.indexrelid,0,false) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class idx ON idx.oid=i.indexrelid "
            "JOIN pg_am am ON am.oid=idx.relam "
            "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
            "ORDER BY c.relname,idx.relname",
            (names,),
        ),
        (
            "trigger",
            "SELECT c.relname,t.tgname,t.tgenabled::text,t.tgisinternal,"
            "pg_get_triggerdef(t.oid,false) FROM pg_trigger t "
            "JOIN pg_class c ON c.oid=t.tgrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=current_schema() AND NOT t.tgisinternal "
            "AND c.relname=ANY($1::text[]) ORDER BY c.relname,t.tgname",
            (names,),
        ),
        (
            "function",
            "SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),"
            "pg_get_function_result(p.oid),l.lanname,p.prosecdef,p.proleakproof,"
            "p.provolatile::text,p.proparallel::text,pg_get_functiondef(p.oid) "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "JOIN pg_language l ON l.oid=p.prolang "
            "WHERE n.nspname=current_schema() "
            "AND p.proname='execution_operation_receipt_immutable' "
            "ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)",
            (),
        ),
    )
    for kind, query, arguments in queries:
        for row in await connection.fetch(query, *arguments):
            facts.append((kind, *tuple(row)))
    absence = await connection.fetchrow(
        "SELECT (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND c.relname=ANY($1::text[])),"
        "(SELECT count(*) FROM pg_inherits h JOIN pg_class c ON c.oid=h.inhrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND c.relname=ANY($1::text[])),"
        "(SELECT count(*) FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND r.rulename<>'_RETURN' AND c.relname=ANY($1::text[]))",
        names,
    )
    gateway = await connection.fetchrow(
        "SELECT singleton_id,mode,catalog_digest,activation_revision,activation_at,revision "
        "FROM execution_gateway_state"
    )
    facts.append(("absence", *tuple(absence)))
    facts.append(("gateway", *tuple(gateway)))
    payload = json.dumps(facts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case_alias", "mutation"),
    _POSTGRES_LITERAL_DRIFT_CASES,
    ids=[case[0] for case in _POSTGRES_LITERAL_DRIFT_CASES],
)
async def test_postgres_runtime_validator_rejects_literal_catalog_drift(
    case_alias: str,
    mutation: str,
) -> None:
    del case_alias
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0010")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(
                harness.config,
                harness.database_name,
                ordinary_driver=True,
            )
        )
        try:
            await connection.execute(mutation)
            with pytest.raises(
                RuntimeError,
                match="Incompatible execution lifecycle schema",
            ):
                await validate_postgresql_lifecycle_catalog(connection)
        finally:
            await connection.close()


@pytest.mark.asyncio
async def test_postgres_head_0010_has_exact_lifecycle_relation_shape() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0010")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(
                harness.config,
                harness.database_name,
                ordinary_driver=True,
            )
        )
        try:
            revision = await connection.fetchval("SELECT version_num FROM alembic_version")
            rows = await connection.fetch(
                "SELECT c.relname,c.relkind::text,c.relpersistence::text,"
                "c.relispartition,c.relrowsecurity,c.relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
                "ORDER BY c.relname",
                list(_EXPECTED_LIFECYCLE_TABLES),
            )
            trigger_rows = await connection.fetch(
                "SELECT c.relname,t.tgname,t.tgenabled::text,t.tgisinternal,"
                "pg_get_triggerdef(t.oid,false) AS definition FROM pg_trigger t "
                "JOIN pg_class c ON c.oid=t.tgrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND NOT t.tgisinternal "
                "AND c.relname=ANY($1::text[]) ORDER BY c.relname,t.tgname",
                list(_EXPECTED_LIFECYCLE_TABLES),
            )
            function_rows = await connection.fetch(
                "SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS arguments,"
                "pg_get_function_result(p.oid) AS result,l.lanname,p.prosecdef,"
                "p.proleakproof,p.provolatile::text,p.proparallel::text,"
                "pg_get_functiondef(p.oid) AS definition FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid=p.pronamespace "
                "JOIN pg_language l ON l.oid=p.prolang "
                "WHERE n.nspname=current_schema() "
                "AND p.proname='execution_operation_receipt_immutable' "
                "ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)"
            )
            policy_count = await connection.fetchval(
                "SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[])",
                list(_EXPECTED_LIFECYCLE_TABLES),
            )
            logical_columns = await connection.fetch(
                "SELECT a.attname FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid=c.oid "
                "AND a.attnum>0 AND NOT a.attisdropped "
                "WHERE n.nspname=current_schema() AND c.relname='logical_executions' "
                "ORDER BY a.attnum"
            )
            receipt_columns = await connection.fetch(
                "SELECT a.attname FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid=c.oid "
                "AND a.attnum>0 AND NOT a.attisdropped "
                "WHERE n.nspname=current_schema() "
                "AND c.relname='execution_operation_receipts' ORDER BY a.attnum"
            )
            receipt_constraints = await connection.fetch(
                "SELECT con.conname,con.contype::text,pg_get_constraintdef(con.oid,false) "
                "AS definition FROM pg_constraint con "
                "JOIN pg_class c ON c.oid=con.conrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() "
                "AND c.relname='execution_operation_receipts' ORDER BY con.conname"
            )
        finally:
            await connection.close()
    assert revision == "0010", "PostgreSQL head changed"
    assert tuple(str(row["relname"]) for row in rows) == _EXPECTED_LIFECYCLE_TABLES, (
        "PostgreSQL lifecycle inventory changed"
    )
    assert all(
        tuple(
            row[key]
            for key in (
                "relkind",
                "relpersistence",
                "relispartition",
                "relrowsecurity",
                "relforcerowsecurity",
            )
        )
        == ("r", "p", False, False, False)
        for row in rows
    ), "PostgreSQL relation metadata changed"
    assert tuple(str(row["attname"]) for row in logical_columns) == (
        _P1B_LOGICAL_EXECUTION_COLUMNS
    ), "submission authority columns changed"
    assert tuple(str(row["attname"]) for row in receipt_columns) == _P1B_RECEIPT_COLUMNS, (
        "receipt-v2 column order changed"
    )
    assert tuple(
        (str(row["relname"]), str(row["tgname"]), str(row["tgenabled"]), row["tgisinternal"])
        for row in trigger_rows
    ) == (("execution_operation_receipts", "trg_eor_immutable", "O", False),), (
        "PostgreSQL receipt immutability trigger allowlist changed"
    )
    assert "BEFORE DELETE OR UPDATE" in str(trigger_rows[0]["definition"]), (
        "PostgreSQL receipt immutability trigger events changed"
    )
    assert "EXECUTE FUNCTION execution_operation_receipt_immutable()" in str(
        trigger_rows[0]["definition"]
    ), "PostgreSQL receipt immutability trigger function changed"
    assert tuple(
        (
            str(row["proname"]),
            str(row["arguments"]),
            str(row["result"]),
            str(row["lanname"]),
            row["prosecdef"],
            row["proleakproof"],
            str(row["provolatile"]),
            str(row["proparallel"]),
        )
        for row in function_rows
    ) == (
        (
            "execution_operation_receipt_immutable",
            "",
            "trigger",
            "plpgsql",
            False,
            False,
            "v",
            "u",
        ),
    ), "PostgreSQL receipt immutability function allowlist changed"
    assert "immutable execution operation receipt" in str(function_rows[0]["definition"]), (
        "PostgreSQL receipt immutability error changed"
    )
    assert "55000" in str(function_rows[0]["definition"]), (
        "PostgreSQL receipt immutability SQLSTATE changed"
    )
    constraint_definitions = {
        str(row["conname"]): (str(row["contype"]), str(row["definition"]))
        for row in receipt_constraints
    }
    assert constraint_definitions["ck_eor_contract"][0] == "c", (
        "receipt-v2 contract constraint type changed"
    )
    assert "binding_contract_version = 2" in constraint_definitions["ck_eor_contract"][1], (
        "receipt-v2 contract check changed"
    )
    assert "ck_eor_principal_shape" in constraint_definitions, (
        "receipt principal-shape check missing"
    )
    assert "ck_eor_presence" in constraint_definitions, "receipt presence-bit check missing"
    assert "ck_eor_operation_shape" in constraint_definitions, (
        "receipt operation-specific revision-presence check missing"
    )
    assert "ck_eor_outbox_owner_shape" in constraint_definitions, (
        "receipt outbox owner/generation check missing"
    )
    assert not any(kind == "f" for kind, _definition in constraint_definitions.values()), (
        "historical receipts gained a target foreign key"
    )
    assert int(policy_count) == 0, "PostgreSQL lifecycle policy object appeared"


@pytest.mark.asyncio
async def test_postgres_empty_database_upgrades_through_exact_head_0011() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "head")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(
                harness.config,
                harness.database_name,
                ordinary_driver=True,
            )
        )
        try:
            revision = await connection.fetchval("SELECT version_num FROM alembic_version")
            tables = {
                str(row["table_name"])
                for row in await connection.fetch(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema=current_schema() AND table_type='BASE TABLE'"
                )
            }
            gateway = await connection.fetch("SELECT mode,revision FROM execution_gateway_state")
            await validate_postgresql_lifecycle_catalog(connection)
            await validate_postgresql_admission_authority_catalog(connection)
        finally:
            await connection.close()
        assert revision == "0011", "PostgreSQL migration head changed"
        assert set(_EXPECTED_LIFECYCLE_TABLES).issubset(tables), "lifecycle tables missing"
        assert set(V11_AUTHORITY_TABLES).issubset(tables), "admission-authority tables missing"
        assert [tuple(row.values()) for row in gateway] == [("disabled", 0)], (
            "gateway was enabled by migration"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("_case", ["empty", "v2-populated"], ids=("empty", "v2-populated"))
async def test_postgres_revision_0011_upgrades_supported_0010_catalog(_case: str) -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0010")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        actor_id = "00000000-0000-4000-8000-000000001201"
        campaign_id = "00000000-0000-4000-8000-000000001202"
        try:
            if _case == "v2-populated":
                async with connection.transaction():
                    await connection.execute(
                        "INSERT INTO users(id,username,hashed_password,role,created_by) "
                        "VALUES($1,$2,$3,$4,$5)",
                        actor_id,
                        "migration-owner",
                        "fixed",
                        "admin",
                        "fixed",
                    )
                    await connection.execute(
                        "INSERT INTO campaigns(id,name,operator,scope_json,targets_json) "
                        "VALUES($1,$2,$3,$4,$5)",
                        campaign_id,
                        "migration-campaign",
                        "migration-owner",
                        '[{"cidr":"10.12.0.0/24"}]',
                        '["Host.Example."]',
                    )
                    await connection.execute(
                        "INSERT INTO execution_actor_authority_revisions("
                        "user_id,latest_operation_id,latest_operation_code) "
                        "VALUES($1,$2,'ensure')",
                        actor_id,
                        "00000000-0000-4000-8000-000000001203",
                    )
                    await connection.execute(
                        "INSERT INTO campaign_execution_authority_revisions("
                        "campaign_id,latest_operation_id,latest_operation_code) "
                        "VALUES($1,$2,'ensure')",
                        campaign_id,
                        "00000000-0000-4000-8000-000000001204",
                    )
                    await connection.execute(
                        "INSERT INTO credentials(id,campaign_id,username,cred_type,source_module) "
                        "VALUES($1,$2,$3,$4,$5)",
                        "00000000-0000-4000-8000-000000001205",
                        campaign_id,
                        "opaque-user",
                        "cleartext",
                        "migration-fixture",
                    )
        finally:
            await connection.close()

        await _alembic(harness, "upgrade", "0011")
        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            await validate_postgresql_admission_authority_catalog(connection)
            revision = await connection.fetchval("SELECT version_num FROM alembic_version")
            observed_counts: list[int] = []
            for table in V11_AUTHORITY_TABLES:
                observed_counts.append(
                    int(
                        await connection.fetchval(
                            f"SELECT count(*) FROM {table}"  # noqa: S608 - frozen table tuple.
                        )
                    )
                )
            counts = tuple(observed_counts)
            if _case == "v2-populated":
                grant = await connection.fetchrow(
                    "SELECT authority_state,revision FROM campaign_execution_actor_grants "
                    "WHERE campaign_id=$1 AND actor_user_id=$2",
                    campaign_id,
                    actor_id,
                )
                destination = await connection.fetchrow(
                    "SELECT authority_state,revision,normalization_version,destination_count "
                    "FROM campaign_execution_destination_authorities WHERE campaign_id=$1",
                    campaign_id,
                )
                credential = await connection.fetchrow(
                    "SELECT execution_authority_state,execution_authority_revision,"
                    "execution_authority_binding_digest FROM credentials WHERE campaign_id=$1",
                    campaign_id,
                )
        finally:
            await connection.close()
        assert revision == "0011", "supported PostgreSQL upgrade missed revision 0011"
        if _case == "empty":
            assert counts == (0,) * len(V11_AUTHORITY_TABLES), (
                "empty PostgreSQL upgrade fabricated authority"
            )
        else:
            assert counts == (1, 1, 0, 0, 0), "PostgreSQL v2 backfill cardinality changed"
            assert tuple(grant.values()) == ("active", 0), "compatibility grant changed"
            assert tuple(destination.values()) == ("active", 0, 1, 2), (
                "destination backfill changed"
            )
            assert tuple(credential.values())[:2] == ("active", 0), (
                "credential authority backfill changed"
            )
            assert len(str(tuple(credential.values())[2])) == 64, "credential binding changed"


@pytest.mark.asyncio
async def test_postgres_revision_0011_downgrade_refuses_before_mutation() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "head")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            async with connection.transaction():
                await connection.execute(
                    "INSERT INTO users(id,username,hashed_password,role,created_by) "
                    "VALUES($1,$2,$3,$4,$5)",
                    "00000000-0000-4000-8000-000000001211",
                    "downgrade-owner",
                    "fixed",
                    "admin",
                    "fixed",
                )
                await connection.execute(
                    "INSERT INTO execution_actor_authority_revisions("
                    "user_id,latest_operation_id,latest_operation_code,authority_revision) "
                    "VALUES($1,$2,'ensure',1)",
                    "00000000-0000-4000-8000-000000001211",
                    "00000000-0000-4000-8000-000000001212",
                )
            before = tuple(
                tuple(row.values())
                for row in await connection.fetch(
                    "SELECT table_name,column_name,ordinal_position,data_type,is_nullable "
                    "FROM information_schema.columns WHERE table_schema=current_schema() "
                    "ORDER BY table_name,ordinal_position"
                )
            )
        finally:
            await connection.close()
        with pytest.raises(RuntimeError):
            await _alembic(harness, "downgrade", "0010")
        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            after = tuple(
                tuple(row.values())
                for row in await connection.fetch(
                    "SELECT table_name,column_name,ordinal_position,data_type,is_nullable "
                    "FROM information_schema.columns WHERE table_schema=current_schema() "
                    "ORDER BY table_name,ordinal_position"
                )
            )
            revision = await connection.fetchval("SELECT version_num FROM alembic_version")
            await validate_postgresql_admission_authority_catalog(connection)
        finally:
            await connection.close()
        assert before == after, "PostgreSQL downgrade refusal mutated catalog"
        assert revision == "0011", "PostgreSQL downgrade refusal changed revision"


@pytest.mark.asyncio
async def test_postgres_revision_0011_failed_upgrade_rolls_back_and_retry_succeeds() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0010")
        with pytest.raises(RuntimeError):
            await _alembic(
                harness,
                "upgrade",
                "0011",
                fault="0011-after-authority-ddl",
            )
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            revision_after_failure = await connection.fetchval(
                "SELECT version_num FROM alembic_version"
            )
            tables_after_failure = {
                str(row["table_name"])
                for row in await connection.fetch(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema=current_schema() AND table_type='BASE TABLE'"
                )
            }
            await validate_postgresql_lifecycle_catalog(connection)
        finally:
            await connection.close()
        assert revision_after_failure == "0010", "failed PostgreSQL upgrade advanced revision"
        assert set(V11_AUTHORITY_TABLES).isdisjoint(tables_after_failure), (
            "failed PostgreSQL upgrade left generation-11 relations"
        )

        await _alembic(harness, "upgrade", "0011", timeout=60.0)
        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            revision = await connection.fetchval("SELECT version_num FROM alembic_version")
            await validate_postgresql_admission_authority_catalog(connection)
        finally:
            await connection.close()
        assert revision == "0011", "PostgreSQL retry did not reach revision 0011"


@pytest.mark.asyncio
async def test_postgres_catalog_matches_independent_literal_fingerprint() -> None:
    async with _postgres_harness() as harness:
        await _alembic(harness, "upgrade", "0010")
        import asyncpg

        connection = await asyncpg.connect(
            _migration_url(harness.config, harness.database_name, ordinary_driver=True)
        )
        try:
            observed = await _independent_postgres_catalog_fingerprint(connection)
            index_row = await connection.fetchrow(
                "SELECT base.relname,idx.relname,am.amname,i.indisunique,i.indisprimary,"
                "i.indisvalid,i.indisready,i.indnkeyatts,i.indnatts,a.attname,"
                "opc_ns.nspname||'.'||opc.opcname,coll_ns.nspname||'.'||coll.collname,"
                "i.indoption::text,pg_get_expr(i.indexprs,i.indrelid,false),"
                "pg_get_expr(i.indpred,i.indrelid,false) FROM pg_index i "
                "JOIN pg_class idx ON idx.oid=i.indexrelid "
                "JOIN pg_class base ON base.oid=i.indrelid "
                "JOIN pg_namespace ns ON ns.oid=idx.relnamespace "
                "JOIN pg_am am ON am.oid=idx.relam "
                "JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=i.indkey[0] "
                "JOIN pg_opclass opc ON opc.oid=i.indclass[0] "
                "JOIN pg_namespace opc_ns ON opc_ns.oid=opc.opcnamespace "
                "JOIN pg_collation coll ON coll.oid=i.indcollation[0] "
                "JOIN pg_namespace coll_ns ON coll_ns.oid=coll.collnamespace "
                "WHERE ns.nspname=current_schema() AND idx.relname='ix_eol_attempt'"
            )
        finally:
            await connection.close()
    assert observed == _POSTGRES_LITERAL_ORACLE_FINGERPRINT_V1, (
        "PostgreSQL whole-catalog fingerprint changed"
    )
    assert tuple(index_row) == (
        "execution_output_links",
        "ix_eol_attempt",
        "btree",
        False,
        False,
        True,
        True,
        1,
        1,
        "attempt_id",
        "pg_catalog.text_ops",
        "pg_catalog.default",
        "0",
        None,
        None,
    ), "operational attempt index changed"


def test_postgres_cyclic_foreign_key_is_added_after_attempt_candidate_key() -> None:
    logical_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("CREATE TABLE logical_executions")
    )
    attempt_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("CREATE TABLE execution_attempts")
    )
    closing_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("ALTER TABLE logical_executions ADD CONSTRAINT")
    )
    assert (logical_index, attempt_index, closing_index) == (0, 1, 2), (
        "PostgreSQL cyclic foreign-key order changed"
    )
    assert "DEFERRABLE INITIALLY DEFERRED" in POSTGRES_LIFECYCLE_DDL[closing_index], (
        "closing foreign key lost deferral"
    )


def test_postgres_receipt_immutability_ddl_follows_receipt_relation() -> None:
    receipt_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("CREATE TABLE execution_operation_receipts")
    )
    function_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("CREATE FUNCTION execution_operation_receipt_immutable()")
    )
    trigger_index = next(
        index
        for index, statement in enumerate(POSTGRES_LIFECYCLE_DDL)
        if statement.startswith("CREATE TRIGGER trg_eor_immutable")
    )
    assert receipt_index < function_index < trigger_index, (
        "receipt immutability DDL dependency order changed"
    )
    assert "ERRCODE='55000'" in POSTGRES_LIFECYCLE_DDL[function_index], (
        "receipt immutability SQLSTATE changed"
    )
    assert "BEFORE UPDATE OR DELETE" in POSTGRES_LIFECYCLE_DDL[trigger_index], (
        "receipt immutability trigger events changed"
    )
