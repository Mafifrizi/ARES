"""Add the authoritative execution-lifecycle persistence catalog.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

import re
from importlib import import_module
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_PREVIOUS = import_module("migrations.versions.0009_refresh_token_families")
classify_unversioned_catalog = _PREVIOUS.classify_unversioned_catalog
_require_sqlite_alembic_version_relation = _PREVIOUS._require_sqlite_alembic_version_relation
_pg_validate_alembic_version_relation = _PREVIOUS._pg_validate_alembic_version_relation

_LIFECYCLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "logical_executions": (
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
    ),
    "execution_attempts": (
        "id",
        "logical_execution_id",
        "campaign_id",
        "ordinal",
        "parent_attempt_id",
        "revision",
        "state",
        "closes_logical",
        "actor_subject_ref",
        "actor_user_id",
        "actor_authority_revision",
        "campaign_authority_revision",
        "destination_authority_revision",
        "credential_authority_revision",
        "request_contract_version",
        "evaluation_mode",
        "request_structure_valid",
        "canonicalization_complete",
        "unknown_fields_absent",
        "alternate_transport_absent",
        "bounded_shape_valid",
        "request_shape_units",
        "descriptor_contract_version",
        "descriptor_semantic_digest",
        "catalog_digest",
        "trusted_first_party_binding",
        "descriptor_binding_current",
        "descriptor_complete",
        "static_policy_evaluable",
        "minimum_role",
        "noise_class",
        "approval_policy",
        "capability_mask_version",
        "required_capability_mask",
        "descriptor_blocker_mask_version",
        "descriptor_blocker_mask",
        "preview_ready",
        "lifecycle_ready",
        "result_authority_ready",
        "transport_ready",
        "future_gateway_eligible",
        "authority_snapshots_complete",
        "authority_revisions_current",
        "actor_authenticated",
        "actor_active",
        "actor_role",
        "campaign_active",
        "actor_campaign_authorized",
        "approval_present",
        "approval_current",
        "approval_exactly_bound",
        "granted_capability_mask",
        "destination_extraction_complete",
        "destinations_in_scope",
        "credential_authority_resolved",
        "credential_authority_current",
        "opaque_handles_only",
        "permitted_handle_kinds_only",
        "raw_credentials_absent",
        "ambient_credentials_absent",
        "budget_authority_resolved",
        "budget_authority_current",
        "budget_capacity_available",
        "gateway_mode_snapshot",
        "gateway_decision_code",
        "policy_evaluation_state",
        "policy_contract_version",
        "policy_verdict",
        "policy_reason_mask_version",
        "policy_reason_mask",
        "external_effect_class",
        "idempotency_class",
        "retry_policy",
        "retry_disposition",
        "cancellation_ownership",
        "compensation_class",
        "timeout_origin",
        "timeout_limit_ms",
        "timeout_settlement",
        "outcome_code",
        "error_action_code",
        "settlement_state",
        "settlement_proof_code",
        "termination_confirmed",
        "dispatch_owner_ref",
        "lease_generation",
        "dispatch_lease_duration_ms",
        "lease_expires_at",
        "lease_invalidated_at",
        "queue_operation_id",
        "dispatch_operation_id",
        "start_operation_id",
        "cancellation_request_operation_id",
        "cancellation_request_revision",
        "cancellation_ack_operation_id",
        "timeout_operation_id",
        "settlement_pending_operation_id",
        "terminal_operation_id",
        "resolver_subject_ref",
        "resolver_user_id",
        "resolver_authority_revision",
        "bounded_recovery_proof_code",
        "created_at",
        "accepted_at",
        "queued_at",
        "dispatching_at",
        "started_at",
        "cancellation_requested_at",
        "cancellation_acknowledged_at",
        "timeout_observed_at",
        "settlement_pending_at",
        "recovery_deadline_at",
        "retry_child_bound_at",
        "finished_at",
        "settled_at",
    ),
    "execution_actor_authority_revisions": (
        "user_id",
        "revision",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "updated_at",
    ),
    "campaign_execution_authority_revisions": (
        "campaign_id",
        "revision",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "updated_at",
    ),
    "campaign_execution_budgets": (
        "id",
        "campaign_id",
        "budget_kind",
        "capacity_units",
        "reserved_units",
        "consumed_units",
        "revision",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "created_at",
        "updated_at",
    ),
    "execution_attempt_approvals": (
        "id",
        "attempt_id",
        "campaign_id",
        "approval_ref",
        "approver_subject_ref",
        "approver_user_id",
        "authority_revision",
        "binding_digest",
        "bound_at",
    ),
    "campaign_execution_budget_ledger": (
        "id",
        "attempt_id",
        "campaign_id",
        "budget_id",
        "budget_kind",
        "reservation_units",
        "consumed_units",
        "disposition",
        "budget_revision_reserved",
        "budget_revision_settled",
        "reserved_at",
        "settled_at",
    ),
    "execution_output_links": (
        "id",
        "attempt_id",
        "campaign_id",
        "finding_id",
        "credential_id",
        "host_id",
        "loot_id",
        "created_at",
    ),
    "execution_publication_outbox": (
        "id",
        "publication_key",
        "attempt_id",
        "campaign_id",
        "event_code",
        "is_attempt_terminal",
        "finding_count",
        "credential_count",
        "host_count",
        "artifact_count",
        "publication_state",
        "delivery_attempt_count",
        "available_at",
        "claim_owner_ref",
        "lease_generation",
        "claimed_at",
        "lease_expires_at",
        "published_at",
        "poisoned_at",
        "failure_code",
        "claim_revision",
        "latest_operation_id",
        "latest_operation_code",
        "latest_operation_base_revision",
        "created_at",
    ),
    "execution_operation_receipts": (
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
    ),
    "execution_gateway_state": (
        "singleton_id",
        "mode",
        "catalog_digest",
        "activation_revision",
        "activation_at",
        "revision",
        "updated_at",
    ),
}


def _ddl_object_names(
    postgres_ddl: tuple[str, ...], lifecycle_tables: tuple[str, ...]
) -> tuple[frozenset[str], frozenset[str]]:
    constraints: set[str] = set()
    indexes: set[str] = set()
    for statement in postgres_ddl:
        table_match = re.match(r"CREATE TABLE ([a-z0-9_]+)", statement)
        alter_match = re.match(r"ALTER TABLE ([a-z0-9_]+)", statement)
        relation = (
            table_match.group(1)
            if table_match is not None
            else alter_match.group(1)
            if alter_match is not None
            else None
        )
        if relation in lifecycle_tables:
            constraints.update(re.findall(r"\bCONSTRAINT ([a-z0-9_]+)\b", statement))
        match = re.match(
            r"CREATE (?:UNIQUE )?INDEX ([a-z0-9_]+) ON ([a-z0-9_]+)",
            statement,
        )
        if match is not None and match.group(2) in lifecycle_tables:
            indexes.add(match.group(1))
    indexes.update(name for name in constraints if name.startswith(("pk_", "uq_")))
    return frozenset(constraints), frozenset(indexes)


_BASE_CANDIDATE_INDEXES = frozenset(
    {
        "uq_findings_campaign_id_id",
        "uq_credentials_campaign_id_id",
        "uq_hosts_campaign_id_id",
        "uq_loot_campaign_id_id",
    }
)

_LIFECYCLE_CONTRACT: (
    tuple[
        tuple[str, ...],
        tuple[str, ...],
        tuple[str, ...],
        Any,
        frozenset[str],
        frozenset[str],
    ]
    | None
) = None


def _lifecycle_contract() -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    Any,
    frozenset[str],
    frozenset[str],
]:
    global _LIFECYCLE_CONTRACT
    if _LIFECYCLE_CONTRACT is None:
        lifecycle = import_module("ares.db.execution_lifecycle")
        lifecycle_tables = tuple(lifecycle.LIFECYCLE_TABLES)
        postgres_ddl = tuple(lifecycle.POSTGRES_LIFECYCLE_DDL)
        constraint_names, index_names = _ddl_object_names(postgres_ddl, lifecycle_tables)
        _LIFECYCLE_CONTRACT = (
            lifecycle_tables,
            tuple(lifecycle.SQLITE_LIFECYCLE_DDL),
            postgres_ddl,
            lifecycle.validate_sqlite_lifecycle_catalog_rows,
            constraint_names,
            index_names,
        )
    return _LIFECYCLE_CONTRACT


def _fail() -> None:
    raise RuntimeError("revision-0010 preflight failed")


def _dialect() -> str:
    dialect = op.get_bind().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        _fail()
    return dialect


def _column_names(inspector: Any, table: str) -> tuple[str, ...]:
    return tuple(str(item["name"]) for item in inspector.get_columns(table))


def _preflight() -> str:
    bind = op.get_bind()
    dialect = _dialect()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    lifecycle_tables, _, _, _, _, _ = _lifecycle_contract()
    if any(table in existing for table in lifecycle_tables):
        _fail()
    if not {"users", "campaigns", "findings", "credentials", "hosts", "loot"}.issubset(existing):
        _fail()
    return dialect


def verify_managed_catalog(connection: Any) -> None:
    """Fail closed unless the connection exposes the exact lifecycle columns."""
    (
        lifecycle_tables,
        _,
        _,
        validate_sqlite_lifecycle_catalog_rows,
        lifecycle_constraint_names,
        lifecycle_index_names,
    ) = _lifecycle_contract()
    inspector = sa.inspect(connection)
    tables = set(inspector.get_table_names())
    if not set(lifecycle_tables).issubset(tables):
        _fail()
    for table, expected in _LIFECYCLE_COLUMNS.items():
        if _column_names(inspector, table) != expected:
            _fail()
    gateway = connection.execute(
        sa.text(
            "SELECT mode,revision,catalog_digest,activation_revision,activation_at "
            "FROM execution_gateway_state WHERE singleton_id=1"
        )
    ).fetchone()
    if gateway is None or tuple(gateway) != ("disabled", 0, None, None, None):
        _fail()
    dialect = connection.dialect.name
    if dialect == "sqlite":
        catalog_rows = connection.execute(
            sa.text(
                "SELECT type,name,sql FROM sqlite_schema "
                "WHERE sql IS NOT NULL AND ("
                "name IN :expected_names OR tbl_name IN :lifecycle_tables) "
                "ORDER BY type,name"
            ).bindparams(
                sa.bindparam(
                    "expected_names",
                    value=tuple(
                        lifecycle_index_names | _BASE_CANDIDATE_INDEXES | set(lifecycle_tables)
                    ),
                    expanding=True,
                ),
                sa.bindparam("lifecycle_tables", value=lifecycle_tables, expanding=True),
            )
        ).fetchall()
        validate_sqlite_lifecycle_catalog_rows(catalog_rows)
    if dialect == "postgresql":
        constraint_rows = connection.execute(
            sa.text(
                "SELECT con.conname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid=con.conrelid "
                "JOIN pg_namespace n ON n.oid=rel.relnamespace "
                "WHERE n.nspname=current_schema() "
                "AND rel.relname = ANY(:names) ORDER BY con.conname"
            ),
            {"names": list(lifecycle_tables)},
        ).fetchall()
        if frozenset(str(row[0]) for row in constraint_rows) != lifecycle_constraint_names:
            _fail()
        index_rows = connection.execute(
            sa.text(
                "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() "
                "AND tablename = ANY(:names) ORDER BY indexname"
            ),
            {"names": list(lifecycle_tables)},
        ).fetchall()
        if frozenset(str(row[0]) for row in index_rows) != lifecycle_index_names:
            _fail()
        base_index_rows = connection.execute(
            sa.text(
                "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() "
                "AND indexname = ANY(:names) ORDER BY indexname"
            ),
            {"names": list(_BASE_CANDIDATE_INDEXES)},
        ).fetchall()
        if frozenset(str(row[0]) for row in base_index_rows) != _BASE_CANDIDATE_INDEXES:
            _fail()
        relation_rows = connection.execute(
            sa.text(
                "SELECT c.relkind::text,c.relpersistence::text,c.relispartition,"
                "c.relrowsecurity,c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=current_schema() AND c.relname=ANY(:names)"
            ),
            {"names": list(lifecycle_tables)},
        ).fetchall()
        if len(relation_rows) != len(lifecycle_tables) or any(
            tuple(row) != ("r", "p", False, False, False) for row in relation_rows
        ):
            _fail()
        trigger_rows = connection.execute(
            sa.text(
                "SELECT c.relname,t.tgname FROM pg_trigger t "
                "JOIN pg_class c ON c.oid=t.tgrelid "
                "WHERE NOT t.tgisinternal AND c.relname = ANY(:names) "
                "ORDER BY c.relname,t.tgname"
            ),
            {"names": list(lifecycle_tables)},
        ).fetchall()
        if tuple(tuple(row) for row in trigger_rows) != (
            ("execution_operation_receipts", "trg_eor_immutable"),
        ):
            _fail()
        policy_exists = connection.execute(
            sa.text(
                "SELECT EXISTS (SELECT 1 FROM pg_policy p "
                "JOIN pg_class c ON c.oid=p.polrelid "
                "WHERE c.relname = ANY(:names))"
            ),
            {"names": list(lifecycle_tables)},
        ).scalar_one()
        if policy_exists:
            _fail()
        lifecycle = import_module("ares.db.execution_lifecycle")
        if not lifecycle._POSTGRES_CATALOG_FINGERPRINT_V1:
            _fail()
        facts_sql = lifecycle._POSTGRES_CATALOG_FACTS_SQL.replace(
            "__NAMES__", "CAST(:lifecycle_names AS text[])"
        ).replace("__BASE_NAMES__", "CAST(:base_names AS text[])")
        fact_rows = connection.execute(
            sa.text(facts_sql),
            {
                "lifecycle_names": list(lifecycle_tables),
                "base_names": list(_BASE_CANDIDATE_INDEXES),
            },
        ).fetchall()
        if (
            lifecycle.postgresql_catalog_fingerprint(tuple(str(row[0]) for row in fact_rows))
            != lifecycle._POSTGRES_CATALOG_FINGERPRINT_V1
        ):
            _fail()


def upgrade() -> None:
    dialect = _preflight()
    _, sqlite_ddl, postgres_ddl, _, _, _ = _lifecycle_contract()
    statements = sqlite_ddl if dialect == "sqlite" else postgres_ddl
    bind = op.get_bind()
    for statement in statements:
        bind.execute(sa.text(statement))
    verify_managed_catalog(bind)


def downgrade() -> None:
    raise RuntimeError("revision-0010 downgrade is not supported")
