# ruff: noqa: E501, S608
"""Authoritative revision-0010 execution-lifecycle persistence primitives.

This module is additive and has no live execution consumer.  It owns the exact
SQLite/PostgreSQL lifecycle catalog, fixed persistence enums, sanitized CAS
results, and internal stores used by migration and persistence tests.  It never
accepts raw module parameters, destinations, credentials, evidence, exception
text, URLs, or DSNs.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import struct
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Final

RUNTIME_GENERATION: Final = 10
LEGACY_SCHEMA_VERSION: Final = 9
REQUEST_CONTRACT_VERSION: Final = 1
POLICY_CONTRACT_VERSION: Final = 1
DESCRIPTOR_CONTRACT_VERSION: Final = "ares.module-descriptor.v2"
MASK_VERSION: Final = 1
MAX_I53: Final = 9_007_199_254_740_991
MIN_TIMEOUT_MS: Final = 1_000
MAX_TIMEOUT_MS: Final = 86_400_000
RECOVERY_WINDOW_MS: Final = 86_400_000
OUTBOX_LEASE_MS: Final = 60_000
SYSTEM_PRINCIPAL_SUBJECT_REF: Final = "004cb934-3a47-4cd0-b0cb-a5b18df76a48"
PRINCIPAL_KINDS: Final[tuple[str, ...]] = ("actor", "resolver", "worker", "system")


LIFECYCLE_LOCK_ORDER = (
    "transaction_key",
    "gateway",
    "authority",
    "logical_execution",
    "attempt",
    "approval",
    "budget",
    "ledger",
    "output_target",
    "output_link",
    "outbox",
    "operation_receipt",
)


class AttemptState(str, Enum):
    REJECTED = "rejected"
    BLOCKED = "blocked"
    ACCEPTED = "accepted"
    QUEUED = "queued"
    DISPATCHING = "dispatching"
    RUNNING = "running"
    CANCELLING = "cancelling"
    SETTLEMENT_PENDING = "settlement_pending"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    INDETERMINATE = "indeterminate"


class OutcomeCode(str, Enum):
    POLICY_REJECTED = "policy_rejected"
    POLICY_BLOCKED = "policy_blocked"
    CONFIRMED_SUCCESS = "confirmed_success"
    CONFIRMED_PARTIAL = "confirmed_partial"
    ORCHESTRATION_SKIPPED = "orchestration_skipped"
    CONFIRMED_CANCELLED_NO_RESULT = "confirmed_cancelled_no_result"
    CONFIRMED_TIMEOUT_TERMINATED = "confirmed_timeout_terminated"
    UNKNOWN_AFTER_RECOVERY = "unknown_after_recovery"
    CONFIRMED_FAILURE_NO_DISPATCH = "confirmed_failure_no_dispatch"
    CONFIRMED_FAILURE = "confirmed_failure"


class FixedResult(str, Enum):
    APPLIED = "applied"
    REPLAYED = "replayed"
    REPLAYED_BOUND_CHILD = "replayed_bound_child"
    REPLAYED_CLOSED = "replayed_closed"
    SUPERSEDED = "superseded"
    NOT_FOUND_OR_PURGED = "not_found_or_purged"
    ALREADY_EXISTS = "already_exists"
    ALREADY_CLOSED = "already_closed"
    RETRY_AUTHORITY_UNRESOLVED = "retry_authority_unresolved"
    AUTHORITY_STALE = "authority_stale"
    CAPACITY_UNAVAILABLE = "capacity_unavailable"
    INCONSISTENT_BUDGET_SET = "inconsistent_budget_set"
    CONFLICT_STATE = "conflict_state"
    CONFLICT_REVISION = "conflict_revision"
    CONFLICT_OWNER = "conflict_owner"
    CONFLICT_GENERATION = "conflict_generation"
    CONFLICT_OPERATION = "conflict_operation"
    INVALID_CONTRACT = "invalid_contract"
    INVARIANT_FAILURE = "invariant_failure"


class PolicyReasonBit(IntEnum):
    INVALID_CONTRACT = 1
    INCONSISTENT_CONTRACT = 2
    INVALID_REQUEST = 4
    DESCRIPTOR_UNTRUSTED = 8
    DESCRIPTOR_BINDING_INVALID = 16
    DESCRIPTOR_INCOMPLETE = 32
    STATIC_POLICY_UNAVAILABLE = 64
    AUTHORITY_RESOLUTION_REQUIRED = 128
    STALE_AUTHORITY = 256
    ACTOR_UNAUTHENTICATED = 512
    ACTOR_INACTIVE = 1_024
    CAMPAIGN_INACTIVE = 2_048
    CAMPAIGN_UNAUTHORIZED = 4_096
    INSUFFICIENT_ROLE = 8_192
    HIGH_NOISE_ROLE_REQUIRED = 16_384
    APPROVAL_REQUIRED = 32_768
    APPROVAL_STALE = 65_536
    APPROVAL_BINDING_INVALID = 131_072
    CAPABILITY_REQUIRED = 262_144
    DESTINATION_RESOLUTION_REQUIRED = 524_288
    DESTINATION_OUT_OF_SCOPE = 1_048_576
    CREDENTIAL_AUTHORITY_REQUIRED = 2_097_152
    CREDENTIAL_AUTHORITY_STALE = 4_194_304
    RAW_CREDENTIAL_FORBIDDEN = 8_388_608
    AMBIENT_CREDENTIAL_FORBIDDEN = 16_777_216
    CREDENTIAL_HANDLE_POLICY_VIOLATION = 33_554_432
    BUDGET_AUTHORITY_REQUIRED = 67_108_864
    BUDGET_AUTHORITY_STALE = 134_217_728
    BUDGET_CAPACITY_UNAVAILABLE = 268_435_456
    DESCRIPTOR_BLOCKED = 536_870_912
    PREVIEW_NOT_READY = 1_073_741_824
    LIFECYCLE_NOT_READY = 2_147_483_648
    RESULT_AUTHORITY_NOT_READY = 4_294_967_296
    TRANSPORT_NOT_READY = 8_589_934_592
    FUTURE_GATEWAY_INELIGIBLE = 17_179_869_184


CAPABILITY_BITS_V1: Final[dict[str, int]] = {
    "network": 1,
    "execution": 2,
    "filesystem": 4,
    "process": 8,
}
DESCRIPTOR_BLOCKER_BITS_V1: Final[dict[str, int]] = {
    "ambient_credentials_forbidden": 1,
    "cancellation_ownership_unproven": 2,
    "dynamic_destination_unbounded": 4,
    "default_factory_unevaluated": 8,
    "llm_egress_policy_required": 16,
    "lifecycle_contract_unproven": 32,
    "raw_credential_input": 64,
    "result_authority_unproven": 128,
    "sensitive_nonempty_default": 256,
}

LEGAL_TRANSITIONS: Final[frozenset[tuple[AttemptState, AttemptState]]] = frozenset(
    {
        (AttemptState.ACCEPTED, AttemptState.QUEUED),
        (AttemptState.ACCEPTED, AttemptState.DISPATCHING),
        (AttemptState.ACCEPTED, AttemptState.CANCELLING),
        (AttemptState.ACCEPTED, AttemptState.SKIPPED),
        (AttemptState.ACCEPTED, AttemptState.FAILED),
        (AttemptState.QUEUED, AttemptState.DISPATCHING),
        (AttemptState.QUEUED, AttemptState.CANCELLING),
        (AttemptState.QUEUED, AttemptState.SKIPPED),
        (AttemptState.QUEUED, AttemptState.FAILED),
        (AttemptState.DISPATCHING, AttemptState.RUNNING),
        (AttemptState.DISPATCHING, AttemptState.CANCELLING),
        (AttemptState.DISPATCHING, AttemptState.FAILED),
        (AttemptState.DISPATCHING, AttemptState.SETTLEMENT_PENDING),
        (AttemptState.RUNNING, AttemptState.CANCELLING),
        (AttemptState.RUNNING, AttemptState.SUCCEEDED),
        (AttemptState.RUNNING, AttemptState.PARTIAL),
        (AttemptState.RUNNING, AttemptState.FAILED),
        (AttemptState.RUNNING, AttemptState.TIMED_OUT),
        (AttemptState.RUNNING, AttemptState.SETTLEMENT_PENDING),
        (AttemptState.CANCELLING, AttemptState.SUCCEEDED),
        (AttemptState.CANCELLING, AttemptState.PARTIAL),
        (AttemptState.CANCELLING, AttemptState.FAILED),
        (AttemptState.CANCELLING, AttemptState.CANCELLED),
        (AttemptState.CANCELLING, AttemptState.TIMED_OUT),
        (AttemptState.CANCELLING, AttemptState.SETTLEMENT_PENDING),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.SUCCEEDED),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.PARTIAL),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.FAILED),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.CANCELLED),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.TIMED_OUT),
        (AttemptState.SETTLEMENT_PENDING, AttemptState.INDETERMINATE),
    }
)

LIFECYCLE_TABLES: Final[tuple[str, ...]] = (
    "logical_executions",
    "execution_attempts",
    "execution_actor_authority_revisions",
    "campaign_execution_authority_revisions",
    "campaign_execution_budgets",
    "execution_attempt_approvals",
    "campaign_execution_budget_ledger",
    "execution_output_links",
    "execution_publication_outbox",
    "execution_operation_receipts",
    "execution_gateway_state",
)

OPERATION_CODES: Final[tuple[str, ...]] = (
    "actor_authority_ensure",
    "actor_authority_invalidate",
    "campaign_authority_ensure",
    "campaign_authority_invalidate",
    "budget_configure",
    "budget_reserve",
    "budget_settle",
    "admission",
    "retry",
    "queue",
    "dispatch",
    "start",
    "cancellation_request",
    "cancellation_acknowledgement",
    "timeout",
    "settlement_pending",
    "lease_loss",
    "recovery_succeeded",
    "recovery_partial",
    "recovery_failed",
    "recovery_cancelled",
    "recovery_timed_out",
    "recovery_indeterminate",
    "terminal_succeeded",
    "terminal_partial",
    "terminal_failed",
    "terminal_skipped",
    "close_without_retry",
    "outbox_insert",
    "outbox_claim",
    "outbox_reclaim",
    "outbox_renew",
    "outbox_publish",
    "outbox_retryable_failure",
    "outbox_nonretryable_failure",
    "outbox_poison",
    "outbox_purge",
    "campaign_delete",
)

_RECEIPT_NO_EXPECTED_REVISION_CODES: Final[frozenset[str]] = frozenset(
    {
        "actor_authority_ensure",
        "campaign_authority_ensure",
        "budget_configure",
        "admission",
        "outbox_insert",
        "campaign_delete",
    }
)
_RECEIPT_TWO_EXPECTED_REVISION_CODES: Final[frozenset[str]] = frozenset(
    {"budget_reserve", "budget_settle"}
)
_RECEIPT_OUTBOX_OWNER_CODES: Final[frozenset[str]] = frozenset(
    {
        "outbox_claim",
        "outbox_reclaim",
        "outbox_renew",
        "outbox_publish",
        "outbox_retryable_failure",
        "outbox_nonretryable_failure",
    }
)
_RECEIPT_OUTBOX_NO_OWNER_CODES: Final[frozenset[str]] = frozenset(
    {"outbox_insert", "outbox_poison", "outbox_purge"}
)

# Generation 11 is deliberately additive.  The generation-10 constants above are
# migration authority for revision 0010 and must never be widened in place.
RUNTIME_GENERATION_V11: Final = 11
ADMISSION_AUTHORITY_CONTRACT_V2: Final = 2
ADMISSION_AUTHORITY_CONTRACT_V3: Final = 3
TERMINAL_COMMIT_CONTRACT_VERSION_V3: Final = 3
MAX_TERMINAL_OUTPUTS_V3: Final = 256
DESTINATION_NORMALIZATION_VERSION: Final = 1
GATEWAY_AUTHORITY_TARGET_ID: Final = "05f6658b-0a58-4ce7-8ccf-0f30c1185103"

_TERMINAL_COMMIT_OPERATION_ID_DOMAIN_V3: Final = "terminal-commit-operation-id.v3"
_TERMINAL_COMMIT_ACTION_V3: Final = "commit-known-settled"
_TERMINAL_COMMIT_REQUEST_DOMAIN_V3: Final = "execution-terminal-commit.v3.request"
_TERMINAL_COMMIT_RESULT_DOMAIN_V3: Final = "execution-terminal-commit.v3.result"
_TERMINAL_COMMIT_LOCK_ORDER_V3: Final[tuple[str, ...]] = (
    "operation_transaction_key",
    "receipt_classification",
    "logical_execution_transaction_key",
    "attempt_transaction_key",
    "attempt",
    "ledger",
    "budget",
    "logical_execution",
    "output_target",
    "output_link",
    "outbox",
    "operation_receipt",
)

V11_AUTHORITY_TABLES: Final[tuple[str, ...]] = (
    "campaign_execution_actor_grants",
    "campaign_execution_destination_authorities",
    "execution_approval_authorities",
    "execution_attempt_destination_observations",
    "execution_attempt_credential_observations",
)

_V11_RESERVED_CAMPAIGN_EXECUTION_RELATIONS: Final[frozenset[str]] = frozenset(
    {
        "campaign_execution_actor_grants",
        "campaign_execution_authority_revisions",
        "campaign_execution_budget_ledger",
        "campaign_execution_budgets",
        "campaign_execution_destination_authorities",
    }
)

V11_ADDITIVE_OPERATION_CODES: Final[tuple[str, ...]] = (
    "gateway_authority_update",
    "actor_authority_activate",
    "actor_authority_update",
    "actor_authority_revoke",
    "campaign_authority_activate",
    "campaign_authority_update",
    "campaign_authority_revoke",
    "campaign_actor_grant_put",
    "campaign_actor_grant_revoke",
    "destination_authority_update",
    "destination_authority_revoke",
    "credential_authority_update",
    "credential_authority_revoke",
    "approval_authority_grant",
    "approval_authority_revoke",
)
V11_OPERATION_CODES: Final[tuple[str, ...]] = OPERATION_CODES + V11_ADDITIVE_OPERATION_CODES
_V11_RECEIPT_NO_EXPECTED_REVISION_CODES: Final[frozenset[str]] = (
    _RECEIPT_NO_EXPECTED_REVISION_CODES | {"approval_authority_grant"}
)
_V11_RECEIPT_OPTIONAL_EXPECTED_REVISION_CODES: Final[frozenset[str]] = frozenset(
    {"campaign_actor_grant_put"}
)

_UUID_SQLITE = (
    "length({c})=36 AND substr({c},9,1)='-' AND substr({c},14,1)='-' "
    "AND substr({c},19,1)='-' AND substr({c},24,1)='-' "
    "AND substr({c},15,1)='4' AND substr({c},20,1) IN ('8','9','a','b') "
    "AND lower({c})={c} AND length(replace({c},'-',''))=32 "
    "AND replace({c},'-','') NOT GLOB '*[^0-9a-f]*'"
)
_UUID_POSTGRES = (
    "{c} ~ '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$'"
)
_H64_SQLITE = "length({c})=64 AND lower({c})={c} AND {c} NOT GLOB '*[^0-9a-f]*'"
_H64_POSTGRES = "{c} ~ '^[0-9a-f]{{64}}$'"
_S128_SQLITE = (
    "length({c}) BETWEEN 1 AND 128 AND substr({c},1,1) GLOB '[a-z]' "
    "AND {c} NOT GLOB '*[^a-z0-9_.:-]*'"
)
_S128_POSTGRES = "char_length({c}) BETWEEN 1 AND 128 AND {c} ~ '^[a-z][a-z0-9_.:-]{{0,127}}$'"


def _uuid_check(column: str, dialect: str) -> str:
    template = _UUID_POSTGRES if dialect == "postgresql" else _UUID_SQLITE
    return template.format(c=column)


def _h64_check(column: str, dialect: str) -> str:
    template = _H64_POSTGRES if dialect == "postgresql" else _H64_SQLITE
    return template.format(c=column)


def _s128_check(column: str, dialect: str) -> str:
    template = _S128_POSTGRES if dialect == "postgresql" else _S128_SQLITE
    return template.format(c=column)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ",".join(f"'{value}'" for value in values) + ")"


def _distinct_nullable(columns: Sequence[str]) -> str:
    pairs = (
        f"({left} IS NULL OR {right} IS NULL OR {left}<>{right})"
        for index, left in enumerate(columns)
        for right in columns[index + 1 :]
    )
    return " AND ".join(pairs)


INGRESS_CODES: Final[tuple[str, ...]] = (
    "api_module",
    "api_campaign_plan",
    "strategy",
    "goal_api",
    "goal_cli",
    "cli_module",
    "cli_chain",
    "sdk",
    "direct_engine",
    "collaboration",
    "worker_controller",
    "redis_cluster",
    "isolated_subprocess",
    "checkpoint_resume",
    "replay",
    "scheduled_background",
)
NOISE_CLASSES: Final[tuple[str, ...]] = ("silent", "local", "low", "medium", "high_noise")
APPROVAL_POLICIES: Final[tuple[str, ...]] = ("none", "attempt_bound")
EXTERNAL_EFFECT_CLASSES: Final[tuple[str, ...]] = (
    "read_only",
    "conditionally_mutating",
    "mutating",
    "local_analysis",
    "planning",
    "billable_nondeterministic_egress",
)
IDEMPOTENCY_CLASSES: Final[tuple[str, ...]] = (
    "proven_idempotent",
    "proven_non_idempotent",
    "conditional",
    "unproven_current_contract",
)
RETRY_POLICIES: Final[tuple[str, ...]] = (
    "after_revalidation",
    "blocked_unproven_prior_attempt",
    "never",
)
RETRY_DISPOSITIONS: Final[tuple[str, ...]] = (
    "not_applicable",
    "eligible",
    "forbidden",
    "child_bound",
    "closed_without_retry",
)
CANCELLATION_OWNERSHIP: Final[tuple[str, ...]] = (
    "owned",
    "not_applicable",
    "unproven_current_contract",
)
COMPENSATION_CLASSES: Final[tuple[str, ...]] = (
    "not_applicable",
    "supported",
    "unsupported",
    "unproven_current_contract",
)
TIMEOUT_ORIGINS: Final[tuple[str, ...]] = (
    "module_defined_bounded",
    "observed_legacy_engine_default",
    "unsupported_or_unbounded",
)
TIMEOUT_SETTLEMENTS: Final[tuple[str, ...]] = ("proven", "unproven_current_contract")
POLICY_VERDICTS: Final[tuple[str, ...]] = (
    "rejected",
    "blocked",
    "preview_ready",
    "live_candidate",
)
ACTOR_ROLES: Final[tuple[str, ...]] = ("reporter", "operator", "team_lead", "admin")
MINIMUM_ROLES: Final[tuple[str, ...]] = ("operator", "team_lead", "admin")


def lifecycle_ddl(dialect: str) -> tuple[str, ...]:
    """Return the ordered exact generation-10 DDL for one supported dialect."""
    if dialect not in {"sqlite", "postgresql"}:
        raise ValueError("Unsupported lifecycle dialect")
    integer = "BIGINT" if dialect == "postgresql" else "INTEGER"
    boolean = "BOOLEAN" if dialect == "postgresql" else "INTEGER"
    false = "FALSE" if dialect == "postgresql" else "0"
    true = "TRUE" if dialect == "postgresql" else "1"
    bool_check = "{c} IN (FALSE,TRUE)" if dialect == "postgresql" else "{c} IN (0,1)"
    pending_default = "'pending'"
    now_ms = (
        "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
        if dialect == "postgresql"
        else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
    )

    def uuid(column: str) -> str:
        return _uuid_check(column, dialect)

    def h64(column: str) -> str:
        return _h64_check(column, dialect)

    def s128(column: str) -> str:
        return _s128_check(column, dialect)

    def b(column: str) -> str:
        return bool_check.format(c=column)

    logical = f"""
CREATE TABLE logical_executions (
    id TEXT NOT NULL CONSTRAINT pk_logical_executions PRIMARY KEY,
    submission_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    actor_subject_ref TEXT NOT NULL,
    actor_user_id TEXT,
    module_id TEXT NOT NULL,
    ingress_code TEXT NOT NULL,
    admission_operation_id TEXT NOT NULL,
    submission_binding_contract_version {integer} NOT NULL,
    submission_request_binding_digest TEXT NOT NULL,
    submission_result_code TEXT NOT NULL,
    submission_exact_replay_code TEXT NOT NULL,
    submission_result_binding_digest TEXT NOT NULL,
    highest_attempt_ordinal {integer} NOT NULL DEFAULT 0,
    revision {integer} NOT NULL DEFAULT 0,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    closure_operation_id TEXT,
    closure_authority_subject_ref TEXT,
    closure_authority_user_id TEXT,
    closure_authority_revision {integer},
    closing_attempt_id TEXT,
    closed_at {integer},
    CONSTRAINT uq_le_campaign_id UNIQUE (campaign_id,id),
    CONSTRAINT uq_le_campaign_submission UNIQUE (campaign_id,submission_id),
    CONSTRAINT ck_le_id CHECK ({uuid("id")}),
    CONSTRAINT ck_le_submission_id CHECK ({uuid("submission_id")}),
    CONSTRAINT ck_le_campaign_id CHECK ({uuid("campaign_id")}),
    CONSTRAINT ck_le_actor_subject CHECK ({uuid("actor_subject_ref")}),
    CONSTRAINT ck_le_actor_user CHECK (actor_user_id IS NULL OR ({uuid("actor_user_id")})),
    CONSTRAINT ck_le_module_id CHECK ({s128("module_id")}),
    CONSTRAINT ck_le_ingress CHECK ({_in("ingress_code", INGRESS_CODES)}),
    CONSTRAINT ck_le_admission_operation CHECK ({uuid("admission_operation_id")}),
    CONSTRAINT ck_le_submission_contract CHECK (submission_binding_contract_version=2),
    CONSTRAINT ck_le_submission_request_digest CHECK ({h64("submission_request_binding_digest")}),
    CONSTRAINT ck_le_submission_result_code CHECK (submission_result_code='applied'),
    CONSTRAINT ck_le_submission_replay_code CHECK (submission_exact_replay_code='replayed'),
    CONSTRAINT ck_le_submission_result_digest CHECK ({h64("submission_result_binding_digest")}),
    CONSTRAINT ck_le_bounds CHECK (
        highest_attempt_ordinal BETWEEN 0 AND {MAX_I53}
        AND revision BETWEEN 0 AND {MAX_I53}
        AND created_at BETWEEN 0 AND {MAX_I53}
        AND (closed_at IS NULL OR closed_at BETWEEN created_at AND {MAX_I53})
    ),
    CONSTRAINT ck_le_closure_operation CHECK (
        closure_operation_id IS NULL OR ({uuid("closure_operation_id")})
    ),
    CONSTRAINT ck_le_closure_subject CHECK (
        closure_authority_subject_ref IS NULL OR ({uuid("closure_authority_subject_ref")})
    ),
    CONSTRAINT ck_le_closure_user CHECK (
        closure_authority_user_id IS NULL OR ({uuid("closure_authority_user_id")})
    ),
    CONSTRAINT ck_le_closing_attempt CHECK (
        closing_attempt_id IS NULL OR ({uuid("closing_attempt_id")})
    ),
    CONSTRAINT ck_le_closure_shape CHECK (
        (
            closure_operation_id IS NULL
            AND closure_authority_subject_ref IS NULL
            AND closure_authority_user_id IS NULL
            AND closure_authority_revision IS NULL
            AND closing_attempt_id IS NULL
            AND closed_at IS NULL
        ) OR (
            closure_operation_id IS NOT NULL
            AND closure_authority_subject_ref IS NOT NULL
            AND closure_authority_revision BETWEEN 0 AND {MAX_I53}
            AND closing_attempt_id IS NOT NULL
            AND closed_at IS NOT NULL
        )
    ),
    CONSTRAINT fk_le_campaign FOREIGN KEY (campaign_id)
        REFERENCES campaigns(id) ON UPDATE NO ACTION ON DELETE NO ACTION
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_le_actor_user FOREIGN KEY (actor_user_id)
        REFERENCES users(id) ON UPDATE NO ACTION ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_le_closure_user FOREIGN KEY (closure_authority_user_id)
        REFERENCES users(id) ON UPDATE NO ACTION ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED
        {"," if dialect == "sqlite" else ""}
    {"CONSTRAINT fk_le_closing_attempt FOREIGN KEY (id,closing_attempt_id) REFERENCES execution_attempts(logical_execution_id,id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED" if dialect == "sqlite" else ""}
)"""

    states = tuple(state.value for state in AttemptState)
    outcomes = tuple(value.value for value in OutcomeCode)
    attempts = f"""
CREATE TABLE execution_attempts (
    id TEXT NOT NULL CONSTRAINT pk_execution_attempts PRIMARY KEY,
    logical_execution_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    ordinal {integer} NOT NULL,
    parent_attempt_id TEXT,
    revision {integer} NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    closes_logical {boolean} NOT NULL DEFAULT {false},
    actor_subject_ref TEXT NOT NULL,
    actor_user_id TEXT,
    actor_authority_revision {integer} NOT NULL,
    campaign_authority_revision {integer} NOT NULL,
    destination_authority_revision {integer} NOT NULL,
    credential_authority_revision {integer} NOT NULL,
    request_contract_version {integer} NOT NULL,
    evaluation_mode TEXT NOT NULL,
    request_structure_valid {boolean} NOT NULL,
    canonicalization_complete {boolean} NOT NULL,
    unknown_fields_absent {boolean} NOT NULL,
    alternate_transport_absent {boolean} NOT NULL,
    bounded_shape_valid {boolean} NOT NULL,
    request_shape_units {integer} NOT NULL,
    descriptor_contract_version TEXT NOT NULL,
    descriptor_semantic_digest TEXT NOT NULL,
    catalog_digest TEXT NOT NULL,
    trusted_first_party_binding {boolean} NOT NULL,
    descriptor_binding_current {boolean} NOT NULL,
    descriptor_complete {boolean} NOT NULL,
    static_policy_evaluable {boolean} NOT NULL,
    minimum_role TEXT NOT NULL,
    noise_class TEXT NOT NULL,
    approval_policy TEXT NOT NULL,
    capability_mask_version {integer} NOT NULL,
    required_capability_mask {integer} NOT NULL,
    descriptor_blocker_mask_version {integer} NOT NULL,
    descriptor_blocker_mask {integer} NOT NULL,
    preview_ready {boolean} NOT NULL,
    lifecycle_ready {boolean} NOT NULL,
    result_authority_ready {boolean} NOT NULL,
    transport_ready {boolean} NOT NULL,
    future_gateway_eligible {boolean} NOT NULL,
    authority_snapshots_complete {boolean} NOT NULL,
    authority_revisions_current {boolean} NOT NULL,
    actor_authenticated {boolean} NOT NULL,
    actor_active {boolean} NOT NULL,
    actor_role TEXT NOT NULL,
    campaign_active {boolean} NOT NULL,
    actor_campaign_authorized {boolean} NOT NULL,
    approval_present {boolean} NOT NULL,
    approval_current {boolean} NOT NULL,
    approval_exactly_bound {boolean} NOT NULL,
    granted_capability_mask {integer} NOT NULL,
    destination_extraction_complete {boolean} NOT NULL,
    destinations_in_scope {boolean} NOT NULL,
    credential_authority_resolved {boolean} NOT NULL,
    credential_authority_current {boolean} NOT NULL,
    opaque_handles_only {boolean} NOT NULL,
    permitted_handle_kinds_only {boolean} NOT NULL,
    raw_credentials_absent {boolean} NOT NULL,
    ambient_credentials_absent {boolean} NOT NULL,
    budget_authority_resolved {boolean} NOT NULL,
    budget_authority_current {boolean} NOT NULL,
    budget_capacity_available {boolean} NOT NULL,
    gateway_mode_snapshot TEXT NOT NULL,
    gateway_decision_code TEXT NOT NULL,
    policy_evaluation_state TEXT NOT NULL,
    policy_contract_version {integer} NOT NULL,
    policy_verdict TEXT,
    policy_reason_mask_version {integer},
    policy_reason_mask {integer},
    external_effect_class TEXT NOT NULL,
    idempotency_class TEXT NOT NULL,
    retry_policy TEXT NOT NULL,
    retry_disposition TEXT NOT NULL,
    cancellation_ownership TEXT NOT NULL,
    compensation_class TEXT NOT NULL,
    timeout_origin TEXT NOT NULL,
    timeout_limit_ms {integer} NOT NULL,
    timeout_settlement TEXT NOT NULL,
    outcome_code TEXT,
    error_action_code TEXT NOT NULL,
    settlement_state TEXT NOT NULL,
    settlement_proof_code TEXT NOT NULL,
    termination_confirmed {boolean} NOT NULL,
    dispatch_owner_ref TEXT,
    lease_generation {integer} NOT NULL DEFAULT 0,
    dispatch_lease_duration_ms {integer},
    lease_expires_at {integer},
    lease_invalidated_at {integer},
    queue_operation_id TEXT,
    dispatch_operation_id TEXT,
    start_operation_id TEXT,
    cancellation_request_operation_id TEXT,
    cancellation_request_revision {integer},
    cancellation_ack_operation_id TEXT,
    timeout_operation_id TEXT,
    settlement_pending_operation_id TEXT,
    terminal_operation_id TEXT,
    resolver_subject_ref TEXT,
    resolver_user_id TEXT,
    resolver_authority_revision {integer},
    bounded_recovery_proof_code TEXT,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    accepted_at {integer},
    queued_at {integer},
    dispatching_at {integer},
    started_at {integer},
    cancellation_requested_at {integer},
    cancellation_acknowledged_at {integer},
    timeout_observed_at {integer},
    settlement_pending_at {integer},
    recovery_deadline_at {integer},
    retry_child_bound_at {integer},
    finished_at {integer},
    settled_at {integer},
    CONSTRAINT uq_ea_logical_ordinal UNIQUE (logical_execution_id,ordinal),
    CONSTRAINT uq_ea_logical_id UNIQUE (logical_execution_id,id),
    CONSTRAINT uq_ea_campaign_id UNIQUE (campaign_id,id),
    CONSTRAINT ck_ea_id CHECK ({uuid("id")}),
    CONSTRAINT ck_ea_logical_campaign CHECK (
        ({uuid("logical_execution_id")}) AND ({uuid("campaign_id")})
    ),
    CONSTRAINT ck_ea_parent CHECK (parent_attempt_id IS NULL OR ({uuid("parent_attempt_id")})),
    CONSTRAINT ck_ea_actor_refs CHECK (
        ({uuid("actor_subject_ref")})
        AND (actor_user_id IS NULL OR ({uuid("actor_user_id")}))
    ),
    CONSTRAINT ck_ea_contract_versions CHECK (
        request_contract_version=1
        AND policy_contract_version=1
        AND descriptor_contract_version='ares.module-descriptor.v2'
        AND capability_mask_version=1
        AND descriptor_blocker_mask_version=1
        AND (policy_reason_mask_version IS NULL OR policy_reason_mask_version=1)
    ),
    CONSTRAINT ck_ea_digests CHECK (
        ({h64("descriptor_semantic_digest")}) AND ({h64("catalog_digest")})
    ),
    CONSTRAINT ck_ea_operation_ids CHECK (
        (queue_operation_id IS NULL OR ({uuid("queue_operation_id")}))
        AND (dispatch_operation_id IS NULL OR ({uuid("dispatch_operation_id")}))
        AND (start_operation_id IS NULL OR ({uuid("start_operation_id")}))
        AND (cancellation_request_operation_id IS NULL OR ({
        uuid("cancellation_request_operation_id")
    }))
        AND (cancellation_ack_operation_id IS NULL OR ({uuid("cancellation_ack_operation_id")}))
        AND (timeout_operation_id IS NULL OR ({uuid("timeout_operation_id")}))
        AND (settlement_pending_operation_id IS NULL OR ({uuid("settlement_pending_operation_id")}))
        AND (terminal_operation_id IS NULL OR ({uuid("terminal_operation_id")}))
        AND (resolver_subject_ref IS NULL OR ({uuid("resolver_subject_ref")}))
        AND (resolver_user_id IS NULL OR ({uuid("resolver_user_id")}))
        AND {
        _distinct_nullable(
            (
                "queue_operation_id",
                "dispatch_operation_id",
                "start_operation_id",
                "cancellation_request_operation_id",
                "cancellation_ack_operation_id",
                "timeout_operation_id",
                "settlement_pending_operation_id",
                "terminal_operation_id",
            )
        )
    }
    ),
    CONSTRAINT ck_ea_state CHECK ({_in("state", states)}),
    CONSTRAINT ck_ea_booleans CHECK (
        {
        " AND ".join(
            b(name)
            for name in (
                "closes_logical",
                "request_structure_valid",
                "canonicalization_complete",
                "unknown_fields_absent",
                "alternate_transport_absent",
                "bounded_shape_valid",
                "trusted_first_party_binding",
                "descriptor_binding_current",
                "descriptor_complete",
                "static_policy_evaluable",
                "preview_ready",
                "lifecycle_ready",
                "result_authority_ready",
                "transport_ready",
                "future_gateway_eligible",
                "authority_snapshots_complete",
                "authority_revisions_current",
                "actor_authenticated",
                "actor_active",
                "campaign_active",
                "actor_campaign_authorized",
                "approval_present",
                "approval_current",
                "approval_exactly_bound",
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
                "termination_confirmed",
            )
        )
    }
    ),
    CONSTRAINT ck_ea_numeric_bounds CHECK (
        ordinal BETWEEN 0 AND {MAX_I53}
        AND revision BETWEEN 0 AND {MAX_I53}
        AND actor_authority_revision BETWEEN 0 AND {MAX_I53}
        AND campaign_authority_revision BETWEEN 0 AND {MAX_I53}
        AND destination_authority_revision BETWEEN 0 AND {MAX_I53}
        AND credential_authority_revision BETWEEN 0 AND {MAX_I53}
        AND request_shape_units BETWEEN 0 AND 4096
        AND required_capability_mask BETWEEN 0 AND 15
        AND granted_capability_mask BETWEEN 0 AND 15
        AND descriptor_blocker_mask BETWEEN 0 AND 511
        AND (policy_reason_mask IS NULL OR policy_reason_mask BETWEEN 0 AND 34359738367)
        AND timeout_limit_ms BETWEEN {MIN_TIMEOUT_MS} AND {MAX_TIMEOUT_MS}
        AND lease_generation BETWEEN 0 AND {MAX_I53}
    ),
    CONSTRAINT ck_ea_timestamps CHECK (
        created_at BETWEEN 0 AND {MAX_I53}
        AND (accepted_at IS NULL OR accepted_at BETWEEN created_at AND {MAX_I53})
        AND (queued_at IS NULL OR queued_at BETWEEN created_at AND {MAX_I53})
        AND (dispatching_at IS NULL OR dispatching_at BETWEEN created_at AND {MAX_I53})
        AND (started_at IS NULL OR started_at BETWEEN created_at AND {MAX_I53})
        AND (cancellation_requested_at IS NULL OR cancellation_requested_at BETWEEN created_at AND {
        MAX_I53
    })
        AND (cancellation_acknowledged_at IS NULL OR cancellation_acknowledged_at BETWEEN created_at AND {
        MAX_I53
    })
        AND (timeout_observed_at IS NULL OR timeout_observed_at BETWEEN created_at AND {MAX_I53})
        AND (settlement_pending_at IS NULL OR settlement_pending_at BETWEEN created_at AND {
        MAX_I53
    })
        AND (recovery_deadline_at IS NULL OR recovery_deadline_at BETWEEN created_at AND {MAX_I53})
        AND (retry_child_bound_at IS NULL OR retry_child_bound_at BETWEEN created_at AND {MAX_I53})
        AND (finished_at IS NULL OR finished_at BETWEEN created_at AND {MAX_I53})
        AND (settled_at IS NULL OR settled_at BETWEEN created_at AND {MAX_I53})
        AND (lease_invalidated_at IS NULL OR lease_invalidated_at BETWEEN created_at AND {MAX_I53})
    ),
    CONSTRAINT ck_ea_enums CHECK (
        {_in("evaluation_mode", ("preview", "live"))}
        AND {_in("minimum_role", MINIMUM_ROLES)}
        AND {_in("actor_role", ACTOR_ROLES)}
        AND {_in("noise_class", NOISE_CLASSES)}
        AND {_in("approval_policy", APPROVAL_POLICIES)}
        AND {_in("external_effect_class", EXTERNAL_EFFECT_CLASSES)}
        AND {_in("idempotency_class", IDEMPOTENCY_CLASSES)}
        AND {_in("retry_policy", RETRY_POLICIES)}
        AND {_in("retry_disposition", RETRY_DISPOSITIONS)}
        AND {_in("cancellation_ownership", CANCELLATION_OWNERSHIP)}
        AND {_in("compensation_class", COMPENSATION_CLASSES)}
        AND {_in("timeout_origin", TIMEOUT_ORIGINS)}
        AND {_in("timeout_settlement", TIMEOUT_SETTLEMENTS)}
        AND {
        _in(
            "gateway_mode_snapshot",
            ("disabled", "shadow_candidate", "enforced", "emergency_disabled"),
        )
    }
        AND {_in("gateway_decision_code", ("none", "emergency_disabled"))}
        AND {_in("policy_evaluation_state", ("evaluated", "not_evaluated"))}
        AND (policy_verdict IS NULL OR {_in("policy_verdict", POLICY_VERDICTS)})
        AND (outcome_code IS NULL OR {_in("outcome_code", outcomes)})
        AND {
        _in(
            "error_action_code",
            (
                "none",
                "retry",
                "skip",
                "fallback",
                "abort",
                "pause",
                "credential_lockout",
                "credential_expired",
                "host_unreachable",
                "rate_limited",
                "dependency_unavailable",
                "operator_cancel",
                "timeout",
                "worker_loss",
                "recovery_required",
            ),
        )
    }
        AND {
        _in(
            "settlement_state",
            (
                "not_applicable",
                "reserved",
                "active",
                "recovery_pending",
                "settled",
                "operator_resolved",
            ),
        )
    }
        AND {
        _in(
            "settlement_proof_code",
            (
                "none",
                "no_dispatch",
                "local_completion",
                "process_group_exit",
                "worker_terminal_ack",
                "external_settlement_ack",
                "cancellation_no_result_ack",
                "timeout_termination_ack",
                "bounded_recovery_exhausted",
                "unresolved",
            ),
        )
    }
        AND (bounded_recovery_proof_code IS NULL OR {
        _in(
            "bounded_recovery_proof_code",
            (
                "owner_late_terminal_ack",
                "process_exit_observed",
                "provider_settlement_ack",
                "cancellation_no_result_ack",
                "timeout_termination_ack",
                "recovery_sources_exhausted",
            ),
        )
    })
    ),
    CONSTRAINT ck_ea_policy_shape CHECK (
        (
            gateway_mode_snapshot='emergency_disabled'
            AND gateway_decision_code='emergency_disabled'
            AND state='blocked'
            AND policy_evaluation_state='not_evaluated'
            AND policy_verdict IS NULL
            AND policy_reason_mask_version IS NULL
            AND policy_reason_mask IS NULL
        ) OR (
            gateway_mode_snapshot<>'emergency_disabled'
            AND gateway_decision_code='none'
            AND policy_evaluation_state='evaluated'
            AND policy_verdict IS NOT NULL
            AND policy_reason_mask_version=1
            AND policy_reason_mask IS NOT NULL
        )
    ),
    CONSTRAINT ck_ea_policy_state_binding CHECK (
        (state='rejected' AND policy_evaluation_state='evaluated' AND policy_verdict='rejected')
        OR (state='blocked' AND (
            (policy_evaluation_state='evaluated' AND policy_verdict IN ('blocked','preview_ready'))
            OR (gateway_mode_snapshot='emergency_disabled' AND policy_evaluation_state='not_evaluated' AND policy_verdict IS NULL)
        ))
        OR (state NOT IN ('rejected','blocked')
            AND evaluation_mode='live'
            AND gateway_mode_snapshot='enforced'
            AND gateway_decision_code='none'
            AND policy_evaluation_state='evaluated'
            AND policy_verdict='live_candidate'
            AND policy_reason_mask_version=1
            AND policy_reason_mask=0
            AND descriptor_blocker_mask=0)
    ),
    CONSTRAINT ck_ea_live_admission_facts CHECK (
        state IN ('rejected','blocked') OR (
            request_structure_valid={true}
            AND canonicalization_complete={true}
            AND unknown_fields_absent={true}
            AND alternate_transport_absent={true}
            AND bounded_shape_valid={true}
            AND trusted_first_party_binding={true}
            AND descriptor_binding_current={true}
            AND descriptor_complete={true}
            AND static_policy_evaluable={true}
            AND preview_ready={true}
            AND lifecycle_ready={true}
            AND result_authority_ready={true}
            AND transport_ready={true}
            AND future_gateway_eligible={true}
            AND authority_snapshots_complete={true}
            AND authority_revisions_current={true}
            AND actor_authenticated={true}
            AND actor_active={true}
            AND campaign_active={true}
            AND actor_campaign_authorized={true}
            AND destination_extraction_complete={true}
            AND destinations_in_scope={true}
            AND credential_authority_resolved={true}
            AND credential_authority_current={true}
            AND opaque_handles_only={true}
            AND permitted_handle_kinds_only={true}
            AND raw_credentials_absent={true}
            AND ambient_credentials_absent={true}
            AND budget_authority_resolved={true}
            AND budget_authority_current={true}
            AND budget_capacity_available={true}
            AND (
                (minimum_role='operator' AND actor_role IN ('operator','team_lead','admin'))
                OR (minimum_role='team_lead' AND actor_role IN ('team_lead','admin'))
                OR (minimum_role='admin' AND actor_role='admin')
            )
            AND (noise_class<>'high_noise' OR actor_role IN ('team_lead','admin'))
            AND ((granted_capability_mask & required_capability_mask)=required_capability_mask)
            AND (
                (approval_policy='none' AND approval_present={false} AND approval_current={
        false
    } AND approval_exactly_bound={false})
                OR (approval_policy='attempt_bound' AND approval_present={
        true
    } AND approval_current={true} AND approval_exactly_bound={true})
            )
        )
    ),
    CONSTRAINT ck_ea_outcome CHECK (
        (state='rejected' AND outcome_code='policy_rejected')
        OR (state='blocked' AND outcome_code='policy_blocked')
        OR (state='succeeded' AND outcome_code='confirmed_success')
        OR (state='partial' AND outcome_code='confirmed_partial')
        OR (state='skipped' AND outcome_code='orchestration_skipped')
        OR (state='cancelled' AND outcome_code='confirmed_cancelled_no_result')
        OR (state='timed_out' AND outcome_code='confirmed_timeout_terminated')
        OR (state='indeterminate' AND outcome_code='unknown_after_recovery')
        OR (state='failed' AND outcome_code IN ('confirmed_failure_no_dispatch','confirmed_failure'))
        OR (state IN ('accepted','queued','dispatching','running','cancelling','settlement_pending') AND outcome_code IS NULL)
    ),
    CONSTRAINT ck_ea_capabilities CHECK (
        state IN ('rejected','blocked')
        OR ((granted_capability_mask & required_capability_mask)=required_capability_mask)
    ),
    CONSTRAINT ck_ea_retry CHECK (
        retry_disposition<>'eligible'
        OR (
            state IN ('failed','timed_out')
            AND closes_logical={false}
            AND external_effect_class='read_only'
            AND idempotency_class='proven_idempotent'
            AND retry_policy='after_revalidation'
            AND (
                (
                    start_operation_id IS NULL
                    AND outcome_code='confirmed_failure_no_dispatch'
                    AND settlement_state='not_applicable'
                    AND settlement_proof_code='no_dispatch'
                    AND termination_confirmed={false}
                ) OR (
                    start_operation_id IS NOT NULL
                    AND settlement_state='settled'
                    AND settlement_proof_code NOT IN ('none','no_dispatch','unresolved')
                    AND termination_confirmed={true}
                )
            )
        )
    ),
    CONSTRAINT ck_ea_lease_shape CHECK (
        (
            dispatch_operation_id IS NULL
            AND dispatch_owner_ref IS NULL
            AND lease_generation=0
            AND dispatch_lease_duration_ms IS NULL
            AND lease_expires_at IS NULL
            AND lease_invalidated_at IS NULL
            AND start_operation_id IS NULL
        ) OR (
            dispatch_operation_id IS NOT NULL
            AND dispatch_owner_ref IS NOT NULL
            AND ({uuid("dispatch_owner_ref")})
            AND lease_generation BETWEEN 1 AND {MAX_I53}
            AND dispatch_lease_duration_ms BETWEEN {MIN_TIMEOUT_MS} AND {MAX_TIMEOUT_MS}
            AND lease_expires_at BETWEEN 0 AND {MAX_I53}
            AND dispatching_at IS NOT NULL
            AND lease_expires_at<=dispatching_at+timeout_limit_ms
        )
    ),
    CONSTRAINT ck_ea_dispatch_history_state CHECK (
        (
            dispatch_operation_id IS NULL
            AND state NOT IN ('dispatching','running','succeeded','partial','timed_out','settlement_pending')
        ) OR (
            dispatch_operation_id IS NOT NULL
            AND (
                (state IN ('dispatching','running','cancelling') AND lease_invalidated_at IS NULL)
                OR (state IN ('succeeded','partial','failed','cancelled','timed_out','indeterminate','settlement_pending') AND lease_invalidated_at IS NOT NULL)
            )
            AND (start_operation_id IS NOT NULL OR state NOT IN ('running','succeeded','partial','timed_out'))
        )
    ),
    CONSTRAINT ck_ea_state_history CHECK (
        (state IN ('rejected','blocked')
            AND accepted_at IS NULL AND queue_operation_id IS NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL)
        OR (state='accepted'
            AND accepted_at IS NOT NULL AND queue_operation_id IS NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL)
        OR (state='queued'
            AND accepted_at IS NOT NULL AND queue_operation_id IS NOT NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL)
        OR (state='dispatching'
            AND accepted_at IS NOT NULL AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NULL AND cancellation_request_operation_id IS NULL)
        OR (state='running'
            AND accepted_at IS NOT NULL AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NOT NULL AND cancellation_request_operation_id IS NULL)
        OR (state='cancelling'
            AND accepted_at IS NOT NULL AND cancellation_request_operation_id IS NOT NULL
            AND ((dispatch_operation_id IS NULL AND start_operation_id IS NULL)
                 OR dispatch_operation_id IS NOT NULL))
        OR state IN ('settlement_pending','succeeded','partial','failed','skipped','cancelled','timed_out','indeterminate')
    ),
    CONSTRAINT ck_ea_history_dnf CHECK (
        (state IN ('rejected','blocked')
            AND accepted_at IS NULL AND queue_operation_id IS NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL
            AND settlement_pending_operation_id IS NULL
            AND terminal_operation_id IS NOT NULL)
        OR (state='accepted'
            AND accepted_at IS NOT NULL AND queue_operation_id IS NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL
            AND settlement_pending_operation_id IS NULL)
        OR (state='queued'
            AND accepted_at IS NOT NULL AND queue_operation_id IS NOT NULL
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL
            AND settlement_pending_operation_id IS NULL)
        OR (state='dispatching'
            AND accepted_at IS NOT NULL AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL
            AND settlement_pending_operation_id IS NULL
            AND lease_invalidated_at IS NULL)
        OR (state='running'
            AND accepted_at IS NOT NULL AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NOT NULL
            AND cancellation_request_operation_id IS NULL
            AND settlement_pending_operation_id IS NULL
            AND lease_invalidated_at IS NULL)
        OR (state='cancelling'
            AND accepted_at IS NOT NULL
            AND cancellation_request_operation_id IS NOT NULL
            AND settlement_pending_operation_id IS NULL
            AND (
                (dispatch_operation_id IS NULL AND start_operation_id IS NULL
                    AND lease_invalidated_at IS NULL)
                OR (dispatch_operation_id IS NOT NULL AND start_operation_id IS NULL
                    AND lease_invalidated_at IS NULL)
                OR (dispatch_operation_id IS NOT NULL AND start_operation_id IS NOT NULL
                    AND lease_invalidated_at IS NULL)
            ))
        OR (state='settlement_pending'
            AND dispatch_operation_id IS NOT NULL
            AND settlement_pending_operation_id IS NOT NULL
            AND lease_invalidated_at IS NOT NULL
            AND terminal_operation_id IS NULL
            AND cancellation_ack_operation_id IS NULL
            AND timeout_operation_id IS NULL)
        OR (state IN ('succeeded','partial')
            AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NOT NULL
            AND lease_invalidated_at IS NOT NULL
            AND ((cancellation_request_operation_id IS NULL
                    AND terminal_operation_id IS NOT NULL
                    AND cancellation_ack_operation_id IS NULL)
                 OR (cancellation_request_operation_id IS NOT NULL
                    AND cancellation_ack_operation_id IS NOT NULL
                    AND terminal_operation_id IS NULL)))
        OR (state='failed'
            AND (
                (dispatch_operation_id IS NULL AND start_operation_id IS NULL
                    AND lease_invalidated_at IS NULL
                    AND outcome_code='confirmed_failure_no_dispatch')
                OR (dispatch_operation_id IS NOT NULL AND start_operation_id IS NULL
                    AND lease_invalidated_at IS NOT NULL
                    AND outcome_code='confirmed_failure_no_dispatch')
                OR (dispatch_operation_id IS NOT NULL AND start_operation_id IS NOT NULL
                    AND lease_invalidated_at IS NOT NULL
                    AND outcome_code='confirmed_failure')
            )
            AND ((cancellation_request_operation_id IS NULL
                    AND terminal_operation_id IS NOT NULL
                    AND cancellation_ack_operation_id IS NULL)
                 OR (cancellation_request_operation_id IS NOT NULL
                    AND cancellation_ack_operation_id IS NOT NULL
                    AND terminal_operation_id IS NULL)))
        OR (state='skipped'
            AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
            AND cancellation_request_operation_id IS NULL
            AND terminal_operation_id IS NOT NULL)
        OR (state='cancelled'
            AND cancellation_ack_operation_id IS NOT NULL
            AND terminal_operation_id IS NULL
            AND ((cancellation_request_operation_id IS NOT NULL
                    AND dispatch_operation_id IS NULL AND start_operation_id IS NULL
                    AND lease_invalidated_at IS NULL)
                 OR (dispatch_operation_id IS NOT NULL
                    AND lease_invalidated_at IS NOT NULL)))
        OR (state='timed_out'
            AND dispatch_operation_id IS NOT NULL
            AND start_operation_id IS NOT NULL
            AND lease_invalidated_at IS NOT NULL
            AND timeout_operation_id IS NOT NULL
            AND terminal_operation_id IS NULL)
        OR (state='indeterminate'
            AND dispatch_operation_id IS NOT NULL
            AND settlement_pending_operation_id IS NOT NULL
            AND lease_invalidated_at IS NOT NULL
            AND terminal_operation_id IS NOT NULL)
    ),
    CONSTRAINT ck_ea_cancellation_shape CHECK (
        (
            cancellation_request_operation_id IS NULL
            AND cancellation_request_revision IS NULL
            AND cancellation_requested_at IS NULL
        ) OR (
            cancellation_request_operation_id IS NOT NULL
            AND cancellation_request_revision BETWEEN 1 AND {MAX_I53}
            AND cancellation_requested_at BETWEEN created_at AND {MAX_I53}
        )
    ),
    CONSTRAINT ck_ea_operation_shape CHECK (
        (queue_operation_id IS NULL)=(queued_at IS NULL)
        AND (dispatch_operation_id IS NULL)=(dispatching_at IS NULL)
        AND (start_operation_id IS NULL)=(started_at IS NULL)
        AND (cancellation_ack_operation_id IS NULL)=(cancellation_acknowledged_at IS NULL)
        AND (timeout_operation_id IS NULL)=(timeout_observed_at IS NULL)
        AND (settlement_pending_operation_id IS NULL)=(settlement_pending_at IS NULL)
        AND (settlement_pending_at IS NULL)=(recovery_deadline_at IS NULL)
        AND (settlement_pending_at IS NULL OR recovery_deadline_at=settlement_pending_at+{
        RECOVERY_WINDOW_MS
    })
        AND (accepted_at IS NULL OR accepted_at>=created_at)
        AND (queued_at IS NULL OR (accepted_at IS NOT NULL AND queued_at>=accepted_at))
        AND (dispatching_at IS NULL OR (accepted_at IS NOT NULL AND dispatching_at>=accepted_at AND (queued_at IS NULL OR dispatching_at>=queued_at)))
        AND (started_at IS NULL OR (dispatching_at IS NOT NULL AND started_at>=dispatching_at))
        AND (cancellation_requested_at IS NULL OR (accepted_at IS NOT NULL AND cancellation_requested_at>=accepted_at))
        AND (cancellation_acknowledged_at IS NULL OR (
            COALESCE(cancellation_requested_at,settlement_pending_at) IS NOT NULL
            AND cancellation_acknowledged_at>=COALESCE(cancellation_requested_at,settlement_pending_at)
        ))
        AND (timeout_observed_at IS NULL OR (started_at IS NOT NULL AND timeout_observed_at>=started_at))
        AND (settlement_pending_at IS NULL OR (dispatching_at IS NOT NULL AND settlement_pending_at>=dispatching_at))
        AND (finished_at IS NULL OR finished_at>=COALESCE(settlement_pending_at,cancellation_requested_at,started_at,dispatching_at,queued_at,accepted_at,created_at))
        AND (settled_at IS NULL OR (finished_at IS NOT NULL AND settled_at>=finished_at))
    ),
    CONSTRAINT ck_ea_terminal_operation CHECK (
        (state IN ('rejected','blocked','succeeded','partial','failed','skipped','indeterminate')
            AND cancellation_ack_operation_id IS NULL
            AND timeout_operation_id IS NULL
            AND terminal_operation_id IS NOT NULL)
        OR (state='cancelled' AND cancellation_ack_operation_id IS NOT NULL AND terminal_operation_id IS NULL)
        OR (state='timed_out' AND timeout_operation_id IS NOT NULL AND terminal_operation_id IS NULL)
        OR (state IN ('accepted','queued','dispatching','running','cancelling','settlement_pending') AND terminal_operation_id IS NULL)
        OR (state IN ('succeeded','partial','failed') AND cancellation_ack_operation_id IS NOT NULL AND terminal_operation_id IS NULL)
    ),
    CONSTRAINT ck_ea_terminal_times CHECK (
        (state IN ('rejected','blocked','succeeded','partial','failed','skipped','cancelled','timed_out','indeterminate')
            AND finished_at IS NOT NULL AND settled_at IS NOT NULL)
        OR (state IN ('accepted','queued','dispatching','running','cancelling','settlement_pending')
            AND finished_at IS NULL AND settled_at IS NULL)
    ),
    CONSTRAINT ck_ea_recovery_shape CHECK (
        (state='settlement_pending'
            AND settlement_pending_operation_id IS NOT NULL
            AND lease_invalidated_at IS NOT NULL
            AND settlement_state='recovery_pending'
            AND settlement_proof_code='unresolved'
            AND termination_confirmed={false})
        OR state<>'settlement_pending'
    ),
    CONSTRAINT ck_ea_resolver_shape CHECK (
        (state='indeterminate'
            AND resolver_subject_ref IS NOT NULL
            AND resolver_authority_revision BETWEEN 0 AND {MAX_I53}
            AND bounded_recovery_proof_code='recovery_sources_exhausted')
        OR (state<>'indeterminate'
            AND resolver_subject_ref IS NULL
            AND resolver_user_id IS NULL
            AND resolver_authority_revision IS NULL
            AND bounded_recovery_proof_code IS NULL)
    ),
    CONSTRAINT fk_ea_logical_campaign FOREIGN KEY (campaign_id,logical_execution_id)
        REFERENCES logical_executions(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_ea_parent FOREIGN KEY (logical_execution_id,parent_attempt_id)
        REFERENCES execution_attempts(logical_execution_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_ea_actor_user FOREIGN KEY (actor_user_id)
        REFERENCES users(id) ON UPDATE NO ACTION ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_ea_resolver_user FOREIGN KEY (resolver_user_id)
        REFERENCES users(id) ON UPDATE NO ACTION ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED
)"""

    actor_authority = f"""
CREATE TABLE execution_actor_authority_revisions (
    user_id TEXT NOT NULL CONSTRAINT pk_eaar PRIMARY KEY,
    revision {integer} NOT NULL DEFAULT 0,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL DEFAULT 0,
    latest_operation_code TEXT NOT NULL,
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_eaar_user CHECK ({uuid("user_id")}),
    CONSTRAINT ck_eaar_operation CHECK ({uuid("latest_operation_id")}),
    CONSTRAINT ck_eaar_shape CHECK (
        revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_code IN ('ensure','invalidate')
        AND ((revision=0 AND latest_operation_code='ensure' AND latest_operation_base_revision=0)
             OR (revision>=1 AND latest_operation_base_revision=revision-1))
        AND updated_at BETWEEN 0 AND {MAX_I53}
    ),
    CONSTRAINT fk_eaar_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON UPDATE NO ACTION ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
)"""

    campaign_authority = f"""
CREATE TABLE campaign_execution_authority_revisions (
    campaign_id TEXT NOT NULL CONSTRAINT pk_cear PRIMARY KEY,
    revision {integer} NOT NULL DEFAULT 0,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL DEFAULT 0,
    latest_operation_code TEXT NOT NULL,
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_cear_operation CHECK ({uuid("latest_operation_id")}),
    CONSTRAINT ck_cear_campaign CHECK ({uuid("campaign_id")}),
    CONSTRAINT ck_cear_shape CHECK (
        revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_code IN ('ensure','invalidate')
        AND ((revision=0 AND latest_operation_code='ensure' AND latest_operation_base_revision=0)
             OR (revision>=1 AND latest_operation_base_revision=revision-1))
        AND updated_at BETWEEN 0 AND {MAX_I53}
    ),
    CONSTRAINT fk_cear_campaign FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)"""

    budgets = f"""
CREATE TABLE campaign_execution_budgets (
    id TEXT NOT NULL CONSTRAINT pk_ceb PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    budget_kind TEXT NOT NULL,
    capacity_units {integer} NOT NULL,
    reserved_units {integer} NOT NULL DEFAULT 0,
    consumed_units {integer} NOT NULL DEFAULT 0,
    revision {integer} NOT NULL DEFAULT 0,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL DEFAULT 0,
    latest_operation_code TEXT NOT NULL,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT uq_ceb_campaign_kind UNIQUE (campaign_id,budget_kind),
    CONSTRAINT uq_ceb_campaign_id_kind UNIQUE (campaign_id,id,budget_kind),
    CONSTRAINT ck_ceb_id CHECK ({uuid("id")}),
    CONSTRAINT ck_ceb_campaign CHECK ({uuid("campaign_id")}),
    CONSTRAINT ck_ceb_operation CHECK ({uuid("latest_operation_id")}),
    CONSTRAINT ck_ceb_shape CHECK (
        budget_kind IN ('noise','exfiltration','concurrency')
        AND capacity_units BETWEEN 0 AND {MAX_I53}
        AND reserved_units BETWEEN 0 AND {MAX_I53}
        AND consumed_units BETWEEN 0 AND {MAX_I53}
        AND reserved_units+consumed_units<=capacity_units
        AND (budget_kind<>'concurrency' OR capacity_units>=1)
        AND revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_code IN ('configure','reserve','settle')
        AND ((revision=0 AND latest_operation_code='configure' AND latest_operation_base_revision=0)
             OR (revision>=1 AND latest_operation_base_revision=revision-1))
        AND created_at BETWEEN 0 AND {MAX_I53}
        AND updated_at BETWEEN created_at AND {MAX_I53}
    ),
    CONSTRAINT fk_ceb_campaign FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)"""

    approvals = f"""
CREATE TABLE execution_attempt_approvals (
    id TEXT NOT NULL CONSTRAINT pk_eaa PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    approval_ref TEXT NOT NULL,
    approver_subject_ref TEXT NOT NULL,
    approver_user_id TEXT,
    authority_revision {integer} NOT NULL,
    binding_digest TEXT NOT NULL,
    bound_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT uq_eaa_attempt UNIQUE (attempt_id),
    CONSTRAINT uq_eaa_approval_ref UNIQUE (approval_ref),
    CONSTRAINT ck_eaa_ids CHECK (
        ({uuid("id")}) AND ({uuid("attempt_id")}) AND ({uuid("campaign_id")})
        AND ({uuid("approval_ref")})
        AND ({uuid("approver_subject_ref")})
        AND (approver_user_id IS NULL OR ({uuid("approver_user_id")}))
    ),
    CONSTRAINT ck_eaa_digest CHECK ({h64("binding_digest")}),
    CONSTRAINT ck_eaa_bounds CHECK (
        authority_revision BETWEEN 0 AND {MAX_I53}
        AND bound_at BETWEEN 0 AND {MAX_I53}
    ),
    CONSTRAINT fk_eaa_attempt FOREIGN KEY (campaign_id,attempt_id)
        REFERENCES execution_attempts(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eaa_user FOREIGN KEY (approver_user_id) REFERENCES users(id)
        ON UPDATE NO ACTION ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
)"""

    ledger = f"""
CREATE TABLE campaign_execution_budget_ledger (
    id TEXT NOT NULL CONSTRAINT pk_cebl PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    budget_id TEXT NOT NULL,
    budget_kind TEXT NOT NULL,
    reservation_units {integer} NOT NULL,
    consumed_units {integer} NOT NULL DEFAULT 0,
    disposition TEXT NOT NULL,
    budget_revision_reserved {integer} NOT NULL,
    budget_revision_settled {integer},
    reserved_at {integer} NOT NULL DEFAULT ({now_ms}),
    settled_at {integer},
    CONSTRAINT uq_cebl_attempt_kind UNIQUE (attempt_id,budget_kind),
    CONSTRAINT uq_cebl_budget_attempt UNIQUE (budget_id,attempt_id),
    CONSTRAINT ck_cebl_ids CHECK (({uuid("id")}) AND ({uuid("attempt_id")}) AND ({uuid("campaign_id")}) AND ({uuid("budget_id")})),
    CONSTRAINT ck_cebl_shape CHECK (
        budget_kind IN ('noise','exfiltration','concurrency')
        AND reservation_units BETWEEN 0 AND {MAX_I53}
        AND consumed_units BETWEEN 0 AND reservation_units
        AND disposition IN ('held','released','consumed')
        AND budget_revision_reserved BETWEEN 0 AND {MAX_I53}
        AND (budget_revision_settled IS NULL OR budget_revision_settled BETWEEN 0 AND {MAX_I53})
        AND reserved_at BETWEEN 0 AND {MAX_I53}
        AND (settled_at IS NULL OR settled_at BETWEEN reserved_at AND {MAX_I53})
        AND ((disposition='held' AND consumed_units=0 AND budget_revision_settled IS NULL AND settled_at IS NULL)
             OR (disposition='released' AND consumed_units=0 AND budget_revision_settled IS NOT NULL AND settled_at IS NOT NULL)
             OR (disposition='consumed' AND budget_revision_settled IS NOT NULL AND settled_at IS NOT NULL))
        AND (budget_kind<>'concurrency' OR (reservation_units=1 AND consumed_units=0 AND disposition<>'consumed'))
    ),
    CONSTRAINT fk_cebl_attempt FOREIGN KEY (campaign_id,attempt_id)
        REFERENCES execution_attempts(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_cebl_budget FOREIGN KEY (campaign_id,budget_id,budget_kind)
        REFERENCES campaign_execution_budgets(campaign_id,id,budget_kind)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)"""

    links = f"""
CREATE TABLE execution_output_links (
    id TEXT NOT NULL CONSTRAINT pk_eol PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    finding_id TEXT,
    credential_id TEXT,
    host_id TEXT,
    loot_id TEXT,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_eol_ids CHECK (
        ({uuid("id")}) AND ({uuid("attempt_id")}) AND ({uuid("campaign_id")})
        AND (finding_id IS NULL OR ({uuid("finding_id")}))
        AND (credential_id IS NULL OR ({uuid("credential_id")}))
        AND (host_id IS NULL OR ({uuid("host_id")}))
        AND (loot_id IS NULL OR ({uuid("loot_id")}))
    ),
    CONSTRAINT ck_eol_exactly_one CHECK (
        (CASE WHEN finding_id IS NOT NULL THEN 1 ELSE 0 END)
        +(CASE WHEN credential_id IS NOT NULL THEN 1 ELSE 0 END)
        +(CASE WHEN host_id IS NOT NULL THEN 1 ELSE 0 END)
        +(CASE WHEN loot_id IS NOT NULL THEN 1 ELSE 0 END)=1
    ),
    CONSTRAINT ck_eol_created CHECK (created_at BETWEEN 0 AND {MAX_I53}),
    CONSTRAINT fk_eol_attempt FOREIGN KEY (campaign_id,attempt_id)
        REFERENCES execution_attempts(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eol_finding FOREIGN KEY (campaign_id,finding_id)
        REFERENCES findings(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eol_credential FOREIGN KEY (campaign_id,credential_id)
        REFERENCES credentials(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eol_host FOREIGN KEY (campaign_id,host_id)
        REFERENCES hosts(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eol_loot FOREIGN KEY (campaign_id,loot_id)
        REFERENCES loot(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)"""

    outbox = f"""
CREATE TABLE execution_publication_outbox (
    id TEXT NOT NULL CONSTRAINT pk_epo PRIMARY KEY,
    publication_key TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    event_code TEXT NOT NULL,
    is_attempt_terminal {boolean} NOT NULL,
    finding_count {integer} NOT NULL DEFAULT 0,
    credential_count {integer} NOT NULL DEFAULT 0,
    host_count {integer} NOT NULL DEFAULT 0,
    artifact_count {integer} NOT NULL DEFAULT 0,
    publication_state TEXT NOT NULL DEFAULT {pending_default},
    delivery_attempt_count {integer} NOT NULL DEFAULT 0,
    available_at {integer},
    claim_owner_ref TEXT,
    lease_generation {integer} NOT NULL DEFAULT 0,
    claimed_at {integer},
    lease_expires_at {integer},
    published_at {integer},
    poisoned_at {integer},
    failure_code TEXT,
    claim_revision {integer} NOT NULL DEFAULT 0,
    latest_operation_id TEXT NOT NULL,
    latest_operation_code TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT uq_epo_publication_key UNIQUE (publication_key),
    CONSTRAINT uq_epo_attempt_event UNIQUE (attempt_id,event_code),
    CONSTRAINT ck_epo_ids CHECK (
        ({uuid("id")}) AND ({uuid("publication_key")}) AND ({uuid("attempt_id")})
        AND ({uuid("campaign_id")})
        AND ({uuid("latest_operation_id")})
        AND (claim_owner_ref IS NULL OR ({uuid("claim_owner_ref")}))
    ),
    CONSTRAINT ck_epo_event CHECK ({_in("event_code", ("recovery_required", "execution_rejected", "execution_blocked", "execution_succeeded", "execution_partial", "execution_failed", "execution_skipped", "execution_cancelled", "execution_timed_out", "execution_indeterminate", "logical_execution_closed"))}),
    CONSTRAINT ck_epo_counts CHECK (
        finding_count BETWEEN 0 AND {MAX_I53}
        AND credential_count BETWEEN 0 AND {MAX_I53}
        AND host_count BETWEEN 0 AND {MAX_I53}
        AND artifact_count BETWEEN 0 AND {MAX_I53}
        AND (event_code IN ('execution_succeeded','execution_partial')
             OR (finding_count=0 AND credential_count=0 AND host_count=0 AND artifact_count=0))
        AND (event_code<>'execution_partial'
             OR finding_count+credential_count+host_count+artifact_count>=1)
    ),
    CONSTRAINT ck_epo_terminal_flag CHECK (
        ({b("is_attempt_terminal")}) AND
        ((event_code IN ('execution_rejected','execution_blocked','execution_succeeded','execution_partial','execution_failed','execution_skipped','execution_cancelled','execution_timed_out','execution_indeterminate') AND is_attempt_terminal={true})
         OR (event_code IN ('recovery_required','logical_execution_closed') AND is_attempt_terminal={false}))
    ),
    CONSTRAINT ck_epo_state CHECK ({_in("publication_state", ("pending", "claimed", "published", "poisoned"))}),
    CONSTRAINT ck_epo_failure CHECK (failure_code IS NULL OR {_in("failure_code", ("delivery_retryable", "delivery_nonretryable", "delivery_attempt_limit"))}),
    CONSTRAINT ck_epo_latest_code CHECK ({_in("latest_operation_code", ("insert", "claim", "reclaim", "renew", "publish", "retryable_failure", "nonretryable_failure", "poison"))}),
    CONSTRAINT ck_epo_bounds CHECK (
        delivery_attempt_count BETWEEN 0 AND 20
        AND lease_generation BETWEEN 0 AND {MAX_I53}
        AND claim_revision BETWEEN 0 AND {MAX_I53}
        AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53}
        AND created_at BETWEEN 0 AND {MAX_I53}
        AND (available_at IS NULL OR available_at BETWEEN created_at AND {MAX_I53})
        AND (claimed_at IS NULL OR claimed_at BETWEEN created_at AND {MAX_I53})
        AND (lease_expires_at IS NULL OR lease_expires_at BETWEEN created_at AND {MAX_I53})
        AND (published_at IS NULL OR published_at BETWEEN created_at AND {MAX_I53})
        AND (poisoned_at IS NULL OR poisoned_at BETWEEN created_at AND {MAX_I53})
    ),
    CONSTRAINT ck_epo_insert_shape CHECK (
        latest_operation_code<>'insert'
        OR (latest_operation_id=publication_key AND latest_operation_base_revision=0 AND claim_revision=0)
    ),
    CONSTRAINT ck_epo_state_shape CHECK (
        (publication_state='pending'
            AND claim_owner_ref IS NULL AND lease_expires_at IS NULL
            AND published_at IS NULL AND poisoned_at IS NULL
            AND ((delivery_attempt_count=0 AND claimed_at IS NULL AND failure_code IS NULL AND available_at IS NOT NULL)
                 OR (delivery_attempt_count BETWEEN 1 AND 19 AND claimed_at IS NOT NULL AND failure_code='delivery_retryable' AND available_at IS NOT NULL)))
        OR (publication_state='claimed'
            AND delivery_attempt_count BETWEEN 1 AND 20
            AND claim_owner_ref IS NOT NULL AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL
            AND available_at IS NULL AND failure_code IS NULL AND published_at IS NULL AND poisoned_at IS NULL)
        OR (publication_state='published'
            AND claim_owner_ref IS NULL AND lease_expires_at IS NULL AND available_at IS NULL
            AND claimed_at IS NOT NULL AND published_at IS NOT NULL AND poisoned_at IS NULL AND failure_code IS NULL)
        OR (publication_state='poisoned'
            AND claim_owner_ref IS NULL AND lease_expires_at IS NULL AND available_at IS NULL
            AND claimed_at IS NOT NULL AND published_at IS NULL AND poisoned_at IS NOT NULL AND failure_code IS NOT NULL)
    ),
    CONSTRAINT fk_epo_attempt FOREIGN KEY (campaign_id,attempt_id)
        REFERENCES execution_attempts(campaign_id,id)
        ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)"""

    receipts = f"""
CREATE TABLE execution_operation_receipts (
    operation_id TEXT NOT NULL CONSTRAINT pk_eor PRIMARY KEY,
    operation_code TEXT NOT NULL,
    campaign_id TEXT,
    primary_target_id TEXT NOT NULL,
    secondary_target_id TEXT,
    principal_kind TEXT NOT NULL,
    principal_subject_ref TEXT NOT NULL,
    principal_user_id TEXT,
    principal_authority_revision_present {boolean} NOT NULL,
    principal_authority_revision {integer},
    binding_contract_version {integer} NOT NULL,
    request_binding_digest TEXT NOT NULL,
    expected_revision_present {boolean} NOT NULL,
    expected_revision {integer},
    secondary_expected_revision_present {boolean} NOT NULL,
    secondary_expected_revision {integer},
    owner_ref TEXT,
    lease_generation {integer},
    result_code TEXT NOT NULL,
    exact_replay_code TEXT NOT NULL,
    result_binding_digest TEXT NOT NULL,
    result_identity TEXT,
    result_revision_present {boolean} NOT NULL,
    result_revision {integer},
    secondary_result_identity TEXT,
    secondary_result_revision_present {boolean} NOT NULL,
    secondary_result_revision {integer},
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_eor_ids CHECK (
        ({uuid("operation_id")})
        AND (campaign_id IS NULL OR ({uuid("campaign_id")}))
        AND ({uuid("primary_target_id")})
        AND (secondary_target_id IS NULL OR ({uuid("secondary_target_id")}))
        AND ({uuid("principal_subject_ref")})
        AND (principal_user_id IS NULL OR ({uuid("principal_user_id")}))
        AND (owner_ref IS NULL OR ({uuid("owner_ref")}))
        AND (result_identity IS NULL OR ({uuid("result_identity")}))
        AND (secondary_result_identity IS NULL OR ({uuid("secondary_result_identity")}))
    ),
    CONSTRAINT ck_eor_operation_code CHECK ({_in("operation_code", OPERATION_CODES)}),
    CONSTRAINT ck_eor_principal_kind CHECK ({_in("principal_kind", PRINCIPAL_KINDS)}),
    CONSTRAINT ck_eor_principal_shape CHECK (
        (
            principal_kind IN ('actor','resolver')
            AND principal_user_id IS NOT NULL
            AND principal_authority_revision_present={true}
            AND principal_authority_revision IS NOT NULL
        ) OR (
            principal_kind IN ('worker','system')
            AND principal_user_id IS NULL
            AND principal_authority_revision_present={false}
            AND principal_authority_revision IS NULL
        )
    ),
    CONSTRAINT ck_eor_system_principal CHECK (
        principal_kind<>'system'
        OR principal_subject_ref='{SYSTEM_PRINCIPAL_SUBJECT_REF}'
    ),
    CONSTRAINT ck_eor_contract CHECK (binding_contract_version=2),
    CONSTRAINT ck_eor_request_digest CHECK ({h64("request_binding_digest")}),
    CONSTRAINT ck_eor_result_code CHECK ({_in("result_code", tuple(value.value for value in FixedResult))}),
    CONSTRAINT ck_eor_exact_replay_code CHECK ({_in("exact_replay_code", ("replayed", "replayed_bound_child", "replayed_closed"))}),
    CONSTRAINT ck_eor_result_digest CHECK ({h64("result_binding_digest")}),
    CONSTRAINT ck_eor_presence CHECK (
        (expected_revision_present={true}) = (expected_revision IS NOT NULL)
        AND (secondary_expected_revision_present={true}) = (secondary_expected_revision IS NOT NULL)
        AND (result_revision_present={true}) = (result_revision IS NOT NULL)
        AND (secondary_result_revision_present={true}) = (secondary_result_revision IS NOT NULL)
    ),
    CONSTRAINT ck_eor_operation_shape CHECK (
        (
            operation_code IN (
                'actor_authority_ensure','campaign_authority_ensure','budget_configure',
                'admission','outbox_insert','campaign_delete'
            )
            AND expected_revision_present={false}
            AND secondary_expected_revision_present={false}
        ) OR (
            operation_code IN (
                'actor_authority_invalidate','campaign_authority_invalidate','retry',
                'queue','dispatch','start','cancellation_request',
                'cancellation_acknowledgement','timeout','settlement_pending','lease_loss',
                'recovery_succeeded','recovery_partial','recovery_failed',
                'recovery_cancelled','recovery_timed_out','recovery_indeterminate',
                'terminal_succeeded','terminal_partial','terminal_failed','terminal_skipped',
                'close_without_retry','outbox_claim','outbox_reclaim','outbox_renew',
                'outbox_publish','outbox_retryable_failure','outbox_nonretryable_failure',
                'outbox_poison','outbox_purge'
            )
            AND expected_revision_present={true}
            AND secondary_expected_revision_present={false}
        ) OR (
            operation_code IN ('budget_reserve','budget_settle')
            AND expected_revision_present={true}
            AND secondary_expected_revision_present={true}
        )
    ),
    CONSTRAINT ck_eor_outbox_owner_shape CHECK (
        (
            operation_code IN (
                'outbox_claim','outbox_reclaim','outbox_renew','outbox_publish',
                'outbox_retryable_failure','outbox_nonretryable_failure'
            )
            AND owner_ref IS NOT NULL
            AND lease_generation IS NOT NULL
        ) OR (
            operation_code IN ('outbox_insert','outbox_poison','outbox_purge')
            AND owner_ref IS NULL
            AND lease_generation IS NULL
        ) OR operation_code NOT IN (
            'outbox_insert','outbox_claim','outbox_reclaim','outbox_renew','outbox_publish',
            'outbox_retryable_failure','outbox_nonretryable_failure','outbox_poison',
            'outbox_purge'
        )
    ),
    CONSTRAINT ck_eor_bounds CHECK (
        (expected_revision IS NULL OR expected_revision BETWEEN 0 AND {MAX_I53})
        AND (secondary_expected_revision IS NULL OR secondary_expected_revision BETWEEN 0 AND {MAX_I53})
        AND (lease_generation IS NULL OR lease_generation BETWEEN 0 AND {MAX_I53})
        AND (result_revision IS NULL OR result_revision BETWEEN 0 AND {MAX_I53})
        AND (secondary_result_revision IS NULL OR secondary_result_revision BETWEEN 0 AND {MAX_I53})
        AND created_at BETWEEN 0 AND {MAX_I53}
    ),
    CONSTRAINT ck_eor_owner_generation CHECK (
        (owner_ref IS NULL AND lease_generation IS NULL)
        OR (owner_ref IS NOT NULL AND lease_generation IS NOT NULL)
    )
)"""

    if dialect == "postgresql":
        receipt_immutability = (
            "CREATE FUNCTION execution_operation_receipt_immutable() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
            "'immutable execution operation receipt' USING ERRCODE='55000'; END $$",
            "CREATE TRIGGER trg_eor_immutable BEFORE UPDATE OR DELETE "
            "ON execution_operation_receipts FOR EACH ROW "
            "EXECUTE FUNCTION execution_operation_receipt_immutable()",
        )
    else:
        receipt_immutability = (
            "CREATE TRIGGER trg_eor_immutable_update BEFORE UPDATE "
            "ON execution_operation_receipts BEGIN "
            "SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
            "CREATE TRIGGER trg_eor_immutable_delete BEFORE DELETE "
            "ON execution_operation_receipts BEGIN "
            "SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
        )

    gateway = f"""
CREATE TABLE execution_gateway_state (
    singleton_id {integer} NOT NULL CONSTRAINT pk_egs PRIMARY KEY,
    mode TEXT NOT NULL,
    catalog_digest TEXT,
    activation_revision {integer},
    activation_at {integer},
    revision {integer} NOT NULL DEFAULT 0,
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_egs_singleton CHECK (singleton_id=1),
    CONSTRAINT ck_egs_mode CHECK ({_in("mode", ("disabled", "shadow_candidate", "enforced", "emergency_disabled"))}),
    CONSTRAINT ck_egs_digest CHECK (catalog_digest IS NULL OR ({h64("catalog_digest")})),
    CONSTRAINT ck_egs_shape CHECK (
        (mode='disabled' AND catalog_digest IS NULL AND activation_revision IS NULL AND activation_at IS NULL AND revision=0)
        OR (mode IN ('shadow_candidate','enforced','emergency_disabled')
            AND catalog_digest IS NOT NULL
            AND activation_revision BETWEEN 1 AND {MAX_I53}
            AND activation_at BETWEEN 0 AND {MAX_I53}
            AND revision BETWEEN 1 AND {MAX_I53})
    )
)"""

    statements: list[str] = [logical, attempts]
    if dialect == "postgresql":
        statements.append(
            "ALTER TABLE logical_executions ADD CONSTRAINT fk_le_closing_attempt "
            "FOREIGN KEY (id,closing_attempt_id) "
            "REFERENCES execution_attempts(logical_execution_id,id) "
            "ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED"
        )
    statements.extend([actor_authority, campaign_authority, budgets, approvals, ledger])

    if dialect == "postgresql":
        statements.extend(
            [
                "ALTER TABLE findings ADD CONSTRAINT uq_findings_campaign_id_id UNIQUE (campaign_id,id)",
                "ALTER TABLE credentials ADD CONSTRAINT uq_credentials_campaign_id_id UNIQUE (campaign_id,id)",
                "ALTER TABLE hosts ADD CONSTRAINT uq_hosts_campaign_id_id UNIQUE (campaign_id,id)",
                "ALTER TABLE loot ADD CONSTRAINT uq_loot_campaign_id_id UNIQUE (campaign_id,id)",
            ]
        )
    else:
        statements.extend(
            [
                "CREATE UNIQUE INDEX uq_findings_campaign_id_id ON findings(campaign_id,id)",
                "CREATE UNIQUE INDEX uq_credentials_campaign_id_id ON credentials(campaign_id,id)",
                "CREATE UNIQUE INDEX uq_hosts_campaign_id_id ON hosts(campaign_id,id)",
                "CREATE UNIQUE INDEX uq_loot_campaign_id_id ON loot(campaign_id,id)",
            ]
        )
    statements.extend([links, outbox, receipts, *receipt_immutability, gateway])
    statements.extend(
        [
            "CREATE UNIQUE INDEX uq_le_closure_operation ON logical_executions(closure_operation_id) WHERE closure_operation_id IS NOT NULL",
            "CREATE INDEX ix_le_campaign_created ON logical_executions(campaign_id,created_at,id)",
            "CREATE UNIQUE INDEX uq_ea_one_child ON execution_attempts(logical_execution_id,parent_attempt_id) WHERE parent_attempt_id IS NOT NULL",
            "CREATE INDEX ix_ea_dispatch_lease ON execution_attempts(state,lease_expires_at,id) WHERE state IN ('dispatching','running','cancelling')",
            "CREATE INDEX ix_ea_recovery_deadline ON execution_attempts(state,recovery_deadline_at,id) WHERE state='settlement_pending'",
            "CREATE INDEX ix_ea_logical_state ON execution_attempts(logical_execution_id,state,ordinal)",
            "CREATE UNIQUE INDEX uq_eaar_latest_operation ON execution_actor_authority_revisions(latest_operation_id)",
            "CREATE UNIQUE INDEX uq_cear_latest_operation ON campaign_execution_authority_revisions(latest_operation_id)",
            "CREATE INDEX ix_cebl_budget ON campaign_execution_budget_ledger(budget_id,disposition,attempt_id)",
            "CREATE INDEX ix_eol_attempt ON execution_output_links(attempt_id)",
            "CREATE UNIQUE INDEX uq_eol_attempt_finding ON execution_output_links(attempt_id,finding_id) WHERE finding_id IS NOT NULL",
            "CREATE UNIQUE INDEX uq_eol_attempt_credential ON execution_output_links(attempt_id,credential_id) WHERE credential_id IS NOT NULL",
            "CREATE UNIQUE INDEX uq_eol_attempt_host ON execution_output_links(attempt_id,host_id) WHERE host_id IS NOT NULL",
            "CREATE UNIQUE INDEX uq_eol_attempt_loot ON execution_output_links(attempt_id,loot_id) WHERE loot_id IS NOT NULL",
            "CREATE INDEX ix_eol_finding ON execution_output_links(campaign_id,finding_id) WHERE finding_id IS NOT NULL",
            "CREATE INDEX ix_eol_credential ON execution_output_links(campaign_id,credential_id) WHERE credential_id IS NOT NULL",
            "CREATE INDEX ix_eol_host ON execution_output_links(campaign_id,host_id) WHERE host_id IS NOT NULL",
            "CREATE INDEX ix_eol_loot ON execution_output_links(campaign_id,loot_id) WHERE loot_id IS NOT NULL",
            "CREATE UNIQUE INDEX uq_epo_one_terminal ON execution_publication_outbox(attempt_id) WHERE is_attempt_terminal="
            + true,
            "CREATE INDEX ix_epo_available ON execution_publication_outbox(publication_state,available_at,id)",
            "CREATE INDEX ix_epo_lease ON execution_publication_outbox(publication_state,lease_expires_at,id)",
            "CREATE INDEX ix_epo_retention ON execution_publication_outbox(publication_state,published_at,poisoned_at,id)",
            "CREATE INDEX ix_eor_campaign_created ON execution_operation_receipts(campaign_id,created_at,operation_id)",
            "CREATE INDEX ix_eor_primary_target ON execution_operation_receipts(primary_target_id,operation_code,created_at)",
            "CREATE INDEX ix_eor_principal_created ON execution_operation_receipts(principal_kind,principal_subject_ref,created_at,operation_id)",
            "INSERT INTO execution_gateway_state(singleton_id,mode,revision) VALUES(1,'disabled',0)",
        ]
    )
    return tuple(statement.strip() for statement in statements)


SQLITE_LIFECYCLE_DDL: Final[tuple[str, ...]] = lifecycle_ddl("sqlite")
POSTGRES_LIFECYCLE_DDL: Final[tuple[str, ...]] = lifecycle_ddl("postgresql")


def _v11_receipt_create_statement(dialect: str) -> str:
    """Return the generation-10 receipt table widened only for v11 codes."""
    source = POSTGRES_LIFECYCLE_DDL if dialect == "postgresql" else SQLITE_LIFECYCLE_DDL
    statement = next(
        item for item in source if item.startswith("CREATE TABLE execution_operation_receipts")
    )
    statement = statement.replace(
        _in("operation_code", OPERATION_CODES),
        _in("operation_code", V11_OPERATION_CODES),
        1,
    )
    statement = statement.replace(
        "'admission','outbox_insert','campaign_delete'\n            )",
        "'admission','outbox_insert','campaign_delete','approval_authority_grant'\n            )",
        1,
    )
    one_revision = ",".join(
        repr(value)
        for value in V11_ADDITIVE_OPERATION_CODES
        if value not in {"approval_authority_grant", "campaign_actor_grant_put"}
    )
    statement = statement.replace(
        "'outbox_poison','outbox_purge'\n            )",
        "'outbox_poison','outbox_purge'," + one_revision + "\n            )",
        1,
    )
    statement = statement.replace(
        ") OR (\n            operation_code IN ('budget_reserve','budget_settle')",
        ") OR (\n            operation_code='campaign_actor_grant_put'\n"
        "            AND secondary_expected_revision_present="
        + ("FALSE" if dialect == "postgresql" else "0")
        + "\n        ) OR (\n            operation_code IN ('budget_reserve','budget_settle')",
        1,
    )
    if _in("operation_code", V11_OPERATION_CODES) not in statement:
        raise RuntimeError("Invalid generation-11 receipt DDL")
    return statement


def admission_authority_v11_ddl(dialect: str) -> tuple[str, ...]:
    """Return additive generation-11 admission-authority DDL.

    Generation-10 objects are altered only through new columns and two widened
    receipt checks.  Historical receipt bytes and all v10 digest semantics stay
    untouched.
    """
    if dialect not in {"sqlite", "postgresql"}:
        raise ValueError("Unsupported admission-authority dialect")
    integer = "BIGINT" if dialect == "postgresql" else "INTEGER"
    now_ms = (
        "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
        if dialect == "postgresql"
        else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
    )

    def uuid(column: str) -> str:
        return _uuid_check(column, dialect)

    def h64(column: str) -> str:
        return _h64_check(column, dialect)

    zero_digest = "0" * 64

    statements: list[str] = [
        "ALTER TABLE logical_executions ADD COLUMN admission_authority_contract_version "
        f"{integer} NOT NULL DEFAULT 2 CHECK (admission_authority_contract_version IN (2,3))",
        "ALTER TABLE logical_executions ADD COLUMN canonical_principal_user_id TEXT "
        f"CHECK (canonical_principal_user_id IS NULL OR ({uuid('canonical_principal_user_id')}))",
        "ALTER TABLE logical_executions ADD COLUMN immutable_intent_digest TEXT "
        f"CHECK (immutable_intent_digest IS NULL OR ({h64('immutable_intent_digest')}))",
        "ALTER TABLE logical_executions ADD COLUMN immutable_work_digest TEXT "
        f"CHECK (immutable_work_digest IS NULL OR ({h64('immutable_work_digest')}))",
        "ALTER TABLE execution_attempts ADD COLUMN authority_contract_version "
        f"{integer} NOT NULL DEFAULT 2 CHECK (authority_contract_version IN (2,3))",
        "ALTER TABLE execution_attempts ADD COLUMN trusted_principal_subject_ref TEXT "
        f"CHECK (trusted_principal_subject_ref IS NULL OR ({uuid('trusted_principal_subject_ref')}))",
        "ALTER TABLE execution_attempts ADD COLUMN trusted_principal_user_id TEXT "
        f"CHECK (trusted_principal_user_id IS NULL OR ({uuid('trusted_principal_user_id')}))",
        "ALTER TABLE execution_attempts ADD COLUMN immutable_intent_digest TEXT "
        f"CHECK (immutable_intent_digest IS NULL OR ({h64('immutable_intent_digest')}))",
        "ALTER TABLE execution_attempts ADD COLUMN immutable_work_digest TEXT "
        f"CHECK (immutable_work_digest IS NULL OR ({h64('immutable_work_digest')}))",
        "ALTER TABLE execution_attempts ADD COLUMN gateway_revision "
        f"{integer} CHECK (gateway_revision IS NULL OR gateway_revision BETWEEN 0 AND {MAX_I53})",
        "ALTER TABLE execution_attempts ADD COLUMN gateway_activation_revision "
        f"{integer} CHECK (gateway_activation_revision IS NULL OR gateway_activation_revision BETWEEN 0 AND {MAX_I53})",
        "ALTER TABLE execution_attempts ADD COLUMN campaign_actor_grant_revision "
        f"{integer} CHECK (campaign_actor_grant_revision IS NULL OR campaign_actor_grant_revision BETWEEN 0 AND {MAX_I53})",
        "ALTER TABLE execution_attempts ADD COLUMN destination_authority_binding_digest TEXT "
        f"CHECK (destination_authority_binding_digest IS NULL OR ({h64('destination_authority_binding_digest')}))",
        "ALTER TABLE execution_attempts ADD COLUMN credential_authority_binding_digest TEXT "
        f"CHECK (credential_authority_binding_digest IS NULL OR ({h64('credential_authority_binding_digest')}))",
        "ALTER TABLE execution_attempts ADD COLUMN approval_authority_binding_digest TEXT "
        f"CHECK (approval_authority_binding_digest IS NULL OR ({h64('approval_authority_binding_digest')}))",
    ]
    for table in (
        "execution_actor_authority_revisions",
        "campaign_execution_authority_revisions",
    ):
        statements.extend(
            [
                f"ALTER TABLE {table} ADD COLUMN authority_state TEXT NOT NULL DEFAULT 'active' "
                "CHECK (authority_state IN ('active','revoked'))",
                f"ALTER TABLE {table} ADD COLUMN authority_revision {integer} NOT NULL DEFAULT 0 "
                f"CHECK (authority_revision BETWEEN 0 AND {MAX_I53})",
                f"ALTER TABLE {table} ADD COLUMN authority_binding_digest TEXT NOT NULL "
                f"DEFAULT '{zero_digest}' CHECK ({h64('authority_binding_digest')})",
                f"ALTER TABLE {table} ADD COLUMN authority_latest_operation_id TEXT "
                f"CHECK (authority_latest_operation_id IS NULL OR ({uuid('authority_latest_operation_id')}))",
                f"ALTER TABLE {table} ADD COLUMN authority_latest_operation_base_revision {integer} "
                f"CHECK (authority_latest_operation_base_revision IS NULL OR authority_latest_operation_base_revision BETWEEN 0 AND {MAX_I53})",
                f"ALTER TABLE {table} ADD COLUMN authority_latest_operation_code TEXT "
                "CHECK (authority_latest_operation_code IS NULL OR authority_latest_operation_code IN ('activate','update','revoke'))",
            ]
        )
    statements.extend(
        [
            "ALTER TABLE credentials ADD COLUMN execution_authority_state TEXT NOT NULL DEFAULT 'active' "
            "CHECK (execution_authority_state IN ('active','revoked'))",
            "ALTER TABLE credentials ADD COLUMN execution_authority_revision "
            f"{integer} NOT NULL DEFAULT 0 CHECK (execution_authority_revision BETWEEN 0 AND {MAX_I53})",
            "ALTER TABLE credentials ADD COLUMN execution_authority_binding_digest TEXT NOT NULL "
            f"DEFAULT '{zero_digest}' CHECK ({h64('execution_authority_binding_digest')})",
            "ALTER TABLE credentials ADD COLUMN execution_authority_latest_operation_id TEXT "
            f"CHECK (execution_authority_latest_operation_id IS NULL OR ({uuid('execution_authority_latest_operation_id')}))",
            "ALTER TABLE credentials ADD COLUMN execution_authority_latest_operation_base_revision "
            f"{integer} CHECK (execution_authority_latest_operation_base_revision IS NULL OR execution_authority_latest_operation_base_revision BETWEEN 0 AND {MAX_I53})",
            "ALTER TABLE credentials ADD COLUMN execution_authority_latest_operation_code TEXT "
            "CHECK (execution_authority_latest_operation_code IS NULL OR execution_authority_latest_operation_code IN ('update','revoke'))",
        ]
    )

    statements.extend(
        [
            f"""CREATE TABLE campaign_execution_actor_grants (
    campaign_id TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    authority_state TEXT NOT NULL,
    revision {integer} NOT NULL DEFAULT 0,
    binding_digest TEXT NOT NULL,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL,
    latest_operation_code TEXT NOT NULL,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT pk_ceag PRIMARY KEY (campaign_id,actor_user_id),
    CONSTRAINT ck_ceag_ids CHECK (({uuid("campaign_id")}) AND ({uuid("actor_user_id")}) AND ({uuid("latest_operation_id")})),
    CONSTRAINT ck_ceag_digest CHECK ({h64("binding_digest")}),
    CONSTRAINT ck_ceag_shape CHECK (authority_state IN ('active','revoked') AND revision BETWEEN 0 AND {MAX_I53} AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53} AND latest_operation_code IN ('put','revoke') AND ((revision=0 AND latest_operation_code='put' AND latest_operation_base_revision=0) OR (revision>=1 AND latest_operation_base_revision=revision-1)) AND ((authority_state='active' AND latest_operation_code='put') OR authority_state='revoked') AND created_at BETWEEN 0 AND {MAX_I53} AND updated_at BETWEEN created_at AND {MAX_I53}),
    CONSTRAINT fk_ceag_campaign FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_ceag_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)""",
            f"""CREATE TABLE campaign_execution_destination_authorities (
    campaign_id TEXT NOT NULL CONSTRAINT pk_ceda PRIMARY KEY,
    authority_state TEXT NOT NULL,
    revision {integer} NOT NULL DEFAULT 0,
    normalization_version {integer} NOT NULL,
    destination_count {integer} NOT NULL,
    destination_set_digest TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL,
    latest_operation_code TEXT NOT NULL,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT ck_ceda_ids CHECK (({uuid("campaign_id")}) AND ({uuid("latest_operation_id")})),
    CONSTRAINT ck_ceda_digests CHECK (({h64("destination_set_digest")}) AND ({h64("binding_digest")})),
    CONSTRAINT ck_ceda_shape CHECK (authority_state IN ('active','revoked') AND revision BETWEEN 0 AND {MAX_I53} AND normalization_version={DESTINATION_NORMALIZATION_VERSION} AND destination_count BETWEEN 0 AND 4096 AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53} AND latest_operation_code IN ('update','revoke') AND ((revision=0 AND latest_operation_code='update' AND latest_operation_base_revision=0) OR (revision>=1 AND latest_operation_base_revision=revision-1)) AND ((authority_state='active' AND latest_operation_code='update') OR authority_state='revoked') AND created_at BETWEEN 0 AND {MAX_I53} AND updated_at BETWEEN created_at AND {MAX_I53}),
    CONSTRAINT fk_ceda_campaign FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)""",
            f"""CREATE TABLE execution_approval_authorities (
    id TEXT NOT NULL CONSTRAINT pk_eapa PRIMARY KEY,
    approval_ref TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    submission_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    actor_subject_ref TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    module_id TEXT NOT NULL,
    approver_subject_ref TEXT NOT NULL,
    approver_user_id TEXT,
    authority_state TEXT NOT NULL,
    revision {integer} NOT NULL DEFAULT 0,
    granted_capability_mask {integer} NOT NULL,
    descriptor_semantic_digest TEXT NOT NULL,
    binding_digest TEXT NOT NULL,
    latest_operation_id TEXT NOT NULL,
    latest_operation_base_revision {integer} NOT NULL,
    latest_operation_code TEXT NOT NULL,
    created_at {integer} NOT NULL DEFAULT ({now_ms}),
    updated_at {integer} NOT NULL DEFAULT ({now_ms}),
    consumed_at {integer},
    CONSTRAINT uq_eapa_ref UNIQUE (approval_ref),
    CONSTRAINT uq_eapa_attempt UNIQUE (attempt_id),
    CONSTRAINT ck_eapa_ids CHECK (({uuid("id")}) AND ({uuid("approval_ref")}) AND ({uuid("campaign_id")}) AND ({uuid("submission_id")}) AND ({uuid("attempt_id")}) AND ({uuid("actor_subject_ref")}) AND ({uuid("actor_user_id")}) AND ({uuid("approver_subject_ref")}) AND (approver_user_id IS NULL OR ({uuid("approver_user_id")})) AND ({uuid("latest_operation_id")})),
    CONSTRAINT ck_eapa_module CHECK ({_s128_check("module_id", dialect)}),
    CONSTRAINT ck_eapa_digests CHECK (({h64("descriptor_semantic_digest")}) AND ({h64("binding_digest")})),
    CONSTRAINT ck_eapa_shape CHECK (authority_state IN ('active','revoked','consumed') AND revision BETWEEN 0 AND {MAX_I53} AND granted_capability_mask BETWEEN 0 AND 15 AND latest_operation_base_revision BETWEEN 0 AND {MAX_I53} AND latest_operation_code IN ('grant','revoke','consume') AND ((revision=0 AND latest_operation_code='grant' AND latest_operation_base_revision=0) OR (revision>=1 AND latest_operation_base_revision=revision-1)) AND ((authority_state='active' AND latest_operation_code='grant' AND consumed_at IS NULL) OR (authority_state='revoked' AND latest_operation_code='revoke' AND consumed_at IS NULL) OR (authority_state='consumed' AND latest_operation_code='consume' AND consumed_at BETWEEN created_at AND {MAX_I53})) AND created_at BETWEEN 0 AND {MAX_I53} AND updated_at BETWEEN created_at AND {MAX_I53}),
    CONSTRAINT fk_eapa_campaign FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_eapa_approver FOREIGN KEY (approver_user_id) REFERENCES users(id) ON UPDATE NO ACTION ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
)""",
            f"""CREATE TABLE execution_attempt_destination_observations (
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    ordinal {integer} NOT NULL,
    destination_ref_digest TEXT NOT NULL,
    authority_revision {integer} NOT NULL,
    normalization_version {integer} NOT NULL,
    observed_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT pk_eado PRIMARY KEY (attempt_id,ordinal),
    CONSTRAINT uq_eado_attempt_destination UNIQUE (attempt_id,destination_ref_digest),
    CONSTRAINT ck_eado_ids CHECK (({uuid("attempt_id")}) AND ({uuid("campaign_id")})),
    CONSTRAINT ck_eado_ref CHECK ({h64("destination_ref_digest")}),
    CONSTRAINT ck_eado_shape CHECK (ordinal BETWEEN 0 AND 4095 AND authority_revision BETWEEN 0 AND {MAX_I53} AND normalization_version={DESTINATION_NORMALIZATION_VERSION} AND observed_at BETWEEN 0 AND {MAX_I53}),
    CONSTRAINT fk_eado_attempt FOREIGN KEY (campaign_id,attempt_id) REFERENCES execution_attempts(campaign_id,id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)""",
            f"""CREATE TABLE execution_attempt_credential_observations (
    attempt_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    ordinal {integer} NOT NULL,
    credential_id TEXT NOT NULL,
    authority_revision {integer} NOT NULL,
    binding_digest TEXT NOT NULL,
    observed_at {integer} NOT NULL DEFAULT ({now_ms}),
    CONSTRAINT pk_eaco PRIMARY KEY (attempt_id,ordinal),
    CONSTRAINT uq_eaco_attempt_credential UNIQUE (attempt_id,credential_id),
    CONSTRAINT ck_eaco_ids CHECK (({uuid("attempt_id")}) AND ({uuid("campaign_id")}) AND ({uuid("credential_id")})),
    CONSTRAINT ck_eaco_digest CHECK ({h64("binding_digest")}),
    CONSTRAINT ck_eaco_shape CHECK (ordinal BETWEEN 0 AND 4095 AND authority_revision BETWEEN 0 AND {MAX_I53} AND observed_at BETWEEN 0 AND {MAX_I53}),
    CONSTRAINT fk_eaco_attempt FOREIGN KEY (campaign_id,attempt_id) REFERENCES execution_attempts(campaign_id,id) ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
)""",
            "CREATE UNIQUE INDEX uq_ceag_latest_operation ON campaign_execution_actor_grants(latest_operation_id)",
            "CREATE INDEX ix_ceag_actor_state ON campaign_execution_actor_grants(actor_user_id,authority_state,campaign_id)",
            "CREATE UNIQUE INDEX uq_ceda_latest_operation ON campaign_execution_destination_authorities(latest_operation_id)",
            "CREATE UNIQUE INDEX uq_eapa_latest_operation ON execution_approval_authorities(latest_operation_id)",
            "CREATE INDEX ix_eapa_campaign_state ON execution_approval_authorities(campaign_id,authority_state,id)",
            "CREATE INDEX ix_eado_campaign_attempt ON execution_attempt_destination_observations(campaign_id,attempt_id,ordinal)",
            "CREATE INDEX ix_eaco_campaign_attempt ON execution_attempt_credential_observations(campaign_id,attempt_id,ordinal)",
            "CREATE INDEX ix_credentials_execution_authority ON credentials(campaign_id,execution_authority_state,id)",
        ]
    )

    if dialect == "postgresql":
        widened = _v11_receipt_create_statement(dialect)
        operation_check = re.search(
            r"CONSTRAINT ck_eor_operation_code CHECK \((.*?)\),\n", widened, re.S
        )
        shape_check = re.search(
            r"CONSTRAINT ck_eor_operation_shape CHECK \((.*?)\),\n    CONSTRAINT ck_eor_outbox_owner_shape",
            widened,
            re.S,
        )
        if operation_check is None or shape_check is None:
            raise RuntimeError("Invalid generation-11 receipt checks")
        statements.extend(
            [
                "ALTER TABLE execution_operation_receipts DROP CONSTRAINT ck_eor_operation_code",
                "ALTER TABLE execution_operation_receipts ADD CONSTRAINT ck_eor_operation_code CHECK ("
                + operation_check.group(1)
                + ")",
                "ALTER TABLE execution_operation_receipts DROP CONSTRAINT ck_eor_operation_shape",
                "ALTER TABLE execution_operation_receipts ADD CONSTRAINT ck_eor_operation_shape CHECK ("
                + shape_check.group(1)
                + ")",
            ]
        )
    else:
        receipt_columns = (
            "operation_id,operation_code,campaign_id,primary_target_id,secondary_target_id,"
            "principal_kind,principal_subject_ref,principal_user_id,"
            "principal_authority_revision_present,principal_authority_revision,"
            "binding_contract_version,request_binding_digest,expected_revision_present,"
            "expected_revision,secondary_expected_revision_present,secondary_expected_revision,"
            "owner_ref,lease_generation,result_code,exact_replay_code,result_binding_digest,"
            "result_identity,result_revision_present,result_revision,secondary_result_identity,"
            "secondary_result_revision_present,secondary_result_revision,created_at"
        )
        statements.extend(
            [
                "DROP TRIGGER trg_eor_immutable_update",
                "DROP TRIGGER trg_eor_immutable_delete",
                "ALTER TABLE execution_operation_receipts RENAME TO execution_operation_receipts_v10",
                _v11_receipt_create_statement(dialect),
                "INSERT INTO execution_operation_receipts("
                + receipt_columns
                + ") SELECT "
                + receipt_columns
                + " FROM execution_operation_receipts_v10",
                "DROP TABLE execution_operation_receipts_v10",
                "CREATE TRIGGER trg_eor_immutable_update BEFORE UPDATE ON execution_operation_receipts BEGIN SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
                "CREATE TRIGGER trg_eor_immutable_delete BEFORE DELETE ON execution_operation_receipts BEGIN SELECT RAISE(ABORT,'immutable execution operation receipt'); END",
                "CREATE INDEX ix_eor_campaign_created ON execution_operation_receipts(campaign_id,created_at,operation_id)",
                "CREATE INDEX ix_eor_primary_target ON execution_operation_receipts(primary_target_id,operation_code,created_at)",
                "CREATE INDEX ix_eor_principal_created ON execution_operation_receipts(principal_kind,principal_subject_ref,created_at,operation_id)",
            ]
        )
    return tuple(statement.strip() for statement in statements)


SQLITE_ADMISSION_AUTHORITY_V11_DDL: Final[tuple[str, ...]] = admission_authority_v11_ddl("sqlite")
POSTGRES_ADMISSION_AUTHORITY_V11_DDL: Final[tuple[str, ...]] = admission_authority_v11_ddl(
    "postgresql"
)


def _postgres_catalog_object_names() -> tuple[frozenset[str], frozenset[str]]:
    constraints: set[str] = set()
    indexes: set[str] = set()
    for statement in POSTGRES_LIFECYCLE_DDL:
        table_match = re.match(r"CREATE TABLE ([a-z0-9_]+)", statement)
        alter_match = re.match(r"ALTER TABLE ([a-z0-9_]+)", statement)
        relation = (
            table_match.group(1)
            if table_match is not None
            else alter_match.group(1)
            if alter_match is not None
            else None
        )
        if relation in LIFECYCLE_TABLES:
            constraints.update(re.findall(r"\bCONSTRAINT ([a-z0-9_]+)\b", statement))
        index_match = re.match(
            r"CREATE (?:UNIQUE )?INDEX ([a-z0-9_]+) ON ([a-z0-9_]+)",
            statement,
        )
        if index_match is not None and index_match.group(2) in LIFECYCLE_TABLES:
            indexes.add(index_match.group(1))
    indexes.update(name for name in constraints if name.startswith(("pk_", "uq_")))
    return frozenset(constraints), frozenset(indexes)


_POSTGRES_LIFECYCLE_CONSTRAINT_NAMES, _POSTGRES_LIFECYCLE_INDEX_NAMES = (
    _postgres_catalog_object_names()
)
_POSTGRES_BASE_CANDIDATE_INDEX_NAMES: Final[frozenset[str]] = frozenset(
    {
        "uq_findings_campaign_id_id",
        "uq_credentials_campaign_id_id",
        "uq_hosts_campaign_id_id",
        "uq_loot_campaign_id_id",
    }
)

_POSTGRES_CATALOG_FACTS_SQL: Final = r"""
WITH lifecycle_relations AS (
    SELECT c.oid,c.relname,n.nspname,c.relkind,c.relpersistence,c.relispartition,
           c.relrowsecurity,c.relforcerowsecurity,c.reloptions,c.relam
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname=current_schema()
      AND (
        c.relname=ANY(__NAMES__)
        OR c.relname LIKE 'execution\_%' ESCAPE '\'
        OR c.relname LIKE 'logical\_execution%' ESCAPE '\'
        OR c.relname LIKE 'campaign\_execution%' ESCAPE '\'
        OR c.relname=ANY(__BASE_NAMES__)
      )
), facts AS (
    SELECT jsonb_build_object(
        'kind','relation','schema',r.nspname,'name',r.relname,
        'relkind',r.relkind::text,'persistence',r.relpersistence::text,
        'partition',r.relispartition,'rls',r.relrowsecurity,
        'forced_rls',r.relforcerowsecurity,'options',r.reloptions
    )::text AS fact
    FROM lifecycle_relations r
    UNION ALL
    SELECT jsonb_build_object(
        'kind','column','relation',r.relname,'ordinal',a.attnum,'name',a.attname,
        'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'dimensions',a.attndims,
        'not_null',a.attnotnull,
        'default',pg_get_expr(d.adbin,d.adrelid,false),
        'identity',a.attidentity::text,'generated',a.attgenerated::text,
        'collation',coll.collname
    )::text
    FROM lifecycle_relations r
    JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
    LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    LEFT JOIN pg_collation coll ON coll.oid=NULLIF(a.attcollation,0)
    WHERE r.relkind IN ('r','p')
    UNION ALL
    SELECT jsonb_build_object(
        'kind','constraint','relation',r.relname,'name',con.conname,
        'type',con.contype::text,'definition',pg_get_constraintdef(con.oid,false),
        'local_keys',con.conkey::text,'referenced_schema',rn.nspname,
        'referenced_relation',rr.relname,'referenced_keys',con.confkey::text,
        'match',con.confmatchtype::text,'update',con.confupdtype::text,
        'delete',con.confdeltype::text,'deferrable',con.condeferrable,
        'deferred',con.condeferred,'validated',con.convalidated
    )::text
    FROM lifecycle_relations r
    JOIN pg_constraint con ON con.conrelid=r.oid
    LEFT JOIN pg_class rr ON rr.oid=con.confrelid
    LEFT JOIN pg_namespace rn ON rn.oid=rr.relnamespace
    UNION ALL
    SELECT jsonb_build_object(
        'kind','index','relation',r.relname,'name',idx.relname,
        'unique',i.indisunique,'primary',i.indisprimary,'valid',i.indisvalid,
        'ready',i.indisready,'method',am.amname,'keys',i.indkey::text,
        'key_count',i.indnkeyatts,'attribute_count',i.indnatts,
        'classes',ARRAY(
            SELECT opc_ns.nspname||'.'||opc.opcname
            FROM generate_series(0,i.indnkeyatts-1) AS position
            JOIN pg_opclass opc ON opc.oid=i.indclass[position]
            JOIN pg_namespace opc_ns ON opc_ns.oid=opc.opcnamespace
            ORDER BY position
        )::text,
        'collations',ARRAY(
            SELECT CASE WHEN i.indcollation[position]=0 THEN ''
                        ELSE col_ns.nspname||'.'||col.collname END
            FROM generate_series(0,i.indnkeyatts-1) AS position
            LEFT JOIN pg_collation col ON col.oid=NULLIF(i.indcollation[position],0)
            LEFT JOIN pg_namespace col_ns ON col_ns.oid=col.collnamespace
            ORDER BY position
        )::text,
        'options',i.indoption::text,'expressions',pg_get_expr(i.indexprs,i.indrelid,false),
        'predicate',pg_get_expr(i.indpred,i.indrelid,false),
        'definition',pg_get_indexdef(i.indexrelid,0,false)
    )::text
    FROM lifecycle_relations r
    JOIN pg_index i ON i.indrelid=r.oid
    JOIN pg_class idx ON idx.oid=i.indexrelid
    JOIN pg_am am ON am.oid=idx.relam
    UNION ALL
    SELECT jsonb_build_object(
        'kind','index','relation',base.relname,'name',r.relname,
        'unique',i.indisunique,'primary',i.indisprimary,'valid',i.indisvalid,
        'ready',i.indisready,'method',am.amname,'keys',i.indkey::text,
        'key_count',i.indnkeyatts,'attribute_count',i.indnatts,
        'classes',ARRAY(
            SELECT opc_ns.nspname||'.'||opc.opcname
            FROM generate_series(0,i.indnkeyatts-1) AS position
            JOIN pg_opclass opc ON opc.oid=i.indclass[position]
            JOIN pg_namespace opc_ns ON opc_ns.oid=opc.opcnamespace
            ORDER BY position
        )::text,
        'collations',ARRAY(
            SELECT CASE WHEN i.indcollation[position]=0 THEN ''
                        ELSE col_ns.nspname||'.'||col.collname END
            FROM generate_series(0,i.indnkeyatts-1) AS position
            LEFT JOIN pg_collation col ON col.oid=NULLIF(i.indcollation[position],0)
            LEFT JOIN pg_namespace col_ns ON col_ns.oid=col.collnamespace
            ORDER BY position
        )::text,
        'options',i.indoption::text,'expressions',pg_get_expr(i.indexprs,i.indrelid,false),
        'predicate',pg_get_expr(i.indpred,i.indrelid,false),
        'definition',pg_get_indexdef(i.indexrelid,0,false)
    )::text
    FROM lifecycle_relations r
    JOIN pg_index i ON i.indexrelid=r.oid
    JOIN pg_class base ON base.oid=i.indrelid
    JOIN pg_am am ON am.oid=r.relam
    WHERE r.relname=ANY(__BASE_NAMES__)
    UNION ALL
    SELECT jsonb_build_object(
        'kind','trigger','relation',r.relname,'name',t.tgname,
        'definition',pg_get_triggerdef(t.oid,false),'enabled',t.tgenabled::text,
        'internal',t.tgisinternal
    )::text
    FROM lifecycle_relations r JOIN pg_trigger t ON t.tgrelid=r.oid
    WHERE NOT t.tgisinternal
    UNION ALL
    SELECT jsonb_build_object(
        'kind','function','schema',n.nspname,'name',p.proname,
        'identity_arguments',pg_get_function_identity_arguments(p.oid),
        'result',pg_get_function_result(p.oid),
        'language',l.lanname,'security_definer',p.prosecdef,
        'leakproof',p.proleakproof,'volatility',p.provolatile::text,
        'parallel',p.proparallel::text,
        'definition',pg_get_functiondef(p.oid)
    )::text
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_language l ON l.oid=p.prolang
    WHERE n.nspname=current_schema()
      AND p.proname='execution_operation_receipt_immutable'
    UNION ALL
    SELECT jsonb_build_object(
        'kind','policy','relation',r.relname,'name',p.polname,
        'permissive',p.polpermissive,'roles',p.polroles::text,'command',p.polcmd::text,
        'using',pg_get_expr(p.polqual,p.polrelid,false),
        'check',pg_get_expr(p.polwithcheck,p.polrelid,false)
    )::text
    FROM lifecycle_relations r JOIN pg_policy p ON p.polrelid=r.oid
    UNION ALL
    SELECT jsonb_build_object(
        'kind','rule','relation',r.relname,'name',rw.rulename,
        'event',rw.ev_type::text,'instead',rw.is_instead,
        'definition',pg_get_ruledef(rw.oid,false)
    )::text
    FROM lifecycle_relations r JOIN pg_rewrite rw ON rw.ev_class=r.oid
    WHERE rw.rulename<>'_RETURN'
    UNION ALL
    SELECT jsonb_build_object(
        'kind','inheritance','relation',r.relname,
        'parent_schema',pn.nspname,'parent',p.relname,'sequence',inh.inhseqno
    )::text
    FROM lifecycle_relations r
    JOIN pg_inherits inh ON inh.inhrelid=r.oid
    JOIN pg_class p ON p.oid=inh.inhparent
    JOIN pg_namespace pn ON pn.oid=p.relnamespace
    UNION ALL
    SELECT jsonb_build_object(
        'kind','gateway','singleton_id',singleton_id,'mode',mode,
        'catalog_digest',catalog_digest,'activation_revision',activation_revision,
        'activation_at',activation_at,'revision',revision
    )::text
    FROM execution_gateway_state
)
SELECT fact FROM facts ORDER BY fact
"""

# Filled from the exact PostgreSQL-16 catalog produced by the literal revision-0010 DDL.
_POSTGRES_CATALOG_FINGERPRINT_V1: Final = (
    "6e3e4c1249d08b524e2f856aaefd86905fb57d51492384fa683b050222c3f250"
)


def postgresql_catalog_fingerprint(facts: Sequence[object]) -> str:
    encoded = bytearray(b"ares.execution-lifecycle.pg-catalog.v1\x00")
    for fact in sorted(str(value) for value in facts):
        value = fact.encode("utf-8")
        encoded.extend(struct.pack(">I", len(value)))
        encoded.extend(value)
    return hashlib.sha256(encoded).hexdigest()


def sqlite_lifecycle_script() -> str:
    return ";\n".join(SQLITE_LIFECYCLE_DDL) + ";\n"


def sqlite_lifecycle_runtime_script() -> str:
    """Return idempotent runtime-bootstrap DDL with the identical catalog."""
    statements: list[str] = []
    for statement in SQLITE_LIFECYCLE_DDL:
        if statement.startswith("CREATE TABLE "):
            statement = statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        elif statement.startswith("CREATE UNIQUE INDEX "):
            statement = statement.replace(
                "CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ", 1
            )
        elif statement.startswith("CREATE INDEX "):
            statement = statement.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
        elif statement.startswith("CREATE TRIGGER "):
            statement = statement.replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1)
        elif statement.startswith("INSERT INTO execution_gateway_state"):
            statement = statement.replace("INSERT INTO", "INSERT OR IGNORE INTO", 1)
        statements.append(statement)
    return ";\n".join(statements) + ";\n"


def sqlite_admission_authority_runtime_script() -> str:
    """Return the exact additive generation-11 SQLite runtime script."""
    return ";\n".join(SQLITE_ADMISSION_AUTHORITY_V11_DDL) + ";\n"


def canonical_operation_binding_digest(
    domain: str,
    fields: tuple[tuple[str, str | int | bool | None], ...],
) -> str:
    """Hash an explicitly ordered, typed, reduced lifecycle fact sequence."""
    if (
        type(domain) is not str
        or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", domain) is None
        or type(fields) is not tuple
    ):
        raise ValueError("Invalid operation binding contract")
    encoded = bytearray(b"ares.execution-operation-binding.v2\x00")
    seen: set[str] = set()

    def frame(value: bytes) -> None:
        encoded.extend(struct.pack(">I", len(value)))
        encoded.extend(value)

    frame(domain.encode("ascii"))
    for item in fields:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("Invalid operation binding contract")
        name, value = item
        if (
            type(name) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", name) is None
            or name in seen
        ):
            raise ValueError("Invalid operation binding contract")
        seen.add(name)
        frame(name.encode("ascii"))
        if value is None:
            encoded.extend(b"n")
        elif type(value) is bool:
            encoded.extend(b"b\x01" if value else b"b\x00")
        elif type(value) is int:
            if not 0 <= value <= MAX_I53:
                raise ValueError("Invalid operation binding contract")
            encoded.extend(b"i")
            frame(value.to_bytes(8, "big", signed=False))
        elif type(value) is str:
            encoded.extend(b"s")
            frame(value.encode("utf-8"))
        else:
            raise ValueError("Invalid operation binding contract")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReceiptSpec:
    operation_id: str
    operation_code: str
    campaign_id: str | None
    primary_target_id: str
    secondary_target_id: str | None
    principal_kind: str
    principal_subject_ref: str
    principal_user_id: str | None
    principal_authority_revision: int | None
    request_binding_digest: str
    expected_revision: int | None
    secondary_expected_revision: int | None
    owner_ref: str | None
    lease_generation: int | None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class TransitionRequest:
    attempt_id: str
    expected_revision: int
    target_state: AttemptState
    operation_id: str
    owner_ref: str | None = None
    lease_generation: int | None = None
    lease_duration_ms: int | None = None
    cancellation_request_revision: int | None = None
    outcome_code: OutcomeCode | None = None
    authoritative_proof: str = "none"
    resolver_subject_ref: str | None = None
    resolver_user_id: str | None = None
    resolver_authority_revision: int | None = None
    outbox_id: str | None = None
    publication_key: str | None = None
    campaign_id: str | None = None
    actor_subject_ref: str | None = None
    actor_user_id: str | None = None
    actor_authority_revision: int | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class OutboxMutation:
    outbox_id: str
    expected_revision: int
    operation_id: str
    owner_ref: str | None = None
    lease_generation: int | None = None
    campaign_id: str | None = None
    attempt_id: str | None = None
    publication_key: str | None = None
    event_code: str | None = None
    purge_poisoned: bool | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class OperationResult:
    result: FixedResult
    revision: int | None

    __hash__ = None

    def __bool__(self) -> bool:
        return self.result in {
            FixedResult.APPLIED,
            FixedResult.REPLAYED,
            FixedResult.REPLAYED_BOUND_CHILD,
            FixedResult.REPLAYED_CLOSED,
        }


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class BudgetConfiguration:
    campaign_id: str
    noise_budget_id: str
    noise_capacity: int
    exfiltration_budget_id: str
    exfiltration_capacity: int
    concurrency_budget_id: str
    concurrency_capacity: int
    operation_id: str
    principal_kind: str | None = "system"
    principal_subject_ref: str | None = SYSTEM_PRINCIPAL_SUBJECT_REF
    principal_user_id: str | None = None
    principal_authority_revision: int | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class BudgetReservation:
    campaign_id: str
    attempt_id: str
    noise_budget_id: str
    noise_ledger_id: str
    noise_units: int
    noise_expected_revision: int
    exfiltration_budget_id: str
    exfiltration_ledger_id: str
    exfiltration_units: int
    exfiltration_expected_revision: int
    concurrency_budget_id: str
    concurrency_ledger_id: str
    concurrency_expected_revision: int
    operation_id: str
    principal_kind: str | None = "system"
    principal_subject_ref: str | None = SYSTEM_PRINCIPAL_SUBJECT_REF
    principal_user_id: str | None = None
    principal_authority_revision: int | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class BudgetSettlement:
    campaign_id: str
    attempt_id: str
    noise_budget_id: str
    noise_units: int
    noise_actual: int
    noise_expected_revision: int
    exfiltration_budget_id: str
    exfiltration_units: int
    exfiltration_actual: int
    exfiltration_expected_revision: int
    concurrency_budget_id: str
    concurrency_expected_revision: int
    operation_id: str
    principal_kind: str | None = "system"
    principal_subject_ref: str | None = SYSTEM_PRINCIPAL_SUBJECT_REF
    principal_user_id: str | None = None
    principal_authority_revision: int | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedTerminalV3BudgetSettlement:
    request: BudgetSettlement
    entries: tuple[tuple[str, str, str, int, int, int, str], ...]


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ClosureRequest:
    logical_execution_id: str
    attempt_id: str
    outbox_id: str
    expected_attempt_revision: int
    operation_id: str
    authority_subject_ref: str
    authority_user_id: str
    authority_revision: int
    campaign_id: str | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class AttemptPolicySnapshot:
    actor_authority_revision: int
    campaign_authority_revision: int
    destination_authority_revision: int
    credential_authority_revision: int
    evaluation_mode: str
    request_structure_valid: bool
    canonicalization_complete: bool
    unknown_fields_absent: bool
    alternate_transport_absent: bool
    bounded_shape_valid: bool
    request_shape_units: int
    descriptor_semantic_digest: str
    catalog_digest: str
    trusted_first_party_binding: bool
    descriptor_binding_current: bool
    descriptor_complete: bool
    static_policy_evaluable: bool
    minimum_role: str
    noise_class: str
    approval_policy: str
    required_capability_mask: int
    descriptor_blocker_mask: int
    preview_ready: bool
    lifecycle_ready: bool
    result_authority_ready: bool
    transport_ready: bool
    future_gateway_eligible: bool
    authority_snapshots_complete: bool
    authority_revisions_current: bool
    actor_authenticated: bool
    actor_active: bool
    actor_role: str
    campaign_active: bool
    actor_campaign_authorized: bool
    approval_present: bool
    approval_current: bool
    approval_exactly_bound: bool
    granted_capability_mask: int
    destination_extraction_complete: bool
    destinations_in_scope: bool
    credential_authority_resolved: bool
    credential_authority_current: bool
    opaque_handles_only: bool
    permitted_handle_kinds_only: bool
    raw_credentials_absent: bool
    ambient_credentials_absent: bool
    budget_authority_resolved: bool
    budget_authority_current: bool
    budget_capacity_available: bool
    gateway_mode_snapshot: str
    gateway_decision_code: str
    policy_evaluation_state: str
    policy_verdict: str | None
    policy_reason_mask: int | None
    external_effect_class: str
    idempotency_class: str
    retry_policy: str
    retry_disposition: str
    cancellation_ownership: str
    compensation_class: str
    timeout_origin: str
    timeout_limit_ms: int
    timeout_settlement: str

    __hash__ = None


_SNAPSHOT_BINDING_FIELDS: Final[tuple[str, ...]] = (
    "actor_authority_revision",
    "campaign_authority_revision",
    "destination_authority_revision",
    "credential_authority_revision",
    "evaluation_mode",
    "request_structure_valid",
    "canonicalization_complete",
    "unknown_fields_absent",
    "alternate_transport_absent",
    "bounded_shape_valid",
    "request_shape_units",
    "descriptor_semantic_digest",
    "catalog_digest",
    "trusted_first_party_binding",
    "descriptor_binding_current",
    "descriptor_complete",
    "static_policy_evaluable",
    "minimum_role",
    "noise_class",
    "approval_policy",
    "required_capability_mask",
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
    "policy_verdict",
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
)


def _snapshot_binding_values(
    snapshot: AttemptPolicySnapshot,
) -> tuple[tuple[str, str | int | bool | None], ...]:
    return (
        ("request_contract_version", REQUEST_CONTRACT_VERSION),
        ("policy_contract_version", POLICY_CONTRACT_VERSION),
        ("descriptor_contract_version", DESCRIPTOR_CONTRACT_VERSION),
        ("capability_mask_version", MASK_VERSION),
        ("descriptor_blocker_mask_version", MASK_VERSION),
        (
            "policy_reason_mask_version",
            MASK_VERSION if snapshot.policy_reason_mask is not None else None,
        ),
    ) + tuple((name, getattr(snapshot, name)) for name in _SNAPSHOT_BINDING_FIELDS)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ApprovalBinding:
    approval_id: str
    approval_ref: str
    approver_subject_ref: str
    approver_user_id: str | None
    authority_revision: int
    binding_digest: str

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class AdmissionRequest:
    logical_execution_id: str
    submission_id: str
    attempt_id: str
    outbox_id: str | None
    publication_key: str | None
    campaign_id: str
    actor_subject_ref: str
    actor_user_id: str
    module_id: str
    ingress_code: str
    initial_state: AttemptState
    operation_id: str
    snapshot: AttemptPolicySnapshot
    approval: ApprovalBinding | None = None
    budgets: BudgetReservation | None = None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class RetryRequest:
    logical_execution_id: str
    parent_attempt_id: str
    child: AdmissionRequest
    expected_parent_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class TrustedPrincipal:
    """Opaque actor identity handle; every fact is re-resolved by the store."""

    subject_ref: str
    user_id: str

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class AdmissionIntentV3:
    """Canonical immutable caller intent; authority facts are never caller supplied."""

    logical_execution_id: str
    submission_id: str
    attempt_id: str
    outbox_id: str | None
    publication_key: str | None
    campaign_id: str
    module_id: str
    ingress_code: str
    operation_id: str
    evaluation_mode: str
    raw_parameters: Mapping[str, Any]
    credential_ids: tuple[str, ...] = ()
    approval_ref: str | None = None
    noise_units: int = 0
    exfiltration_units: int = 0

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class RetryIntentV3:
    logical_execution_id: str
    parent_attempt_id: str
    child_attempt_id: str
    outbox_id: str | None
    publication_key: str | None
    operation_id: str
    expected_parent_revision: int
    evaluation_mode: str
    raw_parameters: Mapping[str, Any]
    credential_ids: tuple[str, ...] = ()
    approval_ref: str | None = None
    noise_units: int = 0
    exfiltration_units: int = 0

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ApprovalAuthorityGrant:
    operation_id: str
    approval_id: str
    approval_ref: str
    campaign_id: str
    submission_id: str
    attempt_id: str
    actor_subject_ref: str
    actor_user_id: str
    module_id: str
    granted_capability_mask: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class GatewayAuthorityMutation:
    operation_id: str
    expected_revision: int
    mode: str

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ActorAuthorityMutation:
    operation_id: str
    actor_user_id: str
    expected_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class CampaignAuthorityMutation:
    operation_id: str
    campaign_id: str
    expected_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class CampaignActorGrantMutation:
    operation_id: str
    campaign_id: str
    actor_user_id: str
    expected_revision: int | None

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class DestinationAuthorityMutation:
    operation_id: str
    campaign_id: str
    expected_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class CredentialAuthorityMutation:
    operation_id: str
    credential_id: str
    expected_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class ApprovalAuthorityMutation:
    operation_id: str
    approval_id: str
    expected_revision: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ResolvedPrincipal:
    subject_ref: str
    user_id: str
    role: str
    auth_epoch: int
    authority_revision: int
    binding_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedAdmissionV3:
    canonical_parameters: Mapping[str, Any]
    destination_refs: tuple[tuple[str, str], ...]
    immutable_intent_digest: str
    immutable_work_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ResolvedAdmissionV3:
    principal: _ResolvedPrincipal
    snapshot: AttemptPolicySnapshot
    approval: ApprovalBinding | None
    budgets: BudgetReservation | None
    destination_binding_digest: str
    credential_binding_digest: str
    approval_binding_digest: str | None
    gateway_revision: int
    gateway_activation_revision: int | None
    grant_revision: int
    destination_observations: tuple[tuple[str, int], ...]
    credential_observations: tuple[tuple[str, int, str], ...]


class OutputKind(str, Enum):
    FINDING = "finding"
    CREDENTIAL = "credential"
    HOST = "host"
    ARTIFACT = "artifact"


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class OutputObservation:
    link_id: str
    kind: OutputKind
    target_id: str

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class TerminalCommitIntentV3:
    """Known-settled terminal facts accepted only from the sealed coordinator."""

    logical_execution_id: str
    campaign_id: str
    attempt_id: str
    expected_attempt_revision: int
    outcome_code: OutcomeCode
    noise_actual: int
    exfiltration_actual: int
    concurrency_actual: int
    execution_result_digest: str | None
    outputs: tuple[OutputObservation, ...] = ()

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class TerminalCommitRequest:
    logical_execution_id: str
    campaign_id: str
    outbox_id: str
    publication_key: str
    transition: TransitionRequest
    budgets: BudgetSettlement
    outputs: tuple[OutputObservation, ...] = ()

    __hash__ = None


class _AbortOperationError(Exception):
    def __init__(self, result: OperationResult) -> None:
        self.result = result


@dataclass(frozen=True, slots=True)
class _CleanupOutcome:
    error: BaseException | None
    cancellation: asyncio.CancelledError | None


async def _await_owned_cleanup(
    operation: Awaitable[Any],
    *,
    name: str,
) -> _CleanupOutcome:
    async def _capture() -> BaseException | None:
        try:
            await operation
        except BaseException as error:
            return error
        return None

    task = asyncio.create_task(_capture(), name=name)
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            error = await asyncio.shield(task)
        except asyncio.CancelledError as caught:
            if cancellation is None:
                cancellation = caught
            continue
        return _CleanupOutcome(error, cancellation)


def _record_cleanup_failure(primary: BaseException, action: str) -> None:
    note = f"Execution lifecycle cleanup failed [{action}]"
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        with suppress(BaseException):
            add_note(note)


_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def valid_uuid(value: object) -> bool:
    return type(value) is str and _UUID_RE.fullmatch(value) is not None


def validate_transition_request(request: object) -> FixedResult | None:
    if type(request) is not TransitionRequest:
        return FixedResult.INVALID_CONTRACT
    if not valid_uuid(request.attempt_id) or not valid_uuid(request.operation_id):
        return FixedResult.INVALID_CONTRACT
    if type(request.expected_revision) is not int or not 0 <= request.expected_revision <= MAX_I53:
        return FixedResult.INVALID_CONTRACT
    if type(request.target_state) is not AttemptState:
        return FixedResult.INVALID_CONTRACT
    if request.owner_ref is not None and not valid_uuid(request.owner_ref):
        return FixedResult.INVALID_CONTRACT
    if request.lease_generation is not None and (
        type(request.lease_generation) is not int or not 1 <= request.lease_generation <= MAX_I53
    ):
        return FixedResult.INVALID_CONTRACT
    if (request.owner_ref is None) != (request.lease_generation is None):
        return FixedResult.INVALID_CONTRACT
    if request.lease_duration_ms is not None and (
        type(request.lease_duration_ms) is not int
        or not MIN_TIMEOUT_MS <= request.lease_duration_ms <= MAX_TIMEOUT_MS
    ):
        return FixedResult.INVALID_CONTRACT
    if request.cancellation_request_revision is not None and (
        type(request.cancellation_request_revision) is not int
        or not 1 <= request.cancellation_request_revision <= MAX_I53
    ):
        return FixedResult.INVALID_CONTRACT
    if request.outcome_code is not None and type(request.outcome_code) is not OutcomeCode:
        return FixedResult.INVALID_CONTRACT
    if type(request.authoritative_proof) is not str or request.authoritative_proof not in {
        "none",
        "no_dispatch",
        "local_completion",
        "process_group_exit",
        "worker_terminal_ack",
        "external_settlement_ack",
        "cancellation_no_result_ack",
        "timeout_termination_ack",
        "bounded_recovery_exhausted",
        "unresolved",
    }:
        return FixedResult.INVALID_CONTRACT
    resolver_present = any(
        value is not None
        for value in (
            request.resolver_subject_ref,
            request.resolver_user_id,
            request.resolver_authority_revision,
        )
    )
    if resolver_present and (
        not valid_uuid(request.resolver_subject_ref)
        or not valid_uuid(request.resolver_user_id)
        or type(request.resolver_authority_revision) is not int
        or not 0 <= request.resolver_authority_revision <= MAX_I53
        or request.owner_ref is not None
    ):
        return FixedResult.INVALID_CONTRACT
    if request.outbox_id is not None and not valid_uuid(request.outbox_id):
        return FixedResult.INVALID_CONTRACT
    if request.publication_key is not None and not valid_uuid(request.publication_key):
        return FixedResult.INVALID_CONTRACT
    if not valid_uuid(request.campaign_id):
        return FixedResult.INVALID_CONTRACT
    actor_present = any(
        value is not None
        for value in (
            request.actor_subject_ref,
            request.actor_user_id,
            request.actor_authority_revision,
        )
    )
    if resolver_present or request.owner_ref is not None:
        if actor_present:
            return FixedResult.INVALID_CONTRACT
    elif (
        not valid_uuid(request.actor_subject_ref)
        or not valid_uuid(request.actor_user_id)
        or type(request.actor_authority_revision) is not int
        or not 0 <= request.actor_authority_revision <= MAX_I53
    ):
        return FixedResult.INVALID_CONTRACT
    return None


def retry_delay_ms(delivery_attempt_count: object) -> int | None:
    """Return the literal bounded retry delay for attempts 1 through 19."""
    if type(delivery_attempt_count) is not int or not 1 <= delivery_attempt_count <= 19:
        return None
    mapping = (
        1_000,
        2_000,
        4_000,
        8_000,
        16_000,
        32_000,
        64_000,
        128_000,
        256_000,
        512_000,
        600_000,
        600_000,
        600_000,
        600_000,
        600_000,
        600_000,
        600_000,
        600_000,
        600_000,
    )
    return mapping[delivery_attempt_count - 1]


def _question_to_postgres(sql: str) -> str:
    parts = sql.split("?")
    if len(parts) == 1:
        return sql
    result = parts[0]
    for index, part in enumerate(parts[1:], 1):
        result += f"${index}{part}"
    return result


class ExecutionLifecycleStore:
    """Internal additive CAS store for an aiosqlite connection or asyncpg pool."""

    def __init__(self, backend: Any, dialect: str) -> None:
        if dialect not in {"sqlite", "postgresql"}:
            raise ValueError("Unsupported lifecycle dialect")
        self._backend = backend
        self._dialect = dialect

    @staticmethod
    def _valid_expected_revision(value: object, *, optional: bool = False) -> bool:
        return (optional and value is None) or (type(value) is int and 0 <= value < MAX_I53)

    @staticmethod
    def _actor_authority_binding(
        user_id: str,
        username: str,
        role: str,
        is_active: bool,
        auth_epoch: int,
    ) -> str:
        return canonical_operation_binding_digest(
            "actor-authority",
            (
                ("user_id", user_id),
                ("username", username),
                ("role", role),
                ("is_active", is_active),
                ("auth_epoch", auth_epoch),
            ),
        )

    @staticmethod
    def _credential_authority_binding(row: Any) -> str:
        return canonical_operation_binding_digest(
            "credential-authority",
            (
                ("credential_id", str(ExecutionLifecycleStore._value(row, "id", 0))),
                ("campaign_id", str(ExecutionLifecycleStore._value(row, "campaign_id", 1))),
                ("host_id", ExecutionLifecycleStore._value(row, "host_id", 2)),
                ("username", str(ExecutionLifecycleStore._value(row, "username", 3))),
                ("credential_type", str(ExecutionLifecycleStore._value(row, "cred_type", 4))),
                ("domain", ExecutionLifecycleStore._value(row, "domain", 5)),
                ("source_module", ExecutionLifecycleStore._value(row, "source_module", 6)),
            ),
        )

    @staticmethod
    def _campaign_authority_binding(row: Any, destination_binding_digest: str) -> str:
        return canonical_operation_binding_digest(
            "campaign-authority",
            (
                ("campaign_id", str(ExecutionLifecycleStore._value(row, "id", 0))),
                ("operator", str(ExecutionLifecycleStore._value(row, "operator", 1))),
                ("status", str(ExecutionLifecycleStore._value(row, "status", 2))),
                ("noise_profile", str(ExecutionLifecycleStore._value(row, "noise_profile", 3))),
                ("destination_binding_digest", destination_binding_digest),
            ),
        )

    @staticmethod
    def _grant_authority_binding(
        campaign_id: str,
        actor_user_id: str,
        authority_state: str,
    ) -> str:
        return canonical_operation_binding_digest(
            "campaign-actor-grant",
            (
                ("campaign_id", campaign_id),
                ("actor_user_id", actor_user_id),
                ("authority_state", authority_state),
            ),
        )

    async def _v11_authority_revision_current(
        self,
        connection: Any,
        *,
        revision: int,
        latest_operation_id: object,
        latest_operation_base_revision: object,
        latest_operation_code: object,
        operation_prefix: str,
        campaign_id: str | None,
        target_id: str,
        destination_baseline: bool = False,
    ) -> bool:
        if revision == 0:
            if destination_baseline:
                return (
                    valid_uuid(latest_operation_id)
                    and latest_operation_base_revision == 0
                    and latest_operation_code == "update"
                )
            return (
                latest_operation_id is None
                and latest_operation_base_revision is None
                and latest_operation_code is None
            )
        if (
            revision < 1
            or not valid_uuid(latest_operation_id)
            or type(latest_operation_base_revision) is not int
            or latest_operation_base_revision != revision - 1
            or latest_operation_code not in {"activate", "update", "revoke"}
            or (
                operation_prefix == "destination_authority_" and latest_operation_code == "activate"
            )
        ):
            return False
        receipt = await self._fetchrow(
            connection,
            "SELECT operation_code,campaign_id,primary_target_id,"
            "expected_revision_present,expected_revision,result_code,"
            "result_revision_present,result_revision "
            "FROM execution_operation_receipts WHERE operation_id=?",
            (latest_operation_id,),
        )
        return receipt is not None and (
            self._value(receipt, "operation_code", 0)
            == operation_prefix + str(latest_operation_code)
            and self._value(receipt, "campaign_id", 1) == campaign_id
            and self._value(receipt, "primary_target_id", 2) == target_id
            and bool(self._value(receipt, "expected_revision_present", 3))
            and self._value(receipt, "expected_revision", 4) == latest_operation_base_revision
            and self._value(receipt, "result_code", 5) == FixedResult.APPLIED.value
            and bool(self._value(receipt, "result_revision_present", 6))
            and self._value(receipt, "result_revision", 7) == revision
        )

    @staticmethod
    def _approval_authority_binding(
        row: Any,
        *,
        authority_state: str | None = None,
    ) -> str:
        return canonical_operation_binding_digest(
            "approval-authority",
            (
                ("approval_ref", str(ExecutionLifecycleStore._value(row, "approval_ref", 1))),
                ("submission_id", str(ExecutionLifecycleStore._value(row, "submission_id", 8))),
                ("attempt_id", str(ExecutionLifecycleStore._value(row, "attempt_id", 9))),
                (
                    "actor_subject_ref",
                    str(ExecutionLifecycleStore._value(row, "actor_subject_ref", 10)),
                ),
                (
                    "actor_user_id",
                    str(ExecutionLifecycleStore._value(row, "actor_user_id", 11)),
                ),
                ("module_id", str(ExecutionLifecycleStore._value(row, "module_id", 12))),
                (
                    "granted_capability_mask",
                    int(ExecutionLifecycleStore._value(row, "granted_capability_mask", 13)),
                ),
                (
                    "descriptor_semantic_digest",
                    str(ExecutionLifecycleStore._value(row, "descriptor_semantic_digest", 14)),
                ),
                (
                    "approver_subject_ref",
                    str(ExecutionLifecycleStore._value(row, "approver_subject_ref", 2)),
                ),
                (
                    "approver_user_id",
                    ExecutionLifecycleStore._value(row, "approver_user_id", 3),
                ),
                (
                    "authority_state",
                    authority_state
                    if authority_state is not None
                    else str(ExecutionLifecycleStore._value(row, "authority_state", 6)),
                ),
            ),
        )

    @staticmethod
    def _canonical_destination_values(
        scope_json: object,
        targets_json: object,
    ) -> tuple[str, ...]:
        try:
            scope = json.loads(str(scope_json))
            targets = json.loads(str(targets_json))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("Invalid destination authority") from None
        if type(scope) is not list or type(targets) is not list:
            raise ValueError("Invalid destination authority")
        values: set[str] = set()
        for entry in scope:
            if type(entry) is not dict or set(entry) - {"cidr", "description"}:
                raise ValueError("Invalid destination authority")
            cidr = entry.get("cidr")
            if type(cidr) is not str:
                raise ValueError("Invalid destination authority")
            try:
                value = str(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                raise ValueError("Invalid destination authority") from None
            values.add("scope:" + value)
        for item in targets:
            if type(item) is not str:
                raise ValueError("Invalid destination authority")
            value = item.strip()
            try:
                value = (
                    str(ipaddress.ip_network(value, strict=False))
                    if "/" in value
                    else str(ipaddress.ip_address(value))
                )
            except ValueError:
                value = value.lower().rstrip(".")
                if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,2047}", value) is None:
                    raise ValueError("Invalid destination authority") from None
            values.add("target:" + value)
        return tuple(sorted(values))

    @staticmethod
    def _destination_authority_facts(values: tuple[str, ...]) -> tuple[int, str, str]:
        encoded = bytearray(b"ares.destination-set.v1\x00")
        for value in values:
            item = value.encode("utf-8")
            encoded.extend(len(item).to_bytes(4, "big"))
            encoded.extend(item)
        digest = hashlib.sha256(encoded).hexdigest()
        binding = canonical_operation_binding_digest(
            "destination-authority",
            (
                ("normalization_version", DESTINATION_NORMALIZATION_VERSION),
                ("destination_count", len(values)),
                ("destination_set_digest", digest),
            ),
        )
        return len(values), digest, binding

    @staticmethod
    def _raw_credential_material_present(
        values: object,
        fields: Sequence[Any],
    ) -> bool:
        """Reject caller-supplied secret material; v3 accepts opaque IDs only."""
        if not isinstance(values, Mapping):
            return False
        for spec in fields:
            name = getattr(spec, "name", None)
            if type(name) is not str or name not in values:
                continue
            value = values[name]
            nonempty = (
                value is not None and value != "" and value != () and value != [] and value != {}
            )
            sensitivity = getattr(getattr(spec, "sensitivity", None), "value", None)
            if nonempty and (
                sensitivity == "secret" or bool(getattr(spec, "legacy_schema_secret", False))
            ):
                return True
            nested = getattr(spec, "nested_fields", ())
            if nested and ExecutionLifecycleStore._raw_credential_material_present(value, nested):
                return True
        return False

    @staticmethod
    def _destination_is_allowed(requested: str, allowed: tuple[str, ...]) -> bool:
        kind, separator, canonical = requested.partition("|")
        if not separator or kind not in {"host", "domain", "network_endpoint"}:
            return False
        requested = canonical
        if requested in allowed:
            return True
        if not requested.startswith("target:"):
            return False
        candidate = requested.removeprefix("target:")
        try:
            if "/" in candidate:
                candidate_network = ipaddress.ip_network(candidate, strict=False)
                return any(
                    candidate_network.subnet_of(
                        ipaddress.ip_network(item.removeprefix("scope:"), strict=False)
                    )
                    for item in allowed
                    if item.startswith("scope:")
                )
            candidate_address = ipaddress.ip_address(candidate)
            return any(
                candidate_address in ipaddress.ip_network(item.removeprefix("scope:"), strict=False)
                for item in allowed
                if item.startswith("scope:")
            )
        except ValueError:
            return False

    @staticmethod
    def _valid_initial_v3_intent_shape(intent: object) -> bool:
        return not (
            type(intent) is not AdmissionIntentV3
            or not all(
                valid_uuid(value)
                for value in (
                    intent.logical_execution_id,
                    intent.submission_id,
                    intent.attempt_id,
                    intent.campaign_id,
                    intent.operation_id,
                )
            )
            or (intent.outbox_id is not None and not valid_uuid(intent.outbox_id))
            or (intent.publication_key is not None and not valid_uuid(intent.publication_key))
            or (intent.outbox_id is None) != (intent.publication_key is None)
            or intent.evaluation_mode not in {"preview", "live"}
            or intent.ingress_code not in INGRESS_CODES
            or type(intent.credential_ids) is not tuple
            or len(intent.credential_ids) > 256
            or len(set(intent.credential_ids)) != len(intent.credential_ids)
            or not all(valid_uuid(value) for value in intent.credential_ids)
            or (intent.approval_ref is not None and not valid_uuid(intent.approval_ref))
            or type(intent.noise_units) is not int
            or not 0 <= intent.noise_units <= MAX_I53
            or type(intent.exfiltration_units) is not int
            or not 0 <= intent.exfiltration_units <= MAX_I53
            or not isinstance(intent.raw_parameters, Mapping)
        )

    @staticmethod
    def _prepared_admission(intent: AdmissionIntentV3) -> _PreparedAdmissionV3 | None:
        if not ExecutionLifecycleStore._valid_initial_v3_intent_shape(intent):
            return None
        try:
            from ares.modules.descriptors import (
                canonicalize_parameters,
                extract_destinations,
                require_descriptor,
            )

            descriptor = require_descriptor(intent.module_id)
            if ExecutionLifecycleStore._raw_credential_material_present(
                intent.raw_parameters,
                descriptor.parameter_fields,
            ):
                return None
            canonical = canonicalize_parameters(intent.module_id, intent.raw_parameters)
            values = {key: canonical.values[key] for key in sorted(canonical.values)}
            extracted = extract_destinations(intent.module_id, canonical)
            destination_refs = tuple(
                sorted(
                    {
                        (item.kind.value, str(item.value).strip().lower())
                        for item in extracted
                        if str(item.value).strip()
                    }
                )
            )
            canonical_json = json.dumps(
                values,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            )
            copied_values = json.loads(canonical_json)
            parameter_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            credential_ids_digest = hashlib.sha256(
                "\x00".join(intent.credential_ids).encode("ascii")
            ).hexdigest()
            work_digest = canonical_operation_binding_digest(
                "admission-immutable-work",
                (
                    ("campaign_id", intent.campaign_id),
                    ("module_id", intent.module_id),
                    ("ingress_code", intent.ingress_code),
                    ("evaluation_mode", intent.evaluation_mode),
                    ("parameter_digest", parameter_digest),
                    ("credential_ids_digest", credential_ids_digest),
                    ("noise_units", intent.noise_units),
                    ("exfiltration_units", intent.exfiltration_units),
                ),
            )
            immutable_digest = ExecutionLifecycleStore._initial_v3_replay_digest(intent)
            if immutable_digest is None:
                return None
        except (TypeError, ValueError, RuntimeError):
            return None
        return _PreparedAdmissionV3(
            copied_values,
            destination_refs,
            immutable_digest,
            work_digest,
        )

    @staticmethod
    def _descriptor_policy_facts(descriptor: Any) -> tuple[str, str, str, int, int]:
        capability_names = {
            "cap_net": 1,
            "cap_exec": 2,
            "cap_fs": 4,
            "cap_process": 8,
        }
        blocker_names = {
            "AMBIENT_CREDENTIALS_FORBIDDEN": 1,
            "CANCELLATION_OWNERSHIP_UNPROVEN": 2,
            "DYNAMIC_DESTINATION_UNBOUNDED": 4,
            "DEFAULT_FACTORY_UNEVALUATED": 8,
            "LLM_EGRESS_POLICY_REQUIRED": 16,
            "LIFECYCLE_CONTRACT_UNPROVEN": 32,
            "RAW_CREDENTIAL_INPUT": 64,
            "RESULT_AUTHORITY_UNPROVEN": 128,
            "SENSITIVE_NONEMPTY_DEFAULT": 256,
        }
        required_mask = 0
        for capability in descriptor.required_capabilities:
            if capability.value not in capability_names:
                raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
            required_mask |= capability_names[capability.value]
        blocker_mask = 0
        for blocker in descriptor.blocker_codes:
            blocker_mask |= blocker_names.get(blocker.value, 0)
        return (
            descriptor.minimum_role.value,
            descriptor.opsec.value,
            "attempt_bound" if descriptor.explicit_attempt_approval else "none",
            required_mask,
            blocker_mask,
        )

    async def _resolve_admission_v3(
        self,
        connection: Any,
        principal: TrustedPrincipal,
        intent: AdmissionIntentV3,
        prepared: _PreparedAdmissionV3,
        *,
        suffix: str,
        reserve_budgets: bool = True,
    ) -> _ResolvedAdmissionV3 | None:
        from ares.modules.descriptors import get_descriptor

        # Generation-11 admission has one intersection lock order.  The gateway
        # precedes the mutable principal, campaign, grant, descriptor/catalog,
        # destination, credential, approval, and budget authorities.
        gateway = await self._fetchrow(
            connection,
            "SELECT mode,catalog_digest,activation_revision,revision "
            "FROM execution_gateway_state WHERE singleton_id=1" + suffix,
            (),
        )
        resolved = await self._resolve_principal(connection, principal, suffix=suffix)
        if resolved is None:
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        campaign = await self._fetchrow(
            connection,
            "SELECT c.id,c.operator,c.status,c.noise_profile,ca.authority_state,"
            "ca.authority_revision,ca.authority_binding_digest,"
            "ca.authority_latest_operation_id,"
            "ca.authority_latest_operation_base_revision,"
            "ca.authority_latest_operation_code "
            "FROM campaigns c JOIN campaign_execution_authority_revisions ca "
            "ON ca.campaign_id=c.id WHERE c.id=?" + suffix,
            (intent.campaign_id,),
        )
        grant = await self._fetchrow(
            connection,
            "SELECT authority_state,revision,binding_digest "
            "FROM campaign_execution_actor_grants "
            "WHERE campaign_id=? AND actor_user_id=?" + suffix,
            (intent.campaign_id, resolved.user_id),
        )
        descriptor = get_descriptor(intent.module_id)
        if descriptor is None:
            raise _AbortOperationError(OperationResult(FixedResult.INVALID_CONTRACT, None))
        destination = await self._fetchrow(
            connection,
            "SELECT authority_state,revision,normalization_version,destination_count,"
            "destination_set_digest,binding_digest,latest_operation_id,"
            "latest_operation_base_revision,latest_operation_code FROM "
            "campaign_execution_destination_authorities WHERE campaign_id=?" + suffix,
            (intent.campaign_id,),
        )
        if gateway is None or campaign is None or grant is None or destination is None:
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        destination_state = str(self._value(destination, "authority_state", 0))
        destination_revision = int(self._value(destination, "revision", 1))
        destination_binding = str(self._value(destination, "binding_digest", 5))
        destination_revision_current = await self._v11_authority_revision_current(
            connection,
            revision=destination_revision,
            latest_operation_id=self._value(destination, "latest_operation_id", 6),
            latest_operation_base_revision=self._value(
                destination, "latest_operation_base_revision", 7
            ),
            latest_operation_code=self._value(destination, "latest_operation_code", 8),
            operation_prefix="destination_authority_",
            campaign_id=intent.campaign_id,
            target_id=intent.campaign_id,
            destination_baseline=True,
        )
        credential_rows: list[Any] = []
        for credential_id in sorted(intent.credential_ids):
            credential_suffix = " FOR UPDATE OF c" if self._dialect == "postgresql" else ""
            row = await self._fetchrow(
                connection,
                "SELECT c.id,c.campaign_id,c.host_id,c.username,c.cred_type,c.domain,"
                "c.source_module,c.execution_authority_state,"
                "c.execution_authority_revision,c.execution_authority_binding_digest,"
                "c.execution_authority_latest_operation_id,"
                "c.execution_authority_latest_operation_base_revision,"
                "c.execution_authority_latest_operation_code "
                "FROM credentials c WHERE c.id=?" + credential_suffix,
                (credential_id,),
            )
            if row is None:
                raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
            host_id = self._value(row, "host_id", 2)
            if host_id is not None:
                host = await self._fetchrow(
                    connection,
                    "SELECT campaign_id FROM hosts WHERE id=?" + suffix,
                    (host_id,),
                )
                if host is None or self._value(host, "campaign_id", 0) != intent.campaign_id:
                    raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
            credential_rows.append(row)
        credential_bindings_current = True
        for row in credential_rows:
            revision = int(self._value(row, "execution_authority_revision", 8))
            credential_id = str(self._value(row, "id", 0))
            revision_current = await self._v11_authority_revision_current(
                connection,
                revision=revision,
                latest_operation_id=self._value(row, "execution_authority_latest_operation_id", 10),
                latest_operation_base_revision=self._value(
                    row, "execution_authority_latest_operation_base_revision", 11
                ),
                latest_operation_code=self._value(
                    row, "execution_authority_latest_operation_code", 12
                ),
                operation_prefix="credential_authority_",
                campaign_id=intent.campaign_id,
                target_id=credential_id,
            )
            credential_bindings_current = credential_bindings_current and (
                str(self._value(row, "campaign_id", 1)) == intent.campaign_id
                and self._value(row, "execution_authority_binding_digest", 9)
                == self._credential_authority_binding(row)
                and revision_current
            )
        credentials_current = credential_bindings_current and all(
            self._value(row, "execution_authority_state", 7) == "active" for row in credential_rows
        )
        credential_observations = tuple(
            (
                str(self._value(row, "id", 0)),
                int(self._value(row, "execution_authority_revision", 8)),
                str(self._value(row, "execution_authority_binding_digest", 9)),
            )
            for row in credential_rows
        )
        credential_binding = canonical_operation_binding_digest(
            "admission-credential-observations",
            (
                ("credential_count", len(credential_observations)),
                (
                    "credential_observations_digest",
                    hashlib.sha256(
                        "\x00".join(
                            f"{item[0]}:{item[1]}:{item[2]}" for item in credential_observations
                        ).encode("utf-8")
                    ).hexdigest(),
                ),
            ),
        )
        approval_row = None
        if intent.approval_ref is not None:
            approval_row = await self._fetchrow(
                connection,
                "SELECT id,approval_ref,approver_subject_ref,approver_user_id,revision,"
                "binding_digest,authority_state,campaign_id,submission_id,attempt_id,"
                "actor_subject_ref,actor_user_id,module_id,granted_capability_mask,"
                "descriptor_semantic_digest FROM execution_approval_authorities "
                "WHERE approval_ref=?" + suffix,
                (intent.approval_ref,),
            )
        approval = (
            None
            if approval_row is None
            else ApprovalBinding(
                str(self._value(approval_row, "id", 0)),
                str(self._value(approval_row, "approval_ref", 1)),
                str(self._value(approval_row, "approver_subject_ref", 2)),
                self._value(approval_row, "approver_user_id", 3),
                int(self._value(approval_row, "revision", 4)),
                str(self._value(approval_row, "binding_digest", 5)),
            )
        )
        approval_current = bool(
            approval_row is not None
            and self._value(approval_row, "authority_state", 6) == "active"
            and self._value(approval_row, "campaign_id", 7) == intent.campaign_id
            and self._value(approval_row, "submission_id", 8) == intent.submission_id
            and self._value(approval_row, "attempt_id", 9) == intent.attempt_id
            and self._value(approval_row, "actor_subject_ref", 10) == resolved.subject_ref
            and self._value(approval_row, "actor_user_id", 11) == resolved.user_id
            and self._value(approval_row, "module_id", 12) == intent.module_id
            and self._value(approval_row, "descriptor_semantic_digest", 14)
            == descriptor.semantic_digest
            and self._value(approval_row, "binding_digest", 5)
            == self._approval_authority_binding(approval_row)
        )
        granted_mask = (
            0
            if approval_row is None
            else int(self._value(approval_row, "granted_capability_mask", 13))
        )
        minimum_role, noise_class, approval_policy, capability_mask, blocker_mask = (
            self._descriptor_policy_facts(descriptor)
        )
        if approval_policy == "none" and intent.approval_ref is not None:
            raise _AbortOperationError(OperationResult(FixedResult.INVALID_CONTRACT, None))
        credential_kind_map = {
            "cleartext": {"password", "vault_record"},
            "ntlm": {"ntlm_hash", "hash_material", "vault_record"},
            "krb5_tgs": {"hash_material", "vault_record"},
            "krb5_asrep": {"hash_material", "vault_record"},
            "krb5_tgt": {"vault_record"},
            "ssh_key": {"ssh_private_key", "vault_record"},
            "api_key": {"api_token", "vault_record"},
            "jwt": {"api_token", "vault_record"},
            "certificate": {"vault_record"},
            "cookie": {"vault_record"},
        }
        policy_state = descriptor.credential_policy.state.value
        allowed_kinds = {item.value for item in descriptor.credential_policy.allowed_handle_kinds}
        credential_policy_current = not descriptor.credential_policy.ambient_dependencies and (
            (policy_state == "not_applicable" and not credential_rows)
            or (
                policy_state == "supported"
                and all(
                    bool(
                        credential_kind_map.get(str(self._value(row, "cred_type", 4)), set())
                        & allowed_kinds
                    )
                    for row in credential_rows
                )
            )
        )
        destination_values: set[str] = set()
        for kind, value in prepared.destination_refs:
            normalized = self._canonical_destination_values(
                json.dumps([]),
                json.dumps([value]),
            )
            if len(normalized) != 1:
                raise _AbortOperationError(OperationResult(FixedResult.INVALID_CONTRACT, None))
            destination_values.add(kind + "|" + normalized[0])
        allowed_values = self._canonical_destination_values(
            # The persisted aggregate is the authority; current campaign bytes are
            # reduced again to prove the aggregate remains current.
            await self._scalar_campaign_value(connection, intent.campaign_id, "scope_json", suffix),
            await self._scalar_campaign_value(
                connection, intent.campaign_id, "targets_json", suffix
            ),
        )
        current_count, current_digest, current_binding = self._destination_authority_facts(
            allowed_values
        )
        destinations_current = (
            destination_state == "active"
            and int(self._value(destination, "normalization_version", 2))
            == DESTINATION_NORMALIZATION_VERSION
            and int(self._value(destination, "destination_count", 3)) == current_count
            and self._value(destination, "destination_set_digest", 4) == current_digest
            and destination_binding == current_binding
        )
        destinations_in_scope = all(
            self._destination_is_allowed(item, allowed_values) for item in destination_values
        )
        gateway_mode = str(self._value(gateway, "mode", 0))
        gateway_mode_current = gateway_mode in {
            "disabled",
            "shadow_candidate",
            "enforced",
            "emergency_disabled",
        }
        gateway_revision = int(self._value(gateway, "revision", 3))
        gateway_activation_revision = self._value(gateway, "activation_revision", 2)
        gateway_revision_current = (
            gateway_revision == 0 and gateway_activation_revision is None
            if gateway_mode == "disabled"
            else gateway_revision >= 1 and gateway_activation_revision == gateway_revision
        )
        catalog_digest = self._descriptor_catalog_digest()
        gateway_catalog_current = (
            self._value(gateway, "catalog_digest", 1) is None
            if gateway_mode == "disabled"
            else self._value(gateway, "catalog_digest", 1) == catalog_digest
        )
        campaign_binding = self._campaign_authority_binding(campaign, destination_binding)
        campaign_binding_current = (
            self._value(campaign, "authority_binding_digest", 6) == campaign_binding
        )
        campaign_revision_current = await self._v11_authority_revision_current(
            connection,
            revision=int(self._value(campaign, "authority_revision", 5)),
            latest_operation_id=self._value(campaign, "authority_latest_operation_id", 7),
            latest_operation_base_revision=self._value(
                campaign, "authority_latest_operation_base_revision", 8
            ),
            latest_operation_code=self._value(campaign, "authority_latest_operation_code", 9),
            operation_prefix="campaign_authority_",
            campaign_id=intent.campaign_id,
            target_id=intent.campaign_id,
        )
        campaign_active = self._value(campaign, "authority_state", 4) == "active" and self._value(
            campaign, "status", 2
        ) in {"created", "running"}
        grant_state = str(self._value(grant, "authority_state", 0))
        grant_active = grant_state == "active" and self._value(
            grant, "binding_digest", 2
        ) == self._grant_authority_binding(
            intent.campaign_id,
            resolved.user_id,
            "active",
        )
        if (
            not gateway_mode_current
            or not gateway_revision_current
            or not gateway_catalog_current
            or not campaign_binding_current
            or not campaign_revision_current
            or not campaign_active
            or not grant_active
            or not destinations_current
            or not destination_revision_current
            or not credentials_current
            or (intent.approval_ref is not None and not approval_current)
        ):
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        if gateway_mode == "emergency_disabled":
            initial_verdict, reason_mask = None, None
            evaluation_state = "not_evaluated"
            gateway_decision = "emergency_disabled"
        else:
            from ares.core.execution_policy import (
                ApprovalPolicy,
                AuthorityFactsV1,
                BlockerBits,
                CapabilityBits,
                DescriptorFactsV1,
                EvaluationMode,
                NoiseClass,
                PolicyInputV1,
                PolicyReason,
                PolicyVerdict,
                RequestFactsV1,
                RoleRank,
                evaluate_policy,
            )

            if resolved.role not in {"reporter", "operator", "team_lead", "admin"}:
                raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
            # ``reporter`` is a persisted lifecycle role outside the pure
            # policy kernel's RoleRank domain.  Evaluate it with the least
            # privileged representable rank so descriptor/request rejection
            # keeps precedence, then apply the exact lifecycle role ceiling.
            role = {
                "reporter": RoleRank.OPERATOR,
                "operator": RoleRank.OPERATOR,
                "team_lead": RoleRank.TEAM_LEAD,
                "admin": RoleRank.ADMIN,
            }[resolved.role]
            minimum = {
                "operator": RoleRank.OPERATOR,
                "team_lead": RoleRank.TEAM_LEAD,
                "admin": RoleRank.ADMIN,
            }[minimum_role]
            decision = evaluate_policy(
                PolicyInputV1(
                    RequestFactsV1(
                        1,
                        EvaluationMode(intent.evaluation_mode),
                        True,
                        True,
                        True,
                        True,
                        True,
                        len(prepared.canonical_parameters),
                    ),
                    DescriptorFactsV1(
                        1,
                        True,
                        True,
                        descriptor.descriptor_complete,
                        True,
                        minimum,
                        NoiseClass(noise_class),
                        ApprovalPolicy(approval_policy),
                        CapabilityBits(capability_mask),
                        BlockerBits(blocker_mask),
                        descriptor.descriptor_complete,
                        descriptor.idempotency.value != "unproven_current_contract",
                        True,
                        True,
                        descriptor.future_gateway_eligible,
                    ),
                    AuthorityFactsV1(
                        1,
                        True,
                        True,
                        True,
                        True,
                        role,
                        campaign_active,
                        grant_active,
                        approval_row is not None,
                        approval_current,
                        approval_current,
                        CapabilityBits(granted_mask),
                        True,
                        destinations_in_scope,
                        True,
                        credentials_current,
                        True,
                        credential_policy_current,
                        True,
                        not descriptor.credential_policy.ambient_dependencies,
                        True,
                        True,
                        True,
                    ),
                )
            )
            initial_verdict = decision.verdict.value
            reasons = decision.reasons
            if resolved.role == "reporter" and initial_verdict != "rejected":
                initial_verdict = PolicyVerdict.BLOCKED.value
                reasons = (PolicyReason.INSUFFICIENT_ROLE,)
            # The policy enum values and lifecycle mask names are intentionally
            # one-to-one.  Sum is equivalent to OR because every bit is unique.
            reason_mask = sum(int(PolicyReasonBit[reason.name]) for reason in reasons)
            if gateway_mode in {"disabled", "shadow_candidate"} and (
                initial_verdict in {"preview_ready", "live_candidate"}
            ):
                initial_verdict = "blocked"
                reason_mask |= int(PolicyReasonBit.AUTHORITY_RESOLUTION_REQUIRED)
            evaluation_state = "evaluated"
            gateway_decision = "none"
        live_candidate = (
            gateway_mode == "enforced" and initial_verdict == "live_candidate" and reason_mask == 0
        )
        budgets = (
            await self._resolve_budget_reservation_v3(connection, resolved, intent, suffix=suffix)
            if reserve_budgets and live_candidate
            else None
        )
        snapshot = AttemptPolicySnapshot(
            resolved.authority_revision,
            int(self._value(campaign, "authority_revision", 5)),
            destination_revision,
            max((row[1] for row in credential_observations), default=0),
            intent.evaluation_mode,
            True,
            True,
            True,
            True,
            True,
            len(prepared.canonical_parameters),
            descriptor.semantic_digest,
            catalog_digest,
            True,
            True,
            descriptor.descriptor_complete,
            True,
            minimum_role,
            noise_class,
            approval_policy,
            capability_mask,
            blocker_mask,
            descriptor.descriptor_complete,
            descriptor.idempotency.value != "unproven_current_contract",
            True,
            True,
            descriptor.future_gateway_eligible,
            True,
            gateway_revision_current and gateway_catalog_current,
            True,
            True,
            resolved.role,
            campaign_active,
            grant_active,
            approval_row is not None,
            approval_current,
            approval_current,
            granted_mask,
            True,
            destinations_in_scope,
            True,
            credentials_current,
            True,
            credential_policy_current,
            True,
            not descriptor.credential_policy.ambient_dependencies,
            (budgets is not None) if live_candidate else True,
            (budgets is not None) if live_candidate else True,
            (budgets is not None) if live_candidate else True,
            gateway_mode,
            gateway_decision,
            evaluation_state,
            initial_verdict,
            reason_mask,
            descriptor.external_effect.value,
            descriptor.idempotency.value,
            descriptor.retry_eligibility.value,
            "not_applicable" if live_candidate else "closed_without_retry",
            descriptor.cancellation_ownership.value,
            descriptor.compensation.value,
            descriptor.timeout.source.value,
            descriptor.timeout.seconds * 1000,
            descriptor.timeout.settlement.value,
        )
        return _ResolvedAdmissionV3(
            resolved,
            snapshot,
            approval if live_candidate else None,
            budgets if live_candidate else None,
            destination_binding,
            credential_binding,
            None if approval is None else approval.binding_digest,
            gateway_revision,
            gateway_activation_revision,
            int(self._value(grant, "revision", 1)),
            tuple(
                (
                    canonical_operation_binding_digest(
                        "destination-observation",
                        (
                            ("normalization_version", DESTINATION_NORMALIZATION_VERSION),
                            ("destination_kind", value.partition("|")[0]),
                            ("canonical_destination", value.partition("|")[2]),
                        ),
                    ),
                    destination_revision,
                )
                for value in sorted(destination_values)
            ),
            credential_observations,
        )

    async def _scalar_campaign_value(
        self, connection: Any, campaign_id: str, column: str, suffix: str
    ) -> Any:
        if column not in {"scope_json", "targets_json"}:
            raise ValueError("Invalid campaign authority column")
        row = await self._fetchrow(
            connection,
            f"SELECT {column} FROM campaigns WHERE id=?" + suffix,
            (campaign_id,),
        )
        if row is None:
            raise ValueError("Missing campaign authority")
        return self._value(row, column, 0)

    async def _resolve_budget_reservation_v3(
        self,
        connection: Any,
        principal: _ResolvedPrincipal,
        intent: AdmissionIntentV3,
        *,
        suffix: str,
    ) -> BudgetReservation | None:
        rows = await self._fetchall(
            connection,
            "SELECT id,budget_kind,capacity_units,reserved_units,consumed_units,revision,"
            "latest_operation_id,latest_operation_base_revision,latest_operation_code "
            "FROM campaign_execution_budgets WHERE campaign_id=? ORDER BY CASE budget_kind "
            "WHEN 'noise' THEN 1 WHEN 'exfiltration' THEN 2 WHEN 'concurrency' THEN 3 END" + suffix,
            (intent.campaign_id,),
        )
        by_kind = {str(self._value(row, "budget_kind", 1)): row for row in rows}
        if set(by_kind) != {"noise", "exfiltration", "concurrency"}:
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        latest_operation_ids = tuple(
            sorted({str(self._value(row, "latest_operation_id", 6)) for row in rows})
        )
        receipt_rows = await self._fetchall(
            connection,
            "SELECT operation_id,operation_code,campaign_id,result_code,"
            "result_revision_present,result_revision "
            "FROM execution_operation_receipts WHERE operation_id IN ("
            + ",".join("?" for _ in latest_operation_ids)
            + ")",
            latest_operation_ids,
        )
        receipts = {str(self._value(row, "operation_id", 0)): row for row in receipt_rows}
        receipt_code_for_latest_code = {
            "configure": "budget_configure",
            "reserve": "budget_reserve",
            "settle": "budget_settle",
        }
        for row in rows:
            revision = int(self._value(row, "revision", 5))
            latest_operation_id = str(self._value(row, "latest_operation_id", 6))
            base_revision = int(self._value(row, "latest_operation_base_revision", 7))
            latest_operation_code = str(self._value(row, "latest_operation_code", 8))
            receipt = receipts.get(latest_operation_id)
            if (
                base_revision != (0 if revision == 0 else revision - 1)
                or receipt is None
                or self._value(receipt, "operation_code", 1)
                != receipt_code_for_latest_code.get(latest_operation_code)
                or self._value(receipt, "campaign_id", 2) != intent.campaign_id
                or self._value(receipt, "result_code", 3) != FixedResult.APPLIED.value
                or not bool(self._value(receipt, "result_revision_present", 4))
                or self._value(receipt, "result_revision", 5) != revision
            ):
                raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        requested = {
            "noise": intent.noise_units,
            "exfiltration": intent.exfiltration_units,
            "concurrency": 1,
        }
        for kind, units in requested.items():
            row = by_kind[kind]
            if int(self._value(row, "reserved_units", 3)) + int(
                self._value(row, "consumed_units", 4)
            ) + units > int(self._value(row, "capacity_units", 2)):
                raise _AbortOperationError(
                    OperationResult(
                        FixedResult.CAPACITY_UNAVAILABLE,
                        int(self._value(row, "revision", 5)),
                    )
                )

        def derived(label: str) -> str:
            digest = hashlib.sha256(
                (intent.operation_id + "\x00" + label).encode("ascii")
            ).hexdigest()
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

        return BudgetReservation(
            intent.campaign_id,
            intent.attempt_id,
            str(self._value(by_kind["noise"], "id", 0)),
            derived("noise-ledger"),
            intent.noise_units,
            int(self._value(by_kind["noise"], "revision", 5)),
            str(self._value(by_kind["exfiltration"], "id", 0)),
            derived("exfiltration-ledger"),
            intent.exfiltration_units,
            int(self._value(by_kind["exfiltration"], "revision", 5)),
            str(self._value(by_kind["concurrency"], "id", 0)),
            derived("concurrency-ledger"),
            int(self._value(by_kind["concurrency"], "revision", 5)),
            derived("budget-operation"),
            "actor",
            principal.subject_ref,
            principal.user_id,
            principal.authority_revision,
        )

    async def _resolve_principal(
        self,
        connection: Any,
        principal: object,
        *,
        suffix: str,
    ) -> _ResolvedPrincipal | None:
        if (
            type(principal) is not TrustedPrincipal
            or not valid_uuid(principal.subject_ref)
            or not valid_uuid(principal.user_id)
            or principal.subject_ref != principal.user_id
        ):
            return None
        row = await self._fetchrow(
            connection,
            "SELECT u.id,u.username,u.role,u.is_active,u.auth_epoch,a.authority_state,"
            "a.authority_revision,a.authority_binding_digest,"
            "a.authority_latest_operation_id,"
            "a.authority_latest_operation_base_revision,"
            "a.authority_latest_operation_code "
            "FROM users u JOIN execution_actor_authority_revisions a ON a.user_id=u.id "
            "WHERE u.id=?" + suffix,
            (principal.user_id,),
        )
        if row is None:
            return None
        binding = self._actor_authority_binding(
            str(self._value(row, "id", 0)),
            str(self._value(row, "username", 1)),
            str(self._value(row, "role", 2)),
            bool(self._value(row, "is_active", 3)),
            int(self._value(row, "auth_epoch", 4)),
        )
        if (
            not bool(self._value(row, "is_active", 3))
            or self._value(row, "authority_state", 5) != "active"
            or self._value(row, "authority_binding_digest", 7) != binding
            or not await self._v11_authority_revision_current(
                connection,
                revision=int(self._value(row, "authority_revision", 6)),
                latest_operation_id=self._value(row, "authority_latest_operation_id", 8),
                latest_operation_base_revision=self._value(
                    row, "authority_latest_operation_base_revision", 9
                ),
                latest_operation_code=self._value(row, "authority_latest_operation_code", 10),
                operation_prefix="actor_authority_",
                campaign_id=None,
                target_id=principal.user_id,
            )
        ):
            return None
        return _ResolvedPrincipal(
            principal.subject_ref,
            principal.user_id,
            str(self._value(row, "role", 2)),
            int(self._value(row, "auth_epoch", 4)),
            int(self._value(row, "authority_revision", 6)),
            binding,
        )

    async def _principal_can_mutate_campaign(
        self,
        connection: Any,
        principal: _ResolvedPrincipal,
        campaign_id: str,
        *,
        suffix: str,
    ) -> bool:
        if principal.role == "admin":
            return True
        if principal.role != "team_lead":
            return False
        row = await self._fetchrow(
            connection,
            "SELECT c.operator,u.username FROM campaigns c JOIN users u ON u.id=? "
            "WHERE c.id=?" + suffix,
            (principal.user_id, campaign_id),
        )
        return bool(
            row is not None and self._value(row, "operator", 0) == self._value(row, "username", 1)
        )

    async def _v11_actor_receipt_spec(
        self,
        connection: Any,
        principal: TrustedPrincipal,
        *,
        suffix: str,
        operation_id: str,
        operation_code: str,
        campaign_id: str | None,
        primary_target_id: str,
        secondary_target_id: str | None = None,
        expected_revision: int | None,
        fields: tuple[tuple[str, str | int | bool | None], ...] = (),
    ) -> tuple[_ReceiptSpec, _ResolvedPrincipal | None] | None:
        """Construct receipt-first v11 authority binding without trusting caller facts."""
        prior = await self._receipt_row(connection, operation_id)
        resolved: _ResolvedPrincipal | None = None
        if prior is not None and bool(
            self._value(prior, "principal_authority_revision_present", 7)
        ):
            authority_revision = int(self._value(prior, "principal_authority_revision", 8))
        else:
            gateway = await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            if gateway is None:
                return None
            resolved = await self._resolve_principal(connection, principal, suffix=suffix)
            if resolved is None:
                return None
            authority_revision = resolved.authority_revision
        try:
            spec = self._receipt_spec(
                operation_id=operation_id,
                operation_code=operation_code,
                campaign_id=campaign_id,
                primary_target_id=primary_target_id,
                secondary_target_id=secondary_target_id,
                principal_kind="actor",
                principal_subject_ref=principal.subject_ref,
                principal_user_id=principal.user_id,
                principal_authority_revision=authority_revision,
                expected_revision=expected_revision,
                fields=fields,
            )
        except (AttributeError, ValueError):
            return None
        return spec, resolved

    @staticmethod
    def _valid_trusted_principal(principal: object) -> bool:
        return (
            type(principal) is TrustedPrincipal
            and valid_uuid(principal.subject_ref)
            and valid_uuid(principal.user_id)
            and principal.subject_ref == principal.user_id
        )

    @staticmethod
    def _canonical_untrusted_parameters_digest(value: object) -> str | None:
        if not isinstance(value, Mapping):
            return None
        try:
            serialized = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def _initial_v3_replay_digest(cls, intent: object) -> str | None:
        if type(intent) is not AdmissionIntentV3:
            return None
        raw_digest = cls._canonical_untrusted_parameters_digest(intent.raw_parameters)
        if raw_digest is None:
            return None
        try:
            credential_ids_digest = hashlib.sha256(
                "\x00".join(intent.credential_ids).encode("ascii")
            ).hexdigest()
            return canonical_operation_binding_digest(
                "admission-immutable-intent",
                (
                    ("logical_execution_id", intent.logical_execution_id),
                    ("submission_id", intent.submission_id),
                    ("attempt_id", intent.attempt_id),
                    ("operation_id", intent.operation_id),
                    ("outbox_id", intent.outbox_id),
                    ("publication_key", intent.publication_key),
                    ("campaign_id", intent.campaign_id),
                    ("module_id", intent.module_id),
                    ("ingress_code", intent.ingress_code),
                    ("evaluation_mode", intent.evaluation_mode),
                    ("raw_parameters_digest", raw_digest),
                    ("credential_ids_digest", credential_ids_digest),
                    ("approval_ref", intent.approval_ref),
                    ("noise_units", intent.noise_units),
                    ("exfiltration_units", intent.exfiltration_units),
                ),
            )
        except (AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    def _derived_v3_uuid(operation_id: str, label: str) -> str:
        digest = hashlib.sha256((operation_id + "\x00" + label).encode("ascii")).hexdigest()
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

    def _retry_v3_receipt_spec(
        self,
        principal: TrustedPrincipal,
        intent: RetryIntentV3,
        *,
        campaign_id: str | None,
        authority_revision: int,
    ) -> _ReceiptSpec | None:
        raw_digest = self._canonical_untrusted_parameters_digest(intent.raw_parameters)
        if raw_digest is None:
            return None
        credential_ids_digest = hashlib.sha256(
            "\x00".join(intent.credential_ids).encode("ascii")
        ).hexdigest()
        try:
            return self._receipt_spec(
                operation_id=intent.operation_id,
                operation_code="retry",
                campaign_id=campaign_id,
                primary_target_id=intent.parent_attempt_id,
                secondary_target_id=intent.child_attempt_id,
                principal_kind="actor",
                principal_subject_ref=principal.subject_ref,
                principal_user_id=principal.user_id,
                principal_authority_revision=authority_revision,
                expected_revision=intent.expected_parent_revision,
                fields=(
                    ("logical_execution_id", intent.logical_execution_id),
                    ("child_outbox_id", intent.outbox_id),
                    ("child_publication_key", intent.publication_key),
                    ("evaluation_mode", intent.evaluation_mode),
                    ("raw_parameters_digest", raw_digest),
                    ("credential_ids_digest", credential_ids_digest),
                    ("approval_ref", intent.approval_ref),
                    ("noise_units", intent.noise_units),
                    ("exfiltration_units", intent.exfiltration_units),
                ),
            )
        except ValueError:
            return None

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[Any]:
        if self._dialect == "sqlite":
            begin = await _await_owned_cleanup(
                self._backend.execute("BEGIN IMMEDIATE"), name="lifecycle-sqlite-begin"
            )
            if begin.error is not None:
                primary = begin.cancellation or begin.error
                if begin.cancellation is not None:
                    _record_cleanup_failure(primary, "sqlite-begin")
                raise primary
            if begin.cancellation is not None:
                rollback = await _await_owned_cleanup(
                    self._backend.rollback(), name="lifecycle-sqlite-rollback"
                )
                if rollback.error is not None:
                    _record_cleanup_failure(begin.cancellation, "sqlite-rollback")
                raise begin.cancellation
            try:
                yield self._backend
            except BaseException as error:
                rollback = await _await_owned_cleanup(
                    self._backend.rollback(), name="lifecycle-sqlite-rollback"
                )
                if rollback.error is not None:
                    _record_cleanup_failure(error, "sqlite-rollback")
                raise
            commit = await _await_owned_cleanup(
                self._backend.commit(), name="lifecycle-sqlite-commit"
            )
            if commit.error is not None:
                primary = commit.cancellation or commit.error
                if commit.cancellation is not None:
                    _record_cleanup_failure(primary, "sqlite-commit")
                rollback = await _await_owned_cleanup(
                    self._backend.rollback(), name="lifecycle-sqlite-rollback"
                )
                if rollback.error is not None:
                    _record_cleanup_failure(primary, "sqlite-rollback")
                raise primary
            if commit.cancellation is not None:
                raise commit.cancellation
            return
        connection = await self._backend.acquire()
        try:
            transaction = connection.transaction()
            await transaction.start()
            try:
                yield connection
            except BaseException as error:
                rollback = await _await_owned_cleanup(
                    transaction.rollback(), name="lifecycle-postgresql-rollback"
                )
                if rollback.error is not None:
                    _record_cleanup_failure(error, "postgresql-rollback")
                raise
            commit = await _await_owned_cleanup(
                transaction.commit(), name="lifecycle-postgresql-commit"
            )
            if commit.error is not None or commit.cancellation is not None:
                primary = commit.cancellation or commit.error
                if commit.error is not None and commit.cancellation is not None:
                    _record_cleanup_failure(primary, "postgresql-commit")
                raise primary
        except BaseException as error:
            release = await _await_owned_cleanup(
                self._backend.release(connection), name="lifecycle-postgresql-release"
            )
            if release.error is not None:
                _record_cleanup_failure(error, "postgresql-release")
            raise
        release = await _await_owned_cleanup(
            self._backend.release(connection), name="lifecycle-postgresql-release"
        )
        if release.error is not None or release.cancellation is not None:
            primary = release.cancellation or release.error
            if release.error is not None and release.cancellation is not None:
                _record_cleanup_failure(primary, "postgresql-release")
            raise primary

    async def _fetchrow(self, connection: Any, sql: str, params: Sequence[Any]) -> Any:
        if self._dialect == "postgresql":
            return await connection.fetchrow(_question_to_postgres(sql), *params)
        cursor = await connection.execute(sql, params)
        return await cursor.fetchone()

    async def _execute(self, connection: Any, sql: str, params: Sequence[Any]) -> None:
        """Execute non-truth-bearing SQL; callers must not infer affected rows."""
        if self._dialect == "postgresql":
            await connection.execute(_question_to_postgres(sql), *params)
        else:
            await connection.execute(sql, params)

    async def _fetchall(self, connection: Any, sql: str, params: Sequence[Any]) -> Sequence[Any]:
        if self._dialect == "postgresql":
            return await connection.fetch(_question_to_postgres(sql), *params)
        cursor = await connection.execute(sql, params)
        return await cursor.fetchall()

    async def _returning_rows(
        self, connection: Any, sql: str, params: Sequence[Any]
    ) -> tuple[Any, ...]:
        if " RETURNING " not in sql.upper():
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        if self._dialect == "postgresql":
            rows = await connection.fetch(_question_to_postgres(sql), *params)
            return tuple(rows)
        cursor = await connection.execute(sql, params)
        rows = tuple(await cursor.fetchall())
        changes_cursor = await connection.execute("SELECT changes() AS affected_rows", ())
        changes_row = await changes_cursor.fetchone()
        if changes_row is None or int(self._value(changes_row, "affected_rows", 0)) != len(rows):
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        return rows

    async def cas_update_one(
        self,
        connection: Any,
        sql: str,
        params: Sequence[Any],
        *,
        identity: str,
        post_revision: int,
        identity_column: str = "id",
        revision_column: str = "revision",
        zero_classifier: Callable[[], Awaitable[OperationResult]] | None,
    ) -> Any | None:
        rows = await self._returning_rows(connection, sql, params)
        if not rows:
            if zero_classifier is not None:
                result = await zero_classifier()
                if type(result) is not OperationResult or result.result is FixedResult.APPLIED:
                    raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
                raise _AbortOperationError(result)
            return None
        if len(rows) != 1:
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        row = rows[0]
        if (
            self._value(row, identity_column, 0) != identity
            or int(self._value(row, revision_column, 1)) != post_revision
        ):
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        return row

    async def insert_or_validate_binding(
        self,
        connection: Any,
        sql: str,
        params: Sequence[Any],
        *,
        identity: str,
        revision: int,
        identity_column: str = "id",
        revision_column: str = "revision",
    ) -> Any | None:
        return await self.cas_update_one(
            connection,
            sql,
            params,
            identity=identity,
            post_revision=revision,
            identity_column=identity_column,
            revision_column=revision_column,
            zero_classifier=None,
        )

    async def update_exact_set(
        self,
        connection: Any,
        sql: str,
        params: Sequence[Any],
        *,
        expected: tuple[tuple[str, Any], ...],
        zero_classifier: Callable[[], Awaitable[OperationResult]] | None,
    ) -> Any | None:
        rows = await self._returning_rows(connection, sql, params)
        if not rows:
            if zero_classifier is not None:
                result = await zero_classifier()
                if type(result) is not OperationResult or result.result is FixedResult.APPLIED:
                    raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
                raise _AbortOperationError(result)
            return None
        if len(rows) != 1:
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        row = rows[0]
        if any(
            self._value(row, name, index) != value for index, (name, value) in enumerate(expected)
        ):
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        return row

    async def delete_exact_set(
        self,
        connection: Any,
        sql: str,
        params: Sequence[Any],
        *,
        expected_identities: tuple[str, ...],
        zero_classifier: Callable[[], Awaitable[OperationResult]] | None,
    ) -> tuple[Any, ...] | None:
        rows = await self._returning_rows(connection, sql, params)
        if not rows:
            if zero_classifier is not None:
                result = await zero_classifier()
                if type(result) is not OperationResult or result.result is FixedResult.APPLIED:
                    raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
                raise _AbortOperationError(result)
            return None
        observed = tuple(sorted(str(self._value(row, "id", 0)) for row in rows))
        if observed != tuple(sorted(expected_identities)):
            raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
        return rows

    @asynccontextmanager
    async def _savepoint(self, connection: Any) -> AsyncIterator[None]:
        await self._execute(connection, "SAVEPOINT lifecycle_compound", ())
        try:
            yield
        except BaseException as error:
            rollback = await _await_owned_cleanup(
                self._execute(connection, "ROLLBACK TO SAVEPOINT lifecycle_compound", ()),
                name="lifecycle-savepoint-rollback",
            )
            if rollback.error is not None:
                _record_cleanup_failure(error, "savepoint-rollback")
            else:
                release = await _await_owned_cleanup(
                    self._execute(connection, "RELEASE SAVEPOINT lifecycle_compound", ()),
                    name="lifecycle-savepoint-release",
                )
                if release.error is not None:
                    _record_cleanup_failure(error, "savepoint-release")
            raise
        release = await _await_owned_cleanup(
            self._execute(connection, "RELEASE SAVEPOINT lifecycle_compound", ()),
            name="lifecycle-savepoint-release",
        )
        if release.error is not None or release.cancellation is not None:
            primary = release.cancellation or release.error
            if release.error is not None and release.cancellation is not None:
                _record_cleanup_failure(primary, "savepoint-release")
            raise primary

    async def _receipt_row(self, connection: Any, operation_id: str) -> Any:
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        return await self._fetchrow(
            connection,
            "SELECT operation_code,campaign_id,primary_target_id,secondary_target_id,"
            "principal_kind,principal_subject_ref,principal_user_id,"
            "principal_authority_revision_present,principal_authority_revision,"
            "binding_contract_version,request_binding_digest,expected_revision_present,"
            "expected_revision,secondary_expected_revision_present,"
            "secondary_expected_revision,owner_ref,lease_generation,result_code,"
            "exact_replay_code,result_binding_digest,result_identity,"
            "result_revision_present,result_revision,secondary_result_identity,"
            "secondary_result_revision_present,secondary_result_revision "
            "FROM execution_operation_receipts WHERE operation_id=?" + suffix,
            (operation_id,),
        )

    def _receipt_matches(self, row: Any, spec: _ReceiptSpec) -> bool:
        expected = (
            spec.operation_code,
            spec.campaign_id,
            spec.primary_target_id,
            spec.secondary_target_id,
            spec.principal_kind,
            spec.principal_subject_ref,
            spec.principal_user_id,
            spec.principal_authority_revision is not None,
            spec.principal_authority_revision,
            2,
            spec.request_binding_digest,
            spec.expected_revision is not None,
            spec.expected_revision,
            spec.secondary_expected_revision is not None,
            spec.secondary_expected_revision,
            spec.owner_ref,
            spec.lease_generation,
        )
        return all(
            self._value(row, name, index) == value
            for index, (name, value) in enumerate(
                zip(
                    (
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
                    ),
                    expected,
                    strict=True,
                )
            )
        )

    async def _receipt_primary_target_conflicts(
        self,
        connection: Any,
        operation_id: str,
        primary_target_id: str,
    ) -> bool:
        row = await self._fetchrow(
            connection,
            "SELECT primary_target_id FROM execution_operation_receipts WHERE operation_id = ?",
            (operation_id,),
        )
        return (
            row is not None and str(self._value(row, "primary_target_id", 0)) != primary_target_id
        )

    async def _classify_receipt(
        self,
        connection: Any,
        spec: _ReceiptSpec,
        *,
        current_revision: int | None,
        exact_result: FixedResult = FixedResult.REPLAYED,
        current_result_fields: tuple[tuple[str, str | int | bool | None], ...] | None = None,
    ) -> OperationResult | None:
        row = await self._receipt_row(connection, spec.operation_id)
        del exact_result, current_result_fields
        if row is None:
            return None
        if not self._receipt_matches(row, spec):
            return OperationResult(FixedResult.CONFLICT_OPERATION, current_revision)
        result_revision = (
            self._value(row, "result_revision", 22)
            if bool(self._value(row, "result_revision_present", 21))
            else None
        )
        stored_result = self._value(row, "result_code", 17)
        if stored_result != FixedResult.APPLIED.value:
            return OperationResult(FixedResult(stored_result), result_revision)
        replay_code = FixedResult(str(self._value(row, "exact_replay_code", 18)))
        return OperationResult(replay_code, result_revision)

    async def _classify_zero_row(
        self,
        connection: Any,
        *,
        table: str,
        identity_column: str,
        identity: str,
        revision_column: str | None = None,
        checks: tuple[tuple[str, tuple[Any, ...], FixedResult], ...] = (),
        missing_result: FixedResult = FixedResult.NOT_FOUND_OR_PURGED,
        matched_result: FixedResult = FixedResult.INVARIANT_FAILURE,
        receipt_spec: _ReceiptSpec | None = None,
        authority_columns: tuple[str, str, str] | None = None,
        authority_before_checks: bool = False,
        expected_authority_user_id: str | None = None,
        expected_authority_revision: int | None = None,
        expected_authority_role: str | None = None,
    ) -> OperationResult:
        if receipt_spec is not None:
            receipt_result = await self._classify_receipt(
                connection,
                receipt_spec,
                current_revision=receipt_spec.expected_revision,
            )
            if receipt_result is not None:
                return receipt_result
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        columns = tuple(
            dict.fromkeys(
                column
                for column in (
                    revision_column,
                    *(name for name, _values, _result in checks),
                    *(() if authority_columns is None else authority_columns),
                )
                if column is not None
            )
        )
        projection = ",".join(columns) if columns else identity_column
        row = await self._fetchrow(
            connection,
            f"SELECT {projection} FROM {table} WHERE {identity_column}=?" + suffix,
            (identity,),
        )
        revision = (
            None
            if row is None or revision_column is None
            else int(self._value(row, revision_column, columns.index(revision_column)))
        )
        if row is None:
            return OperationResult(missing_result, None)

        async def classify_authority() -> OperationResult | None:
            if authority_columns is None:
                return None
            user_column, authority_revision_column, role_column = authority_columns
            user_id = (
                expected_authority_user_id
                if expected_authority_user_id is not None
                else self._value(row, user_column, columns.index(user_column))
            )
            authority_revision = (
                expected_authority_revision
                if expected_authority_revision is not None
                else self._value(
                    row,
                    authority_revision_column,
                    columns.index(authority_revision_column),
                )
            )
            authority_role = (
                expected_authority_role
                if expected_authority_role is not None
                else self._value(row, role_column, columns.index(role_column))
            )
            authority = await self._fetchrow(
                connection,
                "SELECT u.id,u.role,u.is_active,a.revision FROM users u "
                "JOIN execution_actor_authority_revisions a ON a.user_id=u.id "
                "WHERE u.id=?" + suffix,
                (user_id,),
            )
            if not (
                authority is not None
                and self._value(authority, "id", 0) == user_id
                and self._value(authority, "role", 1) == authority_role
                and bool(self._value(authority, "is_active", 2))
                and self._value(authority, "revision", 3) == authority_revision
            ):
                return OperationResult(FixedResult.AUTHORITY_STALE, revision)
            return None

        if authority_before_checks:
            authority_result = await classify_authority()
            if authority_result is not None:
                return authority_result
        for column, expected_values, result in checks:
            if self._value(row, column, columns.index(column)) not in expected_values:
                return OperationResult(result, revision)
        if not authority_before_checks:
            authority_result = await classify_authority()
            if authority_result is not None:
                return authority_result
        return OperationResult(matched_result, revision)

    async def _classify_zero_budget(
        self,
        connection: Any,
        *,
        budget_id: str,
        campaign_id: str,
        budget_kind: str,
        expected_revision: int,
        required_units: int,
        operation: str,
    ) -> OperationResult:
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        row = await self._fetchrow(
            connection,
            "SELECT campaign_id,budget_kind,capacity_units,reserved_units,consumed_units,revision "
            "FROM campaign_execution_budgets WHERE id=?" + suffix,
            (budget_id,),
        )
        if row is None or (
            self._value(row, "campaign_id", 0) != campaign_id
            or self._value(row, "budget_kind", 1) != budget_kind
        ):
            return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
        revision = int(self._value(row, "revision", 5))
        if revision != expected_revision:
            return OperationResult(FixedResult.CONFLICT_REVISION, revision)
        reserved = int(self._value(row, "reserved_units", 3))
        if operation == "reserve" and reserved + int(
            self._value(row, "consumed_units", 4)
        ) + required_units > int(self._value(row, "capacity_units", 2)):
            return OperationResult(FixedResult.CAPACITY_UNAVAILABLE, revision)
        if operation == "settle" and reserved < required_units:
            return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, revision)
        if operation not in {"reserve", "settle"}:
            return OperationResult(FixedResult.INVARIANT_FAILURE, None)
        return OperationResult(FixedResult.INVARIANT_FAILURE, None)

    async def _classify_zero_transition(
        self,
        connection: Any,
        *,
        row: Any,
        current: AttemptState,
        request: TransitionRequest,
        receipt_spec: _ReceiptSpec | None,
        guarded_dispatch: bool,
        require_unexpired_lease: bool,
    ) -> OperationResult:
        checks: tuple[tuple[str, tuple[Any, ...], FixedResult], ...] = (
            ("revision", (request.expected_revision,), FixedResult.CONFLICT_REVISION),
            ("state", (current.value,), FixedResult.CONFLICT_STATE),
        )
        if guarded_dispatch:
            checks += (
                ("dispatch_owner_ref", (request.owner_ref,), FixedResult.CONFLICT_OWNER),
                (
                    "lease_generation",
                    (request.lease_generation,),
                    FixedResult.CONFLICT_GENERATION,
                ),
            )
        if require_unexpired_lease:
            checks += (
                (
                    "lease_expires_at",
                    (self._value(row, "lease_expires_at", 9),),
                    FixedResult.CONFLICT_STATE,
                ),
            )
        if current is AttemptState.CANCELLING:
            checks += (
                (
                    "cancellation_request_revision",
                    (request.cancellation_request_revision,),
                    FixedResult.CONFLICT_REVISION,
                ),
            )
        result = await self._classify_zero_row(
            connection,
            table="execution_attempts",
            identity_column="id",
            identity=request.attempt_id,
            revision_column="revision",
            checks=checks,
            receipt_spec=receipt_spec,
            authority_columns=(
                "actor_user_id",
                "actor_authority_revision",
                "actor_role",
            ),
        )
        if result.result is not FixedResult.INVARIANT_FAILURE or not require_unexpired_lease:
            return result
        lease_expires_at = self._value(row, "lease_expires_at", 9)
        current_time = await self._fetchrow(connection, f"SELECT {self._now_sql} AS value", ())
        if lease_expires_at is None or int(self._value(current_time, "value", 0)) >= int(
            lease_expires_at
        ):
            return OperationResult(FixedResult.CONFLICT_STATE, request.expected_revision)
        return result

    async def _classify_zero_ledger(
        self,
        connection: Any,
        *,
        ledger_id: str,
        attempt_id: str,
        budget_kind: str,
    ) -> OperationResult:
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        row = await self._fetchrow(
            connection,
            "SELECT attempt_id,budget_kind,disposition "
            "FROM campaign_execution_budget_ledger WHERE id=?" + suffix,
            (ledger_id,),
        )
        if row is None or (
            self._value(row, "attempt_id", 0) != attempt_id
            or self._value(row, "budget_kind", 1) != budget_kind
        ):
            return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
        if self._value(row, "disposition", 2) != "held":
            return OperationResult(FixedResult.CONFLICT_OPERATION, None)
        return OperationResult(FixedResult.INVARIANT_FAILURE, None)

    async def _classify_zero_outbox(
        self,
        connection: Any,
        *,
        outbox_id: str,
        expected_revision: int,
        expected_state: str,
        expected_owner: str | None = None,
        expected_generation: int | None = None,
        expected_lease_expires_at: int | None = None,
        time_requirement: str | None = None,
        expected_delivery_count: int | None = None,
        maximum_delivery_count: int | None = None,
    ) -> OperationResult:
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        row = await self._fetchrow(
            connection,
            "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
            "lease_expires_at,delivery_attempt_count,available_at "
            "FROM execution_publication_outbox WHERE id=?" + suffix,
            (outbox_id,),
        )
        if row is None:
            return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
        revision = int(self._value(row, "claim_revision", 1))
        if revision != expected_revision:
            return OperationResult(FixedResult.CONFLICT_REVISION, revision)
        if self._value(row, "publication_state", 0) != expected_state:
            return OperationResult(FixedResult.CONFLICT_STATE, revision)
        if expected_owner is not None and self._value(row, "claim_owner_ref", 2) != expected_owner:
            return OperationResult(FixedResult.CONFLICT_OWNER, revision)
        if (
            expected_generation is not None
            and int(self._value(row, "lease_generation", 3)) != expected_generation
        ):
            return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
        if (
            expected_lease_expires_at is not None
            and self._value(row, "lease_expires_at", 4) != expected_lease_expires_at
        ):
            return OperationResult(FixedResult.CONFLICT_STATE, revision)
        delivery_count = int(self._value(row, "delivery_attempt_count", 5))
        if expected_delivery_count is not None and delivery_count != expected_delivery_count:
            return OperationResult(FixedResult.CONFLICT_STATE, revision)
        if maximum_delivery_count is not None and delivery_count >= maximum_delivery_count:
            return OperationResult(FixedResult.CONFLICT_STATE, revision)
        if time_requirement is not None:
            time_row = await self._fetchrow(connection, f"SELECT {self._now_sql} AS value", ())
            current_time = int(self._value(time_row, "value", 0))
            if time_requirement == "available":
                boundary = self._value(row, "available_at", 6)
                valid = boundary is not None and current_time >= int(boundary)
            else:
                boundary = self._value(row, "lease_expires_at", 4)
                valid = boundary is not None and (
                    current_time >= int(boundary)
                    if time_requirement == "expired"
                    else current_time < int(boundary)
                )
            if not valid or time_requirement not in {"available", "expired", "unexpired"}:
                return OperationResult(FixedResult.CONFLICT_STATE, revision)
        return OperationResult(FixedResult.INVARIANT_FAILURE, None)

    async def _insert_receipt(
        self,
        connection: Any,
        spec: _ReceiptSpec,
        *,
        result: FixedResult,
        exact_replay_code: FixedResult = FixedResult.REPLAYED,
        result_identity: str | None,
        result_revision: int | None,
        secondary_result_identity: str | None = None,
        secondary_result_revision: int | None = None,
        result_fields: tuple[tuple[str, str | int | bool | None], ...] = (),
    ) -> None:
        receipt_result_fields = (
            ("exact_replay_code", exact_replay_code.value),
            ("result_identity_present", result_identity is not None),
            ("result_identity", result_identity),
            ("result_revision_present", result_revision is not None),
            ("result_revision", result_revision),
            ("secondary_result_identity_present", secondary_result_identity is not None),
            ("secondary_result_identity", secondary_result_identity),
            ("secondary_result_revision_present", secondary_result_revision is not None),
            ("secondary_result_revision", secondary_result_revision),
        )
        result_digest = canonical_operation_binding_digest(
            spec.operation_code + ".result",
            (("result_code", result.value),) + receipt_result_fields + result_fields,
        )
        row = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_operation_receipts("
            "operation_id,operation_code,campaign_id,primary_target_id,secondary_target_id,"
            "principal_kind,principal_subject_ref,principal_user_id,"
            "principal_authority_revision_present,principal_authority_revision,"
            "binding_contract_version,request_binding_digest,expected_revision_present,"
            "expected_revision,secondary_expected_revision_present,"
            "secondary_expected_revision,owner_ref,lease_generation,result_code,"
            "exact_replay_code,result_binding_digest,result_identity,"
            "result_revision_present,result_revision,secondary_result_identity,"
            "secondary_result_revision_present,secondary_result_revision) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,2,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(operation_id) DO NOTHING RETURNING operation_id,binding_contract_version",
            (
                spec.operation_id,
                spec.operation_code,
                spec.campaign_id,
                spec.primary_target_id,
                spec.secondary_target_id,
                spec.principal_kind,
                spec.principal_subject_ref,
                spec.principal_user_id,
                spec.principal_authority_revision is not None,
                spec.principal_authority_revision,
                spec.request_binding_digest,
                spec.expected_revision is not None,
                spec.expected_revision,
                spec.secondary_expected_revision is not None,
                spec.secondary_expected_revision,
                spec.owner_ref,
                spec.lease_generation,
                result.value,
                exact_replay_code.value,
                result_digest,
                result_identity,
                result_revision is not None,
                result_revision,
                secondary_result_identity,
                secondary_result_revision is not None,
                secondary_result_revision,
            ),
            identity=spec.operation_id,
            revision=2,
            identity_column="operation_id",
            revision_column="binding_contract_version",
        )
        if row is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))

    async def _insert_terminal_v3_receipt(
        self,
        connection: Any,
        spec: _ReceiptSpec,
        *,
        result_identity: str,
        result_revision: int,
        secondary_result_identity: str,
        secondary_result_revision: int,
        result_fields: tuple[tuple[str, str | int | bool | None], ...],
    ) -> None:
        receipt_result_fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("exact_replay_code", FixedResult.REPLAYED.value),
            ("result_identity_present", True),
            ("result_identity", result_identity),
            ("result_revision_present", True),
            ("result_revision", result_revision),
            ("secondary_result_identity_present", True),
            ("secondary_result_identity", secondary_result_identity),
            ("secondary_result_revision_present", True),
            ("secondary_result_revision", secondary_result_revision),
        )
        result_digest = canonical_operation_binding_digest(
            _TERMINAL_COMMIT_RESULT_DOMAIN_V3,
            (("result_code", FixedResult.APPLIED.value),) + receipt_result_fields + result_fields,
        )
        row = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_operation_receipts("
            "operation_id,operation_code,campaign_id,primary_target_id,secondary_target_id,"
            "principal_kind,principal_subject_ref,principal_user_id,"
            "principal_authority_revision_present,principal_authority_revision,"
            "binding_contract_version,request_binding_digest,expected_revision_present,"
            "expected_revision,secondary_expected_revision_present,"
            "secondary_expected_revision,owner_ref,lease_generation,result_code,"
            "exact_replay_code,result_binding_digest,result_identity,"
            "result_revision_present,result_revision,secondary_result_identity,"
            "secondary_result_revision_present,secondary_result_revision) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,2,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(operation_id) DO NOTHING RETURNING operation_id,binding_contract_version",
            (
                spec.operation_id,
                spec.operation_code,
                spec.campaign_id,
                spec.primary_target_id,
                spec.secondary_target_id,
                spec.principal_kind,
                spec.principal_subject_ref,
                spec.principal_user_id,
                False,
                None,
                spec.request_binding_digest,
                True,
                spec.expected_revision,
                False,
                None,
                None,
                None,
                FixedResult.APPLIED.value,
                FixedResult.REPLAYED.value,
                result_digest,
                result_identity,
                True,
                result_revision,
                secondary_result_identity,
                True,
                secondary_result_revision,
            ),
            identity=spec.operation_id,
            revision=2,
            identity_column="operation_id",
            revision_column="binding_contract_version",
        )
        if row is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))

    @property
    def _now_sql(self) -> str:
        return (
            "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            if self._dialect == "postgresql"
            else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
        )

    @staticmethod
    def _valid_nonnegative_i53(value: object) -> bool:
        return type(value) is int and 0 <= value <= MAX_I53

    @staticmethod
    def _value(row: Any, name: str, index: int) -> Any:
        try:
            return row[name]
        except (KeyError, TypeError, IndexError):
            return row[index]

    @staticmethod
    def _valid_principal_binding(request: object) -> bool:
        kind = getattr(request, "principal_kind", None)
        subject = getattr(request, "principal_subject_ref", None)
        user_id = getattr(request, "principal_user_id", None)
        authority_revision = getattr(request, "principal_authority_revision", None)
        if kind not in PRINCIPAL_KINDS or not valid_uuid(subject):
            return False
        if kind in {"actor", "resolver"}:
            return (
                valid_uuid(user_id)
                and type(authority_revision) is int
                and 0 <= authority_revision <= MAX_I53
            )
        return (
            user_id is None
            and authority_revision is None
            and (kind != "system" or subject == SYSTEM_PRINCIPAL_SUBJECT_REF)
        )

    @staticmethod
    def _principal_binding(request: object) -> tuple[str, str, str | None, int | None]:
        return (
            str(request.principal_kind),  # type: ignore[attr-defined]
            str(request.principal_subject_ref),  # type: ignore[attr-defined]
            request.principal_user_id,  # type: ignore[attr-defined]
            request.principal_authority_revision,  # type: ignore[attr-defined]
        )

    def _receipt_spec(
        self,
        *,
        operation_id: str,
        operation_code: str,
        campaign_id: str | None,
        primary_target_id: str,
        secondary_target_id: str | None = None,
        principal_kind: str = "system",
        principal_subject_ref: str = SYSTEM_PRINCIPAL_SUBJECT_REF,
        principal_user_id: str | None = None,
        principal_authority_revision: int | None = None,
        expected_revision: int | None = None,
        secondary_expected_revision: int | None = None,
        owner_ref: str | None = None,
        lease_generation: int | None = None,
        fields: tuple[tuple[str, str | int | bool | None], ...] = (),
    ) -> _ReceiptSpec:
        no_expected_codes = _V11_RECEIPT_NO_EXPECTED_REVISION_CODES
        two_expected_codes = _RECEIPT_TWO_EXPECTED_REVISION_CODES
        expected_shape_valid = (
            expected_revision is None and secondary_expected_revision is None
            if operation_code in no_expected_codes
            else expected_revision is not None and secondary_expected_revision is not None
            if operation_code in two_expected_codes
            else secondary_expected_revision is None
            if operation_code in _V11_RECEIPT_OPTIONAL_EXPECTED_REVISION_CODES
            else expected_revision is not None and secondary_expected_revision is None
        )
        owner_shape_valid = (
            owner_ref is not None and lease_generation is not None
            if operation_code in _RECEIPT_OUTBOX_OWNER_CODES
            else owner_ref is None and lease_generation is None
            if operation_code in _RECEIPT_OUTBOX_NO_OWNER_CODES
            else True
        )
        if (
            not valid_uuid(operation_id)
            or operation_code not in V11_OPERATION_CODES
            or not expected_shape_valid
            or not owner_shape_valid
            or not valid_uuid(primary_target_id)
            or (campaign_id is not None and not valid_uuid(campaign_id))
            or (secondary_target_id is not None and not valid_uuid(secondary_target_id))
            or principal_kind not in PRINCIPAL_KINDS
            or not valid_uuid(principal_subject_ref)
            or (
                principal_kind == "system" and principal_subject_ref != SYSTEM_PRINCIPAL_SUBJECT_REF
            )
            or (
                principal_kind in {"actor", "resolver"}
                and (
                    not valid_uuid(principal_user_id)
                    or not self._valid_nonnegative_i53(principal_authority_revision)
                )
            )
            or (
                principal_kind in {"worker", "system"}
                and (principal_user_id is not None or principal_authority_revision is not None)
            )
            or (
                expected_revision is not None and not self._valid_nonnegative_i53(expected_revision)
            )
            or (
                secondary_expected_revision is not None
                and not self._valid_nonnegative_i53(secondary_expected_revision)
            )
            or (owner_ref is not None and not valid_uuid(owner_ref))
            or (owner_ref is None) != (lease_generation is None)
            or (lease_generation is not None and not self._valid_nonnegative_i53(lease_generation))
        ):
            raise ValueError("Invalid operation receipt contract")
        standard: tuple[tuple[str, str | int | bool | None], ...] = (
            ("operation_id", operation_id),
            ("operation_code", operation_code),
            ("campaign_id_present", campaign_id is not None),
            ("campaign_id", campaign_id),
            ("primary_target_id", primary_target_id),
            ("secondary_target_id_present", secondary_target_id is not None),
            ("secondary_target_id", secondary_target_id),
            ("principal_kind", principal_kind),
            ("principal_subject_ref", principal_subject_ref),
            ("principal_user_id_present", principal_user_id is not None),
            ("principal_user_id", principal_user_id),
            (
                "principal_authority_revision_present",
                principal_authority_revision is not None,
            ),
            ("principal_authority_revision", principal_authority_revision),
            ("expected_revision_present", expected_revision is not None),
            ("expected_revision", expected_revision),
            (
                "secondary_expected_revision_present",
                secondary_expected_revision is not None,
            ),
            ("secondary_expected_revision", secondary_expected_revision),
            ("owner_ref_present", owner_ref is not None),
            ("owner_ref", owner_ref),
            ("lease_generation_present", lease_generation is not None),
            ("lease_generation", lease_generation),
        )
        return _ReceiptSpec(
            operation_id=operation_id,
            operation_code=operation_code,
            campaign_id=campaign_id,
            primary_target_id=primary_target_id,
            secondary_target_id=secondary_target_id,
            principal_kind=principal_kind,
            principal_subject_ref=principal_subject_ref,
            principal_user_id=principal_user_id,
            principal_authority_revision=principal_authority_revision,
            request_binding_digest=canonical_operation_binding_digest(
                operation_code + ".request", standard + fields
            ),
            expected_revision=expected_revision,
            secondary_expected_revision=secondary_expected_revision,
            owner_ref=owner_ref,
            lease_generation=lease_generation,
        )

    async def _acquire_transaction_key(self, connection: Any, identity: str) -> None:
        """Acquire the class-zero lock before any mutation-authorizing read."""
        if not valid_uuid(identity):
            raise _AbortOperationError(OperationResult(FixedResult.INVALID_CONTRACT, None))
        if self._dialect == "postgresql":
            row = await self._fetchrow(
                connection,
                "SELECT pg_advisory_xact_lock(hashtextextended(?,0)) AS locked",
                (identity,),
            )
            if row is None:
                raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))

    async def _acquire_logical_attempt_transaction_keys(
        self,
        connection: Any,
        logical_execution_id: str,
        attempt_id: str,
    ) -> None:
        """Serialize all row-lock orders that can mutate one logical attempt graph."""
        await self._acquire_transaction_key(connection, logical_execution_id)
        if attempt_id != logical_execution_id:
            await self._acquire_transaction_key(connection, attempt_id)

    async def _lock_attempt_prefix(
        self, connection: Any, attempt_id: str
    ) -> tuple[str, str, str, str, int] | None:
        discovery = await self._fetchrow(
            connection,
            "SELECT logical_execution_id,campaign_id,actor_user_id,actor_subject_ref,"
            "actor_authority_revision "
            "FROM execution_attempts WHERE id=?",
            (attempt_id,),
        )
        if discovery is None:
            return None
        logical_id = str(self._value(discovery, "logical_execution_id", 0))
        campaign_id = str(self._value(discovery, "campaign_id", 1))
        actor_user_id = str(self._value(discovery, "actor_user_id", 2))
        actor_subject_ref = str(self._value(discovery, "actor_subject_ref", 3))
        actor_authority_revision = int(self._value(discovery, "actor_authority_revision", 4))
        await self._acquire_logical_attempt_transaction_keys(
            connection,
            logical_id,
            attempt_id,
        )
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        locks = (
            ("SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1", None),
            ("SELECT id FROM users WHERE id=?", actor_user_id),
            ("SELECT id FROM campaigns WHERE id=?", campaign_id),
            (
                "SELECT user_id FROM execution_actor_authority_revisions WHERE user_id=?",
                actor_user_id,
            ),
            (
                "SELECT campaign_id FROM campaign_execution_authority_revisions WHERE campaign_id=?",
                campaign_id,
            ),
            ("SELECT id FROM logical_executions WHERE id=?", logical_id),
        )
        for sql, value in locks:
            params: tuple[Any, ...] = () if value is None else (value,)
            if await self._fetchrow(connection, sql + suffix, params) is None:
                return None
        return (
            logical_id,
            campaign_id,
            actor_user_id,
            actor_subject_ref,
            actor_authority_revision,
        )

    def _transition_receipt_spec(
        self,
        request: TransitionRequest,
        *,
        operation_code: str | None = None,
    ) -> _ReceiptSpec:
        if operation_code is None and request.resolver_subject_ref is not None:
            operation_code = {
                AttemptState.SUCCEEDED: "recovery_succeeded",
                AttemptState.PARTIAL: "recovery_partial",
                AttemptState.FAILED: "recovery_failed",
                AttemptState.CANCELLED: "recovery_cancelled",
                AttemptState.TIMED_OUT: "recovery_timed_out",
                AttemptState.INDETERMINATE: "recovery_indeterminate",
            }.get(request.target_state)
        if operation_code is None:
            operation_code = {
                AttemptState.QUEUED: "queue",
                AttemptState.DISPATCHING: "dispatch",
                AttemptState.RUNNING: "start",
                AttemptState.CANCELLING: "cancellation_request",
                AttemptState.SETTLEMENT_PENDING: "settlement_pending",
                AttemptState.TIMED_OUT: "timeout",
                AttemptState.SKIPPED: "terminal_skipped",
                AttemptState.INDETERMINATE: "recovery_indeterminate",
            }.get(request.target_state)
        if operation_code is None:
            if (
                request.cancellation_request_revision is not None
                or request.target_state is AttemptState.CANCELLED
            ):
                operation_code = "cancellation_acknowledgement"
            else:
                operation_code = "terminal_" + request.target_state.value
        principal = self._transition_principal(request)
        return self._receipt_spec(
            operation_id=request.operation_id,
            operation_code=operation_code,
            campaign_id=request.campaign_id,
            primary_target_id=request.attempt_id,
            principal_kind=principal[0],
            principal_subject_ref=principal[1],
            principal_user_id=principal[2],
            principal_authority_revision=principal[3],
            expected_revision=request.expected_revision,
            owner_ref=request.owner_ref,
            lease_generation=request.lease_generation,
            fields=(
                ("target_state", request.target_state.value),
                ("lease_duration_ms", request.lease_duration_ms),
                ("cancellation_request_revision", request.cancellation_request_revision),
                (
                    "outcome_code",
                    None if request.outcome_code is None else request.outcome_code.value,
                ),
                ("authoritative_proof", request.authoritative_proof),
                ("resolver_subject_ref", request.resolver_subject_ref),
                ("resolver_user_id", request.resolver_user_id),
                ("resolver_authority_revision", request.resolver_authority_revision),
                ("outbox_id", request.outbox_id),
                ("publication_key", request.publication_key),
            ),
        )

    @staticmethod
    def _transition_principal(
        request: TransitionRequest,
    ) -> tuple[str, str, str | None, int | None]:
        if request.resolver_subject_ref is not None:
            return (
                "resolver",
                request.resolver_subject_ref,
                request.resolver_user_id,
                request.resolver_authority_revision,
            )
        if request.owner_ref is not None:
            return ("worker", request.owner_ref, None, None)
        if request.actor_subject_ref is not None:
            return (
                "actor",
                request.actor_subject_ref,
                request.actor_user_id,
                request.actor_authority_revision,
            )
        return ("system", SYSTEM_PRINCIPAL_SUBJECT_REF, None, None)

    def _terminal_receipt_spec(
        self,
        request: TerminalCommitRequest,
    ) -> _ReceiptSpec:
        transition = request.transition
        operation_code = self._transition_receipt_spec(
            transition,
        ).operation_code
        principal = self._transition_principal(transition)
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("logical_execution_id", request.logical_execution_id),
            ("target_state", transition.target_state.value),
            (
                "outcome_code",
                None if transition.outcome_code is None else transition.outcome_code.value,
            ),
            ("authoritative_proof", transition.authoritative_proof),
            ("cancellation_request_revision", transition.cancellation_request_revision),
            ("resolver_subject_ref", transition.resolver_subject_ref),
            ("resolver_user_id", transition.resolver_user_id),
            ("resolver_authority_revision", transition.resolver_authority_revision),
            ("outbox_id", request.outbox_id),
            ("publication_key", request.publication_key),
            ("noise_budget_id", request.budgets.noise_budget_id),
            ("noise_units", request.budgets.noise_units),
            ("noise_actual", request.budgets.noise_actual),
            ("noise_expected_revision", request.budgets.noise_expected_revision),
            ("exfiltration_budget_id", request.budgets.exfiltration_budget_id),
            ("exfiltration_units", request.budgets.exfiltration_units),
            ("exfiltration_actual", request.budgets.exfiltration_actual),
            (
                "exfiltration_expected_revision",
                request.budgets.exfiltration_expected_revision,
            ),
            ("concurrency_budget_id", request.budgets.concurrency_budget_id),
            (
                "concurrency_expected_revision",
                request.budgets.concurrency_expected_revision,
            ),
        ) + tuple(
            item
            for index, output in enumerate(
                sorted(
                    request.outputs,
                    key=lambda value: (value.kind.value, value.target_id, value.link_id),
                )
            )
            for item in (
                (f"output_{index}_link_id", output.link_id),
                (f"output_{index}_kind", output.kind.value),
                (f"output_{index}_target_id", output.target_id),
            )
        )
        return self._receipt_spec(
            operation_id=transition.operation_id,
            operation_code=operation_code,
            campaign_id=request.campaign_id,
            primary_target_id=transition.attempt_id,
            secondary_target_id=request.logical_execution_id,
            principal_kind=principal[0],
            principal_subject_ref=principal[1],
            principal_user_id=principal[2],
            principal_authority_revision=principal[3],
            expected_revision=transition.expected_revision,
            owner_ref=transition.owner_ref,
            lease_generation=transition.lease_generation,
            fields=fields,
        )

    @staticmethod
    def _terminal_v3_outcome_contract(
        outcome_code: OutcomeCode,
    ) -> tuple[AttemptState, AttemptState, str, str] | None:
        """Return the sole known-settled predecessor/terminal binding for V3."""
        return {
            OutcomeCode.CONFIRMED_SUCCESS: (
                AttemptState.RUNNING,
                AttemptState.SUCCEEDED,
                "terminal_succeeded",
                "local_completion",
            ),
            OutcomeCode.CONFIRMED_FAILURE: (
                AttemptState.RUNNING,
                AttemptState.FAILED,
                "terminal_failed",
                "local_completion",
            ),
            OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT: (
                AttemptState.CANCELLING,
                AttemptState.CANCELLED,
                "cancellation_acknowledgement",
                "cancellation_no_result_ack",
            ),
            OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED: (
                AttemptState.RUNNING,
                AttemptState.TIMED_OUT,
                "timeout",
                "timeout_termination_ack",
            ),
        }.get(outcome_code)

    @classmethod
    def _canonical_terminal_v3_outputs(
        cls,
        intent: object,
    ) -> tuple[OutputObservation, ...] | None:
        if (
            type(intent) is not TerminalCommitIntentV3
            or not all(
                valid_uuid(value)
                for value in (
                    intent.logical_execution_id,
                    intent.campaign_id,
                    intent.attempt_id,
                )
            )
            or type(intent.expected_attempt_revision) is not int
            or not 0 <= intent.expected_attempt_revision < MAX_I53
            or type(intent.outcome_code) is not OutcomeCode
            or cls._terminal_v3_outcome_contract(intent.outcome_code) is None
            or any(
                type(value) is not int or not 0 <= value <= MAX_I53
                for value in (
                    intent.noise_actual,
                    intent.exfiltration_actual,
                    intent.concurrency_actual,
                )
            )
            or intent.concurrency_actual != 0
            or type(intent.outputs) is not tuple
            or len(intent.outputs) > MAX_TERMINAL_OUTPUTS_V3
            or not cls._valid_output_observations(intent.outputs)
        ):
            return None
        result_digest = intent.execution_result_digest
        if intent.outcome_code in {
            OutcomeCode.CONFIRMED_SUCCESS,
            OutcomeCode.CONFIRMED_FAILURE,
        }:
            if (
                type(result_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", result_digest) is None
            ):
                return None
        elif result_digest is not None:
            return None
        if intent.outcome_code is not OutcomeCode.CONFIRMED_SUCCESS and intent.outputs:
            return None
        return tuple(
            sorted(
                intent.outputs,
                key=lambda output: (output.kind.value, output.target_id, output.link_id),
            )
        )

    @staticmethod
    def _terminal_v3_operation_id(attempt_id: str) -> str:
        """Derive one terminal receipt authority for the canonical attempt UUID."""
        digest = canonical_operation_binding_digest(
            _TERMINAL_COMMIT_OPERATION_ID_DOMAIN_V3,
            (
                ("attempt_id", attempt_id),
                ("action", _TERMINAL_COMMIT_ACTION_V3),
            ),
        )
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

    @staticmethod
    def _terminal_v3_receipt_spec(
        intent: TerminalCommitIntentV3,
        operation_id: str,
        operation_code: str,
        outputs: tuple[OutputObservation, ...],
    ) -> _ReceiptSpec:
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("terminal_commit_contract_version", TERMINAL_COMMIT_CONTRACT_VERSION_V3),
            ("logical_execution_id", intent.logical_execution_id),
            ("campaign_id", intent.campaign_id),
            ("attempt_id", intent.attempt_id),
            ("operation_id", operation_id),
            ("expected_attempt_revision", intent.expected_attempt_revision),
            ("operation_code", operation_code),
            ("outcome_code", intent.outcome_code.value),
            ("noise_actual", intent.noise_actual),
            ("exfiltration_actual", intent.exfiltration_actual),
            ("concurrency_actual", intent.concurrency_actual),
            ("execution_result_digest_present", intent.execution_result_digest is not None),
            ("execution_result_digest", intent.execution_result_digest),
            ("output_count", len(outputs)),
        ) + tuple(
            item
            for index, output in enumerate(outputs)
            for item in (
                (f"output_{index}_link_id", output.link_id),
                (f"output_{index}_kind", output.kind.value),
                (f"output_{index}_target_id", output.target_id),
            )
        )
        return _ReceiptSpec(
            operation_id=operation_id,
            operation_code=operation_code,
            campaign_id=intent.campaign_id,
            primary_target_id=intent.attempt_id,
            secondary_target_id=intent.logical_execution_id,
            principal_kind="system",
            principal_subject_ref=SYSTEM_PRINCIPAL_SUBJECT_REF,
            principal_user_id=None,
            principal_authority_revision=None,
            request_binding_digest=canonical_operation_binding_digest(
                _TERMINAL_COMMIT_REQUEST_DOMAIN_V3,
                fields,
            ),
            expected_revision=intent.expected_attempt_revision,
            secondary_expected_revision=None,
            owner_ref=None,
            lease_generation=None,
        )

    async def ensure_actor_authority(self, user_id: str, operation_id: str) -> OperationResult:
        try:
            return await self._ensure_actor_authority(user_id, operation_id)
        except _AbortOperationError as aborted:
            return aborted.result

    async def _ensure_actor_authority(self, user_id: str, operation_id: str) -> OperationResult:
        if not valid_uuid(user_id) or not valid_uuid(operation_id):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._receipt_spec(
            operation_id=operation_id,
            operation_code="actor_authority_ensure",
            campaign_id=None,
            primary_target_id=user_id,
        )
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, operation_id)
            replay = await self._classify_receipt(connection, spec, current_revision=None)
            if replay is not None:
                return replay
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            gateway = await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            if gateway is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
            user = await self._fetchrow(
                connection,
                "SELECT id,username,role,is_active,auth_epoch FROM users WHERE id=?" + suffix,
                (user_id,),
            )
            if user is None:
                return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            row = await self._fetchrow(
                connection,
                "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=?" + suffix,
                (user_id,),
            )
            if row is not None:
                return OperationResult(
                    FixedResult.ALREADY_EXISTS, int(self._value(row, "revision", 0))
                )
            inserted = await self.cas_update_one(
                connection,
                "INSERT INTO execution_actor_authority_revisions("
                "user_id,revision,latest_operation_id,latest_operation_base_revision,"
                "latest_operation_code,authority_state,authority_revision,"
                "authority_binding_digest) VALUES(?,0,?,0,'ensure','active',0,?) "
                "ON CONFLICT(user_id) DO NOTHING RETURNING user_id,revision",
                (
                    user_id,
                    operation_id,
                    self._actor_authority_binding(
                        user_id,
                        str(self._value(user, "username", 1)),
                        str(self._value(user, "role", 2)),
                        bool(self._value(user, "is_active", 3)),
                        int(self._value(user, "auth_epoch", 4)),
                    ),
                ),
                identity=user_id,
                post_revision=0,
                identity_column="user_id",
                zero_classifier=lambda: self._classify_zero_row(
                    connection,
                    table="execution_actor_authority_revisions",
                    identity_column="user_id",
                    identity=user_id,
                    revision_column="revision",
                    missing_result=FixedResult.INVARIANT_FAILURE,
                    matched_result=FixedResult.CONFLICT_OPERATION,
                    receipt_spec=spec,
                ),
            )
            if inserted is None:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
            await self._insert_receipt(
                connection,
                spec,
                result=FixedResult.APPLIED,
                result_identity=user_id,
                result_revision=0,
            )
            return OperationResult(FixedResult.APPLIED, 0)

    async def _mutate_existing_authority_v11(
        self,
        principal: TrustedPrincipal,
        mutation: ActorAuthorityMutation | CampaignAuthorityMutation,
        *,
        kind: str,
        action: str,
    ) -> OperationResult:
        if not self._valid_trusted_principal(principal):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        if kind not in {"actor", "campaign"} or action not in {
            "activate",
            "update",
            "revoke",
        }:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        expected_type = ActorAuthorityMutation if kind == "actor" else CampaignAuthorityMutation
        target = (
            mutation.actor_user_id
            if type(mutation) is ActorAuthorityMutation
            else mutation.campaign_id
            if type(mutation) is CampaignAuthorityMutation
            else None
        )
        if (
            type(mutation) is not expected_type
            or target is None
            or not valid_uuid(target)
            or not valid_uuid(mutation.operation_id)
            or not self._valid_expected_revision(mutation.expected_revision)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        code = f"{kind}_authority_{action}"
        campaign_id = target if kind == "campaign" else None
        table = (
            "execution_actor_authority_revisions"
            if kind == "actor"
            else "campaign_execution_authority_revisions"
        )
        key = "user_id" if kind == "actor" else "campaign_id"
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code=code,
                    campaign_id=campaign_id,
                    primary_target_id=target,
                    expected_revision=mutation.expected_revision,
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, resolved = authority_spec
                replay = await self._classify_receipt(
                    connection, spec, current_revision=mutation.expected_revision
                )
                if replay is not None:
                    return replay
                if resolved is None:
                    resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if kind == "actor" and resolved.role != "admin":
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if kind == "campaign" and not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    target,
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                row = await self._fetchrow(
                    connection,
                    f"SELECT authority_state,authority_revision,authority_binding_digest "
                    f"FROM {table} WHERE {key}=?" + suffix,
                    (target,),
                )
                persisted = await self._fetchrow(
                    connection,
                    (
                        "SELECT id,username,role,is_active,auth_epoch FROM users WHERE id=?"
                        if kind == "actor"
                        else "SELECT id,operator,status,noise_profile FROM campaigns WHERE id=?"
                    )
                    + suffix,
                    (target,),
                )
                if row is None or persisted is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                revision = int(self._value(row, "authority_revision", 1))
                if revision != mutation.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                state = str(self._value(row, "authority_state", 0))
                if action == "activate" and state != "revoked":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if action in {"update", "revoke"} and state != "active":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if kind == "actor":
                    binding = self._actor_authority_binding(
                        str(self._value(persisted, "id", 0)),
                        str(self._value(persisted, "username", 1)),
                        str(self._value(persisted, "role", 2)),
                        bool(self._value(persisted, "is_active", 3)),
                        int(self._value(persisted, "auth_epoch", 4)),
                    )
                else:
                    destination = await self._fetchrow(
                        connection,
                        "SELECT binding_digest FROM campaign_execution_destination_authorities "
                        "WHERE campaign_id=?" + suffix,
                        (target,),
                    )
                    if destination is None:
                        return OperationResult(FixedResult.AUTHORITY_STALE, revision)
                    binding = canonical_operation_binding_digest(
                        "campaign-authority",
                        (
                            ("campaign_id", str(self._value(persisted, "id", 0))),
                            ("operator", str(self._value(persisted, "operator", 1))),
                            ("status", str(self._value(persisted, "status", 2))),
                            ("noise_profile", str(self._value(persisted, "noise_profile", 3))),
                            (
                                "destination_binding_digest",
                                str(self._value(destination, "binding_digest", 0)),
                            ),
                        ),
                    )
                next_state = "revoked" if action == "revoke" else "active"
                updated = await self.cas_update_one(
                    connection,
                    f"UPDATE {table} SET authority_state=?,authority_revision=authority_revision+1,"
                    "authority_binding_digest=?,authority_latest_operation_id=?,"
                    "authority_latest_operation_base_revision=?,authority_latest_operation_code=?,"
                    f"updated_at={self._now_sql} WHERE {key}=? AND authority_revision=? "
                    f"AND authority_state=? RETURNING {key},authority_revision",
                    (
                        next_state,
                        binding,
                        mutation.operation_id,
                        mutation.expected_revision,
                        action,
                        target,
                        mutation.expected_revision,
                        state,
                    ),
                    identity=target,
                    post_revision=revision + 1,
                    identity_column=key,
                    revision_column="authority_revision",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table=table,
                        identity_column=key,
                        identity=target,
                        revision_column="authority_revision",
                        checks=(
                            (
                                "authority_revision",
                                (mutation.expected_revision,),
                                FixedResult.CONFLICT_REVISION,
                            ),
                            ("authority_state", (state,), FixedResult.CONFLICT_STATE),
                        ),
                    ),
                )
                if updated is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=target,
                    result_revision=revision + 1,
                    result_fields=(
                        ("authority_state", next_state),
                        ("authority_binding_digest", binding),
                    ),
                )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def activate_actor_authority(
        self, principal: TrustedPrincipal, mutation: ActorAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="actor", action="activate"
        )

    async def update_actor_authority(
        self, principal: TrustedPrincipal, mutation: ActorAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="actor", action="update"
        )

    async def revoke_actor_authority(
        self, principal: TrustedPrincipal, mutation: ActorAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="actor", action="revoke"
        )

    async def activate_campaign_authority(
        self, principal: TrustedPrincipal, mutation: CampaignAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="campaign", action="activate"
        )

    async def update_campaign_authority(
        self, principal: TrustedPrincipal, mutation: CampaignAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="campaign", action="update"
        )

    async def revoke_campaign_authority(
        self, principal: TrustedPrincipal, mutation: CampaignAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_existing_authority_v11(
            principal, mutation, kind="campaign", action="revoke"
        )

    async def update_gateway_authority(
        self, principal: TrustedPrincipal, mutation: GatewayAuthorityMutation
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not GatewayAuthorityMutation
            or not valid_uuid(mutation.operation_id)
            or not self._valid_expected_revision(mutation.expected_revision)
            or mutation.mode
            not in {"disabled", "shadow_candidate", "enforced", "emergency_disabled"}
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        # Once activated the v10 shape has no representable transition back to
        # disabled (disabled is the unique revision-zero bootstrap state).
        if mutation.mode == "disabled" and mutation.expected_revision != 0:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code="gateway_authority_update",
                    campaign_id=None,
                    primary_target_id=GATEWAY_AUTHORITY_TARGET_ID,
                    expected_revision=mutation.expected_revision,
                    fields=(("mode", mutation.mode),),
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, resolved = authority_spec
                replay = await self._classify_receipt(
                    connection, spec, current_revision=mutation.expected_revision
                )
                if replay is not None:
                    return replay
                if resolved is None:
                    resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if resolved.role != "admin":
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                row = await self._fetchrow(
                    connection,
                    "SELECT mode,revision FROM execution_gateway_state WHERE singleton_id=1"
                    + suffix,
                    (),
                )
                if row is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                revision = int(self._value(row, "revision", 1))
                if revision != mutation.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if mutation.mode == "disabled":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                catalog_digest = self._descriptor_catalog_digest()
                activation = mutation.mode != "disabled"
                updated = await self.cas_update_one(
                    connection,
                    "UPDATE execution_gateway_state SET mode=?,catalog_digest=?,"
                    "activation_revision=?,activation_at="
                    + (self._now_sql if activation else "NULL")
                    + ",revision=revision+1,updated_at="
                    + self._now_sql
                    + " WHERE singleton_id=1 AND revision=? RETURNING singleton_id,revision",
                    (
                        mutation.mode,
                        catalog_digest if activation else None,
                        revision + 1 if activation else None,
                        revision,
                    ),
                    identity=1,
                    post_revision=revision + 1,
                    identity_column="singleton_id",
                    revision_column="revision",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="execution_gateway_state",
                        identity_column="singleton_id",
                        identity=1,
                        revision_column="revision",
                        checks=(
                            (
                                "revision",
                                (mutation.expected_revision,),
                                FixedResult.CONFLICT_REVISION,
                            ),
                        ),
                    ),
                )
                if updated is None:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=GATEWAY_AUTHORITY_TARGET_ID,
                    result_revision=revision + 1,
                    result_fields=(("mode", mutation.mode), ("catalog_digest", catalog_digest)),
                )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    @staticmethod
    def _descriptor_catalog_digest() -> str:
        from ares.modules.descriptors import FIRST_PARTY_DESCRIPTORS

        encoded = bytearray(b"ares.descriptor-catalog.v1\x00")
        for module_id, descriptor in sorted(FIRST_PARTY_DESCRIPTORS.items()):
            for value in (module_id, descriptor.semantic_digest):
                item = value.encode("utf-8")
                encoded.extend(len(item).to_bytes(4, "big"))
                encoded.extend(item)
        return hashlib.sha256(encoded).hexdigest()

    async def _mutate_campaign_actor_grant(
        self,
        principal: TrustedPrincipal,
        mutation: CampaignActorGrantMutation,
        *,
        action: str,
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not CampaignActorGrantMutation
            or action not in {"put", "revoke"}
            or not all(
                valid_uuid(value)
                for value in (
                    mutation.operation_id,
                    mutation.campaign_id,
                    mutation.actor_user_id,
                )
            )
            or not self._valid_expected_revision(
                mutation.expected_revision, optional=action == "put"
            )
            or (action == "revoke" and mutation.expected_revision is None)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code=f"campaign_actor_grant_{action}",
                    campaign_id=mutation.campaign_id,
                    primary_target_id=mutation.campaign_id,
                    secondary_target_id=mutation.actor_user_id,
                    expected_revision=mutation.expected_revision,
                    fields=(("actor_user_id", mutation.actor_user_id),),
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, resolved = authority_spec
                replay = await self._classify_receipt(
                    connection, spec, current_revision=mutation.expected_revision
                )
                if replay is not None:
                    return replay
                if resolved is None:
                    resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    mutation.campaign_id,
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                campaign = await self._fetchrow(
                    connection,
                    "SELECT id FROM campaigns WHERE id=?" + suffix,
                    (mutation.campaign_id,),
                )
                actor = await self._fetchrow(
                    connection,
                    "SELECT id FROM users WHERE id=?" + suffix,
                    (mutation.actor_user_id,),
                )
                if campaign is None or actor is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                row = await self._fetchrow(
                    connection,
                    "SELECT authority_state,revision FROM campaign_execution_actor_grants "
                    "WHERE campaign_id=? AND actor_user_id=?" + suffix,
                    (mutation.campaign_id, mutation.actor_user_id),
                )
                binding = canonical_operation_binding_digest(
                    "campaign-actor-grant",
                    (
                        ("campaign_id", mutation.campaign_id),
                        ("actor_user_id", mutation.actor_user_id),
                        ("authority_state", "active" if action == "put" else "revoked"),
                    ),
                )
                if row is None:
                    if action != "put" or mutation.expected_revision is not None:
                        return OperationResult(FixedResult.CONFLICT_STATE, None)
                    inserted = await self.cas_update_one(
                        connection,
                        "INSERT INTO campaign_execution_actor_grants("
                        "campaign_id,actor_user_id,authority_state,revision,binding_digest,"
                        "latest_operation_id,latest_operation_base_revision,latest_operation_code) "
                        "VALUES(?,?,'active',0,?,?,0,'put') ON CONFLICT(campaign_id,actor_user_id) "
                        "DO NOTHING RETURNING campaign_id,revision",
                        (
                            mutation.campaign_id,
                            mutation.actor_user_id,
                            binding,
                            mutation.operation_id,
                        ),
                        identity=mutation.campaign_id,
                        post_revision=0,
                        identity_column="campaign_id",
                        revision_column="revision",
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="campaign_execution_actor_grants",
                            identity_column="campaign_id",
                            identity=mutation.campaign_id,
                            revision_column="revision",
                            matched_result=FixedResult.CONFLICT_OPERATION,
                        ),
                    )
                    if inserted is None:
                        return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                    next_revision = 0
                else:
                    revision = int(self._value(row, "revision", 1))
                    state = str(self._value(row, "authority_state", 0))
                    if mutation.expected_revision != revision:
                        return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                    if action == "put" and state != "revoked":
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                    if action == "revoke" and state != "active":
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                    next_state = "active" if action == "put" else "revoked"
                    next_revision = revision + 1
                    updated = await self.cas_update_one(
                        connection,
                        "UPDATE campaign_execution_actor_grants SET authority_state=?,"
                        "revision=revision+1,binding_digest=?,latest_operation_id=?,"
                        "latest_operation_base_revision=?,latest_operation_code=?,updated_at="
                        + self._now_sql
                        + " WHERE campaign_id=? AND actor_user_id=? AND revision=? "
                        "AND authority_state=? RETURNING campaign_id,revision",
                        (
                            next_state,
                            binding,
                            mutation.operation_id,
                            revision,
                            action,
                            mutation.campaign_id,
                            mutation.actor_user_id,
                            revision,
                            state,
                        ),
                        identity=mutation.campaign_id,
                        post_revision=next_revision,
                        identity_column="campaign_id",
                        revision_column="revision",
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="campaign_execution_actor_grants",
                            identity_column="campaign_id",
                            identity=mutation.campaign_id,
                            revision_column="revision",
                            checks=(("revision", (revision,), FixedResult.CONFLICT_REVISION),),
                        ),
                    )
                    if updated is None:
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=mutation.actor_user_id,
                    result_revision=next_revision,
                    result_fields=(
                        ("authority_state", "active" if action == "put" else "revoked"),
                    ),
                )
                return OperationResult(FixedResult.APPLIED, next_revision)
        except _AbortOperationError as aborted:
            return aborted.result

    async def put_campaign_actor_grant(
        self, principal: TrustedPrincipal, mutation: CampaignActorGrantMutation
    ) -> OperationResult:
        return await self._mutate_campaign_actor_grant(principal, mutation, action="put")

    async def revoke_campaign_actor_grant(
        self, principal: TrustedPrincipal, mutation: CampaignActorGrantMutation
    ) -> OperationResult:
        return await self._mutate_campaign_actor_grant(principal, mutation, action="revoke")

    async def _mutate_destination_authority(
        self,
        principal: TrustedPrincipal,
        mutation: DestinationAuthorityMutation,
        *,
        action: str,
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not DestinationAuthorityMutation
            or action not in {"update", "revoke"}
            or not valid_uuid(mutation.operation_id)
            or not valid_uuid(mutation.campaign_id)
            or not self._valid_expected_revision(mutation.expected_revision)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code=f"destination_authority_{action}",
                    campaign_id=mutation.campaign_id,
                    primary_target_id=mutation.campaign_id,
                    expected_revision=mutation.expected_revision,
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, resolved = authority_spec
                replay = await self._classify_receipt(
                    connection, spec, current_revision=mutation.expected_revision
                )
                if replay is not None:
                    return replay
                if resolved is None:
                    resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    mutation.campaign_id,
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                campaign = await self._fetchrow(
                    connection,
                    "SELECT scope_json,targets_json FROM campaigns WHERE id=?" + suffix,
                    (mutation.campaign_id,),
                )
                row = await self._fetchrow(
                    connection,
                    "SELECT authority_state,revision FROM "
                    "campaign_execution_destination_authorities WHERE campaign_id=?" + suffix,
                    (mutation.campaign_id,),
                )
                if campaign is None or row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                revision = int(self._value(row, "revision", 1))
                state = str(self._value(row, "authority_state", 0))
                if revision != mutation.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if state != "active":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                try:
                    values = self._canonical_destination_values(
                        self._value(campaign, "scope_json", 0),
                        self._value(campaign, "targets_json", 1),
                    )
                    count, digest, binding = self._destination_authority_facts(values)
                except ValueError:
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                next_state = "revoked" if action == "revoke" else "active"
                updated = await self.cas_update_one(
                    connection,
                    "UPDATE campaign_execution_destination_authorities SET authority_state=?,"
                    "revision=revision+1,normalization_version=?,destination_count=?,"
                    "destination_set_digest=?,binding_digest=?,latest_operation_id=?,"
                    "latest_operation_base_revision=?,latest_operation_code=?,updated_at="
                    + self._now_sql
                    + " WHERE campaign_id=? AND revision=? AND authority_state='active' "
                    "RETURNING campaign_id,revision",
                    (
                        next_state,
                        DESTINATION_NORMALIZATION_VERSION,
                        count,
                        digest,
                        binding,
                        mutation.operation_id,
                        revision,
                        action,
                        mutation.campaign_id,
                        revision,
                    ),
                    identity=mutation.campaign_id,
                    post_revision=revision + 1,
                    identity_column="campaign_id",
                    revision_column="revision",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="campaign_execution_destination_authorities",
                        identity_column="campaign_id",
                        identity=mutation.campaign_id,
                        revision_column="revision",
                        checks=(
                            ("revision", (revision,), FixedResult.CONFLICT_REVISION),
                            ("authority_state", ("active",), FixedResult.CONFLICT_STATE),
                        ),
                    ),
                )
                if updated is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=mutation.campaign_id,
                    result_revision=revision + 1,
                    result_fields=(
                        ("authority_state", next_state),
                        ("binding_digest", binding),
                    ),
                )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def update_destination_authority(
        self, principal: TrustedPrincipal, mutation: DestinationAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_destination_authority(principal, mutation, action="update")

    async def revoke_destination_authority(
        self, principal: TrustedPrincipal, mutation: DestinationAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_destination_authority(principal, mutation, action="revoke")

    async def _mutate_credential_authority(
        self,
        principal: TrustedPrincipal,
        mutation: CredentialAuthorityMutation,
        *,
        action: str,
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not CredentialAuthorityMutation
            or action not in {"update", "revoke"}
            or not valid_uuid(mutation.operation_id)
            or not valid_uuid(mutation.credential_id)
            or not self._valid_expected_revision(mutation.expected_revision)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                prior = await self._receipt_row(connection, mutation.operation_id)
                if prior is not None:
                    authority_spec = await self._v11_actor_receipt_spec(
                        connection,
                        principal,
                        suffix=suffix,
                        operation_id=mutation.operation_id,
                        operation_code=f"credential_authority_{action}",
                        campaign_id=self._value(prior, "campaign_id", 1),
                        primary_target_id=mutation.credential_id,
                        expected_revision=mutation.expected_revision,
                    )
                    if authority_spec is None:
                        return OperationResult(FixedResult.INVALID_CONTRACT, None)
                    spec, _ = authority_spec
                    replay = await self._classify_receipt(
                        connection,
                        spec,
                        current_revision=mutation.expected_revision,
                    )
                    return replay or OperationResult(
                        FixedResult.CONFLICT_OPERATION,
                        mutation.expected_revision,
                    )
                gateway = await self._fetchrow(
                    connection,
                    "SELECT singleton_id FROM execution_gateway_state "
                    "WHERE singleton_id=1" + suffix,
                    (),
                )
                if gateway is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                credential = await self._fetchrow(
                    connection,
                    "SELECT id,campaign_id,host_id,username,cred_type,domain,source_module,"
                    "execution_authority_state,execution_authority_revision "
                    "FROM credentials WHERE id=?" + suffix,
                    (mutation.credential_id,),
                )
                if credential is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                campaign_id = str(self._value(credential, "campaign_id", 1))
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code=f"credential_authority_{action}",
                    campaign_id=campaign_id,
                    primary_target_id=mutation.credential_id,
                    expected_revision=mutation.expected_revision,
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, _ = authority_spec
                if not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    campaign_id,
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                revision = int(self._value(credential, "execution_authority_revision", 8))
                state = str(self._value(credential, "execution_authority_state", 7))
                if revision != mutation.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if state != "active":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                binding = self._credential_authority_binding(credential)
                next_state = "revoked" if action == "revoke" else "active"
                updated = await self.cas_update_one(
                    connection,
                    "UPDATE credentials SET execution_authority_state=?,"
                    "execution_authority_revision=execution_authority_revision+1,"
                    "execution_authority_binding_digest=?,"
                    "execution_authority_latest_operation_id=?,"
                    "execution_authority_latest_operation_base_revision=?,"
                    "execution_authority_latest_operation_code=? WHERE id=? "
                    "AND execution_authority_revision=? AND execution_authority_state='active' "
                    "RETURNING id,execution_authority_revision",
                    (
                        next_state,
                        binding,
                        mutation.operation_id,
                        revision,
                        action,
                        mutation.credential_id,
                        revision,
                    ),
                    identity=mutation.credential_id,
                    post_revision=revision + 1,
                    revision_column="execution_authority_revision",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="credentials",
                        identity_column="id",
                        identity=mutation.credential_id,
                        revision_column="execution_authority_revision",
                        checks=(
                            (
                                "execution_authority_revision",
                                (revision,),
                                FixedResult.CONFLICT_REVISION,
                            ),
                            (
                                "execution_authority_state",
                                ("active",),
                                FixedResult.CONFLICT_STATE,
                            ),
                        ),
                    ),
                )
                if updated is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=mutation.credential_id,
                    result_revision=revision + 1,
                    result_fields=(
                        ("authority_state", next_state),
                        ("binding_digest", binding),
                    ),
                )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def update_credential_authority(
        self, principal: TrustedPrincipal, mutation: CredentialAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_credential_authority(principal, mutation, action="update")

    async def revoke_credential_authority(
        self, principal: TrustedPrincipal, mutation: CredentialAuthorityMutation
    ) -> OperationResult:
        return await self._mutate_credential_authority(principal, mutation, action="revoke")

    async def grant_approval_authority(
        self, principal: TrustedPrincipal, mutation: ApprovalAuthorityGrant
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not ApprovalAuthorityGrant
            or not all(
                valid_uuid(value)
                for value in (
                    mutation.operation_id,
                    mutation.approval_id,
                    mutation.approval_ref,
                    mutation.campaign_id,
                    mutation.submission_id,
                    mutation.attempt_id,
                    mutation.actor_subject_ref,
                    mutation.actor_user_id,
                )
            )
            or type(mutation.module_id) is not str
            or mutation.actor_subject_ref != mutation.actor_user_id
            or type(mutation.granted_capability_mask) is not int
            or not 0 <= mutation.granted_capability_mask <= 15
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("approval_ref", mutation.approval_ref),
            ("submission_id", mutation.submission_id),
            ("attempt_id", mutation.attempt_id),
            ("actor_subject_ref", mutation.actor_subject_ref),
            ("actor_user_id", mutation.actor_user_id),
            ("module_id", mutation.module_id),
            ("granted_capability_mask", mutation.granted_capability_mask),
        )
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code="approval_authority_grant",
                    campaign_id=mutation.campaign_id,
                    primary_target_id=mutation.approval_id,
                    expected_revision=None,
                    fields=fields,
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, resolved = authority_spec
                replay = await self._classify_receipt(connection, spec, current_revision=None)
                if replay is not None:
                    return replay
                if resolved is None:
                    resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                if not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    mutation.campaign_id,
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                from ares.modules.descriptors import get_descriptor

                descriptor = get_descriptor(mutation.module_id)
                if descriptor is None:
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                descriptor_digest = descriptor.semantic_digest
                campaign = await self._fetchrow(
                    connection,
                    "SELECT id FROM campaigns WHERE id=?" + suffix,
                    (mutation.campaign_id,),
                )
                actor = await self._fetchrow(
                    connection,
                    "SELECT id FROM users WHERE id=?" + suffix,
                    (mutation.actor_user_id,),
                )
                if campaign is None or actor is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                binding = canonical_operation_binding_digest(
                    "approval-authority",
                    fields
                    + (
                        ("descriptor_semantic_digest", descriptor_digest),
                        ("approver_subject_ref", resolved.subject_ref),
                        ("approver_user_id", resolved.user_id),
                        ("authority_state", "active"),
                    ),
                )
                inserted = await self.cas_update_one(
                    connection,
                    "INSERT INTO execution_approval_authorities("
                    "id,approval_ref,campaign_id,submission_id,attempt_id,actor_subject_ref,"
                    "actor_user_id,module_id,approver_subject_ref,approver_user_id,authority_state,"
                    "revision,granted_capability_mask,descriptor_semantic_digest,binding_digest,"
                    "latest_operation_id,latest_operation_base_revision,latest_operation_code) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,'active',0,?,?,?,?,0,'grant') "
                    "ON CONFLICT DO NOTHING RETURNING id,revision",
                    (
                        mutation.approval_id,
                        mutation.approval_ref,
                        mutation.campaign_id,
                        mutation.submission_id,
                        mutation.attempt_id,
                        mutation.actor_subject_ref,
                        mutation.actor_user_id,
                        mutation.module_id,
                        resolved.subject_ref,
                        resolved.user_id,
                        mutation.granted_capability_mask,
                        descriptor_digest,
                        binding,
                        mutation.operation_id,
                    ),
                    identity=mutation.approval_id,
                    post_revision=0,
                    revision_column="revision",
                    zero_classifier=None,
                )
                if inserted is None:
                    return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=mutation.approval_id,
                    result_revision=0,
                    result_fields=(("binding_digest", binding),),
                )
                return OperationResult(FixedResult.APPLIED, 0)
        except _AbortOperationError as aborted:
            return aborted.result

    async def revoke_approval_authority(
        self, principal: TrustedPrincipal, mutation: ApprovalAuthorityMutation
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(mutation) is not ApprovalAuthorityMutation
            or not valid_uuid(mutation.operation_id)
            or not valid_uuid(mutation.approval_id)
            or not self._valid_expected_revision(mutation.expected_revision)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, mutation.operation_id)
                prior = await self._receipt_row(connection, mutation.operation_id)
                if prior is not None:
                    authority_spec = await self._v11_actor_receipt_spec(
                        connection,
                        principal,
                        suffix=suffix,
                        operation_id=mutation.operation_id,
                        operation_code="approval_authority_revoke",
                        campaign_id=self._value(prior, "campaign_id", 1),
                        primary_target_id=mutation.approval_id,
                        expected_revision=mutation.expected_revision,
                    )
                    if authority_spec is None:
                        return OperationResult(FixedResult.INVALID_CONTRACT, None)
                    spec, _ = authority_spec
                    replay = await self._classify_receipt(
                        connection,
                        spec,
                        current_revision=mutation.expected_revision,
                    )
                    return replay or OperationResult(
                        FixedResult.CONFLICT_OPERATION,
                        mutation.expected_revision,
                    )
                gateway = await self._fetchrow(
                    connection,
                    "SELECT singleton_id FROM execution_gateway_state "
                    "WHERE singleton_id=1" + suffix,
                    (),
                )
                if gateway is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                resolved = await self._resolve_principal(connection, principal, suffix=suffix)
                if resolved is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                row = await self._fetchrow(
                    connection,
                    "SELECT id,approval_ref,approver_subject_ref,approver_user_id,revision,"
                    "binding_digest,authority_state,campaign_id,submission_id,attempt_id,"
                    "actor_subject_ref,actor_user_id,module_id,granted_capability_mask,"
                    "descriptor_semantic_digest FROM "
                    "execution_approval_authorities WHERE id=?" + suffix,
                    (mutation.approval_id,),
                )
                campaign_id = None if row is None else str(self._value(row, "campaign_id", 7))
                authority_spec = await self._v11_actor_receipt_spec(
                    connection,
                    principal,
                    suffix=suffix,
                    operation_id=mutation.operation_id,
                    operation_code="approval_authority_revoke",
                    campaign_id=campaign_id,
                    primary_target_id=mutation.approval_id,
                    expected_revision=mutation.expected_revision,
                )
                if authority_spec is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                spec, _ = authority_spec
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                if not await self._principal_can_mutate_campaign(
                    connection,
                    resolved,
                    str(campaign_id),
                    suffix=suffix,
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
                revision = int(self._value(row, "revision", 4))
                if revision != mutation.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if self._value(row, "authority_state", 6) != "active":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                binding = self._approval_authority_binding(
                    row,
                    authority_state="revoked",
                )
                updated = await self.cas_update_one(
                    connection,
                    "UPDATE execution_approval_authorities SET authority_state='revoked',"
                    "revision=revision+1,binding_digest=?,latest_operation_id=?,"
                    "latest_operation_base_revision=?,latest_operation_code='revoke',updated_at="
                    + self._now_sql
                    + " WHERE id=? AND revision=? AND authority_state='active' "
                    "RETURNING id,revision",
                    (
                        binding,
                        mutation.operation_id,
                        revision,
                        mutation.approval_id,
                        revision,
                    ),
                    identity=mutation.approval_id,
                    post_revision=revision + 1,
                    revision_column="revision",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="execution_approval_authorities",
                        identity_column="id",
                        identity=mutation.approval_id,
                        revision_column="revision",
                        checks=(
                            ("revision", (revision,), FixedResult.CONFLICT_REVISION),
                            ("authority_state", ("active",), FixedResult.CONFLICT_STATE),
                        ),
                    ),
                )
                if updated is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=mutation.approval_id,
                    result_revision=revision + 1,
                    result_fields=(
                        ("authority_state", "revoked"),
                        ("binding_digest", binding),
                    ),
                )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def ensure_campaign_authority(
        self, campaign_id: str, operation_id: str
    ) -> OperationResult:
        try:
            return await self._ensure_campaign_authority(campaign_id, operation_id)
        except _AbortOperationError as aborted:
            return aborted.result

    async def _ensure_campaign_authority(
        self, campaign_id: str, operation_id: str
    ) -> OperationResult:
        if not valid_uuid(campaign_id) or not valid_uuid(operation_id):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._receipt_spec(
            operation_id=operation_id,
            operation_code="campaign_authority_ensure",
            campaign_id=campaign_id,
            primary_target_id=campaign_id,
        )
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, operation_id)
            replay = await self._classify_receipt(connection, spec, current_revision=None)
            if replay is not None:
                return replay
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            gateway = await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            if gateway is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
            campaign = await self._fetchrow(
                connection,
                "SELECT id,operator,status,noise_profile,scope_json,targets_json "
                "FROM campaigns WHERE id=?" + suffix,
                (campaign_id,),
            )
            if campaign is None:
                return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            row = await self._fetchrow(
                connection,
                "SELECT revision FROM campaign_execution_authority_revisions WHERE campaign_id=?"
                + suffix,
                (campaign_id,),
            )
            if row is not None:
                return OperationResult(
                    FixedResult.ALREADY_EXISTS, int(self._value(row, "revision", 0))
                )
            try:
                destination_values = self._canonical_destination_values(
                    self._value(campaign, "scope_json", 4),
                    self._value(campaign, "targets_json", 5),
                )
                destination_count, destination_digest, destination_binding = (
                    self._destination_authority_facts(destination_values)
                )
            except ValueError:
                return OperationResult(FixedResult.INVALID_CONTRACT, None)
            campaign_binding = self._campaign_authority_binding(
                campaign,
                destination_binding,
            )
            async with self._savepoint(connection):
                destination_insert = await self.cas_update_one(
                    connection,
                    "INSERT INTO campaign_execution_destination_authorities("
                    "campaign_id,authority_state,revision,normalization_version,"
                    "destination_count,destination_set_digest,binding_digest,"
                    "latest_operation_id,latest_operation_base_revision,latest_operation_code) "
                    "VALUES(?,'active',0,?,?,?,?,?,0,'update') ON CONFLICT(campaign_id) "
                    "DO NOTHING RETURNING campaign_id,revision",
                    (
                        campaign_id,
                        DESTINATION_NORMALIZATION_VERSION,
                        destination_count,
                        destination_digest,
                        destination_binding,
                        operation_id,
                    ),
                    identity=campaign_id,
                    post_revision=0,
                    identity_column="campaign_id",
                    revision_column="revision",
                    zero_classifier=None,
                )
                if destination_insert is None:
                    raise _AbortOperationError(
                        OperationResult(FixedResult.CONFLICT_OPERATION, None)
                    )
                inserted = await self.cas_update_one(
                    connection,
                    "INSERT INTO campaign_execution_authority_revisions("
                    "campaign_id,revision,latest_operation_id,latest_operation_base_revision,"
                    "latest_operation_code,authority_state,authority_revision,"
                    "authority_binding_digest) VALUES(?,0,?,0,'ensure','active',0,?) "
                    "ON CONFLICT(campaign_id) DO NOTHING RETURNING campaign_id,revision",
                    (campaign_id, operation_id, campaign_binding),
                    identity=campaign_id,
                    post_revision=0,
                    identity_column="campaign_id",
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="campaign_execution_authority_revisions",
                        identity_column="campaign_id",
                        identity=campaign_id,
                        revision_column="revision",
                        missing_result=FixedResult.INVARIANT_FAILURE,
                        matched_result=FixedResult.CONFLICT_OPERATION,
                        receipt_spec=spec,
                    ),
                )
                if inserted is None:
                    raise _AbortOperationError(
                        OperationResult(FixedResult.CONFLICT_OPERATION, None)
                    )
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=campaign_id,
                    result_revision=0,
                )
            return OperationResult(FixedResult.APPLIED, 0)

    async def _invalidate_authority(
        self,
        *,
        table: str,
        key: str,
        value: str,
        expected_revision: int,
        operation_id: str,
    ) -> OperationResult:
        if (
            table
            not in {"execution_actor_authority_revisions", "campaign_execution_authority_revisions"}
            or key not in {"user_id", "campaign_id"}
            or type(value) is not str
            or type(expected_revision) is not int
            or not 0 <= expected_revision < MAX_I53
            or not valid_uuid(operation_id)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        operation_code = (
            "actor_authority_invalidate"
            if table == "execution_actor_authority_revisions"
            else "campaign_authority_invalidate"
        )
        spec = self._receipt_spec(
            operation_id=operation_id,
            operation_code=operation_code,
            campaign_id=value if key == "campaign_id" else None,
            primary_target_id=value,
            expected_revision=expected_revision,
        )
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, operation_id)
            replay = await self._classify_receipt(
                connection, spec, current_revision=expected_revision
            )
            if replay is not None:
                return replay
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            gateway = await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            if gateway is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
            owner_table = "users" if key == "user_id" else "campaigns"
            owner = await self._fetchrow(
                connection, f"SELECT id FROM {owner_table} WHERE id=?" + suffix, (value,)
            )
            if owner is None:
                return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            row = await self._fetchrow(
                connection,
                f"SELECT revision FROM {table} WHERE {key}=?" + suffix,
                (value,),
            )
            if row is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
            revision = int(self._value(row, "revision", 0))
            if revision != expected_revision:
                return OperationResult(FixedResult.CONFLICT_REVISION, revision)
            updated = await self.cas_update_one(
                connection,
                f"UPDATE {table} SET revision=revision+1,latest_operation_id=?,latest_operation_base_revision=?,latest_operation_code='invalidate',updated_at="
                + (
                    "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
                    if self._dialect == "postgresql"
                    else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
                )
                + f" WHERE {key}=? AND revision=? RETURNING {key},revision",
                (operation_id, expected_revision, value, expected_revision),
                identity=value,
                post_revision=expected_revision + 1,
                identity_column=key,
                zero_classifier=lambda: self._classify_zero_row(
                    connection,
                    table=table,
                    identity_column=key,
                    identity=value,
                    revision_column="revision",
                    checks=(("revision", (expected_revision,), FixedResult.CONFLICT_REVISION),),
                    missing_result=FixedResult.CONFLICT_STATE,
                ),
            )
            if updated is None:
                return OperationResult(FixedResult.CONFLICT_REVISION, revision)
            await self._insert_receipt(
                connection,
                spec,
                result=FixedResult.APPLIED,
                result_identity=value,
                result_revision=expected_revision + 1,
            )
            return OperationResult(FixedResult.APPLIED, expected_revision + 1)

    async def invalidate_actor_authority(
        self, user_id: str, expected_revision: int, operation_id: str
    ) -> OperationResult:
        try:
            return await self._invalidate_authority(
                table="execution_actor_authority_revisions",
                key="user_id",
                value=user_id,
                expected_revision=expected_revision,
                operation_id=operation_id,
            )
        except _AbortOperationError as aborted:
            return aborted.result

    async def invalidate_campaign_authority(
        self, campaign_id: str, expected_revision: int, operation_id: str
    ) -> OperationResult:
        try:
            return await self._invalidate_authority(
                table="campaign_execution_authority_revisions",
                key="campaign_id",
                value=campaign_id,
                expected_revision=expected_revision,
                operation_id=operation_id,
            )
        except _AbortOperationError as aborted:
            return aborted.result

    async def configure_campaign_budgets(self, request: BudgetConfiguration) -> OperationResult:
        try:
            return await self._configure_campaign_budgets(request)
        except _AbortOperationError as aborted:
            return aborted.result

    async def _configure_campaign_budgets(self, request: BudgetConfiguration) -> OperationResult:
        if (
            type(request) is not BudgetConfiguration
            or not all(
                valid_uuid(value)
                for value in (
                    request.campaign_id,
                    request.noise_budget_id,
                    request.exfiltration_budget_id,
                    request.concurrency_budget_id,
                    request.operation_id,
                )
            )
            or not all(
                self._valid_nonnegative_i53(value)
                for value in (
                    request.noise_capacity,
                    request.exfiltration_capacity,
                    request.concurrency_capacity,
                )
            )
            or request.concurrency_capacity < 1
            or not self._valid_principal_binding(request)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        requested = (
            ("noise", request.noise_budget_id, request.noise_capacity),
            (
                "exfiltration",
                request.exfiltration_budget_id,
                request.exfiltration_capacity,
            ),
            (
                "concurrency",
                request.concurrency_budget_id,
                request.concurrency_capacity,
            ),
        )
        spec = self._receipt_spec(
            operation_id=request.operation_id,
            operation_code="budget_configure",
            campaign_id=request.campaign_id,
            primary_target_id=request.campaign_id,
            principal_kind=str(request.principal_kind),
            principal_subject_ref=str(request.principal_subject_ref),
            principal_user_id=request.principal_user_id,
            principal_authority_revision=request.principal_authority_revision,
            fields=(
                ("noise_budget_id", request.noise_budget_id),
                ("noise_capacity", request.noise_capacity),
                ("exfiltration_budget_id", request.exfiltration_budget_id),
                ("exfiltration_capacity", request.exfiltration_capacity),
                ("concurrency_budget_id", request.concurrency_budget_id),
                ("concurrency_capacity", request.concurrency_capacity),
            ),
        )
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, request.operation_id)
            replay = await self._classify_receipt(connection, spec, current_revision=None)
            if replay is not None:
                return replay
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            gateway = await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            if gateway is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
            campaign = await self._fetchrow(
                connection, "SELECT id FROM campaigns WHERE id=?" + suffix, (request.campaign_id,)
            )
            if campaign is None:
                return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            authority = await self._fetchrow(
                connection,
                "SELECT revision FROM campaign_execution_authority_revisions WHERE campaign_id=?"
                + suffix,
                (request.campaign_id,),
            )
            if authority is None:
                return OperationResult(FixedResult.AUTHORITY_STALE, None)
            rows = await self._fetchall(
                connection,
                "SELECT id,budget_kind,capacity_units,reserved_units,consumed_units,"
                "revision,latest_operation_id,latest_operation_code "
                "FROM campaign_execution_budgets WHERE campaign_id=? "
                "ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                "WHEN 'exfiltration' THEN 2 ELSE 3 END" + suffix,
                (request.campaign_id,),
            )
            if rows:
                return OperationResult(FixedResult.ALREADY_EXISTS, None)
            async with self._savepoint(connection):
                for kind, budget_id, capacity in requested:
                    inserted = await self.insert_or_validate_binding(
                        connection,
                        "INSERT INTO campaign_execution_budgets("
                        "id,campaign_id,budget_kind,capacity_units,reserved_units,"
                        "consumed_units,revision,latest_operation_id,"
                        "latest_operation_base_revision,latest_operation_code) "
                        "VALUES(?,?,?,?,0,0,0,?,0,'configure') "
                        "ON CONFLICT(id) DO NOTHING RETURNING id,revision",
                        (
                            budget_id,
                            request.campaign_id,
                            kind,
                            capacity,
                            request.operation_id,
                        ),
                        identity=budget_id,
                        revision=0,
                    )
                    if inserted is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_OPERATION, None)
                        )
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=request.campaign_id,
                    result_revision=0,
                    result_fields=(("budget_count", 3),),
                )
            return OperationResult(FixedResult.APPLIED, 0)

    async def reserve_budgets(self, request: BudgetReservation) -> OperationResult:
        try:
            return await self._reserve_budgets(request)
        except _AbortOperationError as aborted:
            return aborted.result

    async def _reserve_budgets(self, request: BudgetReservation) -> OperationResult:
        if not self._valid_budget_reservation(request):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        entries = (
            (
                "noise",
                request.noise_budget_id,
                request.noise_ledger_id,
                request.noise_units,
                request.noise_expected_revision,
            ),
            (
                "exfiltration",
                request.exfiltration_budget_id,
                request.exfiltration_ledger_id,
                request.exfiltration_units,
                request.exfiltration_expected_revision,
            ),
            (
                "concurrency",
                request.concurrency_budget_id,
                request.concurrency_ledger_id,
                1,
                request.concurrency_expected_revision,
            ),
        )
        spec = self._budget_reservation_receipt_spec(request)
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, request.operation_id)
            replay = await self._classify_receipt(
                connection,
                spec,
                current_revision=max(
                    request.noise_expected_revision,
                    request.exfiltration_expected_revision,
                    request.concurrency_expected_revision,
                ),
            )
            if replay is not None:
                return replay
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            discovery = await self._fetchrow(
                connection,
                "SELECT logical_execution_id,actor_user_id FROM execution_attempts WHERE id=?",
                (request.attempt_id,),
            )
            if discovery is None:
                return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            actor_user_id = str(self._value(discovery, "actor_user_id", 1))
            logical_execution_id = str(self._value(discovery, "logical_execution_id", 0))
            await self._acquire_logical_attempt_transaction_keys(
                connection,
                logical_execution_id,
                request.attempt_id,
            )
            await self._fetchrow(
                connection,
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                (),
            )
            for sql, value in (
                ("SELECT id FROM users WHERE id=?", actor_user_id),
                ("SELECT id FROM campaigns WHERE id=?", request.campaign_id),
                (
                    "SELECT user_id FROM execution_actor_authority_revisions WHERE user_id=?",
                    actor_user_id,
                ),
                (
                    "SELECT campaign_id FROM campaign_execution_authority_revisions WHERE campaign_id=?",
                    request.campaign_id,
                ),
                ("SELECT id FROM logical_executions WHERE id=?", logical_execution_id),
                ("SELECT id FROM execution_attempts WHERE id=?", request.attempt_id),
            ):
                locked = await self._fetchrow(connection, sql + suffix, (value,))
                if locked is None:
                    return OperationResult(FixedResult.AUTHORITY_STALE, None)
            validated: list[tuple[str, str, str, int, int]] = []
            budget_rows: list[Any] = []
            for kind, budget_id, ledger_id, units, expected_revision in entries:
                row = await self._fetchrow(
                    connection,
                    "SELECT id,campaign_id,budget_kind,capacity_units,reserved_units,"
                    "consumed_units,revision FROM campaign_execution_budgets "
                    "WHERE id=?" + suffix,
                    (budget_id,),
                )
                if row is None or (
                    self._value(row, "campaign_id", 1) != request.campaign_id
                    or self._value(row, "budget_kind", 2) != kind
                ):
                    return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
                budget_rows.append(row)
                validated.append((kind, budget_id, ledger_id, units, expected_revision))
            existing = await self._fetchall(
                connection,
                "SELECT id,budget_kind,budget_id,reservation_units,"
                "budget_revision_reserved FROM campaign_execution_budget_ledger "
                "WHERE attempt_id=? ORDER BY CASE budget_kind WHEN 'noise' THEN 1 "
                "WHEN 'exfiltration' THEN 2 ELSE 3 END" + suffix,
                (request.attempt_id,),
            )
            if existing:
                return OperationResult(FixedResult.CONFLICT_OPERATION, None)
            for row, (_kind, _budget_id, _ledger_id, units, expected_revision) in zip(
                budget_rows, validated, strict=True
            ):
                revision = int(self._value(row, "revision", 6))
                if revision != expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                capacity = int(self._value(row, "capacity_units", 3))
                reserved = int(self._value(row, "reserved_units", 4))
                consumed = int(self._value(row, "consumed_units", 5))
                if reserved + consumed + units > capacity:
                    return OperationResult(FixedResult.CAPACITY_UNAVAILABLE, revision)
            async with self._savepoint(connection):
                for kind, budget_id, ledger_id, units, expected_revision in validated:
                    updated = await self.cas_update_one(
                        connection,
                        "UPDATE campaign_execution_budgets SET "
                        "reserved_units=reserved_units+?,revision=revision+1,"
                        "latest_operation_id=?,latest_operation_base_revision=?,"
                        "latest_operation_code='reserve',updated_at="
                        + self._now_sql
                        + " WHERE id=? AND revision=? AND reserved_units+consumed_units+?<=capacity_units RETURNING id,revision",
                        (
                            units,
                            request.operation_id,
                            expected_revision,
                            budget_id,
                            expected_revision,
                            units,
                        ),
                        identity=budget_id,
                        post_revision=expected_revision + 1,
                        zero_classifier=lambda budget_id=budget_id, kind=kind, expected_revision=expected_revision, units=units: (
                            self._classify_zero_budget(
                                connection,
                                budget_id=budget_id,
                                campaign_id=request.campaign_id,
                                budget_kind=kind,
                                expected_revision=expected_revision,
                                required_units=units,
                                operation="reserve",
                            )
                        ),
                    )
                    if updated is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_REVISION, expected_revision)
                        )
                    inserted = await self.insert_or_validate_binding(
                        connection,
                        "INSERT INTO campaign_execution_budget_ledger("
                        "id,attempt_id,campaign_id,budget_id,budget_kind,"
                        "reservation_units,consumed_units,disposition,"
                        "budget_revision_reserved) VALUES(?,?,?,?,?,?,0,'held',?) "
                        "ON CONFLICT(id) DO NOTHING RETURNING id,budget_revision_reserved",
                        (
                            ledger_id,
                            request.attempt_id,
                            request.campaign_id,
                            budget_id,
                            kind,
                            units,
                            expected_revision + 1,
                        ),
                        identity=ledger_id,
                        revision=expected_revision + 1,
                        revision_column="budget_revision_reserved",
                    )
                    if inserted is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_OPERATION, None)
                        )
                result_fields = (
                    ("noise_ledger_id", request.noise_ledger_id),
                    ("noise_post_revision", request.noise_expected_revision + 1),
                    ("exfiltration_ledger_id", request.exfiltration_ledger_id),
                    ("exfiltration_post_revision", request.exfiltration_expected_revision + 1),
                    ("concurrency_ledger_id", request.concurrency_ledger_id),
                    ("concurrency_post_revision", request.concurrency_expected_revision + 1),
                )
                await self._insert_receipt(
                    connection,
                    spec,
                    result=FixedResult.APPLIED,
                    result_identity=request.attempt_id,
                    result_revision=max(
                        request.noise_expected_revision,
                        request.exfiltration_expected_revision,
                        request.concurrency_expected_revision,
                    )
                    + 1,
                    secondary_result_identity=request.noise_budget_id,
                    secondary_result_revision=request.noise_expected_revision + 1,
                    result_fields=result_fields,
                )
            return OperationResult(FixedResult.APPLIED, None)

    def _valid_budget_reservation(self, request: object) -> bool:
        if type(request) is not BudgetReservation:
            return False
        identifiers = (
            request.campaign_id,
            request.attempt_id,
            request.noise_budget_id,
            request.noise_ledger_id,
            request.exfiltration_budget_id,
            request.exfiltration_ledger_id,
            request.concurrency_budget_id,
            request.concurrency_ledger_id,
            request.operation_id,
        )
        numbers = (
            request.noise_units,
            request.noise_expected_revision,
            request.exfiltration_units,
            request.exfiltration_expected_revision,
            request.concurrency_expected_revision,
        )
        return (
            all(valid_uuid(value) for value in identifiers)
            and all(self._valid_nonnegative_i53(value) for value in numbers)
            and self._valid_principal_binding(request)
        )

    def _budget_reservation_receipt_spec(self, request: BudgetReservation) -> _ReceiptSpec:
        return self._receipt_spec(
            operation_id=request.operation_id,
            operation_code="budget_reserve",
            campaign_id=request.campaign_id,
            primary_target_id=request.attempt_id,
            secondary_target_id=request.noise_budget_id,
            principal_kind=str(request.principal_kind),
            principal_subject_ref=str(request.principal_subject_ref),
            principal_user_id=request.principal_user_id,
            principal_authority_revision=request.principal_authority_revision,
            expected_revision=request.noise_expected_revision,
            secondary_expected_revision=request.exfiltration_expected_revision,
            fields=(
                ("noise_budget_id", request.noise_budget_id),
                ("noise_ledger_id", request.noise_ledger_id),
                ("noise_units", request.noise_units),
                ("exfiltration_budget_id", request.exfiltration_budget_id),
                ("exfiltration_ledger_id", request.exfiltration_ledger_id),
                ("exfiltration_units", request.exfiltration_units),
                ("concurrency_budget_id", request.concurrency_budget_id),
                ("concurrency_ledger_id", request.concurrency_ledger_id),
                ("concurrency_expected_revision", request.concurrency_expected_revision),
            ),
        )

    async def settle_budgets(self, request: BudgetSettlement) -> OperationResult:
        if not self._valid_budget_settlement(request):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._budget_settlement_receipt_spec(request)
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection,
                    spec,
                    current_revision=max(
                        request.noise_expected_revision,
                        request.exfiltration_expected_revision,
                        request.concurrency_expected_revision,
                    ),
                )
                if replay is not None:
                    return replay
                suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
                discovery = await self._fetchrow(
                    connection,
                    "SELECT logical_execution_id,actor_user_id FROM execution_attempts WHERE id=?",
                    (request.attempt_id,),
                )
                if discovery is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                actor_user_id = str(self._value(discovery, "actor_user_id", 1))
                logical_execution_id = str(self._value(discovery, "logical_execution_id", 0))
                await self._acquire_logical_attempt_transaction_keys(
                    connection,
                    logical_execution_id,
                    request.attempt_id,
                )
                await self._fetchrow(
                    connection,
                    "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1"
                    + suffix,
                    (),
                )
                for sql, value in (
                    ("SELECT id FROM users WHERE id=?", actor_user_id),
                    ("SELECT id FROM campaigns WHERE id=?", request.campaign_id),
                    (
                        "SELECT user_id FROM execution_actor_authority_revisions WHERE user_id=?",
                        actor_user_id,
                    ),
                    (
                        "SELECT campaign_id FROM campaign_execution_authority_revisions WHERE campaign_id=?",
                        request.campaign_id,
                    ),
                    ("SELECT id FROM logical_executions WHERE id=?", logical_execution_id),
                    ("SELECT id FROM execution_attempts WHERE id=?", request.attempt_id),
                ):
                    if await self._fetchrow(connection, sql + suffix, (value,)) is None:
                        return OperationResult(FixedResult.AUTHORITY_STALE, None)
                async with self._savepoint(connection):
                    result = await self._settle_budgets_locked(connection, request)
                    if result.result not in {
                        FixedResult.APPLIED,
                        FixedResult.REPLAYED,
                        FixedResult.SUPERSEDED,
                    }:
                        raise _AbortOperationError(result)
                    return result
        except _AbortOperationError as aborted:
            return aborted.result

    def _valid_budget_settlement(self, request: object) -> bool:
        if type(request) is not BudgetSettlement:
            return False
        identifiers = (
            request.campaign_id,
            request.attempt_id,
            request.noise_budget_id,
            request.exfiltration_budget_id,
            request.concurrency_budget_id,
            request.operation_id,
        )
        numbers = (
            request.noise_units,
            request.noise_actual,
            request.noise_expected_revision,
            request.exfiltration_units,
            request.exfiltration_actual,
            request.exfiltration_expected_revision,
            request.concurrency_expected_revision,
        )
        return (
            all(valid_uuid(value) for value in identifiers)
            and all(self._valid_nonnegative_i53(value) for value in numbers)
            and request.noise_actual <= request.noise_units
            and request.exfiltration_actual <= request.exfiltration_units
            and self._valid_principal_binding(request)
        )

    @staticmethod
    def _valid_snapshot(snapshot: object) -> bool:
        if type(snapshot) is not AttemptPolicySnapshot:
            return False
        boolean_fields = (
            "request_structure_valid",
            "canonicalization_complete",
            "unknown_fields_absent",
            "alternate_transport_absent",
            "bounded_shape_valid",
            "trusted_first_party_binding",
            "descriptor_binding_current",
            "descriptor_complete",
            "static_policy_evaluable",
            "preview_ready",
            "lifecycle_ready",
            "result_authority_ready",
            "transport_ready",
            "future_gateway_eligible",
            "authority_snapshots_complete",
            "authority_revisions_current",
            "actor_authenticated",
            "actor_active",
            "campaign_active",
            "actor_campaign_authorized",
            "approval_present",
            "approval_current",
            "approval_exactly_bound",
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
        )
        integer_fields = (
            "actor_authority_revision",
            "campaign_authority_revision",
            "destination_authority_revision",
            "credential_authority_revision",
        )
        if not all(type(getattr(snapshot, name)) is bool for name in boolean_fields):
            return False
        if not all(
            type(getattr(snapshot, name)) is int and 0 <= getattr(snapshot, name) <= MAX_I53
            for name in integer_fields
        ):
            return False
        if (
            type(snapshot.request_shape_units) is not int
            or not 0 <= snapshot.request_shape_units <= 4096
            or type(snapshot.required_capability_mask) is not int
            or not 0 <= snapshot.required_capability_mask <= 15
            or type(snapshot.granted_capability_mask) is not int
            or not 0 <= snapshot.granted_capability_mask <= 15
            or type(snapshot.descriptor_blocker_mask) is not int
            or not 0 <= snapshot.descriptor_blocker_mask <= 511
            or (
                snapshot.policy_reason_mask is not None
                and (
                    type(snapshot.policy_reason_mask) is not int
                    or not 0 <= snapshot.policy_reason_mask <= 34_359_738_367
                )
            )
            or type(snapshot.timeout_limit_ms) is not int
            or not MIN_TIMEOUT_MS <= snapshot.timeout_limit_ms <= MAX_TIMEOUT_MS
        ):
            return False
        domains = (
            (snapshot.evaluation_mode, ("preview", "live")),
            (snapshot.minimum_role, MINIMUM_ROLES),
            (snapshot.actor_role, ACTOR_ROLES),
            (snapshot.noise_class, NOISE_CLASSES),
            (snapshot.approval_policy, APPROVAL_POLICIES),
            (
                snapshot.gateway_mode_snapshot,
                ("disabled", "shadow_candidate", "enforced", "emergency_disabled"),
            ),
            (snapshot.gateway_decision_code, ("none", "emergency_disabled")),
            (snapshot.policy_evaluation_state, ("evaluated", "not_evaluated")),
            (snapshot.external_effect_class, EXTERNAL_EFFECT_CLASSES),
            (snapshot.idempotency_class, IDEMPOTENCY_CLASSES),
            (snapshot.retry_policy, RETRY_POLICIES),
            (snapshot.retry_disposition, RETRY_DISPOSITIONS),
            (snapshot.cancellation_ownership, CANCELLATION_OWNERSHIP),
            (snapshot.compensation_class, COMPENSATION_CLASSES),
            (snapshot.timeout_origin, TIMEOUT_ORIGINS),
            (snapshot.timeout_settlement, TIMEOUT_SETTLEMENTS),
        )
        if any(type(value) is not str or value not in domain for value, domain in domains):
            return False
        if snapshot.policy_verdict is not None and (
            type(snapshot.policy_verdict) is not str
            or snapshot.policy_verdict not in POLICY_VERDICTS
        ):
            return False
        if not (
            type(snapshot.descriptor_semantic_digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", snapshot.descriptor_semantic_digest)
            and type(snapshot.catalog_digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", snapshot.catalog_digest)
        ):
            return False
        return True

    @staticmethod
    def _snapshot_columns_values(
        snapshot: AttemptPolicySnapshot,
    ) -> tuple[tuple[str, ...], tuple[Any, ...]]:
        names = tuple(AttemptPolicySnapshot.__dataclass_fields__)
        columns = tuple(
            {
                "policy_reason_mask": "policy_reason_mask",
            }.get(name, name)
            for name in names
        )
        values = tuple(getattr(snapshot, name) for name in names)
        return columns, values

    @staticmethod
    def _role_satisfies(actor_role: str, minimum_role: str) -> bool:
        ranks = {"reporter": 0, "operator": 1, "team_lead": 2, "admin": 3}
        return ranks[actor_role] >= ranks[minimum_role]

    def _valid_admission(self, request: object) -> bool:
        if type(request) is not AdmissionRequest or not self._valid_snapshot(request.snapshot):
            return False
        identifiers = (
            request.logical_execution_id,
            request.submission_id,
            request.attempt_id,
            request.campaign_id,
            request.actor_subject_ref,
            request.actor_user_id,
            request.operation_id,
        )
        if not all(valid_uuid(value) for value in identifiers):
            return False
        if request.outbox_id is not None and not valid_uuid(request.outbox_id):
            return False
        if request.publication_key is not None and not valid_uuid(request.publication_key):
            return False
        if (
            type(request.module_id) is not str
            or re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}", request.module_id) is None
            or type(request.ingress_code) is not str
            or request.ingress_code not in INGRESS_CODES
            or type(request.initial_state) is not AttemptState
            or request.initial_state
            not in {AttemptState.REJECTED, AttemptState.BLOCKED, AttemptState.ACCEPTED}
        ):
            return False
        terminal = request.initial_state in {AttemptState.REJECTED, AttemptState.BLOCKED}
        if terminal != (request.outbox_id is not None and request.publication_key is not None):
            return False
        if terminal and (request.approval is not None or request.budgets is not None):
            return False
        snapshot = request.snapshot
        emergency = snapshot.gateway_mode_snapshot == "emergency_disabled"
        ordinary_policy_shape = (
            not emergency
            and snapshot.gateway_decision_code == "none"
            and snapshot.policy_evaluation_state == "evaluated"
            and snapshot.policy_verdict is not None
            and snapshot.policy_reason_mask is not None
        )
        emergency_policy_shape = (
            emergency
            and snapshot.gateway_decision_code == "emergency_disabled"
            and snapshot.policy_evaluation_state == "not_evaluated"
            and snapshot.policy_verdict is None
            and snapshot.policy_reason_mask is None
        )
        if not (ordinary_policy_shape or emergency_policy_shape):
            return False
        if request.initial_state is AttemptState.ACCEPTED:
            if (
                request.budgets is None
                or request.budgets.campaign_id != request.campaign_id
                or request.budgets.attempt_id != request.attempt_id
                or (
                    self._principal_binding(request.budgets)
                    not in {
                        (
                            "system",
                            SYSTEM_PRINCIPAL_SUBJECT_REF,
                            None,
                            None,
                        ),
                        (
                            "actor",
                            request.actor_subject_ref,
                            request.actor_user_id,
                            request.snapshot.actor_authority_revision,
                        ),
                    }
                )
            ):
                return False
            if snapshot.approval_policy == "none" and request.approval is not None:
                return False
            if snapshot.approval_policy == "attempt_bound" and request.approval is None:
                return False
        if request.initial_state is AttemptState.REJECTED:
            return ordinary_policy_shape and snapshot.policy_verdict == "rejected"
        if request.initial_state is AttemptState.BLOCKED:
            return (
                ordinary_policy_shape
                and snapshot.policy_verdict == "blocked"
                or (ordinary_policy_shape and snapshot.policy_verdict == "preview_ready")
                or (emergency_policy_shape)
            )
        return (
            ordinary_policy_shape
            and snapshot.evaluation_mode == "live"
            and snapshot.policy_verdict == "live_candidate"
            and snapshot.gateway_mode_snapshot == "enforced"
            and snapshot.gateway_decision_code == "none"
            and snapshot.policy_reason_mask == 0
            and snapshot.request_structure_valid
            and snapshot.canonicalization_complete
            and snapshot.unknown_fields_absent
            and snapshot.alternate_transport_absent
            and snapshot.bounded_shape_valid
            and snapshot.trusted_first_party_binding
            and snapshot.descriptor_binding_current
            and snapshot.descriptor_complete
            and snapshot.static_policy_evaluable
            and snapshot.descriptor_blocker_mask == 0
            and snapshot.preview_ready
            and snapshot.future_gateway_eligible
            and snapshot.lifecycle_ready
            and snapshot.result_authority_ready
            and snapshot.transport_ready
            and snapshot.authority_snapshots_complete
            and snapshot.authority_revisions_current
            and snapshot.actor_authenticated
            and snapshot.actor_active
            and snapshot.campaign_active
            and snapshot.actor_campaign_authorized
            and self._role_satisfies(snapshot.actor_role, snapshot.minimum_role)
            and (
                snapshot.noise_class != "high_noise"
                or snapshot.actor_role in {"team_lead", "admin"}
            )
            and (snapshot.granted_capability_mask & snapshot.required_capability_mask)
            == snapshot.required_capability_mask
            and snapshot.destination_extraction_complete
            and snapshot.destinations_in_scope
            and snapshot.credential_authority_resolved
            and snapshot.credential_authority_current
            and snapshot.opaque_handles_only
            and snapshot.permitted_handle_kinds_only
            and snapshot.raw_credentials_absent
            and snapshot.ambient_credentials_absent
            and snapshot.budget_authority_resolved
            and snapshot.budget_authority_current
            and snapshot.budget_capacity_available
            and (
                (
                    snapshot.approval_policy == "none"
                    and not snapshot.approval_present
                    and not snapshot.approval_current
                    and not snapshot.approval_exactly_bound
                )
                or (
                    snapshot.approval_policy == "attempt_bound"
                    and snapshot.approval_present
                    and snapshot.approval_current
                    and snapshot.approval_exactly_bound
                    and request.approval is not None
                )
            )
        )

    def _admission_receipt_spec(
        self, request: AdmissionRequest, *, operation_code: str = "admission"
    ) -> _ReceiptSpec:
        approval = request.approval
        budgets = request.budgets
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("submission_id", request.submission_id),
            ("attempt_id", request.attempt_id),
            ("actor_subject_ref", request.actor_subject_ref),
            ("actor_user_id", request.actor_user_id),
            ("module_id", request.module_id),
            ("ingress_code", request.ingress_code),
            ("initial_state", request.initial_state.value),
            ("outbox_id", request.outbox_id),
            ("publication_key", request.publication_key),
            ("approval_id", None if approval is None else approval.approval_id),
            ("approval_ref", None if approval is None else approval.approval_ref),
            (
                "approver_subject_ref",
                None if approval is None else approval.approver_subject_ref,
            ),
            ("approver_user_id", None if approval is None else approval.approver_user_id),
            (
                "approval_authority_revision",
                None if approval is None else approval.authority_revision,
            ),
            ("approval_binding_digest", None if approval is None else approval.binding_digest),
            ("noise_budget_id", None if budgets is None else budgets.noise_budget_id),
            ("noise_ledger_id", None if budgets is None else budgets.noise_ledger_id),
            ("noise_units", None if budgets is None else budgets.noise_units),
            (
                "noise_expected_revision",
                None if budgets is None else budgets.noise_expected_revision,
            ),
            (
                "exfiltration_budget_id",
                None if budgets is None else budgets.exfiltration_budget_id,
            ),
            (
                "exfiltration_ledger_id",
                None if budgets is None else budgets.exfiltration_ledger_id,
            ),
            ("exfiltration_units", None if budgets is None else budgets.exfiltration_units),
            (
                "exfiltration_expected_revision",
                None if budgets is None else budgets.exfiltration_expected_revision,
            ),
            (
                "concurrency_budget_id",
                None if budgets is None else budgets.concurrency_budget_id,
            ),
            (
                "concurrency_ledger_id",
                None if budgets is None else budgets.concurrency_ledger_id,
            ),
            (
                "concurrency_expected_revision",
                None if budgets is None else budgets.concurrency_expected_revision,
            ),
        ) + _snapshot_binding_values(request.snapshot)
        return self._receipt_spec(
            operation_id=request.operation_id,
            operation_code=operation_code,
            campaign_id=request.campaign_id,
            primary_target_id=request.logical_execution_id,
            secondary_target_id=request.attempt_id,
            principal_kind="actor",
            principal_subject_ref=request.actor_subject_ref,
            principal_user_id=request.actor_user_id,
            principal_authority_revision=request.snapshot.actor_authority_revision,
            fields=fields,
        )

    @staticmethod
    def _submission_result_binding_digest(request: AdmissionRequest) -> str:
        return canonical_operation_binding_digest(
            "admission.submission-result",
            (
                ("result_code", FixedResult.APPLIED.value),
                ("exact_replay_code", FixedResult.REPLAYED.value),
                ("logical_execution_id", request.logical_execution_id),
                ("logical_revision", 0),
                ("attempt_id", request.attempt_id),
                ("attempt_revision", 0),
                ("state", request.initial_state.value),
            ),
        )

    def _classify_submission_authority(
        self,
        row: Any,
        request: AdmissionRequest,
        spec: _ReceiptSpec,
    ) -> OperationResult:
        matches = (
            self._value(row, "id", 0) == request.logical_execution_id
            and self._value(row, "admission_operation_id", 1) == request.operation_id
            and int(self._value(row, "submission_binding_contract_version", 2)) == 2
            and self._value(row, "submission_request_binding_digest", 3)
            == spec.request_binding_digest
            and self._value(row, "submission_result_code", 4) == FixedResult.APPLIED.value
            and self._value(row, "submission_exact_replay_code", 5) == FixedResult.REPLAYED.value
            and self._value(row, "submission_result_binding_digest", 6)
            == self._submission_result_binding_digest(request)
        )
        return OperationResult(
            FixedResult.REPLAYED if matches else FixedResult.CONFLICT_OPERATION,
            0 if matches else None,
        )

    async def create_initial_execution(self, request: AdmissionRequest) -> OperationResult:
        """Reject fresh v2 admission; historical rows use ``replay_initial_execution_v2``."""
        del request
        return OperationResult(FixedResult.INVALID_CONTRACT, None)

    async def _create_initial_execution_v2_for_migration_fixture(
        self, request: AdmissionRequest
    ) -> OperationResult:
        """Create a v2 row only for migration/compatibility fixture construction."""
        if not self._valid_admission(request):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._admission_receipt_spec(request)
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.submission_id)
                suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
                existing = await self._fetchrow(
                    connection,
                    "SELECT id,admission_operation_id,submission_binding_contract_version,"
                    "submission_request_binding_digest,submission_result_code,"
                    "submission_exact_replay_code,submission_result_binding_digest "
                    "FROM logical_executions WHERE campaign_id=? AND submission_id=?" + suffix,
                    (request.campaign_id, request.submission_id),
                )
                if existing is not None:
                    return self._classify_submission_authority(existing, request, spec)
                if request.budgets is not None:
                    budget_spec = self._budget_reservation_receipt_spec(request.budgets)
                    await self._acquire_transaction_key(connection, request.budgets.operation_id)
                    if (
                        await self._classify_receipt(
                            connection,
                            budget_spec,
                            current_revision=max(
                                request.budgets.noise_expected_revision,
                                request.budgets.exfiltration_expected_revision,
                                request.budgets.concurrency_expected_revision,
                            ),
                        )
                        is not None
                    ):
                        return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                gateway = await self._fetchrow(
                    connection,
                    "SELECT mode FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                    (),
                )
                if (
                    gateway is None
                    or self._value(gateway, "mode", 0) != request.snapshot.gateway_mode_snapshot
                ):
                    raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_STATE, None))
                user = await self._fetchrow(
                    connection,
                    "SELECT id,is_active,role FROM users WHERE id=?" + suffix,
                    (request.actor_user_id,),
                )
                campaign = await self._fetchrow(
                    connection,
                    "SELECT id,status FROM campaigns WHERE id=?" + suffix,
                    (request.campaign_id,),
                )
                actor_authority = await self._fetchrow(
                    connection,
                    "SELECT revision FROM execution_actor_authority_revisions WHERE user_id=?"
                    + suffix,
                    (request.actor_user_id,),
                )
                campaign_authority = await self._fetchrow(
                    connection,
                    "SELECT revision FROM campaign_execution_authority_revisions WHERE campaign_id=?"
                    + suffix,
                    (request.campaign_id,),
                )
                if (
                    user is None
                    or campaign is None
                    or actor_authority is None
                    or campaign_authority is None
                    or self._value(user, "id", 0) != request.actor_subject_ref
                    or not bool(self._value(user, "is_active", 1))
                    or self._value(user, "role", 2) != request.snapshot.actor_role
                    or self._value(campaign, "status", 1) not in {"created", "running"}
                    or int(self._value(actor_authority, "revision", 0))
                    != request.snapshot.actor_authority_revision
                    or int(self._value(campaign_authority, "revision", 0))
                    != request.snapshot.campaign_authority_revision
                ):
                    raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
                terminal = request.initial_state in {
                    AttemptState.REJECTED,
                    AttemptState.BLOCKED,
                }
                now = self._now_sql
                logical_columns = (
                    "id,submission_id,campaign_id,actor_subject_ref,actor_user_id,"
                    "module_id,ingress_code,admission_operation_id,"
                    "submission_binding_contract_version,submission_request_binding_digest,"
                    "submission_result_code,submission_exact_replay_code,"
                    "submission_result_binding_digest,highest_attempt_ordinal,revision,created_at"
                )
                logical_values: tuple[Any, ...] = (
                    request.logical_execution_id,
                    request.submission_id,
                    request.campaign_id,
                    request.actor_subject_ref,
                    request.actor_user_id,
                    request.module_id,
                    request.ingress_code,
                    request.operation_id,
                    2,
                    spec.request_binding_digest,
                    FixedResult.APPLIED.value,
                    FixedResult.REPLAYED.value,
                    self._submission_result_binding_digest(request),
                )
                async with self._savepoint(connection):
                    if terminal:
                        logical_columns += (
                            ",closure_operation_id,closure_authority_subject_ref,"
                            "closure_authority_user_id,closure_authority_revision,"
                            "closing_attempt_id,closed_at"
                        )
                        logical_values += (
                            request.operation_id,
                            request.actor_subject_ref,
                            request.actor_user_id,
                            request.snapshot.actor_authority_revision,
                            request.attempt_id,
                        )
                        logical_sql = (
                            "INSERT INTO logical_executions(" + logical_columns + ") "
                            "SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,db_now,?,?,?,?,?,db_now FROM "
                            "(SELECT " + now + " AS db_now) AS clock WHERE 1=1 "
                            "ON CONFLICT(id) DO NOTHING RETURNING id,revision"
                        )
                    else:
                        logical_sql = (
                            "INSERT INTO logical_executions(" + logical_columns + ") "
                            "SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,db_now FROM (SELECT "
                            + now
                            + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING RETURNING id,revision"
                        )
                    inserted_logical = await self.insert_or_validate_binding(
                        connection,
                        logical_sql,
                        logical_values,
                        identity=request.logical_execution_id,
                        revision=0,
                    )
                    if inserted_logical is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_OPERATION, None)
                        )
                    await self._insert_attempt(connection, request, ordinal=0, parent=None)
                    if terminal:
                        await self._insert_initial_terminal_outbox(connection, request)
                    else:
                        if request.approval is not None:
                            await self._insert_approval(connection, request)
                        budget_result = await self._reserve_budgets_locked(
                            connection, request.budgets
                        )
                        if budget_result.result is not FixedResult.APPLIED:
                            raise _AbortOperationError(budget_result)
                return OperationResult(FixedResult.APPLIED, 0)
        except _AbortOperationError as aborted:
            return aborted.result

    async def replay_initial_execution_v2(
        self,
        principal: TrustedPrincipal,
        request: AdmissionRequest,
    ) -> OperationResult:
        """Replay one existing historical v2 submission without live-authority reads."""
        if (
            not self._valid_trusted_principal(principal)
            or not self._valid_admission(request)
            or request.actor_subject_ref != principal.subject_ref
            or request.actor_user_id != principal.user_id
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._admission_receipt_spec(request)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, request.submission_id)
            row = await self._fetchrow(
                connection,
                "SELECT id,admission_operation_id,submission_binding_contract_version,"
                "submission_request_binding_digest,submission_result_code,"
                "submission_exact_replay_code,submission_result_binding_digest,"
                "admission_authority_contract_version,actor_subject_ref,actor_user_id "
                "FROM logical_executions WHERE campaign_id=? AND submission_id=?" + suffix,
                (request.campaign_id, request.submission_id),
            )
            if row is None:
                return OperationResult(FixedResult.INVALID_CONTRACT, None)
            if (
                int(self._value(row, "admission_authority_contract_version", 7))
                != ADMISSION_AUTHORITY_CONTRACT_V2
                or self._value(row, "actor_subject_ref", 8) != principal.subject_ref
                or self._value(row, "actor_user_id", 9) != principal.user_id
            ):
                return OperationResult(FixedResult.CONFLICT_OPERATION, None)
            return self._classify_submission_authority(row, request, spec)

    @staticmethod
    def _v3_initial_state(snapshot: AttemptPolicySnapshot) -> AttemptState:
        if snapshot.policy_verdict == "live_candidate":
            return AttemptState.ACCEPTED
        if snapshot.policy_verdict == "rejected":
            return AttemptState.REJECTED
        return AttemptState.BLOCKED

    async def _insert_v3_observations(
        self,
        connection: Any,
        request: AdmissionRequest,
        resolved: _ResolvedAdmissionV3,
    ) -> None:
        for ordinal, (destination_ref_digest, authority_revision) in enumerate(
            resolved.destination_observations
        ):
            row = await self.insert_or_validate_binding(
                connection,
                "INSERT INTO execution_attempt_destination_observations("
                "attempt_id,campaign_id,ordinal,destination_ref_digest,authority_revision,"
                "normalization_version) VALUES(?,?,?,?,?,?) ON CONFLICT(attempt_id,ordinal) "
                "DO NOTHING RETURNING attempt_id,ordinal",
                (
                    request.attempt_id,
                    request.campaign_id,
                    ordinal,
                    destination_ref_digest,
                    authority_revision,
                    DESTINATION_NORMALIZATION_VERSION,
                ),
                identity=request.attempt_id,
                revision=ordinal,
                identity_column="attempt_id",
                revision_column="ordinal",
            )
            if row is None:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
        for ordinal, (credential_id, authority_revision, binding_digest) in enumerate(
            resolved.credential_observations
        ):
            row = await self.insert_or_validate_binding(
                connection,
                "INSERT INTO execution_attempt_credential_observations("
                "attempt_id,campaign_id,ordinal,credential_id,authority_revision,binding_digest) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(attempt_id,ordinal) DO NOTHING "
                "RETURNING attempt_id,ordinal",
                (
                    request.attempt_id,
                    request.campaign_id,
                    ordinal,
                    credential_id,
                    authority_revision,
                    binding_digest,
                ),
                identity=request.attempt_id,
                revision=ordinal,
                identity_column="attempt_id",
                revision_column="ordinal",
            )
            if row is None:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))

    async def _insert_attempt_v3(
        self,
        connection: Any,
        request: AdmissionRequest,
        resolved: _ResolvedAdmissionV3,
        prepared: _PreparedAdmissionV3,
        *,
        ordinal: int,
        parent: str | None,
    ) -> None:
        await self._insert_attempt(connection, request, ordinal=ordinal, parent=parent)
        await self.update_exact_set(
            connection,
            "UPDATE execution_attempts SET authority_contract_version=3,"
            "trusted_principal_subject_ref=?,trusted_principal_user_id=?,"
            "immutable_intent_digest=?,immutable_work_digest=?,gateway_revision=?,"
            "gateway_activation_revision=?,"
            "campaign_actor_grant_revision=?,destination_authority_binding_digest=?,"
            "credential_authority_binding_digest=?,approval_authority_binding_digest=? "
            "WHERE id=? AND authority_contract_version=2 RETURNING id,authority_contract_version",
            (
                resolved.principal.subject_ref,
                resolved.principal.user_id,
                prepared.immutable_intent_digest,
                prepared.immutable_work_digest,
                resolved.gateway_revision,
                resolved.gateway_activation_revision,
                resolved.grant_revision,
                resolved.destination_binding_digest,
                resolved.credential_binding_digest,
                resolved.approval_binding_digest,
                request.attempt_id,
            ),
            expected=(("id", request.attempt_id), ("authority_contract_version", 3)),
            zero_classifier=lambda: self._classify_zero_row(
                connection,
                table="execution_attempts",
                identity_column="id",
                identity=request.attempt_id,
                revision_column="revision",
                matched_result=FixedResult.CONFLICT_OPERATION,
            ),
        )
        await self._insert_v3_observations(connection, request, resolved)

    async def create_initial_execution_v3(
        self,
        principal: TrustedPrincipal,
        intent: AdmissionIntentV3,
    ) -> OperationResult:
        principal_shape_valid = (
            type(principal) is TrustedPrincipal
            and valid_uuid(principal.subject_ref)
            and valid_uuid(principal.user_id)
            and principal.subject_ref == principal.user_id
        )
        if not principal_shape_valid:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        if (
            not self._valid_initial_v3_intent_shape(intent)
            or intent.outbox_id is not None
            or intent.publication_key is not None
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        replay_digest = self._initial_v3_replay_digest(intent)
        if replay_digest is None:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, intent.submission_id)
                existing = await self._fetchrow(
                    connection,
                    "SELECT id,admission_operation_id,submission_binding_contract_version,"
                    "submission_request_binding_digest,submission_result_code,"
                    "submission_exact_replay_code,submission_result_binding_digest,"
                    "admission_authority_contract_version,canonical_principal_user_id,"
                    "immutable_intent_digest,actor_subject_ref,actor_user_id "
                    "FROM logical_executions "
                    "WHERE campaign_id=? AND submission_id=?" + suffix,
                    (intent.campaign_id, intent.submission_id),
                )
                if existing is not None:
                    matches = (
                        self._value(existing, "id", 0) == intent.logical_execution_id
                        and self._value(existing, "admission_operation_id", 1)
                        == intent.operation_id
                        and int(
                            self._value(
                                existing,
                                "submission_binding_contract_version",
                                2,
                            )
                        )
                        == 2
                        and self._value(existing, "submission_result_code", 4)
                        == FixedResult.APPLIED.value
                        and self._value(existing, "submission_exact_replay_code", 5)
                        == FixedResult.REPLAYED.value
                        and int(
                            self._value(
                                existing,
                                "admission_authority_contract_version",
                                7,
                            )
                        )
                        == ADMISSION_AUTHORITY_CONTRACT_V3
                        and self._value(existing, "canonical_principal_user_id", 8)
                        == principal.user_id
                        and self._value(existing, "immutable_intent_digest", 9) == replay_digest
                        and self._value(existing, "actor_subject_ref", 10) == principal.subject_ref
                        and self._value(existing, "actor_user_id", 11) == principal.user_id
                    )
                    return OperationResult(
                        FixedResult.REPLAYED if matches else FixedResult.CONFLICT_OPERATION,
                        0 if matches else None,
                    )
                prepared = self._prepared_admission(intent)
                if prepared is None:
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                resolved = await self._resolve_admission_v3(
                    connection, principal, intent, prepared, suffix=suffix
                )
                state = self._v3_initial_state(resolved.snapshot)
                terminal = state in {AttemptState.REJECTED, AttemptState.BLOCKED}
                outbox_id = (
                    self._derived_v3_uuid(intent.operation_id, "terminal-outbox")
                    if terminal
                    else None
                )
                publication_key = (
                    self._derived_v3_uuid(intent.operation_id, "terminal-publication")
                    if terminal
                    else None
                )
                request = AdmissionRequest(
                    intent.logical_execution_id,
                    intent.submission_id,
                    intent.attempt_id,
                    outbox_id,
                    publication_key,
                    intent.campaign_id,
                    resolved.principal.subject_ref,
                    resolved.principal.user_id,
                    intent.module_id,
                    intent.ingress_code,
                    state,
                    intent.operation_id,
                    resolved.snapshot,
                    resolved.approval,
                    resolved.budgets,
                )
                if not self._valid_admission(request):
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                spec = self._admission_receipt_spec(request)
                if request.budgets is not None:
                    await self._acquire_transaction_key(connection, request.budgets.operation_id)
                logical_columns = (
                    "id,submission_id,campaign_id,actor_subject_ref,actor_user_id,module_id,"
                    "ingress_code,admission_operation_id,submission_binding_contract_version,"
                    "submission_request_binding_digest,submission_result_code,"
                    "submission_exact_replay_code,submission_result_binding_digest,"
                    "highest_attempt_ordinal,revision,admission_authority_contract_version,"
                    "canonical_principal_user_id,immutable_intent_digest,"
                    "immutable_work_digest"
                )
                values: tuple[Any, ...] = (
                    intent.logical_execution_id,
                    intent.submission_id,
                    intent.campaign_id,
                    resolved.principal.subject_ref,
                    resolved.principal.user_id,
                    intent.module_id,
                    intent.ingress_code,
                    intent.operation_id,
                    2,
                    spec.request_binding_digest,
                    FixedResult.APPLIED.value,
                    FixedResult.REPLAYED.value,
                    self._submission_result_binding_digest(request),
                    0,
                    0,
                    ADMISSION_AUTHORITY_CONTRACT_V3,
                    resolved.principal.user_id,
                    prepared.immutable_intent_digest,
                    prepared.immutable_work_digest,
                )
                if terminal:
                    logical_columns += (
                        ",closure_operation_id,closure_authority_subject_ref,"
                        "closure_authority_user_id,closure_authority_revision,"
                        "closing_attempt_id,created_at,closed_at"
                    )
                    values += (
                        intent.operation_id,
                        resolved.principal.subject_ref,
                        resolved.principal.user_id,
                        resolved.principal.authority_revision,
                        intent.attempt_id,
                    )
                    clock_values = ",db_now,db_now"
                else:
                    logical_columns += ",created_at"
                    clock_values = ",db_now"
                placeholders = ",".join("?" for _ in values)
                sql = (
                    "INSERT INTO logical_executions("
                    + logical_columns
                    + ") SELECT "
                    + placeholders
                    + clock_values
                    + " FROM (SELECT "
                    + self._now_sql
                    + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING "
                    "RETURNING id,revision"
                )
                async with self._savepoint(connection):
                    inserted = await self.insert_or_validate_binding(
                        connection,
                        sql,
                        values,
                        identity=intent.logical_execution_id,
                        revision=0,
                    )
                    if inserted is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_OPERATION, None)
                        )
                    await self._insert_attempt_v3(
                        connection,
                        request,
                        resolved,
                        prepared,
                        ordinal=0,
                        parent=None,
                    )
                    if terminal:
                        await self._insert_initial_terminal_outbox(connection, request)
                    else:
                        if resolved.approval is not None:
                            await self._consume_approval_authority_v3(connection, request, resolved)
                            await self._insert_approval(connection, request)
                        budget_result = await self._reserve_budgets_locked(
                            connection, resolved.budgets
                        )
                        if budget_result.result is not FixedResult.APPLIED:
                            raise _AbortOperationError(budget_result)
                return OperationResult(FixedResult.APPLIED, 0)
        except _AbortOperationError as aborted:
            return aborted.result

    async def _consume_approval_authority_v3(
        self,
        connection: Any,
        request: AdmissionRequest,
        resolved: _ResolvedAdmissionV3,
    ) -> None:
        approval = request.approval
        if approval is None:
            return
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        row = await self._fetchrow(
            connection,
            "SELECT id,approval_ref,approver_subject_ref,approver_user_id,revision,"
            "binding_digest,authority_state,campaign_id,submission_id,attempt_id,"
            "actor_subject_ref,actor_user_id,module_id,granted_capability_mask,"
            "descriptor_semantic_digest FROM execution_approval_authorities WHERE id=?" + suffix,
            (approval.approval_id,),
        )
        if (
            row is None
            or self._value(row, "binding_digest", 5) != approval.binding_digest
            or self._value(row, "authority_state", 6) != "active"
        ):
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))
        consumed_binding = self._approval_authority_binding(
            row,
            authority_state="consumed",
        )
        updated = await self.cas_update_one(
            connection,
            "UPDATE execution_approval_authorities SET authority_state='consumed',"
            "revision=revision+1,binding_digest=?,latest_operation_id=?,"
            "latest_operation_base_revision=?,"
            "latest_operation_code='consume',updated_at="
            + self._now_sql
            + ",consumed_at="
            + self._now_sql
            + " WHERE id=? AND revision=? AND authority_state='active' "
            "RETURNING id,revision",
            (
                consumed_binding,
                request.operation_id,
                approval.authority_revision,
                approval.approval_id,
                approval.authority_revision,
            ),
            identity=approval.approval_id,
            post_revision=approval.authority_revision + 1,
            revision_column="revision",
            zero_classifier=lambda: self._classify_zero_row(
                connection,
                table="execution_approval_authorities",
                identity_column="id",
                identity=approval.approval_id,
                revision_column="revision",
                checks=(
                    (
                        "revision",
                        (approval.authority_revision,),
                        FixedResult.CONFLICT_REVISION,
                    ),
                    ("authority_state", ("active",), FixedResult.CONFLICT_STATE),
                ),
            ),
        )
        if updated is None:
            raise _AbortOperationError(OperationResult(FixedResult.AUTHORITY_STALE, None))

    async def _insert_attempt(
        self,
        connection: Any,
        request: AdmissionRequest,
        *,
        ordinal: int,
        parent: str | None,
    ) -> None:
        snapshot_columns, snapshot_values = self._snapshot_columns_values(request.snapshot)
        state = request.initial_state
        terminal = state in {AttemptState.REJECTED, AttemptState.BLOCKED}
        columns = (
            "id",
            "logical_execution_id",
            "campaign_id",
            "ordinal",
            "parent_attempt_id",
            "state",
            "closes_logical",
            "actor_subject_ref",
            "actor_user_id",
            "request_contract_version",
            "descriptor_contract_version",
            "capability_mask_version",
            "descriptor_blocker_mask_version",
            "policy_contract_version",
            "policy_reason_mask_version",
        ) + snapshot_columns
        values: tuple[Any, ...] = (
            request.attempt_id,
            request.logical_execution_id,
            request.campaign_id,
            ordinal,
            parent,
            state.value,
            terminal,
            request.actor_subject_ref,
            request.actor_user_id,
            REQUEST_CONTRACT_VERSION,
            DESCRIPTOR_CONTRACT_VERSION,
            MASK_VERSION,
            MASK_VERSION,
            POLICY_CONTRACT_VERSION,
            None if request.snapshot.policy_reason_mask is None else MASK_VERSION,
        ) + snapshot_values
        now = self._now_sql
        extra_columns: tuple[str, ...]
        extra_values: tuple[Any, ...]
        if terminal:
            extra_columns = (
                "outcome_code",
                "error_action_code",
                "settlement_state",
                "settlement_proof_code",
                "termination_confirmed",
                "lease_generation",
                "terminal_operation_id",
                "created_at",
                "finished_at",
                "settled_at",
            )
            extra_values = (
                "policy_rejected" if state is AttemptState.REJECTED else "policy_blocked",
                "abort",
                "not_applicable",
                "no_dispatch",
                False,
                0,
                request.operation_id,
            )
            sql = (
                "INSERT INTO execution_attempts("
                + ",".join(columns + extra_columns)
                + ") SELECT "
                + ",".join("?" for _ in values + extra_values)
                + ",db_now,db_now,db_now FROM (SELECT "
                + now
                + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING RETURNING id,revision"
            )
        else:
            extra_columns = (
                "outcome_code",
                "error_action_code",
                "settlement_state",
                "settlement_proof_code",
                "termination_confirmed",
                "lease_generation",
                "created_at",
                "accepted_at",
            )
            extra_values = (None, "none", "reserved", "none", False, 0)
            sql = (
                "INSERT INTO execution_attempts("
                + ",".join(columns + extra_columns)
                + ") SELECT "
                + ",".join("?" for _ in values + extra_values)
                + ",db_now,db_now FROM (SELECT "
                + now
                + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING RETURNING id,revision"
            )
        inserted = await self.insert_or_validate_binding(
            connection,
            sql,
            values + extra_values,
            identity=request.attempt_id,
            revision=0,
        )
        if inserted is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))

    async def create_retry_attempt(self, request: RetryRequest) -> OperationResult:
        """Reject fresh v2 retry; historical receipts use ``replay_retry_attempt_v2``."""
        del request
        return OperationResult(FixedResult.INVALID_CONTRACT, None)

    async def _create_retry_attempt_v2_for_migration_fixture(
        self, request: RetryRequest
    ) -> OperationResult:
        """Create a v2 retry only for migration/compatibility fixture construction."""
        if (
            type(request) is not RetryRequest
            or not valid_uuid(request.logical_execution_id)
            or not valid_uuid(request.parent_attempt_id)
            or type(request.expected_parent_revision) is not int
            or not 0 <= request.expected_parent_revision < MAX_I53
            or not self._valid_admission(request.child)
            or request.child.logical_execution_id != request.logical_execution_id
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        child = request.child
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        approval = child.approval
        budgets = child.budgets
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("logical_execution_id", request.logical_execution_id),
            ("parent_attempt_id", request.parent_attempt_id),
            ("child_attempt_id", child.attempt_id),
            ("child_submission_id", child.submission_id),
            ("child_operation_id", child.operation_id),
            ("child_outbox_id", child.outbox_id),
            ("child_publication_key", child.publication_key),
            ("child_campaign_id", child.campaign_id),
            ("actor_subject_ref", child.actor_subject_ref),
            ("actor_user_id", child.actor_user_id),
            ("module_id", child.module_id),
            ("ingress_code", child.ingress_code),
            ("initial_state", child.initial_state.value),
        ) + _snapshot_binding_values(child.snapshot)
        fields += (
            ("approval_id", None if approval is None else approval.approval_id),
            ("approval_ref", None if approval is None else approval.approval_ref),
            (
                "approval_authority_revision",
                None if approval is None else approval.authority_revision,
            ),
            (
                "approval_binding_digest",
                None if approval is None else approval.binding_digest,
            ),
            ("budget_operation_id", None if budgets is None else budgets.operation_id),
            ("noise_budget_id", None if budgets is None else budgets.noise_budget_id),
            ("noise_ledger_id", None if budgets is None else budgets.noise_ledger_id),
            ("noise_units", None if budgets is None else budgets.noise_units),
            (
                "noise_expected_revision",
                None if budgets is None else budgets.noise_expected_revision,
            ),
            (
                "exfiltration_budget_id",
                None if budgets is None else budgets.exfiltration_budget_id,
            ),
            (
                "exfiltration_ledger_id",
                None if budgets is None else budgets.exfiltration_ledger_id,
            ),
            ("exfiltration_units", None if budgets is None else budgets.exfiltration_units),
            (
                "exfiltration_expected_revision",
                None if budgets is None else budgets.exfiltration_expected_revision,
            ),
            (
                "concurrency_budget_id",
                None if budgets is None else budgets.concurrency_budget_id,
            ),
            (
                "concurrency_ledger_id",
                None if budgets is None else budgets.concurrency_ledger_id,
            ),
            (
                "concurrency_expected_revision",
                None if budgets is None else budgets.concurrency_expected_revision,
            ),
        )
        spec = self._receipt_spec(
            operation_id=child.operation_id,
            operation_code="retry",
            campaign_id=child.campaign_id,
            primary_target_id=request.parent_attempt_id,
            secondary_target_id=child.attempt_id,
            principal_kind="actor",
            principal_subject_ref=child.actor_subject_ref,
            principal_user_id=child.actor_user_id,
            principal_authority_revision=child.snapshot.actor_authority_revision,
            expected_revision=request.expected_parent_revision,
            fields=fields,
        )
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, child.operation_id)
                replay = await self._classify_receipt(
                    connection,
                    spec,
                    current_revision=request.expected_parent_revision,
                )
                if replay is not None:
                    return replay
                if budgets is not None:
                    budget_spec = self._budget_reservation_receipt_spec(budgets)
                    await self._acquire_transaction_key(connection, budgets.operation_id)
                    if (
                        await self._classify_receipt(
                            connection,
                            budget_spec,
                            current_revision=max(
                                budgets.noise_expected_revision,
                                budgets.exfiltration_expected_revision,
                                budgets.concurrency_expected_revision,
                            ),
                        )
                        is not None
                    ):
                        return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                await self._acquire_logical_attempt_transaction_keys(
                    connection,
                    request.logical_execution_id,
                    request.parent_attempt_id,
                )
                gateway = await self._fetchrow(
                    connection,
                    "SELECT mode FROM execution_gateway_state WHERE singleton_id=1" + suffix,
                    (),
                )
                for sql, params in (
                    ("SELECT id FROM users WHERE id=?", (child.actor_user_id,)),
                    ("SELECT id FROM campaigns WHERE id=?", (child.campaign_id,)),
                    (
                        "SELECT user_id FROM execution_actor_authority_revisions WHERE user_id=?",
                        (child.actor_user_id,),
                    ),
                    (
                        "SELECT campaign_id FROM campaign_execution_authority_revisions "
                        "WHERE campaign_id=?",
                        (child.campaign_id,),
                    ),
                ):
                    await self._fetchrow(connection, sql + suffix, params)
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,actor_subject_ref,highest_attempt_ordinal,"
                    "closure_operation_id,revision FROM logical_executions WHERE id=?" + suffix,
                    (request.logical_execution_id,),
                )
                if logical is None:
                    return OperationResult(FixedResult.RETRY_AUTHORITY_UNRESOLVED, None)
                parent_row = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,ordinal,revision,state,closes_logical,"
                    "retry_disposition FROM execution_attempts "
                    "WHERE logical_execution_id=? AND id=?" + suffix,
                    (request.logical_execution_id, request.parent_attempt_id),
                )
                if parent_row is None:
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                parent_revision = int(self._value(parent_row, "revision", 2))
                existing_child = await self._fetchrow(
                    connection,
                    "SELECT logical_execution_id,parent_attempt_id,revision "
                    "FROM execution_attempts WHERE id=?" + suffix,
                    (child.attempt_id,),
                )
                if existing_child is not None:
                    return OperationResult(FixedResult.CONFLICT_OPERATION, parent_revision)
                if self._value(logical, "closure_operation_id", 3) is not None:
                    return OperationResult(FixedResult.ALREADY_CLOSED, parent_revision)
                if parent_revision != request.expected_parent_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, parent_revision)
                sibling = await self._fetchrow(
                    connection,
                    "SELECT id FROM execution_attempts WHERE logical_execution_id=? "
                    "AND parent_attempt_id=?",
                    (request.logical_execution_id, request.parent_attempt_id),
                )
                parent_ordinal = int(self._value(parent_row, "ordinal", 1))
                if (
                    self._value(parent_row, "campaign_id", 0) != child.campaign_id
                    or self._value(logical, "campaign_id", 0) != child.campaign_id
                    or self._value(logical, "actor_subject_ref", 1) != child.actor_subject_ref
                    or parent_ordinal != int(self._value(logical, "highest_attempt_ordinal", 2))
                    or self._value(parent_row, "state", 3) not in {"failed", "timed_out"}
                    or bool(self._value(parent_row, "closes_logical", 4))
                    or self._value(parent_row, "retry_disposition", 5) != "eligible"
                    or sibling is not None
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                output = await self._fetchrow(
                    connection,
                    "SELECT id FROM execution_output_links WHERE attempt_id=?",
                    (request.parent_attempt_id,),
                )
                if output is not None:
                    return OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                if (
                    gateway is None
                    or self._value(gateway, "mode", 0) != child.snapshot.gateway_mode_snapshot
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                authority = await self._fetchrow(
                    connection,
                    "SELECT u.id AS actor_id,u.is_active,u.role,"
                    "a.revision AS actor_revision,c.id AS campaign_id,c.status,"
                    "ca.revision AS campaign_revision "
                    "FROM users u JOIN execution_actor_authority_revisions a ON a.user_id=u.id "
                    "JOIN campaigns c ON c.id=? JOIN campaign_execution_authority_revisions ca ON ca.campaign_id=c.id "
                    "WHERE u.id=?" + suffix,
                    (child.campaign_id, child.actor_user_id),
                )
                if authority is None or not (
                    self._value(authority, "actor_id", 0) == child.actor_subject_ref
                    and bool(self._value(authority, "is_active", 1))
                    and self._value(authority, "role", 2) == child.snapshot.actor_role
                    and int(self._value(authority, "actor_revision", 3))
                    == child.snapshot.actor_authority_revision
                    and self._value(authority, "campaign_id", 4) == child.campaign_id
                    and self._value(authority, "status", 5) in {"created", "running"}
                    and int(self._value(authority, "campaign_revision", 6))
                    == child.snapshot.campaign_authority_revision
                ):
                    return OperationResult(FixedResult.RETRY_AUTHORITY_UNRESOLVED, parent_revision)
                child_ordinal = parent_ordinal + 1
                logical_revision = int(self._value(logical, "revision", 4))
                terminal = child.initial_state in {AttemptState.REJECTED, AttemptState.BLOCKED}
                async with self._savepoint(connection):
                    parent_update = await self.cas_update_one(
                        connection,
                        "UPDATE execution_attempts SET retry_disposition='child_bound',"
                        "retry_child_bound_at="
                        + self._now_sql
                        + ",revision=revision+1 WHERE id=? AND logical_execution_id=? "
                        "AND revision=? AND retry_disposition='eligible' AND closes_logical="
                        + ("FALSE" if self._dialect == "postgresql" else "0")
                        + " RETURNING id,revision,retry_disposition",
                        (
                            request.parent_attempt_id,
                            request.logical_execution_id,
                            request.expected_parent_revision,
                        ),
                        identity=request.parent_attempt_id,
                        post_revision=request.expected_parent_revision + 1,
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="execution_attempts",
                            identity_column="id",
                            identity=request.parent_attempt_id,
                            revision_column="revision",
                            checks=(
                                (
                                    "revision",
                                    (request.expected_parent_revision,),
                                    FixedResult.CONFLICT_REVISION,
                                ),
                                (
                                    "logical_execution_id",
                                    (request.logical_execution_id,),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                (
                                    "retry_disposition",
                                    ("eligible",),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                ("closes_logical", (False,), FixedResult.CONFLICT_STATE),
                            ),
                            missing_result=FixedResult.CONFLICT_STATE,
                        ),
                    )
                    if parent_update is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                        )
                    await self._insert_attempt(
                        connection,
                        child,
                        ordinal=child_ordinal,
                        parent=request.parent_attempt_id,
                    )
                    logical_sql = (
                        "UPDATE logical_executions SET highest_attempt_ordinal=?,"
                        + (
                            "closure_operation_id=?,closure_authority_subject_ref=?,"
                            "closure_authority_user_id=?,closure_authority_revision=?,"
                            "closing_attempt_id=?,closed_at=" + self._now_sql + ","
                            if terminal
                            else ""
                        )
                        + "revision=revision+1 WHERE id=? AND campaign_id=? AND revision=? "
                        "AND closure_operation_id IS NULL RETURNING id,revision"
                    )
                    logical_params: tuple[Any, ...] = (child_ordinal,)
                    if terminal:
                        logical_params += (
                            child.operation_id,
                            child.actor_subject_ref,
                            child.actor_user_id,
                            child.snapshot.actor_authority_revision,
                            child.attempt_id,
                        )
                    logical_params += (
                        request.logical_execution_id,
                        child.campaign_id,
                        logical_revision,
                    )
                    logical_update = await self.cas_update_one(
                        connection,
                        logical_sql,
                        logical_params,
                        identity=request.logical_execution_id,
                        post_revision=logical_revision + 1,
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="logical_executions",
                            identity_column="id",
                            identity=request.logical_execution_id,
                            revision_column="revision",
                            checks=(
                                (
                                    "campaign_id",
                                    (child.campaign_id,),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                (
                                    "closure_operation_id",
                                    (None,),
                                    FixedResult.ALREADY_CLOSED,
                                ),
                                (
                                    "revision",
                                    (logical_revision,),
                                    FixedResult.CONFLICT_REVISION,
                                ),
                            ),
                            missing_result=FixedResult.RETRY_AUTHORITY_UNRESOLVED,
                        ),
                    )
                    if logical_update is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                        )
                    if terminal:
                        await self._insert_initial_terminal_outbox(connection, child)
                    else:
                        if child.approval is not None:
                            await self._insert_approval(connection, child)
                        budget_result = await self._reserve_budgets_locked(
                            connection, child.budgets
                        )
                        if budget_result.result is not FixedResult.APPLIED:
                            raise _AbortOperationError(budget_result)
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        exact_replay_code=FixedResult.REPLAYED_BOUND_CHILD,
                        result_identity=child.attempt_id,
                        result_revision=0,
                        secondary_result_identity=request.parent_attempt_id,
                        secondary_result_revision=request.expected_parent_revision + 1,
                        result_fields=(
                            ("child_attempt_id", child.attempt_id),
                            ("child_revision", 0),
                            (
                                "parent_revision",
                                request.expected_parent_revision + 1,
                            ),
                            ("logical_revision", logical_revision + 1),
                            ("child_ordinal", child_ordinal),
                        ),
                    )
                return OperationResult(FixedResult.APPLIED, 0)
        except _AbortOperationError as aborted:
            return aborted.result

    async def create_retry_attempt_v3(
        self,
        principal: TrustedPrincipal,
        intent: RetryIntentV3,
    ) -> OperationResult:
        if (
            not self._valid_trusted_principal(principal)
            or type(intent) is not RetryIntentV3
            or not valid_uuid(intent.logical_execution_id)
            or not valid_uuid(intent.parent_attempt_id)
            or not valid_uuid(intent.child_attempt_id)
            or not valid_uuid(intent.operation_id)
            or not self._valid_expected_revision(intent.expected_parent_revision)
            or (intent.outbox_id is not None and not valid_uuid(intent.outbox_id))
            or (intent.publication_key is not None and not valid_uuid(intent.publication_key))
            or (intent.outbox_id is None) != (intent.publication_key is None)
            or intent.outbox_id is not None
            or intent.publication_key is not None
            or intent.evaluation_mode not in {"preview", "live"}
            or type(intent.credential_ids) is not tuple
            or len(intent.credential_ids) > 256
            or len(set(intent.credential_ids)) != len(intent.credential_ids)
            or not all(valid_uuid(value) for value in intent.credential_ids)
            or (intent.approval_ref is not None and not valid_uuid(intent.approval_ref))
            or type(intent.noise_units) is not int
            or not 0 <= intent.noise_units <= MAX_I53
            or type(intent.exfiltration_units) is not int
            or not 0 <= intent.exfiltration_units <= MAX_I53
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, intent.operation_id)
                prior = await self._receipt_row(connection, intent.operation_id)
                if prior is not None:
                    if (
                        self._value(prior, "principal_kind", 4) != "actor"
                        or self._value(prior, "principal_subject_ref", 5) != principal.subject_ref
                        or self._value(prior, "principal_user_id", 6) != principal.user_id
                        or not bool(
                            self._value(
                                prior,
                                "principal_authority_revision_present",
                                7,
                            )
                        )
                    ):
                        return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                    receipt_spec = self._retry_v3_receipt_spec(
                        principal,
                        intent,
                        campaign_id=self._value(prior, "campaign_id", 1),
                        authority_revision=int(
                            self._value(prior, "principal_authority_revision", 8)
                        ),
                    )
                    if receipt_spec is None:
                        return OperationResult(FixedResult.INVALID_CONTRACT, None)
                    replay = await self._classify_receipt(
                        connection,
                        receipt_spec,
                        current_revision=intent.expected_parent_revision,
                    )
                    return replay or OperationResult(
                        FixedResult.CONFLICT_OPERATION,
                        intent.expected_parent_revision,
                    )
                await self._acquire_logical_attempt_transaction_keys(
                    connection,
                    intent.logical_execution_id,
                    intent.parent_attempt_id,
                )
                # Discover immutable logical identity without taking a row lock.
                # The complete authority graph is then locked in generation-11
                # order before the logical/parent rows are locked and revalidated.
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,module_id,ingress_code,immutable_work_digest,"
                    "admission_authority_contract_version,highest_attempt_ordinal,revision,"
                    "closure_operation_id,actor_subject_ref,actor_user_id,submission_id "
                    "FROM logical_executions "
                    "WHERE id=?",
                    (intent.logical_execution_id,),
                )
                if logical is None:
                    return OperationResult(FixedResult.RETRY_AUTHORITY_UNRESOLVED, None)
                if int(self._value(logical, "admission_authority_contract_version", 4)) != 3:
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                campaign_id = str(self._value(logical, "campaign_id", 0))
                module_id = str(self._value(logical, "module_id", 1))
                ingress_code = str(self._value(logical, "ingress_code", 2))
                submission_id = str(self._value(logical, "submission_id", 10))
                child_intent = AdmissionIntentV3(
                    intent.logical_execution_id,
                    submission_id,
                    intent.child_attempt_id,
                    intent.outbox_id,
                    intent.publication_key,
                    campaign_id,
                    module_id,
                    ingress_code,
                    intent.operation_id,
                    intent.evaluation_mode,
                    intent.raw_parameters,
                    intent.credential_ids,
                    intent.approval_ref,
                    intent.noise_units,
                    intent.exfiltration_units,
                )
                prepared = self._prepared_admission(child_intent)
                if prepared is None:
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                if (
                    self._value(logical, "immutable_work_digest", 3)
                    != prepared.immutable_work_digest
                ):
                    return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                resolved = await self._resolve_admission_v3(
                    connection, principal, child_intent, prepared, suffix=suffix
                )
                state = self._v3_initial_state(resolved.snapshot)
                terminal = state in {AttemptState.REJECTED, AttemptState.BLOCKED}
                outbox_id = (
                    self._derived_v3_uuid(intent.operation_id, "terminal-outbox")
                    if terminal
                    else None
                )
                publication_key = (
                    self._derived_v3_uuid(intent.operation_id, "terminal-publication")
                    if terminal
                    else None
                )
                request = AdmissionRequest(
                    intent.logical_execution_id,
                    submission_id,
                    intent.child_attempt_id,
                    outbox_id,
                    publication_key,
                    campaign_id,
                    resolved.principal.subject_ref,
                    resolved.principal.user_id,
                    module_id,
                    ingress_code,
                    state,
                    intent.operation_id,
                    resolved.snapshot,
                    resolved.approval,
                    resolved.budgets,
                )
                if not self._valid_admission(request):
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                receipt_spec = self._retry_v3_receipt_spec(
                    principal,
                    intent,
                    campaign_id=campaign_id,
                    authority_revision=resolved.principal.authority_revision,
                )
                if receipt_spec is None:
                    return OperationResult(FixedResult.INVALID_CONTRACT, None)
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,module_id,ingress_code,immutable_work_digest,"
                    "admission_authority_contract_version,highest_attempt_ordinal,revision,"
                    "closure_operation_id,actor_subject_ref,actor_user_id,submission_id "
                    "FROM logical_executions WHERE id=?" + suffix,
                    (intent.logical_execution_id,),
                )
                parent = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,ordinal,revision,state,closes_logical,retry_disposition "
                    "FROM execution_attempts WHERE logical_execution_id=? AND id=?" + suffix,
                    (intent.logical_execution_id, intent.parent_attempt_id),
                )
                if logical is None or parent is None:
                    return OperationResult(FixedResult.RETRY_AUTHORITY_UNRESOLVED, None)
                if (
                    int(self._value(logical, "admission_authority_contract_version", 4)) != 3
                    or self._value(logical, "campaign_id", 0) != campaign_id
                    or self._value(logical, "module_id", 1) != module_id
                    or self._value(logical, "ingress_code", 2) != ingress_code
                    or self._value(logical, "submission_id", 10) != submission_id
                    or self._value(logical, "immutable_work_digest", 3)
                    != prepared.immutable_work_digest
                ):
                    return OperationResult(FixedResult.CONFLICT_OPERATION, None)
                parent_revision = int(self._value(parent, "revision", 2))
                parent_ordinal = int(self._value(parent, "ordinal", 1))
                if parent_revision != intent.expected_parent_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, parent_revision)
                if (
                    self._value(parent, "campaign_id", 0) != campaign_id
                    or self._value(parent, "state", 3) not in {"failed", "timed_out"}
                    or bool(self._value(parent, "closes_logical", 4))
                    or self._value(parent, "retry_disposition", 5) != "eligible"
                    or self._value(logical, "closure_operation_id", 7) is not None
                    or self._value(logical, "actor_subject_ref", 8)
                    != resolved.principal.subject_ref
                    or self._value(logical, "actor_user_id", 9) != resolved.principal.user_id
                    or parent_ordinal != int(self._value(logical, "highest_attempt_ordinal", 5))
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                sibling = await self._fetchrow(
                    connection,
                    "SELECT id FROM execution_attempts WHERE logical_execution_id=? "
                    "AND parent_attempt_id=?",
                    (intent.logical_execution_id, intent.parent_attempt_id),
                )
                if sibling is not None:
                    return OperationResult(FixedResult.CONFLICT_OPERATION, parent_revision)
                if resolved.budgets is not None:
                    await self._acquire_transaction_key(connection, resolved.budgets.operation_id)
                logical_revision = int(self._value(logical, "revision", 6))
                child_ordinal = parent_ordinal + 1
                async with self._savepoint(connection):
                    parent_update = await self.cas_update_one(
                        connection,
                        "UPDATE execution_attempts SET retry_disposition='child_bound',"
                        "retry_child_bound_at="
                        + self._now_sql
                        + ",revision=revision+1 WHERE id=? AND logical_execution_id=? "
                        "AND revision=? AND retry_disposition='eligible' AND closes_logical="
                        + ("FALSE" if self._dialect == "postgresql" else "0")
                        + " RETURNING id,revision",
                        (
                            intent.parent_attempt_id,
                            intent.logical_execution_id,
                            parent_revision,
                        ),
                        identity=intent.parent_attempt_id,
                        post_revision=parent_revision + 1,
                        revision_column="revision",
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="execution_attempts",
                            identity_column="id",
                            identity=intent.parent_attempt_id,
                            revision_column="revision",
                            checks=(
                                ("revision", (parent_revision,), FixedResult.CONFLICT_REVISION),
                            ),
                        ),
                    )
                    if parent_update is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                        )
                    await self._insert_attempt_v3(
                        connection,
                        request,
                        resolved,
                        prepared,
                        ordinal=child_ordinal,
                        parent=intent.parent_attempt_id,
                    )
                    logical_sql = (
                        "UPDATE logical_executions SET highest_attempt_ordinal=?,"
                        + (
                            "closure_operation_id=?,closure_authority_subject_ref=?,"
                            "closure_authority_user_id=?,closure_authority_revision=?,"
                            "closing_attempt_id=?,closed_at=" + self._now_sql + ","
                            if terminal
                            else ""
                        )
                        + "revision=revision+1 WHERE id=? AND revision=? "
                        "AND closure_operation_id IS NULL RETURNING id,revision"
                    )
                    logical_params: tuple[Any, ...] = (child_ordinal,)
                    if terminal:
                        logical_params += (
                            intent.operation_id,
                            resolved.principal.subject_ref,
                            resolved.principal.user_id,
                            resolved.principal.authority_revision,
                            intent.child_attempt_id,
                        )
                    logical_params += (
                        intent.logical_execution_id,
                        logical_revision,
                    )
                    logical_update = await self.cas_update_one(
                        connection,
                        logical_sql,
                        logical_params,
                        identity=intent.logical_execution_id,
                        post_revision=logical_revision + 1,
                        revision_column="revision",
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="logical_executions",
                            identity_column="id",
                            identity=intent.logical_execution_id,
                            revision_column="revision",
                            checks=(
                                ("revision", (logical_revision,), FixedResult.CONFLICT_REVISION),
                                ("closure_operation_id", (None,), FixedResult.ALREADY_CLOSED),
                            ),
                        ),
                    )
                    if logical_update is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, parent_revision)
                        )
                    if terminal:
                        await self._insert_initial_terminal_outbox(connection, request)
                    else:
                        if resolved.approval is not None:
                            await self._consume_approval_authority_v3(connection, request, resolved)
                            await self._insert_approval(connection, request)
                        budget_result = await self._reserve_budgets_locked(
                            connection, resolved.budgets
                        )
                        if budget_result.result is not FixedResult.APPLIED:
                            raise _AbortOperationError(budget_result)
                    await self._insert_receipt(
                        connection,
                        receipt_spec,
                        result=FixedResult.APPLIED,
                        exact_replay_code=FixedResult.REPLAYED_BOUND_CHILD,
                        result_identity=intent.parent_attempt_id,
                        result_revision=parent_revision + 1,
                        secondary_result_identity=intent.child_attempt_id,
                        secondary_result_revision=0,
                        result_fields=(
                            ("logical_execution_id", intent.logical_execution_id),
                            ("child_ordinal", child_ordinal),
                            ("immutable_intent_digest", prepared.immutable_intent_digest),
                        ),
                    )
                return OperationResult(FixedResult.APPLIED, parent_revision + 1)
        except (ValueError, _AbortOperationError) as error:
            if isinstance(error, _AbortOperationError):
                return error.result
            return OperationResult(FixedResult.INVALID_CONTRACT, None)

    async def replay_retry_attempt_v2(
        self,
        principal: TrustedPrincipal,
        request: RetryRequest,
    ) -> OperationResult:
        """Replay one existing historical v2 retry receipt without live authority."""
        if (
            not self._valid_trusted_principal(principal)
            or type(request) is not RetryRequest
            or not valid_uuid(request.logical_execution_id)
            or not valid_uuid(request.parent_attempt_id)
            or not self._valid_expected_revision(request.expected_parent_revision)
            or not self._valid_admission(request.child)
            or request.child.logical_execution_id != request.logical_execution_id
            or request.child.actor_subject_ref != principal.subject_ref
            or request.child.actor_user_id != principal.user_id
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        child = request.child
        approval = child.approval
        budgets = child.budgets
        fields: tuple[tuple[str, str | int | bool | None], ...] = (
            ("logical_execution_id", request.logical_execution_id),
            ("parent_attempt_id", request.parent_attempt_id),
            ("child_attempt_id", child.attempt_id),
            ("child_submission_id", child.submission_id),
            ("child_operation_id", child.operation_id),
            ("child_outbox_id", child.outbox_id),
            ("child_publication_key", child.publication_key),
            ("child_campaign_id", child.campaign_id),
            ("actor_subject_ref", child.actor_subject_ref),
            ("actor_user_id", child.actor_user_id),
            ("module_id", child.module_id),
            ("ingress_code", child.ingress_code),
            ("initial_state", child.initial_state.value),
        ) + _snapshot_binding_values(child.snapshot)
        fields += (
            ("approval_id", None if approval is None else approval.approval_id),
            ("approval_ref", None if approval is None else approval.approval_ref),
            (
                "approval_authority_revision",
                None if approval is None else approval.authority_revision,
            ),
            (
                "approval_binding_digest",
                None if approval is None else approval.binding_digest,
            ),
            ("budget_operation_id", None if budgets is None else budgets.operation_id),
            ("noise_budget_id", None if budgets is None else budgets.noise_budget_id),
            ("noise_ledger_id", None if budgets is None else budgets.noise_ledger_id),
            ("noise_units", None if budgets is None else budgets.noise_units),
            (
                "noise_expected_revision",
                None if budgets is None else budgets.noise_expected_revision,
            ),
            (
                "exfiltration_budget_id",
                None if budgets is None else budgets.exfiltration_budget_id,
            ),
            (
                "exfiltration_ledger_id",
                None if budgets is None else budgets.exfiltration_ledger_id,
            ),
            (
                "exfiltration_units",
                None if budgets is None else budgets.exfiltration_units,
            ),
            (
                "exfiltration_expected_revision",
                None if budgets is None else budgets.exfiltration_expected_revision,
            ),
            (
                "concurrency_budget_id",
                None if budgets is None else budgets.concurrency_budget_id,
            ),
            (
                "concurrency_ledger_id",
                None if budgets is None else budgets.concurrency_ledger_id,
            ),
            (
                "concurrency_expected_revision",
                None if budgets is None else budgets.concurrency_expected_revision,
            ),
        )
        spec = self._receipt_spec(
            operation_id=child.operation_id,
            operation_code="retry",
            campaign_id=child.campaign_id,
            primary_target_id=request.parent_attempt_id,
            secondary_target_id=child.attempt_id,
            principal_kind="actor",
            principal_subject_ref=principal.subject_ref,
            principal_user_id=principal.user_id,
            principal_authority_revision=child.snapshot.actor_authority_revision,
            expected_revision=request.expected_parent_revision,
            fields=fields,
        )
        async with self._transaction() as connection:
            await self._acquire_transaction_key(connection, child.operation_id)
            replay = await self._classify_receipt(
                connection,
                spec,
                current_revision=request.expected_parent_revision,
            )
            if replay is not None:
                return replay
            logical = await self._fetchrow(
                connection,
                "SELECT admission_authority_contract_version FROM logical_executions WHERE id=?",
                (request.logical_execution_id,),
            )
            if logical is None:
                return OperationResult(FixedResult.INVALID_CONTRACT, None)
            if int(self._value(logical, "admission_authority_contract_version", 0)) != 2:
                return OperationResult(FixedResult.CONFLICT_OPERATION, None)
            return OperationResult(FixedResult.INVALID_CONTRACT, None)

    async def _insert_initial_terminal_outbox(
        self, connection: Any, request: AdmissionRequest
    ) -> None:
        event = (
            "execution_rejected"
            if request.initial_state is AttemptState.REJECTED
            else "execution_blocked"
        )
        now = self._now_sql
        inserted = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_publication_outbox("
            "id,publication_key,attempt_id,campaign_id,event_code,"
            "is_attempt_terminal,available_at,latest_operation_id,"
            "latest_operation_code,latest_operation_base_revision,created_at) "
            "SELECT ?,?,?,?,?,"
            + ("TRUE" if self._dialect == "postgresql" else "1")
            + ",db_now,?,'insert',0,db_now FROM (SELECT "
            + now
            + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING RETURNING id,claim_revision",
            (
                request.outbox_id,
                request.publication_key,
                request.attempt_id,
                request.campaign_id,
                event,
                request.publication_key,
            ),
            identity=request.outbox_id,
            revision=0,
            revision_column="claim_revision",
        )
        if inserted is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
        spec = self._receipt_spec(
            operation_id=request.outbox_id,
            operation_code="outbox_insert",
            campaign_id=request.campaign_id,
            primary_target_id=request.outbox_id,
            secondary_target_id=request.attempt_id,
            fields=(
                ("publication_key", request.publication_key),
                ("event_code", event),
                ("terminal", True),
                ("finding_count", 0),
                ("credential_count", 0),
                ("host_count", 0),
                ("artifact_count", 0),
            ),
        )
        await self._insert_receipt(
            connection,
            spec,
            result=FixedResult.APPLIED,
            result_identity=request.outbox_id,
            result_revision=0,
            result_fields=(("publication_state", "pending"), ("claim_revision", 0)),
        )

    async def _insert_approval(self, connection: Any, request: AdmissionRequest) -> None:
        approval = request.approval
        if approval is None or not (
            type(approval) is ApprovalBinding
            and all(
                valid_uuid(value)
                for value in (
                    approval.approval_id,
                    approval.approval_ref,
                    approval.approver_subject_ref,
                )
            )
            and (approval.approver_user_id is None or valid_uuid(approval.approver_user_id))
            and type(approval.authority_revision) is int
            and 0 <= approval.authority_revision <= MAX_I53
            and type(approval.binding_digest) is str
            and re.fullmatch(r"[0-9a-f]{64}", approval.binding_digest)
        ):
            raise _AbortOperationError(OperationResult(FixedResult.INVALID_CONTRACT, None))
        inserted = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_attempt_approvals("
            "id,attempt_id,campaign_id,approval_ref,approver_subject_ref,"
            "approver_user_id,authority_revision,binding_digest) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING RETURNING id,authority_revision",
            (
                approval.approval_id,
                request.attempt_id,
                request.campaign_id,
                approval.approval_ref,
                approval.approver_subject_ref,
                approval.approver_user_id,
                approval.authority_revision,
                approval.binding_digest,
            ),
            identity=approval.approval_id,
            revision=approval.authority_revision,
            revision_column="authority_revision",
        )
        if inserted is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))

    async def _reserve_budgets_locked(
        self, connection: Any, request: BudgetReservation | None
    ) -> OperationResult:
        if request is None or not self._valid_budget_reservation(request):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        entries = (
            (
                "noise",
                request.noise_budget_id,
                request.noise_ledger_id,
                request.noise_units,
                request.noise_expected_revision,
            ),
            (
                "exfiltration",
                request.exfiltration_budget_id,
                request.exfiltration_ledger_id,
                request.exfiltration_units,
                request.exfiltration_expected_revision,
            ),
            (
                "concurrency",
                request.concurrency_budget_id,
                request.concurrency_ledger_id,
                1,
                request.concurrency_expected_revision,
            ),
        )
        if request.attempt_id is None:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._budget_reservation_receipt_spec(request)
        await self._acquire_transaction_key(connection, request.operation_id)
        replay = await self._classify_receipt(
            connection,
            spec,
            current_revision=max(
                request.noise_expected_revision,
                request.exfiltration_expected_revision,
                request.concurrency_expected_revision,
            ),
        )
        if replay is not None:
            return replay
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        validated: list[tuple[str, str, str, int, int]] = []
        for kind, budget_id, ledger_id, units, expected_revision in entries:
            row = await self._fetchrow(
                connection,
                "SELECT campaign_id,budget_kind,capacity_units,reserved_units,"
                "consumed_units,revision FROM campaign_execution_budgets "
                "WHERE id=?" + suffix,
                (budget_id,),
            )
            if row is None or (
                self._value(row, "campaign_id", 0) != request.campaign_id
                or self._value(row, "budget_kind", 1) != kind
            ):
                return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
            revision = int(self._value(row, "revision", 5))
            if revision != expected_revision:
                return OperationResult(FixedResult.CONFLICT_REVISION, revision)
            capacity = int(self._value(row, "capacity_units", 2))
            reserved = int(self._value(row, "reserved_units", 3))
            consumed = int(self._value(row, "consumed_units", 4))
            if reserved + consumed + units > capacity:
                return OperationResult(FixedResult.CAPACITY_UNAVAILABLE, revision)
            validated.append((kind, budget_id, ledger_id, units, expected_revision))
        for kind, budget_id, ledger_id, units, expected_revision in validated:
            updated = await self.cas_update_one(
                connection,
                "UPDATE campaign_execution_budgets SET reserved_units=reserved_units+?,"
                "revision=revision+1,latest_operation_id=?,"
                "latest_operation_base_revision=?,latest_operation_code='reserve',"
                "updated_at=" + self._now_sql + " WHERE id=? AND revision=? "
                "AND reserved_units+consumed_units+?<=capacity_units RETURNING id,revision",
                (
                    units,
                    request.operation_id,
                    expected_revision,
                    budget_id,
                    expected_revision,
                    units,
                ),
                identity=budget_id,
                post_revision=expected_revision + 1,
                zero_classifier=lambda budget_id=budget_id, kind=kind, expected_revision=expected_revision, units=units: (
                    self._classify_zero_budget(
                        connection,
                        budget_id=budget_id,
                        campaign_id=request.campaign_id,
                        budget_kind=kind,
                        expected_revision=expected_revision,
                        required_units=units,
                        operation="reserve",
                    )
                ),
            )
            if updated is None:
                return OperationResult(FixedResult.CONFLICT_REVISION, expected_revision)
            inserted = await self.insert_or_validate_binding(
                connection,
                "INSERT INTO campaign_execution_budget_ledger("
                "id,attempt_id,campaign_id,budget_id,budget_kind,"
                "reservation_units,consumed_units,disposition,"
                "budget_revision_reserved) VALUES(?,?,?,?,?,?,0,'held',?) "
                "ON CONFLICT(id) DO NOTHING RETURNING id,budget_revision_reserved",
                (
                    ledger_id,
                    request.attempt_id,
                    request.campaign_id,
                    budget_id,
                    kind,
                    units,
                    expected_revision + 1,
                ),
                identity=ledger_id,
                revision=expected_revision + 1,
                revision_column="budget_revision_reserved",
            )
            if inserted is None:
                return OperationResult(FixedResult.CONFLICT_OPERATION, None)
        await self._insert_receipt(
            connection,
            spec,
            result=FixedResult.APPLIED,
            result_identity=request.attempt_id,
            result_revision=max(
                request.noise_expected_revision,
                request.exfiltration_expected_revision,
                request.concurrency_expected_revision,
            )
            + 1,
            secondary_result_identity=request.noise_budget_id,
            secondary_result_revision=request.noise_expected_revision + 1,
            result_fields=(
                ("noise_ledger_id", request.noise_ledger_id),
                ("noise_post_revision", request.noise_expected_revision + 1),
                ("exfiltration_ledger_id", request.exfiltration_ledger_id),
                ("exfiltration_post_revision", request.exfiltration_expected_revision + 1),
                ("concurrency_ledger_id", request.concurrency_ledger_id),
                ("concurrency_post_revision", request.concurrency_expected_revision + 1),
            ),
        )
        return OperationResult(FixedResult.APPLIED, None)

    def _budget_settlement_receipt_spec(self, request: BudgetSettlement) -> _ReceiptSpec:
        return self._receipt_spec(
            operation_id=request.operation_id,
            operation_code="budget_settle",
            campaign_id=request.campaign_id,
            primary_target_id=request.attempt_id,
            secondary_target_id=request.noise_budget_id,
            principal_kind=str(request.principal_kind),
            principal_subject_ref=str(request.principal_subject_ref),
            principal_user_id=request.principal_user_id,
            principal_authority_revision=request.principal_authority_revision,
            expected_revision=request.noise_expected_revision,
            secondary_expected_revision=request.exfiltration_expected_revision,
            fields=(
                ("noise_budget_id", request.noise_budget_id),
                ("noise_units", request.noise_units),
                ("noise_actual", request.noise_actual),
                ("exfiltration_budget_id", request.exfiltration_budget_id),
                ("exfiltration_units", request.exfiltration_units),
                ("exfiltration_actual", request.exfiltration_actual),
                ("concurrency_budget_id", request.concurrency_budget_id),
                ("concurrency_expected_revision", request.concurrency_expected_revision),
            ),
        )

    @staticmethod
    def _budget_settlement_result_fields(
        request: BudgetSettlement,
    ) -> tuple[tuple[str, str | int | bool | None], ...]:
        return (
            ("noise_post_revision", request.noise_expected_revision + 1),
            ("noise_disposition", "released" if request.noise_actual == 0 else "consumed"),
            ("noise_consumed", request.noise_actual),
            ("exfiltration_post_revision", request.exfiltration_expected_revision + 1),
            (
                "exfiltration_disposition",
                "released" if request.exfiltration_actual == 0 else "consumed",
            ),
            ("exfiltration_consumed", request.exfiltration_actual),
            ("concurrency_post_revision", request.concurrency_expected_revision + 1),
            ("concurrency_disposition", "released"),
            ("concurrency_consumed", 0),
        )

    async def _insert_budget_settlement_receipt(
        self, connection: Any, request: BudgetSettlement
    ) -> None:
        await self._insert_receipt(
            connection,
            self._budget_settlement_receipt_spec(request),
            result=FixedResult.APPLIED,
            result_identity=request.attempt_id,
            result_revision=max(
                request.noise_expected_revision,
                request.exfiltration_expected_revision,
                request.concurrency_expected_revision,
            )
            + 1,
            secondary_result_identity=request.noise_budget_id,
            secondary_result_revision=request.noise_expected_revision + 1,
            result_fields=self._budget_settlement_result_fields(request),
        )

    async def _settle_budgets_locked(
        self,
        connection: Any,
        request: BudgetSettlement,
        *,
        write_receipt: bool = True,
        prepared_terminal_v3: _PreparedTerminalV3BudgetSettlement | None = None,
    ) -> OperationResult:
        if not self._valid_budget_settlement(request):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        entries = (
            (
                "noise",
                request.noise_budget_id,
                request.noise_units,
                request.noise_actual,
                request.noise_expected_revision,
            ),
            (
                "exfiltration",
                request.exfiltration_budget_id,
                request.exfiltration_units,
                request.exfiltration_actual,
                request.exfiltration_expected_revision,
            ),
            (
                "concurrency",
                request.concurrency_budget_id,
                1,
                0,
                request.concurrency_expected_revision,
            ),
        )
        validated: list[tuple[str, str, str, int, int, int, str]] = []
        if prepared_terminal_v3 is not None:
            if type(prepared_terminal_v3) is not _PreparedTerminalV3BudgetSettlement:
                return OperationResult(FixedResult.INVARIANT_FAILURE, None)
            prepared_entries = prepared_terminal_v3.entries
            if (
                prepared_terminal_v3.request is not request
                or type(prepared_entries) is not tuple
                or len(prepared_entries) != len(entries)
                or any(type(item) is not tuple or len(item) != 7 for item in prepared_entries)
            ):
                return OperationResult(FixedResult.INVARIANT_FAILURE, None)
            for expected, prepared in zip(entries, prepared_entries, strict=True):
                kind, budget_id, reservation, actual, expected_revision = expected
                (
                    prepared_kind,
                    prepared_budget_id,
                    ledger_id,
                    prepared_reservation,
                    prepared_actual,
                    prepared_revision,
                    prepared_disposition,
                ) = prepared
                if (
                    prepared_kind != kind
                    or prepared_budget_id != budget_id
                    or not valid_uuid(ledger_id)
                    or prepared_reservation != reservation
                    or prepared_actual != actual
                    or prepared_revision != expected_revision
                    or prepared_disposition != ("released" if actual == 0 else "consumed")
                ):
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                validated.append(prepared)
        else:
            suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
            budgets: list[Any] = []
            for kind, budget_id, _reservation, _actual, _expected_revision in entries:
                budget = await self._fetchrow(
                    connection,
                    "SELECT id,campaign_id,budget_kind,reserved_units,revision "
                    "FROM campaign_execution_budgets WHERE id=?" + suffix,
                    (budget_id,),
                )
                if budget is None or (
                    self._value(budget, "campaign_id", 1) != request.campaign_id
                    or self._value(budget, "budget_kind", 2) != kind
                ):
                    return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
                budgets.append(budget)
            ledgers: list[Any] = []
            for kind, _budget_id, _reservation, _actual, _expected_revision in entries:
                ledger = await self._fetchrow(
                    connection,
                    "SELECT id,disposition,reservation_units,consumed_units,"
                    "budget_revision_settled FROM campaign_execution_budget_ledger "
                    "WHERE attempt_id=? AND budget_kind=?" + suffix,
                    (request.attempt_id, kind),
                )
                if ledger is None:
                    return OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, None)
                ledgers.append(ledger)
            for index, (kind, budget_id, reservation, actual, expected_revision) in enumerate(
                entries
            ):
                budget = budgets[index]
                ledger = ledgers[index]
                disposition = str(self._value(ledger, "disposition", 1))
                reserved_units = int(self._value(ledger, "reservation_units", 2))
                expected_disposition = "released" if actual == 0 else "consumed"
                revision = int(self._value(budget, "revision", 4))
                if disposition != "held":
                    return OperationResult(FixedResult.CONFLICT_OPERATION, revision)
                if (
                    reserved_units != reservation
                    or revision != expected_revision
                    or int(self._value(budget, "reserved_units", 3)) < reservation
                ):
                    return OperationResult(
                        FixedResult.CONFLICT_REVISION
                        if revision != expected_revision
                        else FixedResult.INCONSISTENT_BUDGET_SET,
                        revision,
                    )
                validated.append(
                    (
                        kind,
                        budget_id,
                        str(self._value(ledger, "id", 0)),
                        reservation,
                        actual,
                        expected_revision,
                        expected_disposition,
                    )
                )
        for (
            kind,
            budget_id,
            ledger_id,
            reservation,
            actual,
            expected_revision,
            disposition,
        ) in validated:
            updated = await self.cas_update_one(
                connection,
                "UPDATE campaign_execution_budgets SET reserved_units=reserved_units-?,"
                "consumed_units=consumed_units+?,revision=revision+1,"
                "latest_operation_id=?,latest_operation_base_revision=?,"
                "latest_operation_code='settle',updated_at="
                + self._now_sql
                + " WHERE id=? AND revision=? AND reserved_units>=? RETURNING id,revision",
                (
                    reservation,
                    actual,
                    request.operation_id,
                    expected_revision,
                    budget_id,
                    expected_revision,
                    reservation,
                ),
                identity=budget_id,
                post_revision=expected_revision + 1,
                zero_classifier=lambda budget_id=budget_id, kind=kind, expected_revision=expected_revision, reservation=reservation: (
                    self._classify_zero_budget(
                        connection,
                        budget_id=budget_id,
                        campaign_id=request.campaign_id,
                        budget_kind=kind,
                        expected_revision=expected_revision,
                        required_units=reservation,
                        operation="settle",
                    )
                ),
            )
            if updated is None:
                return OperationResult(FixedResult.CONFLICT_REVISION, expected_revision)
            updated_ledger = await self.update_exact_set(
                connection,
                "UPDATE campaign_execution_budget_ledger SET consumed_units=?,"
                "disposition=?,budget_revision_settled=?,settled_at="
                + self._now_sql
                + " WHERE id=? AND attempt_id=? AND budget_kind=? AND disposition='held' "
                "RETURNING id,budget_revision_settled,disposition,consumed_units",
                (
                    actual,
                    disposition,
                    expected_revision + 1,
                    ledger_id,
                    request.attempt_id,
                    kind,
                ),
                expected=(
                    ("id", ledger_id),
                    ("budget_revision_settled", expected_revision + 1),
                    ("disposition", disposition),
                    ("consumed_units", actual),
                ),
                zero_classifier=lambda ledger_id=ledger_id, kind=kind: self._classify_zero_ledger(
                    connection,
                    ledger_id=ledger_id,
                    attempt_id=request.attempt_id,
                    budget_kind=kind,
                ),
            )
            if updated_ledger is None:
                return OperationResult(FixedResult.CONFLICT_STATE, None)
        if write_receipt:
            await self._insert_budget_settlement_receipt(connection, request)
        return OperationResult(FixedResult.APPLIED, None)

    @staticmethod
    def _valid_output_observations(outputs: object) -> bool:
        if type(outputs) is not tuple:
            return False
        identities: set[str] = set()
        targets: set[tuple[OutputKind, str]] = set()
        for output in outputs:
            if (
                type(output) is not OutputObservation
                or not valid_uuid(output.link_id)
                or type(output.kind) is not OutputKind
                or not valid_uuid(output.target_id)
                or output.link_id in identities
                or (output.kind, output.target_id) in targets
            ):
                return False
            identities.add(output.link_id)
            targets.add((output.kind, output.target_id))
        return True

    async def _commit_terminal_attempt_same_transaction(
        self,
        connection: Any,
        request: TerminalCommitRequest,
        *,
        receipt_spec: _ReceiptSpec,
        logical: Any,
        attempt: Any,
        current: AttemptState,
        retry_eligible: bool,
        result_binding_domain: str | None = None,
        additional_result_fields: tuple[tuple[str, str | int | bool | None], ...] = (),
        prepared_budget_settlement: _PreparedTerminalV3BudgetSettlement | None = None,
    ) -> OperationResult:
        """Apply a prepared terminal commit without opening a transaction or connection."""
        target = request.transition.target_state
        revision = int(self._value(attempt, "revision", 1))
        async with self._savepoint(connection):
            budget_result = await self._settle_budgets_locked(
                connection,
                request.budgets,
                write_receipt=False,
                prepared_terminal_v3=prepared_budget_settlement,
            )
            if budget_result.result is not FixedResult.APPLIED:
                raise _AbortOperationError(budget_result)
            counts = await self._insert_output_links(
                connection,
                request.campaign_id,
                request.transition.attempt_id,
                request.outputs,
            )
            result = await self._apply_transition(
                connection,
                attempt,
                current,
                request.transition,
                zero_receipt_spec=receipt_spec,
                retry_eligible=retry_eligible,
            )
            if result.result is not FixedResult.APPLIED:
                raise _AbortOperationError(result)
            closes = not retry_eligible
            if closes:
                closed_attempt = await self.cas_update_one(
                    connection,
                    "UPDATE execution_attempts SET closes_logical="
                    + ("TRUE" if self._dialect == "postgresql" else "1")
                    + " WHERE id=? AND revision=? AND closes_logical="
                    + ("FALSE" if self._dialect == "postgresql" else "0")
                    + " RETURNING id,revision",
                    (
                        request.transition.attempt_id,
                        request.transition.expected_revision + 1,
                    ),
                    identity=request.transition.attempt_id,
                    post_revision=request.transition.expected_revision + 1,
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="execution_attempts",
                        identity_column="id",
                        identity=request.transition.attempt_id,
                        revision_column="revision",
                        checks=(
                            (
                                "revision",
                                (request.transition.expected_revision + 1,),
                                FixedResult.CONFLICT_REVISION,
                            ),
                            ("closes_logical", (False,), FixedResult.CONFLICT_STATE),
                        ),
                        receipt_spec=receipt_spec,
                        authority_columns=(
                            "actor_user_id",
                            "actor_authority_revision",
                            "actor_role",
                        ),
                        expected_authority_user_id=self._value(attempt, "actor_user_id", 20),
                    ),
                )
                if closed_attempt is None:
                    raise _AbortOperationError(
                        OperationResult(FixedResult.CONFLICT_STATE, revision)
                    )
                logical_revision = int(self._value(logical, "revision", 2))
                closed_logical = await self.cas_update_one(
                    connection,
                    "UPDATE logical_executions SET closure_operation_id=?,"
                    "closure_authority_subject_ref=?,closure_authority_user_id=?,"
                    "closure_authority_revision=?,closing_attempt_id=?,closed_at="
                    + self._now_sql
                    + ",revision=revision+1 WHERE id=? AND revision=? "
                    "AND closure_operation_id IS NULL RETURNING id,revision",
                    (
                        request.transition.operation_id,
                        self._value(attempt, "actor_subject_ref", 19),
                        self._value(attempt, "actor_user_id", 20),
                        self._value(attempt, "actor_authority_revision", 21),
                        request.transition.attempt_id,
                        request.logical_execution_id,
                        logical_revision,
                    ),
                    identity=request.logical_execution_id,
                    post_revision=logical_revision + 1,
                    zero_classifier=lambda: self._classify_zero_row(
                        connection,
                        table="logical_executions",
                        identity_column="id",
                        identity=request.logical_execution_id,
                        revision_column="revision",
                        checks=(
                            (
                                "campaign_id",
                                (request.campaign_id,),
                                FixedResult.CONFLICT_STATE,
                            ),
                            (
                                "closure_operation_id",
                                (None,),
                                FixedResult.ALREADY_CLOSED,
                            ),
                            (
                                "revision",
                                (logical_revision,),
                                FixedResult.CONFLICT_REVISION,
                            ),
                        ),
                        missing_result=FixedResult.CONFLICT_STATE,
                    ),
                )
                if closed_logical is None:
                    raise _AbortOperationError(
                        OperationResult(FixedResult.ALREADY_CLOSED, revision)
                    )
            await self._insert_terminal_outbox(connection, request, counts)
            await self._insert_budget_settlement_receipt(connection, request.budgets)
            secondary_result_revision = int(self._value(logical, "revision", 2)) + int(closes)
            result_fields = (
                ("state", target.value),
                ("revision", request.transition.expected_revision + 1),
                ("closes_logical", closes),
                ("finding_count", counts[0]),
                ("credential_count", counts[1]),
                ("host_count", counts[2]),
                ("artifact_count", counts[3]),
                ("outbox_id", request.outbox_id),
            ) + additional_result_fields
            if result_binding_domain is None:
                await self._insert_receipt(
                    connection,
                    receipt_spec,
                    result=FixedResult.APPLIED,
                    result_identity=request.transition.attempt_id,
                    result_revision=request.transition.expected_revision + 1,
                    secondary_result_identity=request.logical_execution_id,
                    secondary_result_revision=secondary_result_revision,
                    result_fields=result_fields,
                )
            elif result_binding_domain == _TERMINAL_COMMIT_RESULT_DOMAIN_V3:
                await self._insert_terminal_v3_receipt(
                    connection,
                    receipt_spec,
                    result_identity=request.transition.attempt_id,
                    result_revision=request.transition.expected_revision + 1,
                    secondary_result_identity=request.logical_execution_id,
                    secondary_result_revision=secondary_result_revision,
                    result_fields=result_fields,
                )
            else:
                raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
            return result

    async def _derive_terminal_v3_budget_settlement(
        self,
        connection: Any,
        intent: TerminalCommitIntentV3,
        operation_id: str,
        *,
        attempt_revision: int,
    ) -> _PreparedTerminalV3BudgetSettlement:
        """Lock and derive the exact three-HELD-ledger settlement authority."""
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        ledgers = tuple(
            await self._fetchall(
                connection,
                "SELECT id,attempt_id,campaign_id,budget_id,budget_kind,"
                "reservation_units,consumed_units,disposition,"
                "budget_revision_reserved,budget_revision_settled "
                "FROM campaign_execution_budget_ledger WHERE attempt_id=? "
                "ORDER BY CASE budget_kind WHEN 'noise' THEN 0 "
                "WHEN 'exfiltration' THEN 1 WHEN 'concurrency' THEN 2 ELSE 3 END,id" + suffix,
                (intent.attempt_id,),
            )
        )
        expected_kinds = ("noise", "exfiltration", "concurrency")
        if len(ledgers) != len(expected_kinds):
            raise _AbortOperationError(
                OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, attempt_revision)
            )
        ledger_facts: dict[str, tuple[str, str, int]] = {}
        for expected_kind, ledger in zip(expected_kinds, ledgers, strict=True):
            ledger_id = self._value(ledger, "id", 0)
            ledger_attempt = self._value(ledger, "attempt_id", 1)
            ledger_campaign = self._value(ledger, "campaign_id", 2)
            budget_id = self._value(ledger, "budget_id", 3)
            kind = self._value(ledger, "budget_kind", 4)
            if (
                kind != expected_kind
                or kind in ledger_facts
                or not valid_uuid(ledger_id)
                or not valid_uuid(budget_id)
                or ledger_attempt != intent.attempt_id
                or ledger_campaign != intent.campaign_id
            ):
                raise _AbortOperationError(
                    OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, attempt_revision)
                )
            if self._value(ledger, "disposition", 7) != "held":
                raise _AbortOperationError(
                    OperationResult(FixedResult.CONFLICT_OPERATION, attempt_revision)
                )
            reservation = self._value(ledger, "reservation_units", 5)
            consumed = self._value(ledger, "consumed_units", 6)
            reserved_revision = self._value(ledger, "budget_revision_reserved", 8)
            settled_revision = self._value(ledger, "budget_revision_settled", 9)
            if (
                type(reservation) is not int
                or not 0 <= reservation <= MAX_I53
                or type(consumed) is not int
                or consumed != 0
                or type(reserved_revision) is not int
                or not 0 <= reserved_revision <= MAX_I53
                or settled_revision is not None
                or (kind == "concurrency" and reservation != 1)
            ):
                raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
            ledger_facts[kind] = (str(ledger_id), str(budget_id), reservation)

        actual_by_kind = {
            "noise": intent.noise_actual,
            "exfiltration": intent.exfiltration_actual,
            "concurrency": intent.concurrency_actual,
        }
        for kind in expected_kinds:
            if actual_by_kind[kind] > ledger_facts[kind][2]:
                raise _AbortOperationError(
                    OperationResult(FixedResult.INVALID_CONTRACT, attempt_revision)
                )

        budget_revisions: dict[str, int] = {}
        for kind in expected_kinds:
            _ledger_id, budget_id, reservation = ledger_facts[kind]
            budget = await self._fetchrow(
                connection,
                "SELECT id,campaign_id,budget_kind,capacity_units,reserved_units,"
                "consumed_units,revision FROM campaign_execution_budgets WHERE id=?" + suffix,
                (budget_id,),
            )
            if budget is None or (
                self._value(budget, "id", 0) != budget_id
                or self._value(budget, "campaign_id", 1) != intent.campaign_id
                or self._value(budget, "budget_kind", 2) != kind
            ):
                raise _AbortOperationError(
                    OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, attempt_revision)
                )
            capacity = self._value(budget, "capacity_units", 3)
            reserved = self._value(budget, "reserved_units", 4)
            consumed = self._value(budget, "consumed_units", 5)
            revision = self._value(budget, "revision", 6)
            if (
                any(
                    type(value) is not int or not 0 <= value <= MAX_I53
                    for value in (capacity, reserved, consumed, revision)
                )
                or reserved + consumed > capacity
            ):
                raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
            if reserved < reservation:
                raise _AbortOperationError(
                    OperationResult(FixedResult.INCONSISTENT_BUDGET_SET, attempt_revision)
                )
            if revision == MAX_I53 or consumed > MAX_I53 - actual_by_kind[kind]:
                raise _AbortOperationError(OperationResult(FixedResult.INVARIANT_FAILURE, None))
            budget_revisions[kind] = revision

        request = BudgetSettlement(
            campaign_id=intent.campaign_id,
            attempt_id=intent.attempt_id,
            noise_budget_id=ledger_facts["noise"][1],
            noise_units=ledger_facts["noise"][2],
            noise_actual=intent.noise_actual,
            noise_expected_revision=budget_revisions["noise"],
            exfiltration_budget_id=ledger_facts["exfiltration"][1],
            exfiltration_units=ledger_facts["exfiltration"][2],
            exfiltration_actual=intent.exfiltration_actual,
            exfiltration_expected_revision=budget_revisions["exfiltration"],
            concurrency_budget_id=ledger_facts["concurrency"][1],
            concurrency_expected_revision=budget_revisions["concurrency"],
            operation_id=self._derived_v3_uuid(
                operation_id,
                "terminal-budget-settlement",
            ),
            principal_kind="system",
            principal_subject_ref=SYSTEM_PRINCIPAL_SUBJECT_REF,
            principal_user_id=None,
            principal_authority_revision=None,
        )
        entries = tuple(
            (
                kind,
                ledger_facts[kind][1],
                ledger_facts[kind][0],
                ledger_facts[kind][2],
                actual_by_kind[kind],
                budget_revisions[kind],
                "released" if actual_by_kind[kind] == 0 else "consumed",
            )
            for kind in expected_kinds
        )
        return _PreparedTerminalV3BudgetSettlement(request, entries)

    async def commit_terminal_attempt_v3(
        self,
        intent: TerminalCommitIntentV3,
    ) -> OperationResult:
        """Commit one coordinator-confirmed, quiescent module outcome at most once."""
        outputs = self._canonical_terminal_v3_outputs(intent)
        if outputs is None:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        contract = self._terminal_v3_outcome_contract(intent.outcome_code)
        if contract is None:  # Kept explicit so no future enum value widens this seam.
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        predecessor, target, operation_code, authoritative_proof = contract
        operation_id = self._terminal_v3_operation_id(intent.attempt_id)
        spec = self._terminal_v3_receipt_spec(
            intent,
            operation_id,
            operation_code,
            outputs,
        )
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, operation_id)
                replay = await self._classify_receipt(
                    connection,
                    spec,
                    current_revision=None,
                )
                if replay is not None:
                    return replay
                await self._acquire_logical_attempt_transaction_keys(
                    connection,
                    intent.logical_execution_id,
                    intent.attempt_id,
                )
                attempt = await self._fetchrow(
                    connection,
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "start_operation_id,dispatch_operation_id,"
                    "cancellation_request_revision,recovery_deadline_at,timeout_limit_ms,"
                    "lease_expires_at,queue_operation_id,cancellation_request_operation_id,"
                    "cancellation_ack_operation_id,timeout_operation_id,"
                    "settlement_pending_operation_id,terminal_operation_id,"
                    "logical_execution_id,campaign_id,retry_disposition,"
                    "actor_subject_ref,actor_user_id,actor_authority_revision,closes_logical,"
                    "external_effect_class,idempotency_class,retry_policy "
                    "FROM execution_attempts WHERE id=?" + suffix,
                    (intent.attempt_id,),
                )
                if attempt is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                revision_value = self._value(attempt, "revision", 1)
                if type(revision_value) is not int or not 0 <= revision_value <= MAX_I53:
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                revision = revision_value
                if (
                    self._value(attempt, "logical_execution_id", 16) != intent.logical_execution_id
                    or self._value(attempt, "campaign_id", 17) != intent.campaign_id
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                try:
                    current = AttemptState(str(self._value(attempt, "state", 0)))
                except ValueError:
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                if current is not predecessor:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if revision != intent.expected_attempt_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                started = self._value(attempt, "start_operation_id", 4) is not None
                dispatched = self._value(attempt, "dispatch_operation_id", 5) is not None
                if predecessor is AttemptState.RUNNING and (not started or not dispatched):
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                owner_ref = self._value(attempt, "dispatch_owner_ref", 2)
                lease_generation = self._value(attempt, "lease_generation", 3)
                if dispatched:
                    if (
                        not valid_uuid(owner_ref)
                        or type(lease_generation) is not int
                        or not 1 <= lease_generation <= MAX_I53
                    ):
                        return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                elif owner_ref is not None or lease_generation != 0:
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                cancellation_revision = None
                if current is AttemptState.CANCELLING:
                    cancellation_revision = self._value(
                        attempt,
                        "cancellation_request_revision",
                        6,
                    )
                    if (
                        type(cancellation_revision) is not int
                        or not 1 <= cancellation_revision <= MAX_I53
                    ):
                        return OperationResult(FixedResult.INVARIANT_FAILURE, None)

                prepared_budget_settlement = await self._derive_terminal_v3_budget_settlement(
                    connection,
                    intent,
                    operation_id,
                    attempt_revision=revision,
                )
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,closure_operation_id,revision FROM logical_executions "
                    "WHERE id=?" + suffix,
                    (intent.logical_execution_id,),
                )
                if logical is None or self._value(logical, "campaign_id", 0) != intent.campaign_id:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if self._value(logical, "closure_operation_id", 1) is not None:
                    return OperationResult(FixedResult.ALREADY_CLOSED, revision)
                logical_revision_value = self._value(logical, "revision", 2)
                if (
                    type(logical_revision_value) is not int
                    or not 0 <= logical_revision_value <= MAX_I53
                ):
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                retry_eligible = bool(
                    target in {AttemptState.FAILED, AttemptState.TIMED_OUT}
                    and self._value(attempt, "external_effect_class", 23) == "read_only"
                    and self._value(attempt, "idempotency_class", 24) == "proven_idempotent"
                    and self._value(attempt, "retry_policy", 25) == "after_revalidation"
                )
                if not retry_eligible and logical_revision_value == MAX_I53:
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)
                actor_subject_ref = self._value(attempt, "actor_subject_ref", 19)
                actor_user_id = self._value(attempt, "actor_user_id", 20)
                actor_authority_revision = self._value(
                    attempt,
                    "actor_authority_revision",
                    21,
                )
                if (
                    not valid_uuid(actor_subject_ref)
                    or not valid_uuid(actor_user_id)
                    or type(actor_authority_revision) is not int
                    or not 0 <= actor_authority_revision <= MAX_I53
                ):
                    return OperationResult(FixedResult.INVARIANT_FAILURE, None)

                outbox_id = self._derived_v3_uuid(operation_id, "terminal-outbox")
                publication_key = self._derived_v3_uuid(
                    operation_id,
                    "terminal-publication",
                )
                transition = TransitionRequest(
                    attempt_id=intent.attempt_id,
                    expected_revision=intent.expected_attempt_revision,
                    target_state=target,
                    operation_id=operation_id,
                    owner_ref=str(owner_ref) if dispatched else None,
                    lease_generation=int(lease_generation) if dispatched else None,
                    cancellation_request_revision=cancellation_revision,
                    outcome_code=intent.outcome_code,
                    authoritative_proof=authoritative_proof,
                    campaign_id=intent.campaign_id,
                )
                request = TerminalCommitRequest(
                    logical_execution_id=intent.logical_execution_id,
                    campaign_id=intent.campaign_id,
                    outbox_id=outbox_id,
                    publication_key=publication_key,
                    transition=transition,
                    budgets=prepared_budget_settlement.request,
                    outputs=outputs,
                )
                return await self._commit_terminal_attempt_same_transaction(
                    connection,
                    request,
                    receipt_spec=spec,
                    logical=logical,
                    attempt=attempt,
                    current=current,
                    retry_eligible=retry_eligible,
                    result_binding_domain=_TERMINAL_COMMIT_RESULT_DOMAIN_V3,
                    prepared_budget_settlement=prepared_budget_settlement,
                    additional_result_fields=(
                        (
                            "terminal_commit_contract_version",
                            TERMINAL_COMMIT_CONTRACT_VERSION_V3,
                        ),
                        ("operation_id", operation_id),
                        ("operation_code", operation_code),
                        ("campaign_id", intent.campaign_id),
                        ("logical_execution_id", intent.logical_execution_id),
                        ("attempt_id", intent.attempt_id),
                        ("outcome_code", intent.outcome_code.value),
                        ("authoritative_proof", authoritative_proof),
                        ("retry_eligible", retry_eligible),
                        (
                            "execution_result_digest_present",
                            intent.execution_result_digest is not None,
                        ),
                        ("execution_result_digest", intent.execution_result_digest),
                        ("publication_key", publication_key),
                    ),
                )
        except _AbortOperationError as aborted:
            return aborted.result

    async def commit_terminal_attempt(self, request: TerminalCommitRequest) -> OperationResult:
        """Atomically settle budgets, bind outputs, close state, and enqueue publication."""
        terminal_states = {
            AttemptState.SUCCEEDED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.SKIPPED,
            AttemptState.CANCELLED,
            AttemptState.TIMED_OUT,
            AttemptState.INDETERMINATE,
        }
        if (
            type(request) is not TerminalCommitRequest
            or not all(
                valid_uuid(value)
                for value in (
                    request.logical_execution_id,
                    request.campaign_id,
                    request.outbox_id,
                    request.publication_key,
                )
            )
            or validate_transition_request(request.transition) is not None
            or request.transition.target_state not in terminal_states
            or request.transition.outbox_id is not None
            or request.transition.publication_key is not None
            or request.transition.campaign_id != request.campaign_id
            or not self._valid_budget_settlement(request.budgets)
            or request.budgets.attempt_id != request.transition.attempt_id
            or request.budgets.campaign_id != request.campaign_id
            or not self._valid_output_observations(request.outputs)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        target = request.transition.target_state
        if target is AttemptState.PARTIAL and not request.outputs:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        if target not in {AttemptState.SUCCEEDED, AttemptState.PARTIAL} and request.outputs:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._terminal_receipt_spec(request)
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.transition.operation_id)
                replay = await self._classify_receipt(
                    connection,
                    spec,
                    current_revision=request.transition.expected_revision,
                )
                if replay is not None:
                    return replay
                context = await self._lock_attempt_prefix(connection, request.transition.attempt_id)
                if context is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                (
                    context_logical,
                    context_campaign,
                    context_actor_user_id,
                    context_actor_subject_ref,
                    context_actor_authority_revision,
                ) = context
                if (
                    context_logical != request.logical_execution_id
                    or context_campaign != request.campaign_id
                    or (
                        request.transition.actor_subject_ref is not None
                        and (
                            context_actor_subject_ref != request.transition.actor_subject_ref
                            or context_actor_user_id != request.transition.actor_user_id
                            or context_actor_authority_revision
                            != request.transition.actor_authority_revision
                        )
                    )
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,closure_operation_id,revision FROM logical_executions "
                    "WHERE id=?" + suffix,
                    (request.logical_execution_id,),
                )
                if logical is None or self._value(logical, "campaign_id", 0) != request.campaign_id:
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                row = await self._fetchrow(
                    connection,
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "start_operation_id,dispatch_operation_id,"
                    "cancellation_request_revision,recovery_deadline_at,timeout_limit_ms,"
                    "lease_expires_at,queue_operation_id,cancellation_request_operation_id,"
                    "cancellation_ack_operation_id,timeout_operation_id,"
                    "settlement_pending_operation_id,terminal_operation_id,"
                    "logical_execution_id,campaign_id,retry_disposition,"
                    "actor_subject_ref,actor_user_id,actor_authority_revision,closes_logical,"
                    "external_effect_class,idempotency_class,retry_policy "
                    "FROM execution_attempts WHERE id=?" + suffix,
                    (request.transition.attempt_id,),
                )
                if row is None or (
                    self._value(row, "logical_execution_id", 16) != request.logical_execution_id
                    or self._value(row, "campaign_id", 17) != request.campaign_id
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                current = AttemptState(str(self._value(row, "state", 0)))
                revision = int(self._value(row, "revision", 1))
                if current is target:
                    return OperationResult(FixedResult.CONFLICT_OPERATION, revision)
                if self._value(logical, "closure_operation_id", 1) is not None:
                    return OperationResult(FixedResult.ALREADY_CLOSED, revision)
                if revision != request.transition.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if (current, target) not in LEGAL_TRANSITIONS:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                started = self._value(row, "start_operation_id", 4) is not None
                dispatched = self._value(row, "dispatch_operation_id", 5) is not None
                if (
                    target in {AttemptState.SUCCEEDED, AttemptState.PARTIAL, AttemptState.TIMED_OUT}
                    and not started
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                outcome_by_target = {
                    AttemptState.SUCCEEDED: OutcomeCode.CONFIRMED_SUCCESS,
                    AttemptState.PARTIAL: OutcomeCode.CONFIRMED_PARTIAL,
                    AttemptState.SKIPPED: OutcomeCode.ORCHESTRATION_SKIPPED,
                    AttemptState.CANCELLED: OutcomeCode.CONFIRMED_CANCELLED_NO_RESULT,
                    AttemptState.TIMED_OUT: OutcomeCode.CONFIRMED_TIMEOUT_TERMINATED,
                    AttemptState.INDETERMINATE: OutcomeCode.UNKNOWN_AFTER_RECOVERY,
                }
                required_outcome = outcome_by_target.get(target)
                if target is AttemptState.FAILED:
                    required_outcome = (
                        OutcomeCode.CONFIRMED_FAILURE
                        if started
                        else OutcomeCode.CONFIRMED_FAILURE_NO_DISPATCH
                    )
                if request.transition.outcome_code is not required_outcome:
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                proof = request.transition.authoritative_proof
                result_proofs = {
                    "local_completion",
                    "process_group_exit",
                    "worker_terminal_ack",
                    "external_settlement_ack",
                }
                if target in {AttemptState.SUCCEEDED, AttemptState.PARTIAL} and (
                    proof not in result_proofs
                ):
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if target is AttemptState.FAILED and (
                    (started and proof not in result_proofs)
                    or (not started and proof != "no_dispatch")
                ):
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if target is AttemptState.SKIPPED and proof != "no_dispatch":
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if target is AttemptState.CANCELLED and proof != "cancellation_no_result_ack":
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if target is AttemptState.TIMED_OUT and proof != "timeout_termination_ack":
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if target is AttemptState.INDETERMINATE and proof != "bounded_recovery_exhausted":
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                owner_required = dispatched and target is not AttemptState.INDETERMINATE
                if owner_required:
                    if request.transition.owner_ref != self._value(row, "dispatch_owner_ref", 2):
                        return OperationResult(FixedResult.CONFLICT_OWNER, revision)
                    if request.transition.lease_generation != int(
                        self._value(row, "lease_generation", 3)
                    ):
                        return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
                if current is AttemptState.CANCELLING and (
                    request.transition.cancellation_request_revision
                    != int(self._value(row, "cancellation_request_revision", 6))
                ):
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if target is AttemptState.INDETERMINATE:
                    if not await self._resolver_is_current_admin(connection, request.transition):
                        return OperationResult(FixedResult.AUTHORITY_STALE, revision)
                    current_time = await self._fetchrow(
                        connection, f"SELECT {self._now_sql} AS value", ()
                    )
                    if int(self._value(current_time, "value", 0)) < int(
                        self._value(row, "recovery_deadline_at", 7)
                    ):
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                    if (
                        request.budgets.noise_actual != request.budgets.noise_units
                        or request.budgets.exfiltration_actual != request.budgets.exfiltration_units
                    ):
                        return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                retry_eligible = bool(
                    target in {AttemptState.FAILED, AttemptState.TIMED_OUT}
                    and self._value(row, "external_effect_class", 23) == "read_only"
                    and self._value(row, "idempotency_class", 24) == "proven_idempotent"
                    and self._value(row, "retry_policy", 25) == "after_revalidation"
                )
                return await self._commit_terminal_attempt_same_transaction(
                    connection,
                    request,
                    receipt_spec=spec,
                    logical=logical,
                    attempt=row,
                    current=current,
                    retry_eligible=retry_eligible,
                )
        except _AbortOperationError as aborted:
            return aborted.result

    async def _insert_output_links(
        self,
        connection: Any,
        campaign_id: str,
        attempt_id: str,
        outputs: tuple[OutputObservation, ...],
    ) -> tuple[int, int, int, int]:
        table_columns = {
            OutputKind.FINDING: ("findings", "finding_id", 0),
            OutputKind.CREDENTIAL: ("credentials", "credential_id", 1),
            OutputKind.HOST: ("hosts", "host_id", 2),
            OutputKind.ARTIFACT: ("loot", "loot_id", 3),
        }
        counts = [0, 0, 0, 0]
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        host_ids = tuple(
            sorted(output.target_id for output in outputs if output.kind is OutputKind.HOST)
        )
        if host_ids:
            host_rows = await self._fetchall(
                connection,
                "SELECT id FROM hosts WHERE campaign_id=? AND id IN ("
                + ",".join("?" for _ in host_ids)
                + ") ORDER BY ip_address,id"
                + suffix,
                (campaign_id, *host_ids),
            )
            if tuple(sorted(str(self._value(row, "id", 0)) for row in host_rows)) != host_ids:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_STATE, None))
        non_hosts = tuple(
            sorted(
                (output for output in outputs if output.kind is not OutputKind.HOST),
                key=lambda item: (item.kind.value, item.target_id),
            )
        )
        for output in non_hosts:
            table, _column, _count_index = table_columns[output.kind]
            target = await self._fetchrow(
                connection,
                f"SELECT id FROM {table} WHERE campaign_id=? AND id=?" + suffix,
                (campaign_id, output.target_id),
            )
            if target is None:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_STATE, None))
        for output in sorted(outputs, key=lambda item: (item.kind.value, item.target_id)):
            _table, column, count_index = table_columns[output.kind]
            values: dict[str, Any] = {
                "finding_id": None,
                "credential_id": None,
                "host_id": None,
                "loot_id": None,
            }
            values[column] = output.target_id
            inserted = await self.update_exact_set(
                connection,
                "INSERT INTO execution_output_links("
                "id,attempt_id,campaign_id,finding_id,credential_id,host_id,loot_id) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING RETURNING id,attempt_id",
                (
                    output.link_id,
                    attempt_id,
                    campaign_id,
                    values["finding_id"],
                    values["credential_id"],
                    values["host_id"],
                    values["loot_id"],
                ),
                expected=(("id", output.link_id), ("attempt_id", attempt_id)),
                zero_classifier=None,
            )
            if inserted is None:
                raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
            counts[count_index] += 1
        return tuple(counts)  # type: ignore[return-value]

    async def _insert_terminal_outbox(
        self,
        connection: Any,
        request: TerminalCommitRequest,
        counts: tuple[int, int, int, int],
    ) -> None:
        events = {
            AttemptState.SUCCEEDED: "execution_succeeded",
            AttemptState.PARTIAL: "execution_partial",
            AttemptState.FAILED: "execution_failed",
            AttemptState.SKIPPED: "execution_skipped",
            AttemptState.CANCELLED: "execution_cancelled",
            AttemptState.TIMED_OUT: "execution_timed_out",
            AttemptState.INDETERMINATE: "execution_indeterminate",
        }
        now = self._now_sql
        inserted = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_publication_outbox("
            "id,publication_key,attempt_id,campaign_id,event_code,is_attempt_terminal,"
            "finding_count,credential_count,host_count,artifact_count,available_at,"
            "latest_operation_id,latest_operation_code,latest_operation_base_revision,"
            "created_at) SELECT ?,?,?,?,?,"
            + ("TRUE" if self._dialect == "postgresql" else "1")
            + ",?,?,?,?,db_now,?,'insert',0,db_now FROM (SELECT "
            + now
            + " AS db_now) AS clock WHERE 1=1 ON CONFLICT(id) DO NOTHING RETURNING id,claim_revision",
            (
                request.outbox_id,
                request.publication_key,
                request.transition.attempt_id,
                request.campaign_id,
                events[request.transition.target_state],
                *counts,
                request.publication_key,
            ),
            identity=request.outbox_id,
            revision=0,
            revision_column="claim_revision",
        )
        if inserted is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
        spec = self._receipt_spec(
            operation_id=request.outbox_id,
            operation_code="outbox_insert",
            campaign_id=request.campaign_id,
            primary_target_id=request.outbox_id,
            secondary_target_id=request.transition.attempt_id,
            fields=(
                ("publication_key", request.publication_key),
                ("event_code", events[request.transition.target_state]),
                ("terminal", True),
                ("finding_count", counts[0]),
                ("credential_count", counts[1]),
                ("host_count", counts[2]),
                ("artifact_count", counts[3]),
            ),
        )
        await self._insert_receipt(
            connection,
            spec,
            result=FixedResult.APPLIED,
            result_identity=request.outbox_id,
            result_revision=0,
            result_fields=(("publication_state", "pending"), ("claim_revision", 0)),
        )

    async def close_without_retry(self, request: ClosureRequest) -> OperationResult:
        """Permanently close a retryable terminal attempt in one locking CAS."""
        if (
            type(request) is not ClosureRequest
            or not all(
                valid_uuid(value)
                for value in (
                    request.logical_execution_id,
                    request.attempt_id,
                    request.outbox_id,
                    request.operation_id,
                    request.authority_subject_ref,
                    request.authority_user_id,
                    request.campaign_id,
                )
            )
            or type(request.expected_attempt_revision) is not int
            or not 0 <= request.expected_attempt_revision < MAX_I53
            or type(request.authority_revision) is not int
            or not 0 <= request.authority_revision <= MAX_I53
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._receipt_spec(
            operation_id=request.operation_id,
            operation_code="close_without_retry",
            campaign_id=request.campaign_id,
            primary_target_id=request.attempt_id,
            secondary_target_id=request.logical_execution_id,
            principal_kind="resolver",
            principal_subject_ref=request.authority_subject_ref,
            principal_user_id=request.authority_user_id,
            principal_authority_revision=request.authority_revision,
            expected_revision=request.expected_attempt_revision,
            fields=(
                ("outbox_id", request.outbox_id),
                ("authority_subject_ref", request.authority_subject_ref),
                ("authority_user_id", request.authority_user_id),
                ("authority_revision", request.authority_revision),
            ),
        )
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection,
                    spec,
                    current_revision=request.expected_attempt_revision,
                )
                if replay is not None:
                    return replay
                await self._acquire_logical_attempt_transaction_keys(
                    connection,
                    request.logical_execution_id,
                    request.attempt_id,
                )
                discovery = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,actor_user_id FROM execution_attempts "
                    "WHERE logical_execution_id=? AND id=?",
                    (request.logical_execution_id, request.attempt_id),
                )
                if discovery is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                campaign_id = str(self._value(discovery, "campaign_id", 0))
                actor_user_id = str(self._value(discovery, "actor_user_id", 1))
                if campaign_id != request.campaign_id:
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                for sql, params in (
                    ("SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1", ()),
                    (
                        "SELECT id FROM users WHERE id IN (?,?) ORDER BY id",
                        tuple(sorted((actor_user_id, request.authority_user_id))),
                    ),
                    ("SELECT id FROM campaigns WHERE id=?", (campaign_id,)),
                    (
                        "SELECT user_id FROM execution_actor_authority_revisions "
                        "WHERE user_id IN (?,?) ORDER BY user_id",
                        tuple(sorted((actor_user_id, request.authority_user_id))),
                    ),
                    (
                        "SELECT campaign_id FROM campaign_execution_authority_revisions "
                        "WHERE campaign_id=?",
                        (campaign_id,),
                    ),
                ):
                    await self._fetchall(connection, sql + suffix, params)
                logical = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,highest_attempt_ordinal,revision,"
                    "closure_operation_id,closing_attempt_id "
                    "FROM logical_executions WHERE id=?" + suffix,
                    (request.logical_execution_id,),
                )
                attempt = await self._fetchrow(
                    connection,
                    "SELECT campaign_id,ordinal,revision,state,closes_logical,"
                    "retry_disposition FROM execution_attempts "
                    "WHERE logical_execution_id=? AND id=?" + suffix,
                    (request.logical_execution_id, request.attempt_id),
                )
                if logical is None or attempt is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                revision = int(self._value(attempt, "revision", 2))
                logical_revision = int(self._value(logical, "revision", 2))
                closure_operation = self._value(logical, "closure_operation_id", 3)
                if closure_operation is not None:
                    return OperationResult(FixedResult.ALREADY_CLOSED, revision)
                if revision != request.expected_attempt_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                child = await self._fetchrow(
                    connection,
                    "SELECT id FROM execution_attempts WHERE logical_execution_id=? "
                    "AND parent_attempt_id=?" + suffix,
                    (request.logical_execution_id, request.attempt_id),
                )
                if (
                    self._value(logical, "campaign_id", 0) != campaign_id
                    or self._value(attempt, "campaign_id", 0) != campaign_id
                    or int(self._value(attempt, "ordinal", 1))
                    != int(self._value(logical, "highest_attempt_ordinal", 1))
                    or bool(self._value(attempt, "closes_logical", 4))
                    or self._value(attempt, "retry_disposition", 5) != "eligible"
                    or self._value(attempt, "state", 3) not in {"failed", "timed_out"}
                    or child is not None
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                authority = await self._fetchrow(
                    connection,
                    "SELECT u.id,u.role,u.is_active,a.revision "
                    "FROM users u JOIN execution_actor_authority_revisions a "
                    "ON a.user_id=u.id WHERE u.id=?" + suffix,
                    (request.authority_user_id,),
                )
                if not (
                    authority is not None
                    and self._value(authority, "id", 0) == request.authority_subject_ref
                    and self._value(authority, "role", 1) == "admin"
                    and bool(self._value(authority, "is_active", 2))
                    and int(self._value(authority, "revision", 3)) == request.authority_revision
                ):
                    return OperationResult(FixedResult.AUTHORITY_STALE, revision)
                now = self._now_sql
                async with self._savepoint(connection):
                    updated_attempt = await self.cas_update_one(
                        connection,
                        "UPDATE execution_attempts SET closes_logical="
                        + ("TRUE" if self._dialect == "postgresql" else "1")
                        + ",retry_disposition='closed_without_retry',revision=revision+1 "
                        "WHERE id=? AND logical_execution_id=? AND revision=? "
                        "AND closes_logical="
                        + ("FALSE" if self._dialect == "postgresql" else "0")
                        + " AND retry_disposition='eligible' "
                        "RETURNING id,revision,retry_disposition",
                        (
                            request.attempt_id,
                            request.logical_execution_id,
                            request.expected_attempt_revision,
                        ),
                        identity=request.attempt_id,
                        post_revision=request.expected_attempt_revision + 1,
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="execution_attempts",
                            identity_column="id",
                            identity=request.attempt_id,
                            revision_column="revision",
                            checks=(
                                (
                                    "revision",
                                    (request.expected_attempt_revision,),
                                    FixedResult.CONFLICT_REVISION,
                                ),
                                (
                                    "logical_execution_id",
                                    (request.logical_execution_id,),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                (
                                    "state",
                                    ("failed", "timed_out"),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                (
                                    "retry_disposition",
                                    ("eligible",),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                ("closes_logical", (False,), FixedResult.CONFLICT_STATE),
                            ),
                            receipt_spec=spec,
                            authority_columns=(
                                "actor_user_id",
                                "actor_authority_revision",
                                "actor_role",
                            ),
                            authority_before_checks=True,
                            expected_authority_user_id=request.authority_user_id,
                            expected_authority_revision=request.authority_revision,
                            expected_authority_role="admin",
                        ),
                    )
                    if updated_attempt is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, revision)
                        )
                    updated_logical = await self.cas_update_one(
                        connection,
                        "UPDATE logical_executions SET closure_operation_id=?,"
                        "closure_authority_subject_ref=?,closure_authority_user_id=?,"
                        "closure_authority_revision=?,closing_attempt_id=?,closed_at="
                        + now
                        + ",revision=revision+1 WHERE id=? AND campaign_id=? "
                        "AND revision=? AND closure_operation_id IS NULL "
                        "RETURNING id,revision,closing_attempt_id",
                        (
                            request.operation_id,
                            request.authority_subject_ref,
                            request.authority_user_id,
                            request.authority_revision,
                            request.attempt_id,
                            request.logical_execution_id,
                            campaign_id,
                            logical_revision,
                        ),
                        identity=request.logical_execution_id,
                        post_revision=logical_revision + 1,
                        zero_classifier=lambda: self._classify_zero_row(
                            connection,
                            table="logical_executions",
                            identity_column="id",
                            identity=request.logical_execution_id,
                            revision_column="revision",
                            checks=(
                                (
                                    "campaign_id",
                                    (campaign_id,),
                                    FixedResult.CONFLICT_STATE,
                                ),
                                (
                                    "closure_operation_id",
                                    (None,),
                                    FixedResult.ALREADY_CLOSED,
                                ),
                                (
                                    "revision",
                                    (logical_revision,),
                                    FixedResult.CONFLICT_REVISION,
                                ),
                            ),
                        ),
                    )
                    if updated_logical is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.ALREADY_CLOSED, revision)
                        )
                    inserted_outbox = await self.insert_or_validate_binding(
                        connection,
                        "INSERT INTO execution_publication_outbox("
                        "id,publication_key,attempt_id,campaign_id,event_code,"
                        "is_attempt_terminal,available_at,latest_operation_id,"
                        "latest_operation_code,latest_operation_base_revision,created_at) "
                        "SELECT ?,?,?,?,'logical_execution_closed',"
                        + ("FALSE" if self._dialect == "postgresql" else "0")
                        + ",db_now,?,'insert',0,db_now FROM (SELECT "
                        + now
                        + " AS db_now) AS clock WHERE 1=1 "
                        "ON CONFLICT(id) DO NOTHING RETURNING id,claim_revision",
                        (
                            request.outbox_id,
                            request.operation_id,
                            request.attempt_id,
                            campaign_id,
                            request.operation_id,
                        ),
                        identity=request.outbox_id,
                        revision=0,
                        revision_column="claim_revision",
                    )
                    if inserted_outbox is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_OPERATION, revision)
                        )
                    outbox_spec = self._receipt_spec(
                        operation_id=request.outbox_id,
                        operation_code="outbox_insert",
                        campaign_id=campaign_id,
                        primary_target_id=request.outbox_id,
                        secondary_target_id=request.attempt_id,
                        fields=(
                            ("publication_key", request.operation_id),
                            ("event_code", "logical_execution_closed"),
                            ("terminal", False),
                            ("finding_count", 0),
                            ("credential_count", 0),
                            ("host_count", 0),
                            ("artifact_count", 0),
                        ),
                    )
                    await self._insert_receipt(
                        connection,
                        outbox_spec,
                        result=FixedResult.APPLIED,
                        result_identity=request.outbox_id,
                        result_revision=0,
                        result_fields=(
                            ("publication_state", "pending"),
                            ("claim_revision", 0),
                        ),
                    )
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        exact_replay_code=FixedResult.REPLAYED_CLOSED,
                        result_identity=request.attempt_id,
                        result_revision=request.expected_attempt_revision + 1,
                        secondary_result_identity=request.logical_execution_id,
                        secondary_result_revision=logical_revision + 1,
                        result_fields=(
                            ("attempt_revision", request.expected_attempt_revision + 1),
                            ("logical_revision", logical_revision + 1),
                            ("closing_attempt_id", request.attempt_id),
                        ),
                    )
                return OperationResult(FixedResult.APPLIED, request.expected_attempt_revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def transition_attempt(self, request: TransitionRequest) -> OperationResult:
        invalid = validate_transition_request(request)
        if invalid is not None:
            return OperationResult(invalid, None)
        if request.target_state not in {
            AttemptState.QUEUED,
            AttemptState.DISPATCHING,
            AttemptState.RUNNING,
            AttemptState.CANCELLING,
        }:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._transition_receipt_spec(request)
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=request.expected_revision
                )
                if replay is not None:
                    return replay
                context = await self._lock_attempt_prefix(connection, request.attempt_id)
                if context is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                (
                    _logical_id,
                    campaign_id,
                    actor_user_id,
                    actor_subject_ref,
                    actor_authority_revision,
                ) = context
                if campaign_id != request.campaign_id or (
                    request.actor_subject_ref is not None
                    and (
                        actor_subject_ref != request.actor_subject_ref
                        or actor_user_id != request.actor_user_id
                        or actor_authority_revision != request.actor_authority_revision
                    )
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
                row = await self._fetchrow(
                    connection,
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "start_operation_id,dispatch_operation_id,"
                    "cancellation_request_revision,recovery_deadline_at,timeout_limit_ms "
                    ",lease_expires_at,queue_operation_id,cancellation_request_operation_id,"
                    "cancellation_ack_operation_id,timeout_operation_id,"
                    "settlement_pending_operation_id,terminal_operation_id "
                    "FROM execution_attempts WHERE id=?" + suffix,
                    (request.attempt_id,),
                )
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                current = AttemptState(str(self._value(row, "state", 0)))
                revision = int(self._value(row, "revision", 1))
                if revision != request.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if (current, request.target_state) not in LEGAL_TRANSITIONS:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                owner = self._value(row, "dispatch_owner_ref", 2)
                generation = int(self._value(row, "lease_generation", 3))
                started = self._value(row, "start_operation_id", 4) is not None
                dispatched = self._value(row, "dispatch_operation_id", 5) is not None
                if request.target_state is AttemptState.DISPATCHING and (
                    not valid_uuid(request.owner_ref)
                    or request.lease_generation is None
                    or request.lease_duration_ms is None
                    or request.lease_generation != generation + 1
                    or request.lease_duration_ms > int(self._value(row, "timeout_limit_ms", 8))
                ):
                    return OperationResult(FixedResult.INVALID_CONTRACT, revision)
                if dispatched and request.target_state not in {AttemptState.QUEUED}:
                    if request.owner_ref != owner:
                        return OperationResult(FixedResult.CONFLICT_OWNER, revision)
                    if request.lease_generation != generation:
                        return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
                if current is AttemptState.CANCELLING:
                    requested_revision = int(self._value(row, "cancellation_request_revision", 6))
                    if request.cancellation_request_revision != requested_revision:
                        return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                    if not dispatched and request.target_state not in {
                        AttemptState.CANCELLED,
                        AttemptState.FAILED,
                    }:
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                    if (
                        dispatched
                        and not started
                        and request.target_state
                        not in {
                            AttemptState.CANCELLED,
                            AttemptState.FAILED,
                            AttemptState.SETTLEMENT_PENDING,
                        }
                    ):
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                async with self._savepoint(connection):
                    return await self._apply_transition(
                        connection,
                        row,
                        current,
                        request,
                        receipt_spec=spec,
                        require_unexpired_lease=(
                            dispatched and request.target_state is not AttemptState.QUEUED
                        ),
                    )
        except _AbortOperationError as aborted:
            return aborted.result

    def _transition_operation_id(self, row: Any, target: AttemptState) -> Any:
        if (
            target
            in {
                AttemptState.SUCCEEDED,
                AttemptState.PARTIAL,
                AttemptState.FAILED,
            }
            and self._value(row, "cancellation_ack_operation_id", 12) is not None
        ):
            return self._value(row, "cancellation_ack_operation_id", 12)
        index_by_target = {
            AttemptState.QUEUED: 10,
            AttemptState.DISPATCHING: 5,
            AttemptState.RUNNING: 4,
            AttemptState.CANCELLING: 11,
            AttemptState.SETTLEMENT_PENDING: 14,
            AttemptState.CANCELLED: 12,
            AttemptState.TIMED_OUT: 13,
            AttemptState.REJECTED: 15,
            AttemptState.BLOCKED: 15,
            AttemptState.SUCCEEDED: 15,
            AttemptState.PARTIAL: 15,
            AttemptState.FAILED: 15,
            AttemptState.SKIPPED: 15,
            AttemptState.INDETERMINATE: 15,
        }
        index = index_by_target.get(target)
        if index is None:
            return None
        names = {
            4: "start_operation_id",
            5: "dispatch_operation_id",
            10: "queue_operation_id",
            11: "cancellation_request_operation_id",
            12: "cancellation_ack_operation_id",
            13: "timeout_operation_id",
            14: "settlement_pending_operation_id",
            15: "terminal_operation_id",
        }
        return self._value(row, names[index], index)

    async def mark_expired_lease_settlement_pending(
        self, request: TransitionRequest
    ) -> OperationResult:
        return await self._enter_settlement_pending(request, require_expired=True)

    async def enter_settlement_pending(self, request: TransitionRequest) -> OperationResult:
        return await self._enter_settlement_pending(request, require_expired=False)

    async def _enter_settlement_pending(
        self, request: TransitionRequest, *, require_expired: bool
    ) -> OperationResult:
        invalid = validate_transition_request(request)
        if (
            invalid is not None
            or request.target_state is not AttemptState.SETTLEMENT_PENDING
            or not valid_uuid(request.outbox_id)
            or not valid_uuid(request.publication_key)
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        operation_code = "lease_loss" if require_expired else "settlement_pending"
        spec = self._transition_receipt_spec(request, operation_code=operation_code)
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=request.expected_revision
                )
                if replay is not None:
                    return replay
                context = await self._lock_attempt_prefix(connection, request.attempt_id)
                if context is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                (
                    _logical_id,
                    campaign_id,
                    actor_user_id,
                    actor_subject_ref,
                    actor_authority_revision,
                ) = context
                if campaign_id != request.campaign_id or (
                    request.actor_subject_ref is not None
                    and (
                        actor_subject_ref != request.actor_subject_ref
                        or actor_user_id != request.actor_user_id
                        or actor_authority_revision != request.actor_authority_revision
                    )
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
                row = await self._fetchrow(
                    connection,
                    "SELECT state,revision,dispatch_owner_ref,lease_generation,"
                    "start_operation_id,dispatch_operation_id,"
                    "cancellation_request_revision,recovery_deadline_at,"
                    "timeout_limit_ms,lease_expires_at,settlement_pending_operation_id "
                    "FROM execution_attempts WHERE id=?" + suffix,
                    (request.attempt_id,),
                )
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                current = AttemptState(str(self._value(row, "state", 0)))
                revision = int(self._value(row, "revision", 1))
                if revision != request.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if current not in {
                    AttemptState.DISPATCHING,
                    AttemptState.RUNNING,
                    AttemptState.CANCELLING,
                }:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if self._value(row, "dispatch_owner_ref", 2) != request.owner_ref:
                    return OperationResult(FixedResult.CONFLICT_OWNER, revision)
                if int(self._value(row, "lease_generation", 3)) != request.lease_generation:
                    return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
                if require_expired:
                    current_time = await self._fetchrow(
                        connection, f"SELECT {self._now_sql} AS value", ()
                    )
                    if int(self._value(current_time, "value", 0)) < int(
                        self._value(row, "lease_expires_at", 9)
                    ):
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                async with self._savepoint(connection):
                    result = await self._apply_transition(
                        connection, row, current, request, zero_receipt_spec=spec
                    )
                    if result.result is not FixedResult.APPLIED:
                        raise _AbortOperationError(result)
                    if require_expired:
                        exact = await self.update_exact_set(
                            connection,
                            "UPDATE execution_attempts SET error_action_code='worker_loss' "
                            "WHERE id=? AND revision=? AND state='settlement_pending' "
                            "RETURNING id,revision,error_action_code",
                            (request.attempt_id, request.expected_revision + 1),
                            expected=(
                                ("id", request.attempt_id),
                                ("revision", request.expected_revision + 1),
                                ("error_action_code", "worker_loss"),
                            ),
                            zero_classifier=lambda: self._classify_zero_row(
                                connection,
                                table="execution_attempts",
                                identity_column="id",
                                identity=request.attempt_id,
                                revision_column="revision",
                                checks=(
                                    (
                                        "revision",
                                        (request.expected_revision + 1,),
                                        FixedResult.CONFLICT_REVISION,
                                    ),
                                    (
                                        "state",
                                        ("settlement_pending",),
                                        FixedResult.CONFLICT_STATE,
                                    ),
                                ),
                            ),
                        )
                        if exact is None:
                            raise _AbortOperationError(
                                OperationResult(FixedResult.CONFLICT_STATE, revision)
                            )
                    await self._insert_recovery_outbox(connection, request, campaign_id)
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        result_identity=request.attempt_id,
                        result_revision=request.expected_revision + 1,
                        secondary_result_identity=request.outbox_id,
                        secondary_result_revision=0,
                        result_fields=(
                            ("state", AttemptState.SETTLEMENT_PENDING.value),
                            ("revision", request.expected_revision + 1),
                            ("outbox_id", request.outbox_id),
                        ),
                    )
                    return result
        except _AbortOperationError as aborted:
            return aborted.result

    async def _insert_recovery_outbox(
        self, connection: Any, request: TransitionRequest, campaign_id: str
    ) -> None:
        now = self._now_sql
        inserted = await self.insert_or_validate_binding(
            connection,
            "INSERT INTO execution_publication_outbox("
            "id,publication_key,attempt_id,campaign_id,event_code,"
            "is_attempt_terminal,available_at,latest_operation_id,"
            "latest_operation_code,latest_operation_base_revision,created_at) "
            "SELECT ?,?,?,a.campaign_id,'recovery_required',"
            + ("FALSE" if self._dialect == "postgresql" else "0")
            + ",db_now,?,'insert',0,db_now FROM execution_attempts a,"
            "(SELECT " + now + " AS db_now) AS clock WHERE a.id=? "
            "ON CONFLICT(id) DO NOTHING RETURNING id,claim_revision",
            (
                request.outbox_id,
                request.publication_key,
                request.attempt_id,
                request.publication_key,
                request.attempt_id,
            ),
            identity=request.outbox_id,
            revision=0,
            revision_column="claim_revision",
        )
        if inserted is None:
            raise _AbortOperationError(OperationResult(FixedResult.CONFLICT_OPERATION, None))
        spec = self._receipt_spec(
            operation_id=request.outbox_id,
            operation_code="outbox_insert",
            campaign_id=campaign_id,
            primary_target_id=request.outbox_id,
            secondary_target_id=request.attempt_id,
            fields=(
                ("publication_key", request.publication_key),
                ("event_code", "recovery_required"),
                ("terminal", False),
                ("finding_count", 0),
                ("credential_count", 0),
                ("host_count", 0),
                ("artifact_count", 0),
            ),
        )
        await self._insert_receipt(
            connection,
            spec,
            result=FixedResult.APPLIED,
            result_identity=request.outbox_id,
            result_revision=0,
            result_fields=(("publication_state", "pending"), ("claim_revision", 0)),
        )

    async def _resolver_is_current_admin(self, connection: Any, request: TransitionRequest) -> bool:
        if (
            not valid_uuid(request.resolver_subject_ref)
            or not valid_uuid(request.resolver_user_id)
            or request.resolver_authority_revision is None
        ):
            return False
        row = await self._fetchrow(
            connection,
            "SELECT u.id,u.role,u.is_active,a.revision "
            "FROM users u JOIN execution_actor_authority_revisions a "
            "ON a.user_id=u.id WHERE u.id=?",
            (request.resolver_user_id,),
        )
        return bool(
            row is not None
            and self._value(row, "id", 0) == request.resolver_subject_ref
            and self._value(row, "role", 1) == "admin"
            and bool(self._value(row, "is_active", 2))
            and int(self._value(row, "revision", 3)) == request.resolver_authority_revision
        )

    async def _apply_transition(
        self,
        connection: Any,
        row: Any,
        current: AttemptState,
        request: TransitionRequest,
        *,
        receipt_spec: _ReceiptSpec | None = None,
        zero_receipt_spec: _ReceiptSpec | None = None,
        require_unexpired_lease: bool = False,
        retry_eligible: bool = False,
    ) -> OperationResult:
        now = (
            "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            if self._dialect == "postgresql"
            else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
        )
        target = request.target_state
        fields: list[str] = ["state=?", "revision=revision+1"]
        params: list[Any] = [target.value]
        terminal = target in {
            AttemptState.SUCCEEDED,
            AttemptState.PARTIAL,
            AttemptState.FAILED,
            AttemptState.SKIPPED,
            AttemptState.CANCELLED,
            AttemptState.TIMED_OUT,
            AttemptState.INDETERMINATE,
        }
        if target is AttemptState.QUEUED:
            fields += ["queue_operation_id=?", f"queued_at={now}"]
            params.append(request.operation_id)
        elif target is AttemptState.DISPATCHING:
            fields += [
                "dispatch_operation_id=?",
                "dispatch_owner_ref=?",
                "lease_generation=?",
                "dispatch_lease_duration_ms=?",
                f"dispatching_at={now}",
                f"lease_expires_at={now}+?",
            ]
            params.extend(
                (
                    request.operation_id,
                    request.owner_ref,
                    request.lease_generation,
                    request.lease_duration_ms,
                    request.lease_duration_ms,
                )
            )
        elif target is AttemptState.RUNNING:
            fields += ["start_operation_id=?", f"started_at={now}", "settlement_state='active'"]
            params.append(request.operation_id)
        elif target is AttemptState.CANCELLING:
            fields += [
                "cancellation_request_operation_id=?",
                "cancellation_request_revision=revision+1",
                f"cancellation_requested_at={now}",
                "error_action_code='operator_cancel'",
            ]
            params.append(request.operation_id)
        elif target is AttemptState.SETTLEMENT_PENDING:
            fields += [
                "settlement_pending_operation_id=?",
                f"settlement_pending_at={now}",
                f"recovery_deadline_at={now}+{RECOVERY_WINDOW_MS}",
                f"lease_invalidated_at={now}",
                "settlement_state='recovery_pending'",
                "settlement_proof_code='unresolved'",
                "termination_confirmed=" + ("FALSE" if self._dialect == "postgresql" else "0"),
                "error_action_code='recovery_required'",
            ]
            params.append(request.operation_id)
        elif terminal:
            if target is AttemptState.TIMED_OUT:
                fields += ["timeout_operation_id=?", f"timeout_observed_at={now}"]
            elif current is AttemptState.CANCELLING or target is AttemptState.CANCELLED:
                fields += [
                    "cancellation_ack_operation_id=?",
                    f"cancellation_acknowledged_at={now}",
                ]
            else:
                fields.append("terminal_operation_id=?")
            params.append(request.operation_id)
            fields += [f"finished_at={now}", f"settled_at={now}"]
            fields.append(
                "retry_disposition='eligible'"
                if retry_eligible
                else "retry_disposition='closed_without_retry'"
            )
            if self._value(row, "dispatch_operation_id", 5) is not None:
                fields.append(f"lease_invalidated_at=COALESCE(lease_invalidated_at,{now})")
            if request.outcome_code is not None:
                fields.append("outcome_code=?")
                params.append(request.outcome_code.value)
            if target is AttemptState.INDETERMINATE:
                fields += [
                    "settlement_proof_code=?",
                    "settlement_state='operator_resolved'",
                    "termination_confirmed=" + ("FALSE" if self._dialect == "postgresql" else "0"),
                    "resolver_subject_ref=?",
                    "resolver_user_id=?",
                    "resolver_authority_revision=?",
                    "bounded_recovery_proof_code='recovery_sources_exhausted'",
                ]
                params.extend(
                    (
                        request.authoritative_proof,
                        request.resolver_subject_ref,
                        request.resolver_user_id,
                        request.resolver_authority_revision,
                    )
                )
            elif self._value(row, "start_operation_id", 4) is None:
                fields += [
                    "settlement_state='not_applicable'",
                    "settlement_proof_code='no_dispatch'",
                    (
                        "termination_confirmed=FALSE"
                        if self._dialect == "postgresql"
                        else "termination_confirmed=0"
                    ),
                ]
            else:
                fields += [
                    "settlement_proof_code=?",
                    "settlement_state='settled'",
                    "termination_confirmed=" + ("TRUE" if self._dialect == "postgresql" else "1"),
                ]
                params.append(request.authoritative_proof)
        where = " WHERE id=? AND revision=? AND state=?"
        params.extend([request.attempt_id, request.expected_revision, current.value])
        guarded_dispatch = (
            self._value(row, "dispatch_operation_id", 5) is not None
            and request.owner_ref is not None
        )
        if guarded_dispatch:
            where += " AND dispatch_owner_ref=? AND lease_generation=?"
            params.extend([request.owner_ref, request.lease_generation])
        if current is AttemptState.CANCELLING:
            where += " AND cancellation_request_revision=?"
            params.append(request.cancellation_request_revision)
        if require_unexpired_lease:
            where += f" AND lease_expires_at=? AND lease_expires_at>{now}"
            params.append(self._value(row, "lease_expires_at", 9))
        updated = await self.cas_update_one(
            connection,
            "UPDATE execution_attempts SET "
            + ",".join(fields)
            + where
            + " RETURNING id,revision,state,dispatch_owner_ref,lease_generation",
            tuple(params),
            identity=request.attempt_id,
            post_revision=request.expected_revision + 1,
            zero_classifier=lambda: self._classify_zero_transition(
                connection,
                row=row,
                current=current,
                request=request,
                receipt_spec=receipt_spec or zero_receipt_spec,
                guarded_dispatch=guarded_dispatch,
                require_unexpired_lease=require_unexpired_lease,
            ),
        )
        if updated is None:
            return OperationResult(FixedResult.CONFLICT_STATE, request.expected_revision)
        if receipt_spec is not None:
            await self._insert_receipt(
                connection,
                receipt_spec,
                result=FixedResult.APPLIED,
                result_identity=request.attempt_id,
                result_revision=request.expected_revision + 1,
                result_fields=(
                    ("state", target.value),
                    ("revision", request.expected_revision + 1),
                    ("owner_ref", self._value(updated, "dispatch_owner_ref", 3)),
                    ("lease_generation", int(self._value(updated, "lease_generation", 4))),
                ),
            )
        return OperationResult(FixedResult.APPLIED, request.expected_revision + 1)

    def _outbox_receipt_spec(
        self,
        request: OutboxMutation,
        operation: str,
    ) -> _ReceiptSpec:
        principal_kind = "worker" if request.owner_ref is not None else "system"
        principal_subject_ref = request.owner_ref or SYSTEM_PRINCIPAL_SUBJECT_REF
        return self._receipt_spec(
            operation_id=request.operation_id,
            operation_code="outbox_" + operation,
            campaign_id=request.campaign_id,
            primary_target_id=request.outbox_id,
            secondary_target_id=request.attempt_id,
            principal_kind=principal_kind,
            principal_subject_ref=principal_subject_ref,
            expected_revision=request.expected_revision,
            owner_ref=request.owner_ref,
            lease_generation=request.lease_generation,
            fields=(
                ("publication_key", request.publication_key),
                ("event_code", request.event_code),
                ("operation", operation),
                ("purge_poisoned", request.purge_poisoned),
            ),
        )

    def _outbox_row_matches_binding(self, row: Any, request: OutboxMutation) -> bool:
        return (
            self._value(row, "campaign_id", 10) == request.campaign_id
            and self._value(row, "attempt_id", 11) == request.attempt_id
            and self._value(row, "publication_key", 12) == request.publication_key
            and self._value(row, "event_code", 13) == request.event_code
        )

    def _outbox_result_fields(self, row: Any) -> tuple[tuple[str, str | int | bool | None], ...]:
        return (
            ("publication_state", str(self._value(row, "publication_state", 0))),
            ("claim_revision", int(self._value(row, "claim_revision", 1))),
            ("claim_owner_ref", self._value(row, "claim_owner_ref", 2)),
            ("lease_generation", int(self._value(row, "lease_generation", 3))),
            (
                "delivery_attempt_count",
                int(self._value(row, "delivery_attempt_count", 5)),
            ),
            ("failure_code", self._value(row, "failure_code", 14)),
        )

    async def _locked_outbox_row(self, connection: Any, outbox_id: str) -> Any:
        suffix = " FOR UPDATE" if self._dialect == "postgresql" else ""
        return await self._fetchrow(
            connection,
            "SELECT publication_state,claim_revision,claim_owner_ref,lease_generation,"
            "lease_expires_at,delivery_attempt_count,latest_operation_id,"
            "latest_operation_code,latest_operation_base_revision,available_at,"
            "campaign_id,attempt_id,publication_key,event_code,failure_code "
            "FROM execution_publication_outbox WHERE id=?" + suffix,
            (outbox_id,),
        )

    async def claim_outbox(
        self, request: OutboxMutation, *, reclaim: bool = False
    ) -> OperationResult:
        if not self._valid_outbox_mutation(request, require_owner=True):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        code = "reclaim" if reclaim else "claim"
        spec = self._outbox_receipt_spec(request, code)
        now = (
            "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            if self._dialect == "postgresql"
            else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
        )
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=request.expected_revision
                )
                if replay is not None:
                    return replay
                row = await self._locked_outbox_row(connection, request.outbox_id)
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                if not self._outbox_row_matches_binding(row, request):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                revision = int(self._value(row, "claim_revision", 1))
                if revision != request.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                state = str(self._value(row, "publication_state", 0))
                count = int(self._value(row, "delivery_attempt_count", 5))
                if (
                    (not reclaim and state != "pending")
                    or (reclaim and state != "claimed")
                    or count >= 20
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                stored_generation = int(self._value(row, "lease_generation", 3))
                if stored_generation != request.lease_generation:
                    return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
                time_row = await self._fetchrow(connection, f"SELECT {now} AS value", ())
                db_now = int(self._value(time_row, "value", 0))
                if reclaim:
                    if db_now < int(self._value(row, "lease_expires_at", 4)):
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                elif db_now < int(self._value(row, "available_at", 9)):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                state_predicate = "claimed" if reclaim else "pending"
                time_predicate = (
                    "lease_expires_at IS NOT NULL AND " + now + ">=lease_expires_at"
                    if reclaim
                    else "available_at IS NOT NULL AND " + now + ">=available_at"
                )
                async with self._savepoint(connection):
                    updated = await self.cas_update_one(
                        connection,
                        "UPDATE execution_publication_outbox SET "
                        "publication_state='claimed',"
                        "delivery_attempt_count=delivery_attempt_count+1,"
                        "available_at=NULL,failure_code=NULL,claim_owner_ref=?,"
                        "lease_generation=lease_generation+1,claimed_at="
                        + now
                        + ",lease_expires_at="
                        + now
                        + f"+{OUTBOX_LEASE_MS},latest_operation_id=?,"
                        "latest_operation_code=?,latest_operation_base_revision=?,"
                        "claim_revision=claim_revision+1 WHERE id=? AND claim_revision=? "
                        "AND publication_state=? AND lease_generation=? AND "
                        + time_predicate
                        + " RETURNING id,claim_revision,publication_state,claim_owner_ref,"
                        "lease_generation,delivery_attempt_count,failure_code",
                        (
                            request.owner_ref,
                            request.operation_id,
                            code,
                            request.expected_revision,
                            request.outbox_id,
                            request.expected_revision,
                            state_predicate,
                            request.lease_generation,
                        ),
                        identity=request.outbox_id,
                        post_revision=request.expected_revision + 1,
                        revision_column="claim_revision",
                        zero_classifier=lambda: self._classify_zero_outbox(
                            connection,
                            outbox_id=request.outbox_id,
                            expected_revision=request.expected_revision,
                            expected_state=state_predicate,
                            expected_generation=request.lease_generation,
                            time_requirement="expired" if reclaim else "available",
                            maximum_delivery_count=20,
                        ),
                    )
                    if updated is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, revision)
                        )
                    result_fields = (
                        ("publication_state", str(self._value(updated, "publication_state", 2))),
                        ("claim_revision", request.expected_revision + 1),
                        ("claim_owner_ref", self._value(updated, "claim_owner_ref", 3)),
                        ("lease_generation", int(self._value(updated, "lease_generation", 4))),
                        (
                            "delivery_attempt_count",
                            int(self._value(updated, "delivery_attempt_count", 5)),
                        ),
                        ("failure_code", self._value(updated, "failure_code", 6)),
                    )
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        result_identity=request.outbox_id,
                        result_revision=request.expected_revision + 1,
                        result_fields=result_fields,
                    )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    @staticmethod
    def _valid_outbox_mutation(request: object, *, require_owner: bool) -> bool:
        return (
            type(request) is OutboxMutation
            and valid_uuid(request.outbox_id)
            and valid_uuid(request.operation_id)
            and type(request.expected_revision) is int
            and 0 <= request.expected_revision < MAX_I53
            and valid_uuid(request.campaign_id)
            and valid_uuid(request.attempt_id)
            and valid_uuid(request.publication_key)
            and request.event_code
            in {
                "recovery_required",
                "execution_rejected",
                "execution_blocked",
                "execution_succeeded",
                "execution_partial",
                "execution_failed",
                "execution_skipped",
                "execution_cancelled",
                "execution_timed_out",
                "execution_indeterminate",
                "logical_execution_closed",
            }
            and (request.purge_poisoned is None or type(request.purge_poisoned) is bool)
            and (request.owner_ref is None) == (request.lease_generation is None)
            and (
                request.owner_ref is None
                or (
                    valid_uuid(request.owner_ref)
                    and type(request.lease_generation) is int
                    and 0 <= request.lease_generation <= MAX_I53
                )
            )
            and (
                not require_owner
                or (
                    valid_uuid(request.owner_ref)
                    and type(request.lease_generation) is int
                    and 0 <= request.lease_generation <= MAX_I53
                )
            )
        )

    async def poison_expired_attempt_twenty(self, request: OutboxMutation) -> OperationResult:
        if (
            not self._valid_outbox_mutation(request, require_owner=False)
            or request.owner_ref is not None
            or request.lease_generation is not None
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._outbox_receipt_spec(request, "poison")
        now = (
            "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            if self._dialect == "postgresql"
            else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
        )
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=request.expected_revision
                )
                if replay is not None:
                    return replay
                row = await self._locked_outbox_row(connection, request.outbox_id)
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                if not self._outbox_row_matches_binding(row, request):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                revision = int(self._value(row, "claim_revision", 1))
                if revision != request.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if (
                    str(self._value(row, "publication_state", 0)) != "claimed"
                    or int(self._value(row, "delivery_attempt_count", 5)) != 20
                ):
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                expiry = int(self._value(row, "lease_expires_at", 4))
                time_row = await self._fetchrow(connection, f"SELECT {now} AS value", ())
                if int(self._value(time_row, "value", 0)) < expiry:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                async with self._savepoint(connection):
                    updated = await self.cas_update_one(
                        connection,
                        "UPDATE execution_publication_outbox SET publication_state='poisoned',"
                        "claim_owner_ref=NULL,lease_expires_at=NULL,available_at=NULL,"
                        "poisoned_at="
                        + now
                        + ",failure_code='delivery_attempt_limit',latest_operation_id=?,"
                        "latest_operation_code='poison',latest_operation_base_revision=?,"
                        "claim_revision=claim_revision+1 WHERE id=? AND claim_revision=? "
                        "AND publication_state='claimed' AND delivery_attempt_count=20 "
                        "AND lease_expires_at IS NOT NULL AND "
                        + now
                        + ">=lease_expires_at RETURNING id,claim_revision,publication_state,"
                        "claim_owner_ref,lease_generation,delivery_attempt_count,failure_code",
                        (
                            request.operation_id,
                            request.expected_revision,
                            request.outbox_id,
                            request.expected_revision,
                        ),
                        identity=request.outbox_id,
                        post_revision=request.expected_revision + 1,
                        revision_column="claim_revision",
                        zero_classifier=lambda: self._classify_zero_outbox(
                            connection,
                            outbox_id=request.outbox_id,
                            expected_revision=request.expected_revision,
                            expected_state="claimed",
                            time_requirement="expired",
                            expected_delivery_count=20,
                        ),
                    )
                    if updated is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, revision)
                        )
                    result_fields = (
                        ("publication_state", "poisoned"),
                        ("claim_revision", request.expected_revision + 1),
                        ("claim_owner_ref", None),
                        ("lease_generation", int(self._value(updated, "lease_generation", 4))),
                        ("delivery_attempt_count", 20),
                        ("failure_code", "delivery_attempt_limit"),
                    )
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        result_identity=request.outbox_id,
                        result_revision=request.expected_revision + 1,
                        result_fields=result_fields,
                    )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def renew_outbox(self, request: OutboxMutation) -> OperationResult:
        return await self._mutate_claimed_outbox(request, "renew")

    async def publish_outbox(self, request: OutboxMutation) -> OperationResult:
        return await self._mutate_claimed_outbox(request, "publish")

    async def fail_outbox(self, request: OutboxMutation, *, retryable: bool) -> OperationResult:
        return await self._mutate_claimed_outbox(
            request,
            "retryable_failure" if retryable else "nonretryable_failure",
        )

    async def _mutate_claimed_outbox(
        self, request: OutboxMutation, operation: str
    ) -> OperationResult:
        if operation not in {
            "renew",
            "publish",
            "retryable_failure",
            "nonretryable_failure",
        } or not self._valid_outbox_mutation(request, require_owner=True):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        spec = self._outbox_receipt_spec(request, operation)
        now = (
            "floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            if self._dialect == "postgresql"
            else "CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)"
        )
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, request.operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=request.expected_revision
                )
                if replay is not None:
                    return replay
                row = await self._locked_outbox_row(connection, request.outbox_id)
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                if not self._outbox_row_matches_binding(row, request):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                revision = int(self._value(row, "claim_revision", 1))
                if revision != request.expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if str(self._value(row, "publication_state", 0)) != "claimed":
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                if self._value(row, "claim_owner_ref", 2) != request.owner_ref:
                    return OperationResult(FixedResult.CONFLICT_OWNER, revision)
                if int(self._value(row, "lease_generation", 3)) != request.lease_generation:
                    return OperationResult(FixedResult.CONFLICT_GENERATION, revision)
                expiry = int(self._value(row, "lease_expires_at", 4))
                current_row = await self._fetchrow(connection, f"SELECT {now} AS value", ())
                if int(self._value(current_row, "value", 0)) >= expiry:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                common_where = (
                    " WHERE id=? AND claim_revision=? AND publication_state='claimed' "
                    "AND claim_owner_ref=? AND lease_generation=? AND lease_expires_at=? "
                    "AND " + now + "<lease_expires_at"
                )
                common_params: tuple[Any, ...] = (
                    request.operation_id,
                    operation,
                    request.expected_revision,
                    request.outbox_id,
                    request.expected_revision,
                    request.owner_ref,
                    request.lease_generation,
                    expiry,
                )
                if operation == "renew":
                    update = (
                        "UPDATE execution_publication_outbox SET "
                        f"lease_expires_at=lease_expires_at+{OUTBOX_LEASE_MS},"
                        "latest_operation_id=?,latest_operation_code=?,"
                        "latest_operation_base_revision=?,claim_revision=claim_revision+1"
                        + common_where
                    )
                elif operation == "publish":
                    update = (
                        "UPDATE execution_publication_outbox SET publication_state='published',"
                        "claim_owner_ref=NULL,lease_expires_at=NULL,published_at="
                        + now
                        + ",failure_code=NULL,latest_operation_id=?,latest_operation_code=?,"
                        "latest_operation_base_revision=?,claim_revision=claim_revision+1"
                        + common_where
                    )
                elif operation == "retryable_failure":
                    attempt_count = int(self._value(row, "delivery_attempt_count", 5))
                    delay = retry_delay_ms(attempt_count)
                    if delay is None or attempt_count >= 20:
                        return OperationResult(FixedResult.CONFLICT_STATE, revision)
                    update = (
                        "UPDATE execution_publication_outbox SET publication_state='pending',"
                        "claim_owner_ref=NULL,lease_expires_at=NULL,available_at="
                        + now
                        + f"+{delay},failure_code='delivery_retryable',latest_operation_id=?,"
                        "latest_operation_code=?,latest_operation_base_revision=?,"
                        "claim_revision=claim_revision+1" + common_where
                    )
                else:
                    update = (
                        "UPDATE execution_publication_outbox SET publication_state='poisoned',"
                        "claim_owner_ref=NULL,lease_expires_at=NULL,available_at=NULL,poisoned_at="
                        + now
                        + ",failure_code='delivery_nonretryable',latest_operation_id=?,"
                        "latest_operation_code=?,latest_operation_base_revision=?,"
                        "claim_revision=claim_revision+1" + common_where
                    )
                update += (
                    " RETURNING id,claim_revision,publication_state,claim_owner_ref,"
                    "lease_generation,delivery_attempt_count,failure_code"
                )
                async with self._savepoint(connection):
                    updated = await self.cas_update_one(
                        connection,
                        update,
                        common_params,
                        identity=request.outbox_id,
                        post_revision=request.expected_revision + 1,
                        revision_column="claim_revision",
                        zero_classifier=lambda: self._classify_zero_outbox(
                            connection,
                            outbox_id=request.outbox_id,
                            expected_revision=request.expected_revision,
                            expected_state="claimed",
                            expected_owner=request.owner_ref,
                            expected_generation=request.lease_generation,
                            expected_lease_expires_at=expiry,
                            time_requirement="unexpired",
                        ),
                    )
                    if updated is None:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, revision)
                        )
                    result_fields = (
                        ("publication_state", str(self._value(updated, "publication_state", 2))),
                        ("claim_revision", request.expected_revision + 1),
                        ("claim_owner_ref", self._value(updated, "claim_owner_ref", 3)),
                        ("lease_generation", int(self._value(updated, "lease_generation", 4))),
                        (
                            "delivery_attempt_count",
                            int(self._value(updated, "delivery_attempt_count", 5)),
                        ),
                        ("failure_code", self._value(updated, "failure_code", 6)),
                    )
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        result_identity=request.outbox_id,
                        result_revision=request.expected_revision + 1,
                        result_fields=result_fields,
                    )
                return OperationResult(FixedResult.APPLIED, revision + 1)
        except _AbortOperationError as aborted:
            return aborted.result

    async def purge_outbox(
        self,
        outbox_id: str,
        expected_revision: int,
        operation_id: str,
        *,
        poisoned: bool,
        campaign_id: str | None = None,
        attempt_id: str | None = None,
        publication_key: str | None = None,
        event_code: str | None = None,
    ) -> OperationResult:
        request = OutboxMutation(
            outbox_id,
            expected_revision,
            operation_id,
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            publication_key=publication_key,
            event_code=event_code,
            purge_poisoned=poisoned,
        )
        if (
            not self._valid_outbox_mutation(request, require_owner=False)
            or type(poisoned) is not bool
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        required_state = "poisoned" if poisoned else "published"
        spec = self._outbox_receipt_spec(request, "purge")
        try:
            async with self._transaction() as connection:
                await self._acquire_transaction_key(connection, operation_id)
                replay = await self._classify_receipt(
                    connection, spec, current_revision=expected_revision
                )
                if replay is not None:
                    return replay
                row = await self._locked_outbox_row(connection, outbox_id)
                if row is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
                if not self._outbox_row_matches_binding(row, request):
                    return OperationResult(FixedResult.CONFLICT_STATE, None)
                revision = int(self._value(row, "claim_revision", 1))
                if revision != expected_revision:
                    return OperationResult(FixedResult.CONFLICT_REVISION, revision)
                if self._value(row, "publication_state", 0) != required_state:
                    return OperationResult(FixedResult.CONFLICT_STATE, revision)
                async with self._savepoint(connection):
                    await self._insert_receipt(
                        connection,
                        spec,
                        result=FixedResult.APPLIED,
                        result_identity=outbox_id,
                        result_revision=expected_revision,
                        result_fields=(
                            ("publication_state", required_state),
                            ("purged", True),
                        ),
                    )
                    deleted = await self.delete_exact_set(
                        connection,
                        "DELETE FROM execution_publication_outbox WHERE id=? "
                        "AND claim_revision=? AND publication_state=? RETURNING id",
                        (outbox_id, expected_revision, required_state),
                        expected_identities=(outbox_id,),
                        zero_classifier=lambda: self._classify_zero_outbox(
                            connection,
                            outbox_id=outbox_id,
                            expected_revision=expected_revision,
                            expected_state=required_state,
                        ),
                    )
                    if not deleted:
                        raise _AbortOperationError(
                            OperationResult(FixedResult.CONFLICT_STATE, revision)
                        )
                return OperationResult(FixedResult.APPLIED, None)
        except _AbortOperationError as aborted:
            return aborted.result


def sqlite_catalog_names(connection: Any) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name IN ("
        + ",".join("?" for _ in LIFECYCLE_TABLES)
        + ") ORDER BY name",
        LIFECYCLE_TABLES,
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


def _normalized_sql(value: object) -> str:
    if type(value) is not str:
        return ""
    return " ".join(value.replace("IF NOT EXISTS ", "").replace(" OR IGNORE", "").split())


def _expected_sqlite_catalog_sql() -> tuple[tuple[str, str, str], ...]:
    entries: list[tuple[str, str, str]] = []
    for statement in SQLITE_LIFECYCLE_DDL:
        normalized = _normalized_sql(statement)
        table_match = re.match(r"CREATE TABLE ([a-z0-9_]+) ", normalized)
        if table_match is not None and table_match.group(1) in LIFECYCLE_TABLES:
            entries.append(("table", table_match.group(1), normalized))
            continue
        index_match = re.match(
            r"CREATE (?:UNIQUE )?INDEX ([a-z0-9_]+) ON ([a-z0-9_]+)",
            normalized,
        )
        if index_match is not None:
            entries.append(("index", index_match.group(1), normalized))
            continue
        trigger_match = re.match(
            r"CREATE TRIGGER ([a-z0-9_]+) BEFORE (?:UPDATE|DELETE) ON ([a-z0-9_]+)",
            normalized,
        )
        if trigger_match is not None and trigger_match.group(2) in LIFECYCLE_TABLES:
            entries.append(("trigger", trigger_match.group(1), normalized))
    return tuple(sorted(entries))


_EXPECTED_SQLITE_CATALOG_SQL: Final = _expected_sqlite_catalog_sql()
_V11_ALTERED_LIFECYCLE_TABLES: Final[frozenset[str]] = frozenset(
    {
        "logical_executions",
        "execution_attempts",
        "execution_actor_authority_revisions",
        "campaign_execution_authority_revisions",
        "execution_operation_receipts",
    }
)


def _validate_sqlite_catalog_sql(rows: Sequence[Any]) -> None:
    observed = tuple(
        sorted(
            (
                str(row[0]),
                str(row[1]),
                _normalized_sql(row[2]),
            )
            for row in rows
        )
    )
    if observed != _EXPECTED_SQLITE_CATALOG_SQL:
        raise RuntimeError("Incompatible execution lifecycle schema")


def _validate_sqlite_v11_base_catalog_sql(rows: Sequence[Any]) -> None:
    """Prove generation-10 objects untouched except the five v11-altered tables."""
    expected = tuple(
        entry
        for entry in _EXPECTED_SQLITE_CATALOG_SQL
        if not (entry[0] == "table" and entry[1] in _V11_ALTERED_LIFECYCLE_TABLES)
    )
    observed = tuple(
        sorted(
            (
                str(row[0]),
                str(row[1]),
                _normalized_sql(row[2]),
            )
            for row in rows
            if not (str(row[0]) == "table" and str(row[1]) in _V11_ALTERED_LIFECYCLE_TABLES)
        )
    )
    if observed != expected:
        raise RuntimeError("Incompatible execution lifecycle schema")


def _sqlite_create_table_items(create_sql: object) -> tuple[str, ...]:
    """Split a SQLite CREATE TABLE body without treating nested commas as separators."""
    if type(create_sql) is not str:
        return ()
    source = _normalized_sql(create_sql)
    opening = source.find("(")
    if opening < 0:
        return ()
    items: list[str] = []
    start = opening + 1
    depth = 0
    quoted = False
    index = start
    while index < len(source):
        character = source[index]
        if character == "'":
            if quoted and index + 1 < len(source) and source[index + 1] == "'":
                index += 1
            else:
                quoted = not quoted
        elif not quoted:
            if character == "(":
                depth += 1
            elif character == ")":
                if depth == 0:
                    items.append(source[start:index].strip())
                    return tuple(items)
                depth -= 1
            elif character == "," and depth == 0:
                items.append(source[start:index].strip())
                start = index + 1
        index += 1
    return ()


def _validate_sqlite_v11_altered_table_catalog_sql(rows: Sequence[Any]) -> None:
    """Validate v10 portions of ALTERed tables and the rebuilt v11 receipt table."""
    observed = {
        str(row[1]): row[2]
        for row in rows
        if str(row[0]) == "table" and str(row[1]) in _V11_ALTERED_LIFECYCLE_TABLES
    }
    if set(observed) != _V11_ALTERED_LIFECYCLE_TABLES:
        raise RuntimeError("Incompatible execution lifecycle schema")
    expected = {
        str(name): sql
        for kind, name, sql in _EXPECTED_SQLITE_CATALOG_SQL
        if kind == "table" and name in _V11_ALTERED_LIFECYCLE_TABLES
    }
    if set(expected) != _V11_ALTERED_LIFECYCLE_TABLES:
        raise RuntimeError("Incompatible execution lifecycle schema")

    for table in _V11_ALTERED_LIFECYCLE_TABLES - {"execution_operation_receipts"}:
        expected_items = _sqlite_create_table_items(expected[table])
        observed_items = _sqlite_create_table_items(observed[table])
        expected_columns = tuple(
            item for item in expected_items if not item.startswith("CONSTRAINT ")
        )
        observed_columns = tuple(
            item for item in observed_items if not item.startswith("CONSTRAINT ")
        )
        if observed_columns[: len(expected_columns)] != expected_columns:
            raise RuntimeError("Incompatible execution lifecycle schema")
        expected_constraints = {
            match.group(1): item
            for item in expected_items
            if (match := re.match(r"CONSTRAINT ([a-z0-9_]+) ", item)) is not None
        }
        observed_constraints = {
            match.group(1): item
            for item in observed_items
            if (match := re.match(r"CONSTRAINT ([a-z0-9_]+) ", item)) is not None
        }
        if any(observed_constraints.get(name) != item for name, item in expected_constraints.items()):
            raise RuntimeError("Incompatible execution lifecycle schema")

    if _normalized_sql(observed["execution_operation_receipts"]) != _normalized_sql(
        _v11_receipt_create_statement("sqlite")
    ):
        raise RuntimeError("Incompatible execution lifecycle schema")


def validate_sqlite_lifecycle_catalog_rows(rows: Sequence[Any]) -> None:
    """Validate pre-fetched SQLite catalog rows against the exact generation-10 DDL."""
    _validate_sqlite_catalog_sql(rows)


def validate_sqlite_lifecycle_catalog(connection: Any) -> None:
    if sqlite_catalog_names(connection) != tuple(sorted(LIFECYCLE_TABLES)):
        raise RuntimeError("Incompatible execution lifecycle schema")
    row = connection.execute(
        "SELECT mode,revision,catalog_digest,activation_revision,activation_at FROM execution_gateway_state WHERE singleton_id=1"
    ).fetchone()
    if row != ("disabled", 0, None, None, None):
        raise RuntimeError("Incompatible execution lifecycle schema")
    triggers = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ("
        + ",".join("?" for _ in LIFECYCLE_TABLES)
        + ") ORDER BY name",
        LIFECYCLE_TABLES,
    ).fetchall()
    if tuple(str(item[0]) for item in triggers) != (
        "trg_eor_immutable_delete",
        "trg_eor_immutable_update",
    ):
        raise RuntimeError("Incompatible execution lifecycle schema")
    names = tuple(name for _, name, _ in _EXPECTED_SQLITE_CATALOG_SQL)
    rows = connection.execute(
        "SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND ("
        "name IN ("
        + ",".join("?" for _ in names)
        + ") OR tbl_name IN ("
        + ",".join("?" for _ in LIFECYCLE_TABLES)
        + ")) ORDER BY type,name",
        names + LIFECYCLE_TABLES,
    ).fetchall()
    v11_tables = {
        str(item[0])
        for item in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name IN ("
            + ",".join("?" for _ in V11_AUTHORITY_TABLES)
            + ")",
            V11_AUTHORITY_TABLES,
        ).fetchall()
    }
    if v11_tables:
        if v11_tables != set(V11_AUTHORITY_TABLES):
            raise RuntimeError("Incompatible execution lifecycle schema")
        _validate_sqlite_v11_base_catalog_sql(rows)
        _validate_sqlite_v11_altered_table_catalog_sql(rows)
    else:
        _validate_sqlite_catalog_sql(rows)


async def validate_sqlite_lifecycle_catalog_async(connection: Any) -> None:
    placeholders = ",".join("?" for _ in LIFECYCLE_TABLES)
    async with connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name IN ("
        + placeholders
        + ") ORDER BY name",
        LIFECYCLE_TABLES,
    ) as cursor:
        rows = await cursor.fetchall()
    if tuple(str(row[0]) for row in rows) != tuple(sorted(LIFECYCLE_TABLES)):
        raise RuntimeError("Incompatible execution lifecycle schema")
    async with connection.execute(
        "SELECT mode,revision,catalog_digest,activation_revision,activation_at "
        "FROM execution_gateway_state WHERE singleton_id=1"
    ) as cursor:
        row = await cursor.fetchone()
    if row is None or tuple(row) != ("disabled", 0, None, None, None):
        raise RuntimeError("Incompatible execution lifecycle schema")
    async with connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ("
        + placeholders
        + ") ORDER BY name",
        LIFECYCLE_TABLES,
    ) as cursor:
        triggers = await cursor.fetchall()
    if tuple(str(item[0]) for item in triggers) != (
        "trg_eor_immutable_delete",
        "trg_eor_immutable_update",
    ):
        raise RuntimeError("Incompatible execution lifecycle schema")
    names = tuple(name for _, name, _ in _EXPECTED_SQLITE_CATALOG_SQL)
    async with connection.execute(
        "SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND ("
        "name IN ("
        + ",".join("?" for _ in names)
        + ") OR tbl_name IN ("
        + ",".join("?" for _ in LIFECYCLE_TABLES)
        + ")) ORDER BY type,name",
        names + LIFECYCLE_TABLES,
    ) as cursor:
        catalog_rows = await cursor.fetchall()
    v11_placeholders = ",".join("?" for _ in V11_AUTHORITY_TABLES)
    async with connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name IN (" + v11_placeholders + ")",
        V11_AUTHORITY_TABLES,
    ) as cursor:
        v11_rows = await cursor.fetchall()
    v11_tables = {str(item[0]) for item in v11_rows}
    if v11_tables:
        if v11_tables != set(V11_AUTHORITY_TABLES):
            raise RuntimeError("Incompatible execution lifecycle schema")
        _validate_sqlite_v11_base_catalog_sql(catalog_rows)
        _validate_sqlite_v11_altered_table_catalog_sql(catalog_rows)
    else:
        _validate_sqlite_catalog_sql(catalog_rows)


async def validate_postgresql_lifecycle_catalog(connection: Any) -> None:
    if not _POSTGRES_CATALOG_FINGERPRINT_V1:
        raise RuntimeError("Incompatible execution lifecycle schema")
    v11_rows = await connection.fetch(
        "SELECT c.relname FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[])",
        list(V11_AUTHORITY_TABLES),
    )
    v11_tables = {str(row["relname"]) for row in v11_rows}
    if v11_tables:
        if v11_tables != set(V11_AUTHORITY_TABLES):
            raise RuntimeError("Incompatible execution lifecycle schema")
        try:
            await validate_postgresql_admission_authority_catalog(connection)
        except RuntimeError as error:
            raise RuntimeError("Incompatible execution lifecycle schema") from error
        return

    facts_sql = _POSTGRES_CATALOG_FACTS_SQL.replace(
        "__NAMES__", "CAST($1 AS text[])"
    ).replace("__BASE_NAMES__", "CAST($2 AS text[])")
    fact_rows = await connection.fetch(
        facts_sql,
        list(LIFECYCLE_TABLES),
        list(_POSTGRES_BASE_CANDIDATE_INDEX_NAMES),
    )
    if postgresql_catalog_fingerprint(tuple(str(row["fact"]) for row in fact_rows)) != (
        _POSTGRES_CATALOG_FINGERPRINT_V1
    ):
        raise RuntimeError("Incompatible execution lifecycle schema")


_V11_EXISTING_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "logical_executions": (
        "admission_authority_contract_version",
        "canonical_principal_user_id",
        "immutable_intent_digest",
        "immutable_work_digest",
    ),
    "execution_attempts": (
        "authority_contract_version",
        "trusted_principal_subject_ref",
        "trusted_principal_user_id",
        "immutable_intent_digest",
        "immutable_work_digest",
        "gateway_revision",
        "gateway_activation_revision",
        "campaign_actor_grant_revision",
        "destination_authority_binding_digest",
        "credential_authority_binding_digest",
        "approval_authority_binding_digest",
    ),
    "execution_actor_authority_revisions": (
        "authority_state",
        "authority_revision",
        "authority_binding_digest",
        "authority_latest_operation_id",
        "authority_latest_operation_base_revision",
        "authority_latest_operation_code",
    ),
    "campaign_execution_authority_revisions": (
        "authority_state",
        "authority_revision",
        "authority_binding_digest",
        "authority_latest_operation_id",
        "authority_latest_operation_base_revision",
        "authority_latest_operation_code",
    ),
    "credentials": (
        "execution_authority_state",
        "execution_authority_revision",
        "execution_authority_binding_digest",
        "execution_authority_latest_operation_id",
        "execution_authority_latest_operation_base_revision",
        "execution_authority_latest_operation_code",
    ),
}

_V11_NEW_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "campaign_execution_actor_grants": (
        "campaign_id",
        "actor_user_id",
        "authority_state",
        "revision",
        "binding_digest",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "created_at",
        "updated_at",
    ),
    "campaign_execution_destination_authorities": (
        "campaign_id",
        "authority_state",
        "revision",
        "normalization_version",
        "destination_count",
        "destination_set_digest",
        "binding_digest",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "created_at",
        "updated_at",
    ),
    "execution_approval_authorities": (
        "id",
        "approval_ref",
        "campaign_id",
        "submission_id",
        "attempt_id",
        "actor_subject_ref",
        "actor_user_id",
        "module_id",
        "approver_subject_ref",
        "approver_user_id",
        "authority_state",
        "revision",
        "granted_capability_mask",
        "descriptor_semantic_digest",
        "binding_digest",
        "latest_operation_id",
        "latest_operation_base_revision",
        "latest_operation_code",
        "created_at",
        "updated_at",
        "consumed_at",
    ),
    "execution_attempt_destination_observations": (
        "attempt_id",
        "campaign_id",
        "ordinal",
        "destination_ref_digest",
        "authority_revision",
        "normalization_version",
        "observed_at",
    ),
    "execution_attempt_credential_observations": (
        "attempt_id",
        "campaign_id",
        "ordinal",
        "credential_id",
        "authority_revision",
        "binding_digest",
        "observed_at",
    ),
}

_V11_ADDED_COLUMN_PROPERTIES: Final[dict[str, dict[str, tuple[str, bool, str | None]]]] = {
    "logical_executions": {
        "admission_authority_contract_version": ("integer", False, "2"),
        "canonical_principal_user_id": ("text", True, None),
        "immutable_intent_digest": ("text", True, None),
        "immutable_work_digest": ("text", True, None),
    },
    "execution_attempts": {
        "authority_contract_version": ("integer", False, "2"),
        "trusted_principal_subject_ref": ("text", True, None),
        "trusted_principal_user_id": ("text", True, None),
        "immutable_intent_digest": ("text", True, None),
        "immutable_work_digest": ("text", True, None),
        "gateway_revision": ("integer", True, None),
        "gateway_activation_revision": ("integer", True, None),
        "campaign_actor_grant_revision": ("integer", True, None),
        "destination_authority_binding_digest": ("text", True, None),
        "credential_authority_binding_digest": ("text", True, None),
        "approval_authority_binding_digest": ("text", True, None),
    },
    "execution_actor_authority_revisions": {
        "authority_state": ("text", False, "active"),
        "authority_revision": ("integer", False, "0"),
        "authority_binding_digest": ("text", False, "0" * 64),
        "authority_latest_operation_id": ("text", True, None),
        "authority_latest_operation_base_revision": ("integer", True, None),
        "authority_latest_operation_code": ("text", True, None),
    },
    "campaign_execution_authority_revisions": {
        "authority_state": ("text", False, "active"),
        "authority_revision": ("integer", False, "0"),
        "authority_binding_digest": ("text", False, "0" * 64),
        "authority_latest_operation_id": ("text", True, None),
        "authority_latest_operation_base_revision": ("integer", True, None),
        "authority_latest_operation_code": ("text", True, None),
    },
    "credentials": {
        "execution_authority_state": ("text", False, "active"),
        "execution_authority_revision": ("integer", False, "0"),
        "execution_authority_binding_digest": ("text", False, "0" * 64),
        "execution_authority_latest_operation_id": ("text", True, None),
        "execution_authority_latest_operation_base_revision": ("integer", True, None),
        "execution_authority_latest_operation_code": ("text", True, None),
    },
}

_V11_NEW_COLUMN_PROPERTIES: Final[dict[str, dict[str, tuple[str, bool, str | None]]]] = {
    "campaign_execution_actor_grants": {
        "campaign_id": ("text", False, None),
        "actor_user_id": ("text", False, None),
        "authority_state": ("text", False, None),
        "revision": ("integer", False, "0"),
        "binding_digest": ("text", False, None),
        "latest_operation_id": ("text", False, None),
        "latest_operation_base_revision": ("integer", False, None),
        "latest_operation_code": ("text", False, None),
        "created_at": ("integer", False, "$epoch_ms"),
        "updated_at": ("integer", False, "$epoch_ms"),
    },
    "campaign_execution_destination_authorities": {
        "campaign_id": ("text", False, None),
        "authority_state": ("text", False, None),
        "revision": ("integer", False, "0"),
        "normalization_version": ("integer", False, None),
        "destination_count": ("integer", False, None),
        "destination_set_digest": ("text", False, None),
        "binding_digest": ("text", False, None),
        "latest_operation_id": ("text", False, None),
        "latest_operation_base_revision": ("integer", False, None),
        "latest_operation_code": ("text", False, None),
        "created_at": ("integer", False, "$epoch_ms"),
        "updated_at": ("integer", False, "$epoch_ms"),
    },
    "execution_approval_authorities": {
        "id": ("text", False, None),
        "approval_ref": ("text", False, None),
        "campaign_id": ("text", False, None),
        "submission_id": ("text", False, None),
        "attempt_id": ("text", False, None),
        "actor_subject_ref": ("text", False, None),
        "actor_user_id": ("text", False, None),
        "module_id": ("text", False, None),
        "approver_subject_ref": ("text", False, None),
        "approver_user_id": ("text", True, None),
        "authority_state": ("text", False, None),
        "revision": ("integer", False, "0"),
        "granted_capability_mask": ("integer", False, None),
        "descriptor_semantic_digest": ("text", False, None),
        "binding_digest": ("text", False, None),
        "latest_operation_id": ("text", False, None),
        "latest_operation_base_revision": ("integer", False, None),
        "latest_operation_code": ("text", False, None),
        "created_at": ("integer", False, "$epoch_ms"),
        "updated_at": ("integer", False, "$epoch_ms"),
        "consumed_at": ("integer", True, None),
    },
    "execution_attempt_destination_observations": {
        "attempt_id": ("text", False, None),
        "campaign_id": ("text", False, None),
        "ordinal": ("integer", False, None),
        "destination_ref_digest": ("text", False, None),
        "authority_revision": ("integer", False, None),
        "normalization_version": ("integer", False, None),
        "observed_at": ("integer", False, "$epoch_ms"),
    },
    "execution_attempt_credential_observations": {
        "attempt_id": ("text", False, None),
        "campaign_id": ("text", False, None),
        "ordinal": ("integer", False, None),
        "credential_id": ("text", False, None),
        "authority_revision": ("integer", False, None),
        "binding_digest": ("text", False, None),
        "observed_at": ("integer", False, "$epoch_ms"),
    },
}

# Independent semantic catalog authority.  These facts are intentionally
# literal and do not reuse the migration DDL or its generators.
_V11_CONSTRAINT_FACTS: Final[dict[str, dict[str, object]]] = {
    "campaign_execution_actor_grants": {
        "primary": {"pk_ceag": ("campaign_id", "actor_user_id")},
        "unique": {},
        "checks": {
            "ck_ceag_ids": ("campaign_id", "actor_user_id", "latest_operation_id", "0-9a-f"),
            "ck_ceag_digest": ("binding_digest", "64", "0-9a-f"),
            "ck_ceag_shape": (
                "authority_state",
                "active",
                "revoked",
                "revision",
                "9007199254740991",
                "latest_operation_base_revision",
                "latest_operation_code",
                "put",
                "revoke",
                "created_at",
                "updated_at",
            ),
        },
        "foreign": {
            "fk_ceag_campaign": (
                ("campaign_id",),
                "campaigns",
                ("id",),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
            "fk_ceag_actor": (
                ("actor_user_id",),
                "users",
                ("id",),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
        },
    },
    "campaign_execution_destination_authorities": {
        "primary": {"pk_ceda": ("campaign_id",)},
        "unique": {},
        "checks": {
            "ck_ceda_ids": ("campaign_id", "latest_operation_id", "0-9a-f"),
            "ck_ceda_digests": (
                "destination_set_digest",
                "binding_digest",
                "64",
                "0-9a-f",
            ),
            "ck_ceda_shape": (
                "authority_state",
                "active",
                "revoked",
                "revision",
                "normalization_version",
                "destination_count",
                "4096",
                "latest_operation_base_revision",
                "latest_operation_code",
                "update",
                "revoke",
                "created_at",
                "updated_at",
            ),
        },
        "foreign": {
            "fk_ceda_campaign": (
                ("campaign_id",),
                "campaigns",
                ("id",),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
        },
    },
    "execution_approval_authorities": {
        "primary": {"pk_eapa": ("id",)},
        "unique": {
            "uq_eapa_ref": ("approval_ref",),
            "uq_eapa_attempt": ("attempt_id",),
        },
        "checks": {
            "ck_eapa_ids": (
                "id",
                "approval_ref",
                "campaign_id",
                "submission_id",
                "attempt_id",
                "actor_subject_ref",
                "actor_user_id",
                "approver_subject_ref",
                "approver_user_id",
                "latest_operation_id",
                "0-9a-f",
            ),
            "ck_eapa_module": ("module_id", "128", "a-z"),
            "ck_eapa_digests": (
                "descriptor_semantic_digest",
                "binding_digest",
                "64",
                "0-9a-f",
            ),
            "ck_eapa_shape": (
                "authority_state",
                "active",
                "revoked",
                "consumed",
                "revision",
                "granted_capability_mask",
                "15",
                "latest_operation_base_revision",
                "latest_operation_code",
                "grant",
                "revoke",
                "consume",
                "consumed_at",
                "created_at",
                "updated_at",
            ),
        },
        "foreign": {
            "fk_eapa_campaign": (
                ("campaign_id",),
                "campaigns",
                ("id",),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
            "fk_eapa_approver": (
                ("approver_user_id",),
                "users",
                ("id",),
                "NO ACTION",
                "SET NULL",
                True,
                True,
            ),
        },
    },
    "execution_attempt_destination_observations": {
        "primary": {"pk_eado": ("attempt_id", "ordinal")},
        "unique": {
            "uq_eado_attempt_destination": ("attempt_id", "destination_ref_digest"),
        },
        "checks": {
            "ck_eado_ids": ("attempt_id", "campaign_id", "0-9a-f"),
            "ck_eado_ref": ("destination_ref_digest", "64", "0-9a-f"),
            "ck_eado_shape": (
                "ordinal",
                "4095",
                "authority_revision",
                "9007199254740991",
                "normalization_version",
                "observed_at",
            ),
        },
        "foreign": {
            "fk_eado_attempt": (
                ("campaign_id", "attempt_id"),
                "execution_attempts",
                ("campaign_id", "id"),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
        },
    },
    "execution_attempt_credential_observations": {
        "primary": {"pk_eaco": ("attempt_id", "ordinal")},
        "unique": {
            "uq_eaco_attempt_credential": ("attempt_id", "credential_id"),
        },
        "checks": {
            "ck_eaco_ids": ("attempt_id", "campaign_id", "credential_id", "0-9a-f"),
            "ck_eaco_digest": ("binding_digest", "64", "0-9a-f"),
            "ck_eaco_shape": (
                "ordinal",
                "4095",
                "authority_revision",
                "9007199254740991",
                "observed_at",
            ),
        },
        "foreign": {
            "fk_eaco_attempt": (
                ("campaign_id", "attempt_id"),
                "execution_attempts",
                ("campaign_id", "id"),
                "NO ACTION",
                "NO ACTION",
                True,
                True,
            ),
        },
    },
}

_V11_INDEX_FACTS: Final[dict[str, tuple[str, bool, tuple[str, ...], str | None]]] = {
    "uq_ceag_latest_operation": (
        "campaign_execution_actor_grants",
        True,
        ("latest_operation_id",),
        None,
    ),
    "ix_ceag_actor_state": (
        "campaign_execution_actor_grants",
        False,
        ("actor_user_id", "authority_state", "campaign_id"),
        None,
    ),
    "uq_ceda_latest_operation": (
        "campaign_execution_destination_authorities",
        True,
        ("latest_operation_id",),
        None,
    ),
    "uq_eapa_latest_operation": (
        "execution_approval_authorities",
        True,
        ("latest_operation_id",),
        None,
    ),
    "ix_eapa_campaign_state": (
        "execution_approval_authorities",
        False,
        ("campaign_id", "authority_state", "id"),
        None,
    ),
    "ix_eado_campaign_attempt": (
        "execution_attempt_destination_observations",
        False,
        ("campaign_id", "attempt_id", "ordinal"),
        None,
    ),
    "ix_eaco_campaign_attempt": (
        "execution_attempt_credential_observations",
        False,
        ("campaign_id", "attempt_id", "ordinal"),
        None,
    ),
    "ix_credentials_execution_authority": (
        "credentials",
        False,
        ("campaign_id", "execution_authority_state", "id"),
        None,
    ),
}

_V11_EXISTING_CHECK_REQUIREMENTS: Final[dict[str, dict[str, tuple[str, ...]]]] = {
    "logical_executions": {
        "admission_authority_contract_version": ("admission_authority_contract_version", "2", "3"),
        "canonical_principal_user_id": ("canonical_principal_user_id", "isnull", "0-9a-f"),
        "immutable_intent_digest": ("immutable_intent_digest", "isnull", "64", "0-9a-f"),
        "immutable_work_digest": ("immutable_work_digest", "isnull", "64", "0-9a-f"),
    },
    "execution_attempts": {
        "authority_contract_version": ("authority_contract_version", "2", "3"),
        "trusted_principal_subject_ref": ("trusted_principal_subject_ref", "isnull", "0-9a-f"),
        "trusted_principal_user_id": ("trusted_principal_user_id", "isnull", "0-9a-f"),
        "immutable_intent_digest": ("immutable_intent_digest", "isnull", "64", "0-9a-f"),
        "immutable_work_digest": ("immutable_work_digest", "isnull", "64", "0-9a-f"),
        "gateway_revision": ("gateway_revision", "isnull", "9007199254740991"),
        "gateway_activation_revision": (
            "gateway_activation_revision",
            "isnull",
            "9007199254740991",
        ),
        "campaign_actor_grant_revision": (
            "campaign_actor_grant_revision",
            "isnull",
            "9007199254740991",
        ),
        "destination_authority_binding_digest": (
            "destination_authority_binding_digest",
            "isnull",
            "64",
            "0-9a-f",
        ),
        "credential_authority_binding_digest": (
            "credential_authority_binding_digest",
            "isnull",
            "64",
            "0-9a-f",
        ),
        "approval_authority_binding_digest": (
            "approval_authority_binding_digest",
            "isnull",
            "64",
            "0-9a-f",
        ),
    },
    "execution_actor_authority_revisions": {
        "authority_state": ("authority_state", "active", "revoked"),
        "authority_revision": ("authority_revision", "9007199254740991"),
        "authority_binding_digest": ("authority_binding_digest", "64", "0-9a-f"),
        "authority_latest_operation_id": ("authority_latest_operation_id", "isnull", "0-9a-f"),
        "authority_latest_operation_base_revision": (
            "authority_latest_operation_base_revision",
            "isnull",
            "9007199254740991",
        ),
        "authority_latest_operation_code": (
            "authority_latest_operation_code",
            "isnull",
            "activate",
            "update",
            "revoke",
        ),
    },
    "campaign_execution_authority_revisions": {
        "authority_state": ("authority_state", "active", "revoked"),
        "authority_revision": ("authority_revision", "9007199254740991"),
        "authority_binding_digest": ("authority_binding_digest", "64", "0-9a-f"),
        "authority_latest_operation_id": ("authority_latest_operation_id", "isnull", "0-9a-f"),
        "authority_latest_operation_base_revision": (
            "authority_latest_operation_base_revision",
            "isnull",
            "9007199254740991",
        ),
        "authority_latest_operation_code": (
            "authority_latest_operation_code",
            "isnull",
            "activate",
            "update",
            "revoke",
        ),
    },
    "credentials": {
        "execution_authority_state": ("execution_authority_state", "active", "revoked"),
        "execution_authority_revision": (
            "execution_authority_revision",
            "9007199254740991",
        ),
        "execution_authority_binding_digest": (
            "execution_authority_binding_digest",
            "64",
            "0-9a-f",
        ),
        "execution_authority_latest_operation_id": (
            "execution_authority_latest_operation_id",
            "isnull",
            "0-9a-f",
        ),
        "execution_authority_latest_operation_base_revision": (
            "execution_authority_latest_operation_base_revision",
            "isnull",
            "9007199254740991",
        ),
        "execution_authority_latest_operation_code": (
            "execution_authority_latest_operation_code",
            "isnull",
            "update",
            "revoke",
        ),
    },
}


def _validate_v11_columns(rows: Sequence[Any]) -> None:
    observed: dict[str, list[str]] = {}
    for row in rows:
        table = str(row[0])
        observed.setdefault(table, []).append(str(row[1]))
    for table, expected in _V11_EXISTING_COLUMNS.items():
        columns = tuple(observed.get(table, ()))
        if not columns or columns[-len(expected) :] != expected:
            raise RuntimeError("Incompatible admission authority schema")
    for table, expected in _V11_NEW_COLUMNS.items():
        if tuple(observed.get(table, ())) != expected:
            raise RuntimeError("Incompatible admission authority schema")


def _validate_v11_column_properties(rows: Sequence[Any], dialect: str) -> None:
    observed = {
        (str(row[0]), str(row[1])): (
            str(row[2]).lower(),
            (not bool(row[3])) if dialect == "sqlite" else str(row[3]) == "YES",
            None if row[4] is None else str(row[4]),
        )
        for row in rows
    }
    expected_tables = _V11_ADDED_COLUMN_PROPERTIES | _V11_NEW_COLUMN_PROPERTIES
    for table, columns in expected_tables.items():
        for column, (kind, nullable, default) in columns.items():
            actual = observed.get((table, column))
            expected_kind = "bigint" if dialect == "postgresql" and kind == "integer" else kind
            if actual is None or actual[:2] != (expected_kind, nullable):
                raise RuntimeError("Incompatible admission authority schema")
            actual_default = actual[2]
            if default is None:
                if actual_default is not None:
                    raise RuntimeError("Incompatible admission authority schema")
            elif default == "$epoch_ms":
                normalized_default = (
                    "" if actual_default is None else "".join(actual_default.lower().split())
                )
                required = (
                    ("julianday('now')", "2440587.5", "86400000")
                    if dialect == "sqlite"
                    else ("extract(epochfromclock_timestamp())", "1000")
                )
                if not all(token in normalized_default for token in required):
                    raise RuntimeError("Incompatible admission authority schema")
            elif kind == "text":
                expected_default = (
                    f"'{default}'::text" if dialect == "postgresql" else f"'{default}'"
                )
                if actual_default != expected_default:
                    raise RuntimeError("Incompatible admission authority schema")
            elif actual_default != default:
                raise RuntimeError("Incompatible admission authority schema")


def _balanced_check_expressions(create_sql: object) -> tuple[str, ...]:
    if type(create_sql) is not str:
        return ()
    source = create_sql
    lowered = source.lower()
    expressions: list[str] = []
    offset = 0
    while True:
        index = lowered.find("check", offset)
        if index < 0:
            break
        cursor = index + 5
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "(":
            offset = cursor
            continue
        depth = 0
        quote: str | None = None
        while cursor < len(source):
            character = source[cursor]
            if quote is not None:
                if character == quote:
                    if cursor + 1 < len(source) and source[cursor + 1] == quote:
                        cursor += 2
                        continue
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    expressions.append(source[index : cursor + 1])
                    cursor += 1
                    break
            cursor += 1
        if depth != 0 or quote is not None:
            return ()
        offset = cursor
    return tuple(expressions)


def _normalized_catalog_expression(value: object) -> str:
    return (
        "".join(str(value).lower().replace('"', "").split())
        .replace("::text", "")
        .replace("::bigint", "")
    )


def _validate_check_requirements(
    definitions: Sequence[object],
    requirements: dict[str, tuple[str, ...]],
) -> None:
    normalized = tuple(_normalized_catalog_expression(value) for value in definitions)
    if len(normalized) != len(requirements):
        raise RuntimeError("Incompatible admission authority schema")
    for requirement in requirements.values():
        matches = [value for value in normalized if all(token in value for token in requirement)]
        if len(matches) != 1 or "ortrue" in matches[0]:
            raise RuntimeError("Incompatible admission authority schema")


def _named_sqlite_constraints(create_sql: object) -> dict[str, tuple[str, str]]:
    if type(create_sql) is not str:
        return {}
    source = create_sql
    matches = tuple(
        re.finditer(
            r"\bCONSTRAINT\s+([a-z0-9_]+)\s+"
            r"(PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b",
            source,
            re.I,
        )
    )
    result: dict[str, tuple[str, str]] = {}
    for index, match in enumerate(matches):
        name = match.group(1).lower()
        kind = " ".join(match.group(2).lower().split())
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        if name in result:
            return {}
        result[name] = (kind, source[match.start() : end])
    return result


def _parenthesized_columns(fragment: str, marker: str) -> tuple[str, ...]:
    normalized = " ".join(fragment.lower().replace('"', "").split())
    match = re.search(re.escape(marker) + r"\s*\(([^()]*)\)", normalized)
    if match is None:
        return ()
    return tuple(item.strip() for item in match.group(1).split(","))


def _validate_sqlite_v11_semantics(
    schema_rows: Sequence[Any],
    index_rows: Sequence[Any],
    foreign_key_rows: Sequence[Any],
) -> None:
    table_sql = {
        str(row[1]): row[3]
        for row in schema_rows
        if str(row[0]) == "table" and str(row[1]) in _V11_NEW_COLUMNS
    }
    if set(table_sql) != set(_V11_NEW_COLUMNS):
        raise RuntimeError("Incompatible admission authority schema")

    explicit_expected = {
        name: fact for name, fact in _V11_INDEX_FACTS.items() if fact[0] in _V11_NEW_COLUMNS
    }
    explicit_observed = {
        str(row[1])
        for row in schema_rows
        if str(row[0]) == "index" and str(row[2]) in _V11_NEW_COLUMNS and row[3] is not None
    }
    if explicit_observed != set(explicit_expected):
        raise RuntimeError("Incompatible admission authority schema")
    if any(str(row[0]) == "trigger" and str(row[2]) in _V11_NEW_COLUMNS for row in schema_rows):
        raise RuntimeError("Incompatible admission authority schema")

    for table, facts in _V11_CONSTRAINT_FACTS.items():
        constraints = _named_sqlite_constraints(table_sql[table])
        expected_kinds = {
            **dict.fromkeys(facts["primary"], "primary key"),
            **dict.fromkeys(facts["unique"], "unique"),
            **dict.fromkeys(facts["checks"], "check"),
            **dict.fromkeys(facts["foreign"], "foreign key"),
        }
        if {name: value[0] for name, value in constraints.items()} != expected_kinds:
            raise RuntimeError("Incompatible admission authority schema")
        for name, columns in facts["primary"].items():
            observed_columns = _parenthesized_columns(constraints[name][1], "primary key")
            inline_singleton = (
                len(columns) == 1
                and not observed_columns
                and "primarykey" in _normalized_catalog_expression(constraints[name][1])
            )
            if not inline_singleton and observed_columns != columns:
                raise RuntimeError("Incompatible admission authority schema")
        for name, columns in facts["unique"].items():
            if _parenthesized_columns(constraints[name][1], "unique") != columns:
                raise RuntimeError("Incompatible admission authority schema")
        _validate_check_requirements(
            tuple(constraints[name][1] for name in facts["checks"]),
            facts["checks"],
        )
        for name, expected in facts["foreign"].items():
            local, referenced_table, referenced, on_update, on_delete, deferred, initially = (
                expected
            )
            fragment = _normalized_catalog_expression(constraints[name][1])
            required = (
                "foreignkey(" + ",".join(local) + ")",
                "references" + referenced_table + "(" + ",".join(referenced) + ")",
                "onupdate" + on_update.lower().replace(" ", ""),
                "ondelete" + on_delete.lower().replace(" ", ""),
            )
            if not all(token in fragment for token in required):
                raise RuntimeError("Incompatible admission authority schema")
            if deferred != ("deferrable" in fragment) or initially != (
                "initiallydeferred" in fragment
            ):
                raise RuntimeError("Incompatible admission authority schema")

    grouped_indexes: dict[str, list[Any]] = {}
    for row in index_rows:
        grouped_indexes.setdefault(str(row[1]), []).append(row)
    for name, (table, unique, columns, predicate) in _V11_INDEX_FACTS.items():
        rows = grouped_indexes.get(name, [])
        if (
            len(rows) != len(columns)
            or any(str(row[0]) != table for row in rows)
            or bool(rows[0][2]) is not unique
            or any(str(row[3]) != "c" or bool(row[4]) for row in rows)
            or tuple(str(row[6]) for row in sorted(rows, key=lambda value: int(value[5])))
            != columns
            or predicate is not None
        ):
            raise RuntimeError("Incompatible admission authority schema")

    expected_backing = {
        table: sorted(
            tuple(columns)
            for columns in tuple(facts["primary"].values()) + tuple(facts["unique"].values())
        )
        for table, facts in _V11_CONSTRAINT_FACTS.items()
    }
    observed_backing: dict[str, list[tuple[str, ...]]] = {
        table: [] for table in _V11_CONSTRAINT_FACTS
    }
    backing_groups: dict[tuple[str, str], list[Any]] = {}
    for row in index_rows:
        if str(row[0]) in _V11_CONSTRAINT_FACTS and str(row[3]) in {"pk", "u"}:
            backing_groups.setdefault((str(row[0]), str(row[1])), []).append(row)
    for (table, _), rows in backing_groups.items():
        observed_backing[table].append(
            tuple(str(row[6]) for row in sorted(rows, key=lambda value: int(value[5])))
        )
    if any(
        sorted(observed_backing[table]) != expected for table, expected in expected_backing.items()
    ):
        raise RuntimeError("Incompatible admission authority schema")

    fk_groups: dict[tuple[str, int], list[Any]] = {}
    for row in foreign_key_rows:
        fk_groups.setdefault((str(row[0]), int(row[1])), []).append(row)
    observed_foreign: dict[str, list[tuple[object, ...]]] = {
        table: [] for table in _V11_CONSTRAINT_FACTS
    }
    for (table, _), rows in fk_groups.items():
        ordered = sorted(rows, key=lambda value: int(value[2]))
        observed_foreign[table].append(
            (
                tuple(str(row[4]) for row in ordered),
                str(ordered[0][3]),
                tuple(str(row[5]) for row in ordered),
                str(ordered[0][6]).upper(),
                str(ordered[0][7]).upper(),
            )
        )
    for table, facts in _V11_CONSTRAINT_FACTS.items():
        expected = sorted(tuple(value[:5]) for value in facts["foreign"].values())
        if sorted(observed_foreign[table]) != expected:
            raise RuntimeError("Incompatible admission authority schema")


def _validate_v11_existing_checks(table_sql: dict[str, object]) -> None:
    for table, requirements in _V11_EXISTING_CHECK_REQUIREMENTS.items():
        expressions = _balanced_check_expressions(table_sql.get(table))
        selected = tuple(
            expression
            for expression in expressions
            if any(column in expression.lower() for column in requirements)
        )
        _validate_check_requirements(selected, requirements)


def _row_value(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError):
        return getattr(row, key)


def _postgres_action(code: object) -> str:
    actions = {
        "a": "NO ACTION",
        "r": "RESTRICT",
        "c": "CASCADE",
        "n": "SET NULL",
        "d": "SET DEFAULT",
    }
    try:
        return actions[str(code)]
    except KeyError as error:
        raise RuntimeError("Incompatible admission authority schema") from error


def _validate_postgresql_v11_semantics(
    relation_rows: Sequence[Any],
    collation_rows: Sequence[Any],
    constraint_rows: Sequence[Any],
    index_rows: Sequence[Any],
    existing_check_rows: Sequence[Any],
) -> None:
    campaign_relations = {
        str(_row_value(row, "table_name")): str(_row_value(row, "relkind"))
        for row in relation_rows
        if str(_row_value(row, "table_name")).startswith("campaign_execution_")
    }
    if campaign_relations != dict.fromkeys(
        _V11_RESERVED_CAMPAIGN_EXECUTION_RELATIONS,
        "r",
    ):
        raise RuntimeError("Incompatible admission authority schema")
    relations = {
        str(_row_value(row, "table_name")): (
            str(_row_value(row, "relkind")),
            str(_row_value(row, "relpersistence")),
            bool(_row_value(row, "relispartition")),
            bool(_row_value(row, "relrowsecurity")),
            bool(_row_value(row, "relforcerowsecurity")),
            int(_row_value(row, "user_trigger_count")),
            int(_row_value(row, "policy_count")),
            int(_row_value(row, "user_rule_count")),
        )
        for row in relation_rows
        if str(_row_value(row, "table_name")) in V11_AUTHORITY_TABLES
    }
    if relations != dict.fromkeys(
        _V11_NEW_COLUMNS,
        ("r", "p", False, False, False, 0, 0, 0),
    ):
        raise RuntimeError("Incompatible admission authority schema")

    observed_collations = {
        (
            str(_row_value(row, "table_name")),
            str(_row_value(row, "column_name")),
        ): bool(_row_value(row, "collation_is_default"))
        for row in collation_rows
    }
    expected_collations = {
        (table, column)
        for table, columns in (_V11_EXISTING_COLUMNS | _V11_NEW_COLUMNS).items()
        for column in columns
    }
    if any(not observed_collations.get(key, False) for key in expected_collations):
        raise RuntimeError("Incompatible admission authority schema")

    observed_constraints: dict[str, dict[str, Any]] = {table: {} for table in _V11_CONSTRAINT_FACTS}
    for row in constraint_rows:
        table = str(_row_value(row, "table_name"))
        name = str(_row_value(row, "constraint_name"))
        if name in observed_constraints[table]:
            raise RuntimeError("Incompatible admission authority schema")
        observed_constraints[table][name] = row
    for table, facts in _V11_CONSTRAINT_FACTS.items():
        expected_types = {
            **dict.fromkeys(facts["primary"], "p"),
            **dict.fromkeys(facts["unique"], "u"),
            **dict.fromkeys(facts["checks"], "c"),
            **dict.fromkeys(facts["foreign"], "f"),
        }
        rows = observed_constraints[table]
        if set(rows) != set(expected_types) or any(
            str(_row_value(rows[name], "constraint_type")) != kind
            for name, kind in expected_types.items()
        ):
            raise RuntimeError("Incompatible admission authority schema")
        for name, columns in {**facts["primary"], **facts["unique"]}.items():
            row = rows[name]
            if tuple(_row_value(row, "local_columns") or ()) != columns:
                raise RuntimeError("Incompatible admission authority schema")
        _validate_check_requirements(
            tuple(_row_value(rows[name], "definition") for name in facts["checks"]),
            facts["checks"],
        )
        for name, expected in facts["foreign"].items():
            row = rows[name]
            local, referenced_table, referenced, on_update, on_delete, deferred, initially = (
                expected
            )
            actual = (
                tuple(_row_value(row, "local_columns") or ()),
                str(_row_value(row, "referenced_table")),
                tuple(_row_value(row, "referenced_columns") or ()),
                _postgres_action(_row_value(row, "update_action")),
                _postgres_action(_row_value(row, "delete_action")),
                bool(_row_value(row, "is_deferrable")),
                bool(_row_value(row, "is_deferred")),
            )
            if actual != expected or not bool(_row_value(row, "is_validated")):
                raise RuntimeError("Incompatible admission authority schema")

    expected_indexes: dict[str, tuple[str, bool, bool, tuple[str, ...]]] = {}
    for table, facts in _V11_CONSTRAINT_FACTS.items():
        expected_indexes.update(
            {name: (table, True, True, columns) for name, columns in facts["primary"].items()}
        )
        expected_indexes.update(
            {name: (table, True, False, columns) for name, columns in facts["unique"].items()}
        )
    expected_indexes.update(
        {
            name: (table, unique, False, columns)
            for name, (table, unique, columns, _) in _V11_INDEX_FACTS.items()
        }
    )
    observed_indexes = {str(_row_value(row, "index_name")): row for row in index_rows}
    if set(observed_indexes) != set(expected_indexes):
        raise RuntimeError("Incompatible admission authority schema")
    for name, expected in expected_indexes.items():
        row = observed_indexes[name]
        actual = (
            str(_row_value(row, "table_name")),
            bool(_row_value(row, "is_unique")),
            bool(_row_value(row, "is_primary")),
            tuple(_row_value(row, "key_columns") or ()),
        )
        if (
            actual != expected
            or str(_row_value(row, "method")) != "btree"
            or _row_value(row, "predicate") is not None
            or bool(_row_value(row, "has_expressions"))
            or not bool(_row_value(row, "is_valid"))
            or not bool(_row_value(row, "is_ready"))
        ):
            raise RuntimeError("Incompatible admission authority schema")

    observed_existing: dict[str, list[object]] = {
        table: [] for table in _V11_EXISTING_CHECK_REQUIREMENTS
    }
    observed_columns: dict[str, list[tuple[str, ...]]] = {
        table: [] for table in _V11_EXISTING_CHECK_REQUIREMENTS
    }
    for row in existing_check_rows:
        table = str(_row_value(row, "table_name"))
        observed_existing[table].append(_row_value(row, "definition"))
        observed_columns[table].append(tuple(_row_value(row, "local_columns") or ()))
    for table, requirements in _V11_EXISTING_CHECK_REQUIREMENTS.items():
        if sorted(observed_columns[table]) != sorted((column,) for column in requirements):
            raise RuntimeError("Incompatible admission authority schema")
        _validate_check_requirements(observed_existing[table], requirements)


def _validate_v11_credential_checks(definitions: Sequence[object]) -> None:
    normalized = tuple("".join(str(value).lower().split()) for value in definitions)
    requirements = (
        ("execution_authority_state", "active", "revoked"),
        ("execution_authority_revision", "between0and9007199254740991"),
        ("execution_authority_binding_digest", "64", "0-9a-f"),
        ("execution_authority_latest_operation_id", "isnull", "36", "0-9a-f"),
        (
            "execution_authority_latest_operation_base_revision",
            "isnull",
            "between0and9007199254740991",
        ),
        ("execution_authority_latest_operation_code", "isnull", "update", "revoke"),
    )
    if len(normalized) != len(requirements):
        raise RuntimeError("Incompatible admission authority schema")
    for requirement in requirements:
        matches = [value for value in normalized if all(token in value for token in requirement)]
        if len(matches) != 1 or "ortrue" in matches[0]:
            raise RuntimeError("Incompatible admission authority schema")


def validate_sqlite_admission_authority_catalog(connection: Any) -> None:
    campaign_relations = connection.execute(
        "SELECT type,name FROM sqlite_schema WHERE type IN ('table','view') "
        "AND name GLOB 'campaign_execution_*' ORDER BY type,name"
    ).fetchall()
    if {(str(row[0]), str(row[1])) for row in campaign_relations} != {
        ("table", name) for name in _V11_RESERVED_CAMPAIGN_EXECUTION_RELATIONS
    }:
        raise RuntimeError("Incompatible admission authority schema")
    rows = connection.execute(
        'SELECT m.name,p.name,p.type,p."notnull",p.dflt_value '
        "FROM sqlite_schema AS m JOIN pragma_table_info(m.name) AS p "
        "WHERE m.type='table' AND m.name IN ("
        + ",".join("?" for _ in tuple(_V11_EXISTING_COLUMNS) + V11_AUTHORITY_TABLES)
        + ") ORDER BY m.name,p.cid",
        tuple(_V11_EXISTING_COLUMNS) + V11_AUTHORITY_TABLES,
    ).fetchall()
    _validate_v11_columns(rows)
    _validate_v11_column_properties(rows, "sqlite")
    catalog_rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE "
        "(tbl_name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES)
        + ") OR name IN ("
        + ",".join("?" for _ in _V11_EXISTING_CHECK_REQUIREMENTS)
        + ")) ORDER BY type,name",
        V11_AUTHORITY_TABLES + tuple(_V11_EXISTING_CHECK_REQUIREMENTS),
    ).fetchall()
    index_rows = connection.execute(
        'SELECT m.name,il.name,il."unique",il.origin,il.partial,xi.seqno,xi.name '
        "FROM sqlite_schema AS m JOIN pragma_index_list(m.name) AS il "
        "JOIN pragma_index_xinfo(il.name) AS xi WHERE m.type='table' "
        "AND m.name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES + ("credentials",))
        + ") AND xi.key=1 ORDER BY m.name,il.name,xi.seqno",
        V11_AUTHORITY_TABLES + ("credentials",),
    ).fetchall()
    foreign_rows = connection.execute(
        'SELECT m.name,f.id,f.seq,f."table",f."from",f."to",f.on_update,f.on_delete '
        "FROM sqlite_schema AS m JOIN pragma_foreign_key_list(m.name) AS f "
        "WHERE m.type='table' AND m.name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES)
        + ") ORDER BY m.name,f.id,f.seq",
        V11_AUTHORITY_TABLES,
    ).fetchall()
    _validate_sqlite_v11_semantics(catalog_rows, index_rows, foreign_rows)
    _validate_v11_existing_checks(
        {str(row[1]): row[3] for row in catalog_rows if str(row[0]) == "table"}
    )
    receipt = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='execution_operation_receipts'"
    ).fetchone()
    if receipt is None or not all(code in str(receipt[0]) for code in V11_OPERATION_CODES):
        raise RuntimeError("Incompatible admission authority schema")
    triggers = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='trigger' "
        "AND tbl_name='execution_operation_receipts' ORDER BY name"
    ).fetchall()
    if tuple(str(row[0]) for row in triggers) != (
        "trg_eor_immutable_delete",
        "trg_eor_immutable_update",
    ):
        raise RuntimeError("Incompatible admission authority schema")
    credential_sql = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='credentials'"
    ).fetchone()
    if credential_sql is None:
        raise RuntimeError("Incompatible admission authority schema")
    checks = tuple(
        expression
        for expression in _balanced_check_expressions(credential_sql[0])
        if "execution_authority_" in expression.lower()
    )
    _validate_v11_credential_checks(checks)


async def validate_sqlite_admission_authority_catalog_async(connection: Any) -> None:
    async with connection.execute(
        "SELECT type,name FROM sqlite_schema WHERE type IN ('table','view') "
        "AND name GLOB 'campaign_execution_*' ORDER BY type,name"
    ) as cursor:
        campaign_relations = await cursor.fetchall()
    if {(str(row[0]), str(row[1])) for row in campaign_relations} != {
        ("table", name) for name in _V11_RESERVED_CAMPAIGN_EXECUTION_RELATIONS
    }:
        raise RuntimeError("Incompatible admission authority schema")
    placeholders = ",".join("?" for _ in tuple(_V11_EXISTING_COLUMNS) + V11_AUTHORITY_TABLES)
    async with connection.execute(
        'SELECT m.name,p.name,p.type,p."notnull",p.dflt_value '
        "FROM sqlite_schema AS m JOIN pragma_table_info(m.name) AS p "
        "WHERE m.type='table' AND m.name IN (" + placeholders + ") ORDER BY m.name,p.cid",
        tuple(_V11_EXISTING_COLUMNS) + V11_AUTHORITY_TABLES,
    ) as cursor:
        rows = await cursor.fetchall()
    _validate_v11_columns(rows)
    _validate_v11_column_properties(rows, "sqlite")
    async with connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE "
        "(tbl_name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES)
        + ") OR name IN ("
        + ",".join("?" for _ in _V11_EXISTING_CHECK_REQUIREMENTS)
        + ")) ORDER BY type,name",
        V11_AUTHORITY_TABLES + tuple(_V11_EXISTING_CHECK_REQUIREMENTS),
    ) as cursor:
        catalog_rows = await cursor.fetchall()
    async with connection.execute(
        'SELECT m.name,il.name,il."unique",il.origin,il.partial,xi.seqno,xi.name '
        "FROM sqlite_schema AS m JOIN pragma_index_list(m.name) AS il "
        "JOIN pragma_index_xinfo(il.name) AS xi WHERE m.type='table' "
        "AND m.name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES + ("credentials",))
        + ") AND xi.key=1 ORDER BY m.name,il.name,xi.seqno",
        V11_AUTHORITY_TABLES + ("credentials",),
    ) as cursor:
        index_rows = await cursor.fetchall()
    async with connection.execute(
        'SELECT m.name,f.id,f.seq,f."table",f."from",f."to",f.on_update,f.on_delete '
        "FROM sqlite_schema AS m JOIN pragma_foreign_key_list(m.name) AS f "
        "WHERE m.type='table' AND m.name IN ("
        + ",".join("?" for _ in V11_AUTHORITY_TABLES)
        + ") ORDER BY m.name,f.id,f.seq",
        V11_AUTHORITY_TABLES,
    ) as cursor:
        foreign_rows = await cursor.fetchall()
    _validate_sqlite_v11_semantics(catalog_rows, index_rows, foreign_rows)
    _validate_v11_existing_checks(
        {str(row[1]): row[3] for row in catalog_rows if str(row[0]) == "table"}
    )
    async with connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='execution_operation_receipts'"
    ) as cursor:
        receipt = await cursor.fetchone()
    if receipt is None or not all(code in str(receipt[0]) for code in V11_OPERATION_CODES):
        raise RuntimeError("Incompatible admission authority schema")
    async with connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='trigger' "
        "AND tbl_name='execution_operation_receipts' ORDER BY name"
    ) as cursor:
        triggers = await cursor.fetchall()
    if tuple(str(row[0]) for row in triggers) != (
        "trg_eor_immutable_delete",
        "trg_eor_immutable_update",
    ):
        raise RuntimeError("Incompatible admission authority schema")
    async with connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='credentials'"
    ) as cursor:
        credential_sql = await cursor.fetchone()
    if credential_sql is None:
        raise RuntimeError("Incompatible admission authority schema")
    checks = tuple(
        expression
        for expression in _balanced_check_expressions(credential_sql[0])
        if "execution_authority_" in expression.lower()
    )
    _validate_v11_credential_checks(checks)


async def validate_postgresql_admission_authority_catalog(connection: Any) -> None:
    tables = list(tuple(_V11_EXISTING_COLUMNS) + V11_AUTHORITY_TABLES)
    rows = await connection.fetch(
        "SELECT table_name,column_name,data_type,is_nullable,column_default "
        "FROM information_schema.columns WHERE table_schema=current_schema() "
        "AND table_name=ANY($1::text[]) ORDER BY table_name,ordinal_position",
        tables,
    )
    properties = tuple(
        (
            row["table_name"],
            row["column_name"],
            row["data_type"],
            row["is_nullable"],
            row["column_default"],
        )
        for row in rows
    )
    _validate_v11_columns(properties)
    _validate_v11_column_properties(properties, "postgresql")
    relation_rows = await connection.fetch(
        "SELECT c.relname AS table_name,c.relkind::text AS relkind,"
        "c.relpersistence::text AS relpersistence,c.relispartition,"
        "c.relrowsecurity,c.relforcerowsecurity,"
        "(SELECT count(*) FROM pg_trigger t WHERE t.tgrelid=c.oid "
        "AND NOT t.tgisinternal) AS user_trigger_count,"
        "(SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid) AS policy_count,"
        "(SELECT count(*) FROM pg_rewrite r WHERE r.ev_class=c.oid "
        "AND r.rulename<>'_RETURN') AS user_rule_count FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND c.relkind IN ('r','p','v','m','f') AND ("
        "c.relname=ANY($1::text[]) OR "
        "c.relname LIKE 'campaign$_execution$_%' ESCAPE '$') ORDER BY c.relname",
        list(V11_AUTHORITY_TABLES),
    )
    collation_rows = await connection.fetch(
        "SELECT c.relname AS table_name,a.attname AS column_name,"
        "a.attcollation=t.typcollation AS collation_is_default FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_attribute a ON a.attrelid=c.oid "
        "JOIN pg_type t ON t.oid=a.atttypid WHERE n.nspname=current_schema() "
        "AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped "
        "ORDER BY c.relname,a.attnum",
        tables,
    )
    constraint_rows = await connection.fetch(
        "SELECT c.relname AS table_name,con.conname AS constraint_name,"
        "con.contype::text AS constraint_type,"
        "ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum,ord) "
        "JOIN pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=k.attnum "
        "ORDER BY k.ord) AS local_columns,rc.relname AS referenced_table,"
        "ARRAY(SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum,ord) "
        "JOIN pg_attribute a ON a.attrelid=con.confrelid AND a.attnum=k.attnum "
        "ORDER BY k.ord) AS referenced_columns,"
        "con.confupdtype::text AS update_action,"
        "con.confdeltype::text AS delete_action,"
        "con.condeferrable AS is_deferrable,"
        "con.condeferred AS is_deferred,con.convalidated AS is_validated,"
        "pg_get_expr(con.conbin,con.conrelid,false) AS definition "
        "FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "LEFT JOIN pg_class rc ON rc.oid=con.confrelid "
        "WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[]) "
        "ORDER BY c.relname,con.conname",
        list(V11_AUTHORITY_TABLES),
    )
    index_rows = await connection.fetch(
        "SELECT c.relname AS table_name,ic.relname AS index_name,i.indisunique AS is_unique,"
        "i.indisprimary AS is_primary,i.indisvalid AS is_valid,i.indisready AS is_ready,"
        "am.amname AS method,pg_get_expr(i.indpred,i.indrelid,false) AS predicate,"
        "i.indexprs IS NOT NULL AS has_expressions,"
        "ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum,ord) "
        "JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum "
        "WHERE k.ord<=i.indnkeyatts ORDER BY k.ord) AS key_columns "
        "FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class ic ON ic.oid=i.indexrelid "
        "JOIN pg_am am ON am.oid=ic.relam WHERE n.nspname=current_schema() "
        "AND (c.relname=ANY($1::text[]) OR ic.relname='ix_credentials_execution_authority') "
        "ORDER BY ic.relname",
        list(V11_AUTHORITY_TABLES),
    )
    existing_check_rows = await connection.fetch(
        "SELECT c.relname AS table_name,"
        "ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum,ord) "
        "JOIN pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=k.attnum "
        "ORDER BY k.ord) AS local_columns,pg_get_expr(con.conbin,con.conrelid,false) AS definition "
        "FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND con.contype='c' AND c.relname=ANY($1::text[]) "
        "AND con.conkey <@ ARRAY(SELECT a.attnum FROM pg_attribute a "
        "WHERE a.attrelid=c.oid AND a.attname=ANY($2::text[])) "
        "ORDER BY c.relname,con.conname",
        list(_V11_EXISTING_CHECK_REQUIREMENTS),
        sorted(
            {column for columns in _V11_EXISTING_CHECK_REQUIREMENTS.values() for column in columns}
        ),
    )
    _validate_postgresql_v11_semantics(
        relation_rows,
        collation_rows,
        constraint_rows,
        index_rows,
        existing_check_rows,
    )
    definitions = await connection.fetch(
        "SELECT con.conname,pg_get_constraintdef(con.oid,true) AS definition "
        "FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND c.relname='execution_operation_receipts' "
        "AND con.conname IN ('ck_eor_operation_code','ck_eor_operation_shape')",
    )
    if len(definitions) != 2 or not all(
        all(code in str(row["definition"]) for code in V11_ADDITIVE_OPERATION_CODES)
        for row in definitions
        if row["conname"] == "ck_eor_operation_code"
    ):
        raise RuntimeError("Incompatible admission authority schema")


__all__ = [
    "ADMISSION_AUTHORITY_CONTRACT_V2",
    "ADMISSION_AUTHORITY_CONTRACT_V3",
    "ACTOR_ROLES",
    "AdmissionRequest",
    "AdmissionIntentV3",
    "ActorAuthorityMutation",
    "ApprovalBinding",
    "ApprovalAuthorityGrant",
    "ApprovalAuthorityMutation",
    "AttemptState",
    "AttemptPolicySnapshot",
    "BudgetConfiguration",
    "BudgetReservation",
    "BudgetSettlement",
    "CampaignActorGrantMutation",
    "CampaignAuthorityMutation",
    "ClosureRequest",
    "CAPABILITY_BITS_V1",
    "DESCRIPTOR_BLOCKER_BITS_V1",
    "DESCRIPTOR_CONTRACT_VERSION",
    "DESTINATION_NORMALIZATION_VERSION",
    "DestinationAuthorityMutation",
    "CredentialAuthorityMutation",
    "ExecutionLifecycleStore",
    "FixedResult",
    "GATEWAY_AUTHORITY_TARGET_ID",
    "GatewayAuthorityMutation",
    "LEGAL_TRANSITIONS",
    "LEGACY_SCHEMA_VERSION",
    "LIFECYCLE_TABLES",
    "MAX_I53",
    "MAX_TERMINAL_OUTPUTS_V3",
    "OperationResult",
    "OutcomeCode",
    "OutputKind",
    "OutputObservation",
    "OutboxMutation",
    "POSTGRES_LIFECYCLE_DDL",
    "POSTGRES_ADMISSION_AUTHORITY_V11_DDL",
    "POLICY_CONTRACT_VERSION",
    "PolicyReasonBit",
    "REQUEST_CONTRACT_VERSION",
    "RetryRequest",
    "RetryIntentV3",
    "RUNTIME_GENERATION",
    "RUNTIME_GENERATION_V11",
    "SYSTEM_PRINCIPAL_SUBJECT_REF",
    "SQLITE_LIFECYCLE_DDL",
    "SQLITE_ADMISSION_AUTHORITY_V11_DDL",
    "TransitionRequest",
    "TrustedPrincipal",
    "TerminalCommitRequest",
    "TerminalCommitIntentV3",
    "TERMINAL_COMMIT_CONTRACT_VERSION_V3",
    "canonical_operation_binding_digest",
    "admission_authority_v11_ddl",
    "lifecycle_ddl",
    "postgresql_catalog_fingerprint",
    "retry_delay_ms",
    "sqlite_lifecycle_script",
    "sqlite_lifecycle_runtime_script",
    "sqlite_admission_authority_runtime_script",
    "valid_uuid",
    "validate_sqlite_lifecycle_catalog",
    "validate_sqlite_lifecycle_catalog_async",
    "validate_sqlite_lifecycle_catalog_rows",
    "validate_postgresql_lifecycle_catalog",
    "validate_postgresql_admission_authority_catalog",
    "validate_sqlite_admission_authority_catalog",
    "validate_sqlite_admission_authority_catalog_async",
    "V11_ADDITIVE_OPERATION_CODES",
    "V11_AUTHORITY_TABLES",
    "V11_OPERATION_CODES",
    "validate_transition_request",
]
