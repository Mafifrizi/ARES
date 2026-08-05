"""Independent contract tests for the pure offline execution-policy kernel."""

# Tuple-valued case tables are immutable test-oracle data.
# ruff: noqa: PT007

from __future__ import annotations

import ast
import builtins
import importlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ares.core.execution_policy import (
    CONTRACT_VERSION_V1,
    MAX_REQUEST_SHAPE_UNITS_V1,
    ApprovalPolicy,
    AuthorityFactsV1,
    BlockerBits,
    CapabilityBits,
    DescriptorFactsV1,
    EvaluationMode,
    NoiseClass,
    PolicyDecisionV1,
    PolicyInputV1,
    PolicyReason,
    PolicyVerdict,
    RequestFactsV1,
    RoleRank,
    evaluate_policy,
)

ROOT = Path(__file__).resolve().parents[2]
KERNEL_PATH = ROOT / "ares" / "core" / "execution_policy.py"


def _request(*, mode: EvaluationMode = EvaluationMode.LIVE) -> RequestFactsV1:
    return RequestFactsV1(
        contract_version=CONTRACT_VERSION_V1,
        mode=mode,
        structure_valid=True,
        canonicalization_complete=True,
        unknown_fields_absent=True,
        alternate_transport_absent=True,
        bounded_shape_valid=True,
        shape_units=8,
    )


def _descriptor(
    *,
    preview_ready: bool = True,
    live_ready: bool = True,
    blocker_bits: BlockerBits = BlockerBits.NONE,
) -> DescriptorFactsV1:
    return DescriptorFactsV1(
        contract_version=CONTRACT_VERSION_V1,
        trusted_first_party_binding=True,
        descriptor_binding_current=True,
        descriptor_complete=True,
        static_policy_evaluable=True,
        minimum_role=RoleRank.OPERATOR,
        noise_class=NoiseClass.MEDIUM,
        approval_policy=ApprovalPolicy.NONE,
        required_capabilities=CapabilityBits.NETWORK | CapabilityBits.FILESYSTEM,
        blocker_bits=blocker_bits,
        preview_ready=preview_ready,
        lifecycle_ready=live_ready,
        result_authority_ready=live_ready,
        transport_ready=live_ready,
        future_gateway_eligible=live_ready and blocker_bits == BlockerBits.NONE,
    )


def _authority() -> AuthorityFactsV1:
    return AuthorityFactsV1(
        contract_version=CONTRACT_VERSION_V1,
        required_snapshots_complete=True,
        revisions_current=True,
        actor_authenticated=True,
        actor_active=True,
        actor_role=RoleRank.ADMIN,
        campaign_active=True,
        actor_campaign_authorized=True,
        approval_present=True,
        approval_current=True,
        approval_exactly_bound=True,
        granted_capabilities=(
            CapabilityBits.NETWORK
            | CapabilityBits.EXECUTION
            | CapabilityBits.FILESYSTEM
            | CapabilityBits.PROCESS
        ),
        destination_extraction_complete=True,
        destinations_in_scope=True,
        credential_authority_resolved=True,
        credential_authority_current=True,
        opaque_handles_only=True,
        permitted_handle_kinds_only=True,
        raw_credentials_absent=True,
        ambient_credentials_absent=True,
        budget_authority_resolved=True,
        budget_authority_current=True,
        budget_capacity_available=True,
    )


def _policy_input(
    *,
    request: RequestFactsV1 | None = None,
    descriptor: DescriptorFactsV1 | None = None,
    authority: AuthorityFactsV1 | None = None,
) -> PolicyInputV1:
    return PolicyInputV1(
        request=request if request is not None else _request(),
        descriptor=descriptor if descriptor is not None else _descriptor(),
        authority=authority if authority is not None else _authority(),
    )


def _outcome(decision: PolicyDecisionV1) -> tuple[PolicyVerdict, tuple[PolicyReason, ...]]:
    return decision.verdict, decision.reasons


def _assert_outcome(
    decision: PolicyDecisionV1,
    verdict: PolicyVerdict,
    reasons: tuple[PolicyReason, ...],
) -> None:
    assert decision.verdict is verdict, "fixed verdict mismatch"
    assert decision.reasons == reasons, "fixed reason order mismatch"


REQUEST_FIELDS = (
    "contract_version",
    "mode",
    "structure_valid",
    "canonicalization_complete",
    "unknown_fields_absent",
    "alternate_transport_absent",
    "bounded_shape_valid",
    "shape_units",
)
DESCRIPTOR_FIELDS = (
    "contract_version",
    "trusted_first_party_binding",
    "descriptor_binding_current",
    "descriptor_complete",
    "static_policy_evaluable",
    "minimum_role",
    "noise_class",
    "approval_policy",
    "required_capabilities",
    "blocker_bits",
    "preview_ready",
    "lifecycle_ready",
    "result_authority_ready",
    "transport_ready",
    "future_gateway_eligible",
)
AUTHORITY_FIELDS = (
    "contract_version",
    "required_snapshots_complete",
    "revisions_current",
    "actor_authenticated",
    "actor_active",
    "actor_role",
    "campaign_active",
    "actor_campaign_authorized",
    "approval_present",
    "approval_current",
    "approval_exactly_bound",
    "granted_capabilities",
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


@pytest.mark.parametrize("field_name", REQUEST_FIELDS, ids=REQUEST_FIELDS)
def test_request_field_wrong_exact_type_is_rejected(field_name: str) -> None:
    candidate = _policy_input(request=replace(_request(), **{field_name: None}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize("field_name", DESCRIPTOR_FIELDS, ids=DESCRIPTOR_FIELDS)
def test_descriptor_field_wrong_exact_type_is_rejected(field_name: str) -> None:
    candidate = _policy_input(descriptor=replace(_descriptor(), **{field_name: None}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize("field_name", AUTHORITY_FIELDS, ids=AUTHORITY_FIELDS)
def test_authority_field_wrong_exact_type_is_rejected(field_name: str) -> None:
    candidate = _policy_input(authority=replace(_authority(), **{field_name: None}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("request", None),
        ("descriptor", None),
        ("authority", None),
    ),
    ids=("request", "descriptor", "authority"),
)
def test_aggregate_field_wrong_record_type_is_rejected(
    field_name: str,
    value: object,
) -> None:
    candidate = replace(_policy_input(), **{field_name: value})
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    "candidate",
    (None, {}, (), object()),
    ids=("none", "mapping", "tuple", "object"),
)
def test_wrong_top_level_type_is_rejected(candidate: object) -> None:
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


class _InputSubclass(PolicyInputV1):
    __slots__ = ()


class _RequestSubclass(RequestFactsV1):
    __slots__ = ()


class _IntSubclass(int):
    pass


def test_top_level_subclass_is_rejected() -> None:
    pristine = _policy_input()
    candidate = _InputSubclass(
        request=pristine.request,
        descriptor=pristine.descriptor,
        authority=pristine.authority,
    )
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


def test_nested_record_subclass_is_rejected() -> None:
    pristine = _request()
    candidate_request = _RequestSubclass(
        **{field.name: getattr(pristine, field.name) for field in fields(pristine)}
    )
    _assert_outcome(
        evaluate_policy(_policy_input(request=candidate_request)),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("record_name", "field_name"),
    (
        ("request", "contract_version"),
        ("descriptor", "contract_version"),
        ("authority", "contract_version"),
        ("request", "shape_units"),
    ),
    ids=(
        "request-version",
        "descriptor-version",
        "authority-version",
        "shape-units",
    ),
)
def test_integer_subclass_is_rejected(record_name: str, field_name: str) -> None:
    if record_name == "request":
        request = replace(_request(), **{field_name: _IntSubclass(1)})
        candidate = _policy_input(request=request)
    elif record_name == "descriptor":
        candidate = _policy_input(
            descriptor=replace(_descriptor(), **{field_name: _IntSubclass(1)})
        )
    else:
        candidate = _policy_input(authority=replace(_authority(), **{field_name: _IntSubclass(1)}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("contract_version", True),
        ("shape_units", False),
        ("structure_valid", 1),
        ("canonicalization_complete", 1),
        ("unknown_fields_absent", 1),
        ("alternate_transport_absent", 1),
        ("bounded_shape_valid", 1),
    ),
    ids=(
        "version-bool",
        "shape-bool",
        "structure-int",
        "canonical-int",
        "unknown-int",
        "transport-int",
        "bounded-int",
    ),
)
def test_bool_integer_coercion_is_rejected(field_name: str, value: object) -> None:
    candidate = _policy_input(request=replace(_request(), **{field_name: value}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    "shape_units",
    (-1, MAX_REQUEST_SHAPE_UNITS_V1 + 1),
    ids=("negative", "oversized"),
)
def test_shape_bounds_are_rejected(shape_units: int) -> None:
    candidate = _policy_input(request=replace(_request(), shape_units=shape_units))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("record_name", "version"),
    (("request", 2), ("descriptor", 2), ("authority", 2)),
    ids=("request", "descriptor", "authority"),
)
def test_wrong_record_version_is_rejected(record_name: str, version: int) -> None:
    if record_name == "request":
        candidate = _policy_input(request=replace(_request(), contract_version=version))
    elif record_name == "descriptor":
        candidate = _policy_input(descriptor=replace(_descriptor(), contract_version=version))
    else:
        candidate = _policy_input(authority=replace(_authority(), contract_version=version))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("record_name", "field_name", "substitute"),
    (
        ("request", "mode", RoleRank.ADMIN),
        ("descriptor", "minimum_role", NoiseClass.HIGH_NOISE),
        ("descriptor", "noise_class", ApprovalPolicy.NONE),
        ("descriptor", "approval_policy", EvaluationMode.LIVE),
        ("descriptor", "required_capabilities", BlockerBits.NONE),
        ("descriptor", "blocker_bits", CapabilityBits.NONE),
        ("authority", "actor_role", EvaluationMode.LIVE),
        ("authority", "granted_capabilities", BlockerBits.NONE),
    ),
    ids=(
        "mode",
        "minimum-role",
        "noise",
        "approval",
        "required-capabilities",
        "blockers",
        "actor-role",
        "granted-capabilities",
    ),
)
def test_enum_substitution_is_rejected(
    record_name: str,
    field_name: str,
    substitute: EnumLike,
) -> None:
    if record_name == "request":
        candidate = _policy_input(request=replace(_request(), **{field_name: substitute}))
    elif record_name == "descriptor":
        candidate = _policy_input(descriptor=replace(_descriptor(), **{field_name: substitute}))
    else:
        candidate = _policy_input(authority=replace(_authority(), **{field_name: substitute}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


EnumLike = EvaluationMode | RoleRank | NoiseClass | ApprovalPolicy | CapabilityBits | BlockerBits


@pytest.mark.parametrize(
    ("record_name", "field_name", "value"),
    (
        ("descriptor", "required_capabilities", CapabilityBits(1 << 4)),
        ("authority", "granted_capabilities", CapabilityBits(1 << 4)),
        ("descriptor", "blocker_bits", BlockerBits(1 << 9)),
    ),
    ids=("required-capability", "granted-capability", "blocker"),
)
def test_unknown_bit_is_rejected(
    record_name: str,
    field_name: str,
    value: CapabilityBits | BlockerBits,
) -> None:
    if record_name == "descriptor":
        candidate = _policy_input(descriptor=replace(_descriptor(), **{field_name: value}))
    else:
        candidate = _policy_input(authority=replace(_authority(), **{field_name: value}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_CONTRACT,),
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "structure_valid",
        "canonicalization_complete",
        "unknown_fields_absent",
        "alternate_transport_absent",
        "bounded_shape_valid",
    ],
    ids=[
        "structure",
        "canonicalization",
        "unknown-fields",
        "alternate-transport",
        "bounded-shape",
    ],
)
def test_each_request_policy_fact_fails_closed(field_name: str) -> None:
    candidate = _policy_input(request=replace(_request(), **{field_name: False}))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INVALID_REQUEST,),
    )


@pytest.mark.parametrize(
    "blocker",
    [
        BlockerBits.AMBIENT_CREDENTIALS_FORBIDDEN,
        BlockerBits.CANCELLATION_OWNERSHIP_UNPROVEN,
        BlockerBits.DYNAMIC_DESTINATION_UNBOUNDED,
        BlockerBits.DEFAULT_FACTORY_UNEVALUATED,
        BlockerBits.LLM_EGRESS_POLICY_REQUIRED,
        BlockerBits.LIFECYCLE_CONTRACT_UNPROVEN,
        BlockerBits.RAW_CREDENTIAL_INPUT,
        BlockerBits.RESULT_AUTHORITY_UNPROVEN,
        BlockerBits.SENSITIVE_NONEMPTY_DEFAULT,
    ],
    ids=[
        "ambient-credentials",
        "cancellation-ownership",
        "dynamic-destination",
        "default-factory",
        "llm-egress",
        "lifecycle-contract",
        "raw-credential-input",
        "result-authority",
        "sensitive-default",
    ],
)
def test_each_known_descriptor_blocker_fails_closed(blocker: BlockerBits) -> None:
    descriptor = _descriptor(live_ready=False, blocker_bits=blocker)
    _assert_outcome(
        evaluate_policy(_policy_input(descriptor=descriptor)),
        PolicyVerdict.BLOCKED,
        (PolicyReason.DESCRIPTOR_BLOCKED,),
    )


INCONSISTENCY_CASES = (
    ("binding-without-trust", "descriptor", {"trusted_first_party_binding": False}),
    ("preview-without-trust", "descriptor", {"trusted_first_party_binding": False}),
    ("preview-without-binding", "descriptor", {"descriptor_binding_current": False}),
    ("preview-without-completeness", "descriptor", {"descriptor_complete": False}),
    ("preview-without-static", "descriptor", {"static_policy_evaluable": False}),
    (
        "eligible-with-blocker",
        "descriptor",
        {"blocker_bits": BlockerBits.LIFECYCLE_CONTRACT_UNPROVEN},
    ),
    ("eligible-without-lifecycle", "descriptor", {"lifecycle_ready": False}),
    ("eligible-without-result", "descriptor", {"result_authority_ready": False}),
    ("eligible-without-transport", "descriptor", {"transport_ready": False}),
    ("approval-current-without-present", "authority", {"approval_present": False}),
    (
        "approval-bound-without-present",
        "authority",
        {"approval_present": False, "approval_current": False},
    ),
    (
        "current-revision-without-snapshots",
        "authority",
        {"required_snapshots_complete": False},
    ),
    ("active-without-authentication", "authority", {"actor_authenticated": False}),
    ("campaign-authority-without-active", "authority", {"campaign_active": False}),
    (
        "credential-current-without-resolution",
        "authority",
        {"credential_authority_resolved": False},
    ),
    (
        "permitted-kinds-without-opaque",
        "authority",
        {"opaque_handles_only": False},
    ),
    ("opaque-with-raw", "authority", {"raw_credentials_absent": False}),
    ("opaque-with-ambient", "authority", {"ambient_credentials_absent": False}),
    (
        "budget-current-without-resolution",
        "authority",
        {"budget_authority_resolved": False},
    ),
)


@pytest.mark.parametrize(
    ("case_id", "record_name", "changes"),
    INCONSISTENCY_CASES,
    ids=tuple(case[0] for case in INCONSISTENCY_CASES),
)
def test_contradictory_facts_are_rejected(
    case_id: str,
    record_name: str,
    changes: dict[str, object],
) -> None:
    del case_id
    if record_name == "descriptor":
        candidate = _policy_input(descriptor=replace(_descriptor(), **changes))
    else:
        candidate = _policy_input(authority=replace(_authority(), **changes))
    _assert_outcome(
        evaluate_policy(candidate),
        PolicyVerdict.REJECTED,
        (PolicyReason.INCONSISTENT_CONTRACT,),
    )


@pytest.mark.parametrize(
    ("case_id", "candidate", "verdict", "reasons"),
    (
        (
            "invalid-request-all",
            _policy_input(
                request=replace(
                    _request(),
                    structure_valid=False,
                    canonicalization_complete=False,
                    unknown_fields_absent=False,
                    alternate_transport_absent=False,
                    bounded_shape_valid=False,
                )
            ),
            PolicyVerdict.REJECTED,
            (PolicyReason.INVALID_REQUEST,),
        ),
        (
            "descriptor-all",
            _policy_input(
                descriptor=replace(
                    _descriptor(),
                    trusted_first_party_binding=False,
                    descriptor_binding_current=False,
                    descriptor_complete=False,
                    static_policy_evaluable=False,
                    preview_ready=False,
                    future_gateway_eligible=False,
                )
            ),
            PolicyVerdict.REJECTED,
            (
                PolicyReason.DESCRIPTOR_UNTRUSTED,
                PolicyReason.DESCRIPTOR_BINDING_INVALID,
                PolicyReason.DESCRIPTOR_INCOMPLETE,
                PolicyReason.STATIC_POLICY_UNAVAILABLE,
            ),
        ),
        (
            "authority-resolution",
            _policy_input(
                authority=replace(
                    _authority(),
                    required_snapshots_complete=False,
                    revisions_current=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.AUTHORITY_RESOLUTION_REQUIRED,),
        ),
        (
            "stale-authority",
            _policy_input(authority=replace(_authority(), revisions_current=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.STALE_AUTHORITY,),
        ),
        (
            "actor-all",
            _policy_input(
                authority=replace(
                    _authority(),
                    actor_authenticated=False,
                    actor_active=False,
                    campaign_active=False,
                    actor_campaign_authorized=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (
                PolicyReason.ACTOR_UNAUTHENTICATED,
                PolicyReason.ACTOR_INACTIVE,
                PolicyReason.CAMPAIGN_INACTIVE,
                PolicyReason.CAMPAIGN_UNAUTHORIZED,
            ),
        ),
        (
            "role",
            _policy_input(
                descriptor=replace(_descriptor(), minimum_role=RoleRank.ADMIN),
                authority=replace(_authority(), actor_role=RoleRank.TEAM_LEAD),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.INSUFFICIENT_ROLE,),
        ),
        (
            "high-noise-role",
            _policy_input(
                descriptor=replace(_descriptor(), noise_class=NoiseClass.HIGH_NOISE),
                authority=replace(_authority(), actor_role=RoleRank.OPERATOR),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.HIGH_NOISE_ROLE_REQUIRED,),
        ),
        (
            "approval-required",
            _policy_input(
                descriptor=replace(_descriptor(), approval_policy=ApprovalPolicy.ATTEMPT_BOUND),
                authority=replace(
                    _authority(),
                    approval_present=False,
                    approval_current=False,
                    approval_exactly_bound=False,
                ),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.APPROVAL_REQUIRED,),
        ),
        (
            "approval-stale",
            _policy_input(
                descriptor=replace(_descriptor(), approval_policy=ApprovalPolicy.ATTEMPT_BOUND),
                authority=replace(
                    _authority(),
                    approval_current=False,
                    approval_exactly_bound=False,
                ),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.APPROVAL_STALE,),
        ),
        (
            "approval-binding",
            _policy_input(
                descriptor=replace(_descriptor(), approval_policy=ApprovalPolicy.ATTEMPT_BOUND),
                authority=replace(_authority(), approval_exactly_bound=False),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.APPROVAL_BINDING_INVALID,),
        ),
        (
            "destination-resolution",
            _policy_input(authority=replace(_authority(), destination_extraction_complete=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.DESTINATION_RESOLUTION_REQUIRED,),
        ),
        (
            "destination-scope",
            _policy_input(authority=replace(_authority(), destinations_in_scope=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.DESTINATION_OUT_OF_SCOPE,),
        ),
        (
            "credential-resolution",
            _policy_input(
                authority=replace(
                    _authority(),
                    credential_authority_resolved=False,
                    credential_authority_current=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.CREDENTIAL_AUTHORITY_REQUIRED,),
        ),
        (
            "credential-stale",
            _policy_input(authority=replace(_authority(), credential_authority_current=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.CREDENTIAL_AUTHORITY_STALE,),
        ),
        (
            "credential-raw",
            _policy_input(
                authority=replace(
                    _authority(),
                    opaque_handles_only=False,
                    permitted_handle_kinds_only=False,
                    raw_credentials_absent=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (
                PolicyReason.RAW_CREDENTIAL_FORBIDDEN,
                PolicyReason.CREDENTIAL_HANDLE_POLICY_VIOLATION,
            ),
        ),
        (
            "credential-ambient",
            _policy_input(
                authority=replace(
                    _authority(),
                    opaque_handles_only=False,
                    permitted_handle_kinds_only=False,
                    ambient_credentials_absent=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (
                PolicyReason.AMBIENT_CREDENTIAL_FORBIDDEN,
                PolicyReason.CREDENTIAL_HANDLE_POLICY_VIOLATION,
            ),
        ),
        (
            "credential-handle",
            _policy_input(
                authority=replace(
                    _authority(),
                    opaque_handles_only=False,
                    permitted_handle_kinds_only=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.CREDENTIAL_HANDLE_POLICY_VIOLATION,),
        ),
        (
            "budget-resolution",
            _policy_input(
                authority=replace(
                    _authority(),
                    budget_authority_resolved=False,
                    budget_authority_current=False,
                )
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.BUDGET_AUTHORITY_REQUIRED,),
        ),
        (
            "budget-stale",
            _policy_input(authority=replace(_authority(), budget_authority_current=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.BUDGET_AUTHORITY_STALE,),
        ),
        (
            "budget-capacity",
            _policy_input(authority=replace(_authority(), budget_capacity_available=False)),
            PolicyVerdict.BLOCKED,
            (PolicyReason.BUDGET_CAPACITY_UNAVAILABLE,),
        ),
        (
            "descriptor-blocker",
            _policy_input(
                descriptor=_descriptor(
                    live_ready=False,
                    blocker_bits=BlockerBits.CANCELLATION_OWNERSHIP_UNPROVEN,
                )
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.DESCRIPTOR_BLOCKED,),
        ),
        (
            "preview-not-ready",
            _policy_input(
                request=_request(mode=EvaluationMode.PREVIEW),
                descriptor=_descriptor(preview_ready=False),
            ),
            PolicyVerdict.BLOCKED,
            (PolicyReason.PREVIEW_NOT_READY,),
        ),
        (
            "live-readiness",
            _policy_input(descriptor=_descriptor(live_ready=False)),
            PolicyVerdict.BLOCKED,
            (
                PolicyReason.LIFECYCLE_NOT_READY,
                PolicyReason.RESULT_AUTHORITY_NOT_READY,
                PolicyReason.TRANSPORT_NOT_READY,
                PolicyReason.FUTURE_GATEWAY_INELIGIBLE,
            ),
        ),
        (
            "preview-ready",
            _policy_input(request=_request(mode=EvaluationMode.PREVIEW)),
            PolicyVerdict.PREVIEW_READY,
            (),
        ),
        (
            "live-candidate",
            _policy_input(),
            PolicyVerdict.LIVE_CANDIDATE,
            (),
        ),
    ),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_literal_decision_cases(
    case_id: str,
    candidate: PolicyInputV1,
    verdict: PolicyVerdict,
    reasons: tuple[PolicyReason, ...],
) -> None:
    del case_id
    _assert_outcome(evaluate_policy(candidate), verdict, reasons)


CAPABILITY_CASES = tuple(
    (CapabilityBits(required), CapabilityBits(granted))
    for required in range(16)
    for granted in range(16)
)


@pytest.mark.parametrize(
    ("required", "granted"),
    CAPABILITY_CASES,
    ids=tuple(
        f"required-{int(required):02d}-granted-{int(granted):02d}"
        for required, granted in CAPABILITY_CASES
    ),
)
def test_all_capability_combinations_use_all_of_semantics(
    required: CapabilityBits,
    granted: CapabilityBits,
) -> None:
    descriptor = replace(_descriptor(), required_capabilities=required)
    authority = replace(_authority(), granted_capabilities=granted)
    decision = evaluate_policy(_policy_input(descriptor=descriptor, authority=authority))
    independently_satisfied = (int(granted) & int(required)) == int(required)
    expected = (
        (PolicyVerdict.LIVE_CANDIDATE, ())
        if independently_satisfied
        else (PolicyVerdict.BLOCKED, (PolicyReason.CAPABILITY_REQUIRED,))
    )
    assert _outcome(decision) == expected, "all-of capability decision mismatch"


@pytest.mark.parametrize(
    ("case_id", "candidate", "first_reason"),
    (
        (
            "invalid-before-request",
            replace(_policy_input(), request=None),
            PolicyReason.INVALID_CONTRACT,
        ),
        (
            "inconsistent-before-request",
            _policy_input(
                request=replace(_request(), structure_valid=False),
                authority=replace(_authority(), approval_present=False),
            ),
            PolicyReason.INCONSISTENT_CONTRACT,
        ),
        (
            "request-before-descriptor",
            _policy_input(
                request=replace(_request(), structure_valid=False),
                descriptor=replace(
                    _descriptor(),
                    descriptor_complete=False,
                    preview_ready=False,
                    future_gateway_eligible=False,
                ),
            ),
            PolicyReason.INVALID_REQUEST,
        ),
        (
            "descriptor-before-authority",
            _policy_input(
                descriptor=replace(
                    _descriptor(),
                    descriptor_complete=False,
                    preview_ready=False,
                    future_gateway_eligible=False,
                ),
                authority=replace(
                    _authority(),
                    required_snapshots_complete=False,
                    revisions_current=False,
                ),
            ),
            PolicyReason.DESCRIPTOR_INCOMPLETE,
        ),
        (
            "authority-before-actor",
            _policy_input(
                authority=replace(
                    _authority(),
                    required_snapshots_complete=False,
                    revisions_current=False,
                    actor_authenticated=False,
                    actor_active=False,
                )
            ),
            PolicyReason.AUTHORITY_RESOLUTION_REQUIRED,
        ),
        (
            "actor-before-access",
            _policy_input(
                descriptor=replace(_descriptor(), minimum_role=RoleRank.ADMIN),
                authority=replace(
                    _authority(),
                    actor_authenticated=False,
                    actor_active=False,
                    actor_role=RoleRank.OPERATOR,
                ),
            ),
            PolicyReason.ACTOR_UNAUTHENTICATED,
        ),
        (
            "access-before-capability",
            _policy_input(
                descriptor=replace(
                    _descriptor(),
                    minimum_role=RoleRank.ADMIN,
                    required_capabilities=CapabilityBits.PROCESS,
                ),
                authority=replace(
                    _authority(),
                    actor_role=RoleRank.OPERATOR,
                    granted_capabilities=CapabilityBits.NONE,
                ),
            ),
            PolicyReason.INSUFFICIENT_ROLE,
        ),
        (
            "capability-before-destination",
            _policy_input(
                descriptor=replace(_descriptor(), required_capabilities=CapabilityBits.PROCESS),
                authority=replace(
                    _authority(),
                    granted_capabilities=CapabilityBits.NONE,
                    destination_extraction_complete=False,
                ),
            ),
            PolicyReason.CAPABILITY_REQUIRED,
        ),
        (
            "destination-before-credential",
            _policy_input(
                authority=replace(
                    _authority(),
                    destination_extraction_complete=False,
                    credential_authority_current=False,
                )
            ),
            PolicyReason.DESTINATION_RESOLUTION_REQUIRED,
        ),
        (
            "credential-before-budget",
            _policy_input(
                authority=replace(
                    _authority(),
                    credential_authority_current=False,
                    budget_authority_current=False,
                )
            ),
            PolicyReason.CREDENTIAL_AUTHORITY_STALE,
        ),
        (
            "budget-before-blocker",
            _policy_input(
                descriptor=_descriptor(
                    live_ready=False,
                    blocker_bits=BlockerBits.RESULT_AUTHORITY_UNPROVEN,
                ),
                authority=replace(_authority(), budget_capacity_available=False),
            ),
            PolicyReason.BUDGET_CAPACITY_UNAVAILABLE,
        ),
        (
            "blocker-before-readiness",
            _policy_input(
                descriptor=_descriptor(
                    live_ready=False,
                    blocker_bits=BlockerBits.RESULT_AUTHORITY_UNPROVEN,
                )
            ),
            PolicyReason.DESCRIPTOR_BLOCKED,
        ),
    ),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_failure_precedence_is_fixed(
    case_id: str,
    candidate: PolicyInputV1,
    first_reason: PolicyReason,
) -> None:
    del case_id
    decision = evaluate_policy(candidate)
    assert decision.reasons[0] is first_reason, "precedence mismatch"


def test_preview_does_not_imply_live_eligibility() -> None:
    descriptor = _descriptor(live_ready=False)
    preview = evaluate_policy(
        _policy_input(request=_request(mode=EvaluationMode.PREVIEW), descriptor=descriptor)
    )
    live = evaluate_policy(_policy_input(descriptor=descriptor))
    _assert_outcome(preview, PolicyVerdict.PREVIEW_READY, ())
    _assert_outcome(
        live,
        PolicyVerdict.BLOCKED,
        (
            PolicyReason.LIFECYCLE_NOT_READY,
            PolicyReason.RESULT_AUTHORITY_NOT_READY,
            PolicyReason.TRANSPORT_NOT_READY,
            PolicyReason.FUTURE_GATEWAY_INELIGIBLE,
        ),
    )


@pytest.mark.parametrize(
    ("field_name", "expected_reasons"),
    [
        (
            "lifecycle_ready",
            (
                PolicyReason.LIFECYCLE_NOT_READY,
                PolicyReason.FUTURE_GATEWAY_INELIGIBLE,
            ),
        ),
        (
            "result_authority_ready",
            (
                PolicyReason.RESULT_AUTHORITY_NOT_READY,
                PolicyReason.FUTURE_GATEWAY_INELIGIBLE,
            ),
        ),
        (
            "transport_ready",
            (
                PolicyReason.TRANSPORT_NOT_READY,
                PolicyReason.FUTURE_GATEWAY_INELIGIBLE,
            ),
        ),
        (
            "future_gateway_eligible",
            (PolicyReason.FUTURE_GATEWAY_INELIGIBLE,),
        ),
    ],
    ids=["lifecycle", "result-authority", "transport", "eligibility"],
)
def test_each_live_readiness_fact_fails_independently(
    field_name: str,
    expected_reasons: tuple[PolicyReason, ...],
) -> None:
    baseline = replace(_descriptor(), future_gateway_eligible=False)
    descriptor = (
        baseline
        if field_name == "future_gateway_eligible"
        else replace(baseline, **{field_name: False})
    )
    _assert_outcome(
        evaluate_policy(_policy_input(descriptor=descriptor)),
        PolicyVerdict.BLOCKED,
        expected_reasons,
    )


def test_live_candidate_is_not_acceptance() -> None:
    decision = evaluate_policy(_policy_input())
    assert decision.verdict is PolicyVerdict.LIVE_CANDIDATE, "candidate verdict mismatch"
    assert "ACCEPTED" not in PolicyVerdict.__members__, "acceptance verdict exists"
    prohibited = ("accept", "reserve", "queue", "dispatch", "execute", "retry", "publish")
    public_names = tuple(
        name.casefold() for name in dir(importlib.import_module("ares.core.execution_policy"))
    )
    assert not any(marker in name for marker in prohibited for name in public_names), (
        "acceptance-like public helper exists"
    )


def test_high_noise_team_lead_and_admin_are_sufficient() -> None:
    descriptor = replace(_descriptor(), noise_class=NoiseClass.HIGH_NOISE)
    for role in (RoleRank.TEAM_LEAD, RoleRank.ADMIN):
        decision = evaluate_policy(
            _policy_input(descriptor=descriptor, authority=replace(_authority(), actor_role=role))
        )
        _assert_outcome(decision, PolicyVerdict.LIVE_CANDIDATE, ())


class _HostileValue:
    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls = 0

    def _fail(self) -> Any:
        self.calls += 1
        raise AssertionError("hostile method executed")

    def __repr__(self) -> str:
        return self._fail()

    def __str__(self) -> str:
        return self._fail()

    def __hash__(self) -> int:
        return self._fail()

    def __eq__(self, other: object) -> bool:
        del other
        return self._fail()

    def __iter__(self) -> Any:
        return self._fail()

    def __format__(self, format_spec: str) -> str:
        del format_spec
        return self._fail()

    def __reduce__(self) -> Any:
        return self._fail()


@pytest.mark.parametrize(
    ("position", "field_name"),
    (
        ("top", "value"),
        ("aggregate", "request"),
        ("request", "mode"),
        ("descriptor", "minimum_role"),
        ("descriptor", "required_capabilities"),
        ("authority", "actor_role"),
        ("authority", "granted_capabilities"),
    ),
    ids=(
        "top-level",
        "aggregate-record",
        "request-enum",
        "descriptor-enum",
        "descriptor-bits",
        "authority-enum",
        "authority-bits",
    ),
)
def test_hostile_invalid_values_are_not_observed(
    position: str,
    field_name: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = _HostileValue()
    if position == "top":
        candidate: object = hostile
    elif position == "aggregate":
        candidate = replace(_policy_input(), **{field_name: hostile})
    elif position == "request":
        candidate = _policy_input(request=replace(_request(), **{field_name: hostile}))
    elif position == "descriptor":
        candidate = _policy_input(descriptor=replace(_descriptor(), **{field_name: hostile}))
    else:
        candidate = _policy_input(authority=replace(_authority(), **{field_name: hostile}))
    decision = evaluate_policy(candidate)
    captured = capsys.readouterr()
    observations = (
        hostile.calls == 0,
        captured.out == "",
        captured.err == "",
        decision.verdict is PolicyVerdict.REJECTED,
        decision.reasons == (PolicyReason.INVALID_CONTRACT,),
    )
    assert all(observations), "hostile confidentiality boundary failed"


def test_records_are_immutable_identity_contracts() -> None:
    instances = (
        _request(),
        _descriptor(),
        _authority(),
        _policy_input(),
        evaluate_policy(_policy_input()),
    )
    for instance in instances:
        cls = type(instance)
        assert is_dataclass(instance), "record is not a dataclass"
        assert cls.__repr__ is object.__repr__, "generated repr present"
        assert cls.__eq__ is object.__eq__, "generated equality present"
        assert cls.__hash__ is None, "generated value hash present"
        assert "__dict__" not in dir(instance), "slotted record has dictionary"
        with pytest.raises((AttributeError, TypeError)):
            setattr(instance, fields(instance)[0].name, None)


def test_result_contains_only_fixed_types() -> None:
    decision = evaluate_policy(_policy_input())
    assert type(decision) is PolicyDecisionV1, "wrong result record"
    assert type(decision.verdict) is PolicyVerdict, "wrong verdict type"
    assert type(decision.reasons) is tuple, "wrong reasons type"
    assert all(type(reason) is PolicyReason for reason in decision.reasons), "wrong reason type"


NONINTERFERENCE_BOUNDARIES = (
    "filesystem",
    "environment",
    "database",
    "network",
    "process",
    "thread",
    "async",
    "time",
    "randomness",
    "logging",
    "pydantic",
    "registry",
    "module",
    "llm",
    "reservation",
    "telemetry",
)


@pytest.mark.parametrize(
    "boundary",
    NONINTERFERENCE_BOUNDARIES,
    ids=NONINTERFERENCE_BOUNDARIES,
)
def test_evaluation_has_no_external_boundary_calls(
    boundary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    patches = ExitStack()

    def poison(*args: object, **kwargs: object) -> Any:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise AssertionError("noninterference poison called")

    if boundary == "filesystem":
        monkeypatch.setattr(builtins, "open", poison)
    elif boundary == "environment":
        monkeypatch.setattr(os, "getenv", poison)
    elif boundary == "network":
        import socket

        monkeypatch.setattr(socket, "socket", poison)
        monkeypatch.setattr(socket, "getaddrinfo", poison)
    elif boundary == "process":
        monkeypatch.setattr(subprocess, "Popen", poison)
        monkeypatch.setattr(subprocess, "run", poison)
    elif boundary == "thread":
        import threading

        monkeypatch.setattr(threading, "Thread", poison)
    elif boundary == "async":
        import asyncio

        monkeypatch.setattr(asyncio, "create_task", poison)
        monkeypatch.setattr(asyncio, "sleep", poison)
    elif boundary == "time":
        import time

        monkeypatch.setattr(time, "time", poison)
        monkeypatch.setattr(time, "monotonic", poison)
    elif boundary == "randomness":
        import random
        import secrets
        import uuid

        monkeypatch.setattr(random, "random", poison)
        monkeypatch.setattr(secrets, "token_bytes", poison)
        monkeypatch.setattr(uuid, "uuid4", poison)
    elif boundary == "logging":
        import logging

        monkeypatch.setattr(logging.Logger, "_log", poison)
    elif boundary == "database":
        from ares.db.database import AresDatabase

        patches.enter_context(patch.object(AresDatabase, "__init__", poison))
        patches.enter_context(patch.object(AresDatabase, "connect", poison))
        patches.enter_context(patch.object(AresDatabase, "get_campaign", poison))
    elif boundary == "pydantic":
        from pydantic import BaseModel, TypeAdapter

        patches.enter_context(patch.object(BaseModel, "model_validate", poison))
        patches.enter_context(patch.object(BaseModel, "model_dump", poison))
        patches.enter_context(patch.object(TypeAdapter, "validate_python", poison))
    elif boundary == "registry":
        from ares.core.plugin.loader import ModuleRegistry, PluginLoader

        patches.enter_context(patch.object(ModuleRegistry, "get", poison))
        patches.enter_context(patch.object(ModuleRegistry, "register", poison))
        patches.enter_context(patch.object(PluginLoader, "load_all", poison))
    elif boundary == "module":
        from ares.modules.base import BaseModule

        patches.enter_context(patch.object(BaseModule, "__init__", poison))
        patches.enter_context(patch.object(BaseModule, "validate", poison))
        patches.enter_context(patch.object(BaseModule, "execute", poison))
        patches.enter_context(patch.object(BaseModule, "run", poison))
    elif boundary == "llm":
        from ares.modules.ai.autonomous_planner import (
            ClaudeBackend,
            LocalOllamaBackend,
            OpenAIBackend,
        )

        patches.enter_context(patch.object(ClaudeBackend, "generate_plan", poison))
        patches.enter_context(patch.object(OpenAIBackend, "generate_plan", poison))
        patches.enter_context(patch.object(LocalOllamaBackend, "generate_plan", poison))
    elif boundary == "reservation":
        from ares.core.noise import NoiseController, RateLimiter
        from ares.core.runtime_state import CampaignRuntimeStateStore

        patches.enter_context(patch.object(NoiseController, "before_action", poison))
        patches.enter_context(patch.object(RateLimiter, "acquire", poison))
        patches.enter_context(patch.object(CampaignRuntimeStateStore, "ensure", poison))
    else:
        from ares.telemetry.collector import TelemetryCollector

        patches.enter_context(patch.object(TelemetryCollector, "record_execution", poison))
        patches.enter_context(patch.object(TelemetryCollector, "record_finding", poison))
        patches.enter_context(patch.object(TelemetryCollector, "snapshot", poison))

    representatives = (
        None,
        _policy_input(
            authority=replace(
                _authority(),
                required_snapshots_complete=False,
                revisions_current=False,
            )
        ),
        _policy_input(request=_request(mode=EvaluationMode.PREVIEW)),
        _policy_input(),
    )
    try:
        outcomes = tuple(_outcome(evaluate_policy(candidate)) for candidate in representatives)
    finally:
        patches.close()
    assert calls == 0, "external boundary was called"
    assert outcomes == (
        (PolicyVerdict.REJECTED, (PolicyReason.INVALID_CONTRACT,)),
        (PolicyVerdict.BLOCKED, (PolicyReason.AUTHORITY_RESOLUTION_REQUIRED,)),
        (PolicyVerdict.PREVIEW_READY, ()),
        (PolicyVerdict.LIVE_CANDIDATE, ()),
    ), "representative policy outcome mismatch"


def test_fresh_import_adds_no_forbidden_module(tmp_path: Path) -> None:
    script = tmp_path / "import_probe.py"
    script.write_text(
        """
import importlib
import importlib.abc
import sys

forbidden = (
    "pydantic",
    "ares.modules",
    "ares.core.plugin",
    "ares.api",
    "ares.core.engine",
    "ares.worker",
    "ares.db",
    "ares.telemetry",
    "ares.core.logger",
    "ares.core.tracing",
)

import ares.core
baseline = frozenset(sys.modules)
calls = 0

class Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        global calls
        del path, target
        if fullname not in baseline and any(
            fullname == prefix or fullname.startswith(prefix + ".")
            for prefix in forbidden
        ):
            calls += 1
            raise RuntimeError("IMPORT_BLOCKED")
        return None

finder = Finder()
sys.meta_path.insert(0, finder)
try:
    importlib.import_module("ares.core.execution_policy")
    added = frozenset(sys.modules).difference(baseline)
    clean = not any(
        name == prefix or name.startswith(prefix + ".")
        for name in added
        for prefix in forbidden
    )
    negative_tripwire = False
    try:
        importlib.import_module("ares.modules.synthetic_import_tripwire")
    except RuntimeError:
        negative_tripwire = True
    ok = clean and calls == 1 and negative_tripwire
finally:
    sys.meta_path.remove(finder)
print("IMPORT_OK" if ok else "IMPORT_FAIL")
""".lstrip(),
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPYCACHEPREFIX"] = str(tmp_path / "pycache")
    environment["PYTHONPATH"] = str(ROOT)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(script)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    observations = (
        completed.returncode == 0,
        completed.stdout == "IMPORT_OK\n",
        completed.stderr == "",
    )
    assert all(observations), "fresh import isolation failed"


def test_kernel_source_has_only_standard_library_imports() -> None:
    tree = ast.parse(KERNEL_PATH.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imports.add(node.module.split(".")[0])
    assert imports == {"__future__", "dataclasses", "enum", "typing"}, "import boundary changed"


def test_kernel_source_has_no_forbidden_operations() -> None:
    source = KERNEL_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_names = {
        "open",
        "getenv",
        "environ",
        "socket",
        "subprocess",
        "threading",
        "asyncio",
        "time",
        "random",
        "secrets",
        "uuid",
        "logging",
        "telemetry",
        "pydantic",
        "serialize",
        "digest",
        "hashlib",
    }
    used = {node.id.casefold() for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not used.intersection(forbidden_names), "forbidden operation name present"
    assert "ACCEPTED" not in source, "acceptance state present"


def test_no_live_consumer_imports_kernel() -> None:
    importers: list[str] = []
    for path in sorted((ROOT / "ares").rglob("*.py")):
        if path == KERNEL_PATH:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "ares.core.execution_policy":
                importers.append(path.name)
            elif isinstance(node, ast.Import) and any(
                alias.name == "ares.core.execution_policy" for alias in node.names
            ):
                importers.append(path.name)
    assert importers == [], "production consumer imports policy kernel"
    for package_init in (ROOT / "ares" / "__init__.py", ROOT / "ares" / "core" / "__init__.py"):
        assert "execution_policy" not in package_init.read_text(encoding="utf-8"), (
            "package exports kernel"
        )


def test_public_api_is_bounded() -> None:
    module = importlib.import_module("ares.core.execution_policy")
    expected = {
        "ApprovalPolicy",
        "AuthorityFactsV1",
        "BlockerBits",
        "CONTRACT_VERSION_V1",
        "CapabilityBits",
        "DescriptorFactsV1",
        "EvaluationMode",
        "MAX_REQUEST_SHAPE_UNITS_V1",
        "NoiseClass",
        "PolicyDecisionV1",
        "PolicyInputV1",
        "PolicyReason",
        "PolicyVerdict",
        "RequestFactsV1",
        "RoleRank",
        "evaluate_policy",
    }
    assert set(module.__all__) == expected, "public API changed"


def test_determinism_under_capability_construction_order() -> None:
    forward = CapabilityBits.NONE
    for bit in (
        CapabilityBits.NETWORK,
        CapabilityBits.EXECUTION,
        CapabilityBits.FILESYSTEM,
        CapabilityBits.PROCESS,
    ):
        forward |= bit
    reverse = CapabilityBits.NONE
    for bit in (
        CapabilityBits.PROCESS,
        CapabilityBits.FILESYSTEM,
        CapabilityBits.EXECUTION,
        CapabilityBits.NETWORK,
    ):
        reverse |= bit
    first = evaluate_policy(
        _policy_input(authority=replace(_authority(), granted_capabilities=forward))
    )
    second = evaluate_policy(
        _policy_input(authority=replace(_authority(), granted_capabilities=reverse))
    )
    assert _outcome(first) == _outcome(second), "capability order changed outcome"


def test_determinism_under_blocker_construction_order() -> None:
    first_bits = BlockerBits.AMBIENT_CREDENTIALS_FORBIDDEN | BlockerBits.RESULT_AUTHORITY_UNPROVEN
    second_bits = BlockerBits.RESULT_AUTHORITY_UNPROVEN | BlockerBits.AMBIENT_CREDENTIALS_FORBIDDEN
    first = evaluate_policy(
        _policy_input(descriptor=_descriptor(live_ready=False, blocker_bits=first_bits))
    )
    second = evaluate_policy(
        _policy_input(descriptor=_descriptor(live_ready=False, blocker_bits=second_bits))
    )
    assert _outcome(first) == _outcome(second), "blocker order changed outcome"


def test_fixed_outcome_serialization_is_environment_independent() -> None:
    decisions = (
        evaluate_policy(None),
        evaluate_policy(
            _policy_input(
                authority=replace(
                    _authority(),
                    required_snapshots_complete=False,
                    revisions_current=False,
                )
            )
        ),
        evaluate_policy(_policy_input(request=_request(mode=EvaluationMode.PREVIEW))),
        evaluate_policy(_policy_input()),
    )
    reduced = tuple(
        (decision.verdict.value, tuple(reason.value for reason in decision.reasons))
        for decision in decisions
    )
    assert json.dumps(reduced, separators=(",", ":")) == (
        '[["rejected",["invalid_contract"]],'
        '["blocked",["authority_resolution_required"]],'
        '["preview_ready",[]],["live_candidate",[]]]'
    ), "fixed reduced outcomes changed"
