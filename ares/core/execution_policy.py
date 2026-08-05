"""Pure offline execution-policy evaluation over reduced immutable facts.

This module is deliberately isolated from every ARES runtime authority.  It does
not parse requests, load descriptors, resolve identities, reserve resources, or
authorize execution.  ``LIVE_CANDIDATE`` means only that the reduced facts
supplied by a future adapter passed this static evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Final

CONTRACT_VERSION_V1: Final = 1
MAX_REQUEST_SHAPE_UNITS_V1: Final = 4096


class EvaluationMode(Enum):
    """Static evaluation mode."""

    PREVIEW = "preview"
    LIVE = "live"


class RoleRank(Enum):
    """Reduced actor-role rank supplied by a future authority adapter."""

    OPERATOR = 1
    TEAM_LEAD = 2
    ADMIN = 3


class NoiseClass(Enum):
    """Reduced descriptor noise classification."""

    SILENT = "silent"
    LOCAL = "local"
    LOW = "low"
    MEDIUM = "medium"
    HIGH_NOISE = "high_noise"


class ApprovalPolicy(Enum):
    """Reduced attempt-approval policy."""

    NONE = "none"
    ATTEMPT_BOUND = "attempt_bound"


class CapabilityBits(IntFlag):
    """The four execution capabilities declared by the Phase 5C.1 sidecar."""

    NONE = 0
    NETWORK = 1 << 0
    EXECUTION = 1 << 1
    FILESYSTEM = 1 << 2
    PROCESS = 1 << 3


class BlockerBits(IntFlag):
    """Fixed blocker classes representable by reduced descriptor facts."""

    NONE = 0
    AMBIENT_CREDENTIALS_FORBIDDEN = 1 << 0
    CANCELLATION_OWNERSHIP_UNPROVEN = 1 << 1
    DYNAMIC_DESTINATION_UNBOUNDED = 1 << 2
    DEFAULT_FACTORY_UNEVALUATED = 1 << 3
    LLM_EGRESS_POLICY_REQUIRED = 1 << 4
    LIFECYCLE_CONTRACT_UNPROVEN = 1 << 5
    RAW_CREDENTIAL_INPUT = 1 << 6
    RESULT_AUTHORITY_UNPROVEN = 1 << 7
    SENSITIVE_NONEMPTY_DEFAULT = 1 << 8


class PolicyVerdict(Enum):
    """A static result.  No member represents execution acceptance."""

    REJECTED = "rejected"
    BLOCKED = "blocked"
    PREVIEW_READY = "preview_ready"
    LIVE_CANDIDATE = "live_candidate"


class PolicyReason(Enum):
    """Fixed sanitized reason codes in deterministic evaluation order."""

    INVALID_CONTRACT = "invalid_contract"
    INCONSISTENT_CONTRACT = "inconsistent_contract"
    INVALID_REQUEST = "invalid_request"
    DESCRIPTOR_UNTRUSTED = "descriptor_untrusted"
    DESCRIPTOR_BINDING_INVALID = "descriptor_binding_invalid"
    DESCRIPTOR_INCOMPLETE = "descriptor_incomplete"
    STATIC_POLICY_UNAVAILABLE = "static_policy_unavailable"
    AUTHORITY_RESOLUTION_REQUIRED = "authority_resolution_required"
    STALE_AUTHORITY = "stale_authority"
    ACTOR_UNAUTHENTICATED = "actor_unauthenticated"
    ACTOR_INACTIVE = "actor_inactive"
    CAMPAIGN_INACTIVE = "campaign_inactive"
    CAMPAIGN_UNAUTHORIZED = "campaign_unauthorized"
    INSUFFICIENT_ROLE = "insufficient_role"
    HIGH_NOISE_ROLE_REQUIRED = "high_noise_role_required"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_STALE = "approval_stale"
    APPROVAL_BINDING_INVALID = "approval_binding_invalid"
    CAPABILITY_REQUIRED = "capability_required"
    DESTINATION_RESOLUTION_REQUIRED = "destination_resolution_required"
    DESTINATION_OUT_OF_SCOPE = "destination_out_of_scope"
    CREDENTIAL_AUTHORITY_REQUIRED = "credential_authority_required"
    CREDENTIAL_AUTHORITY_STALE = "credential_authority_stale"
    RAW_CREDENTIAL_FORBIDDEN = "raw_credential_forbidden"
    AMBIENT_CREDENTIAL_FORBIDDEN = "ambient_credential_forbidden"
    CREDENTIAL_HANDLE_POLICY_VIOLATION = "credential_handle_policy_violation"
    BUDGET_AUTHORITY_REQUIRED = "budget_authority_required"
    BUDGET_AUTHORITY_STALE = "budget_authority_stale"
    BUDGET_CAPACITY_UNAVAILABLE = "budget_capacity_unavailable"
    DESCRIPTOR_BLOCKED = "descriptor_blocked"
    PREVIEW_NOT_READY = "preview_not_ready"
    LIFECYCLE_NOT_READY = "lifecycle_not_ready"
    RESULT_AUTHORITY_NOT_READY = "result_authority_not_ready"
    TRANSPORT_NOT_READY = "transport_not_ready"
    FUTURE_GATEWAY_INELIGIBLE = "future_gateway_ineligible"


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class RequestFactsV1:
    """Reduced request-shape facts; contains no request-controlled values."""

    contract_version: int
    mode: EvaluationMode
    structure_valid: bool
    canonicalization_complete: bool
    unknown_fields_absent: bool
    alternate_transport_absent: bool
    bounded_shape_valid: bool
    shape_units: int

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class DescriptorFactsV1:
    """Reduced static descriptor facts; contains no descriptor or module object."""

    contract_version: int
    trusted_first_party_binding: bool
    descriptor_binding_current: bool
    descriptor_complete: bool
    static_policy_evaluable: bool
    minimum_role: RoleRank
    noise_class: NoiseClass
    approval_policy: ApprovalPolicy
    required_capabilities: CapabilityBits
    blocker_bits: BlockerBits
    preview_ready: bool
    lifecycle_ready: bool
    result_authority_ready: bool
    transport_ready: bool
    future_gateway_eligible: bool

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class AuthorityFactsV1:
    """Reduced authority facts; contains no identities, destinations, or secrets."""

    contract_version: int
    required_snapshots_complete: bool
    revisions_current: bool
    actor_authenticated: bool
    actor_active: bool
    actor_role: RoleRank
    campaign_active: bool
    actor_campaign_authorized: bool
    approval_present: bool
    approval_current: bool
    approval_exactly_bound: bool
    granted_capabilities: CapabilityBits
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

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PolicyInputV1:
    """One exact aggregate of reduced request, descriptor, and authority facts."""

    request: RequestFactsV1
    descriptor: DescriptorFactsV1
    authority: AuthorityFactsV1

    __hash__ = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PolicyDecisionV1:
    """Fixed verdict and ordered fixed reasons only."""

    verdict: PolicyVerdict
    reasons: tuple[PolicyReason, ...]

    __hash__ = None


_ALL_CAPABILITIES: Final = (
    CapabilityBits.NETWORK
    | CapabilityBits.EXECUTION
    | CapabilityBits.FILESYSTEM
    | CapabilityBits.PROCESS
)
_ALL_BLOCKERS: Final = (
    BlockerBits.AMBIENT_CREDENTIALS_FORBIDDEN
    | BlockerBits.CANCELLATION_OWNERSHIP_UNPROVEN
    | BlockerBits.DYNAMIC_DESTINATION_UNBOUNDED
    | BlockerBits.DEFAULT_FACTORY_UNEVALUATED
    | BlockerBits.LLM_EGRESS_POLICY_REQUIRED
    | BlockerBits.LIFECYCLE_CONTRACT_UNPROVEN
    | BlockerBits.RAW_CREDENTIAL_INPUT
    | BlockerBits.RESULT_AUTHORITY_UNPROVEN
    | BlockerBits.SENSITIVE_NONEMPTY_DEFAULT
)


def _decision(
    verdict: PolicyVerdict,
    *reasons: PolicyReason,
) -> PolicyDecisionV1:
    return PolicyDecisionV1(verdict=verdict, reasons=reasons)


def _valid_version(value: object) -> bool:
    return type(value) is int and value == CONTRACT_VERSION_V1


def _valid_bool(value: object) -> bool:
    return type(value) is bool


def _valid_capabilities(value: object) -> bool:
    return (
        type(value) is CapabilityBits
        and int(value) >= 0
        and int(value) & ~int(_ALL_CAPABILITIES) == 0
    )


def _valid_blockers(value: object) -> bool:
    return type(value) is BlockerBits and int(value) >= 0 and int(value) & ~int(_ALL_BLOCKERS) == 0


def _valid_request(value: object) -> bool:
    if type(value) is not RequestFactsV1:
        return False
    return (
        _valid_version(value.contract_version)
        and type(value.mode) is EvaluationMode
        and _valid_bool(value.structure_valid)
        and _valid_bool(value.canonicalization_complete)
        and _valid_bool(value.unknown_fields_absent)
        and _valid_bool(value.alternate_transport_absent)
        and _valid_bool(value.bounded_shape_valid)
        and type(value.shape_units) is int
        and 0 <= value.shape_units <= MAX_REQUEST_SHAPE_UNITS_V1
    )


def _valid_descriptor(value: object) -> bool:
    if type(value) is not DescriptorFactsV1:
        return False
    return (
        _valid_version(value.contract_version)
        and _valid_bool(value.trusted_first_party_binding)
        and _valid_bool(value.descriptor_binding_current)
        and _valid_bool(value.descriptor_complete)
        and _valid_bool(value.static_policy_evaluable)
        and type(value.minimum_role) is RoleRank
        and type(value.noise_class) is NoiseClass
        and type(value.approval_policy) is ApprovalPolicy
        and _valid_capabilities(value.required_capabilities)
        and _valid_blockers(value.blocker_bits)
        and _valid_bool(value.preview_ready)
        and _valid_bool(value.lifecycle_ready)
        and _valid_bool(value.result_authority_ready)
        and _valid_bool(value.transport_ready)
        and _valid_bool(value.future_gateway_eligible)
    )


def _valid_authority(value: object) -> bool:
    if type(value) is not AuthorityFactsV1:
        return False
    return (
        _valid_version(value.contract_version)
        and _valid_bool(value.required_snapshots_complete)
        and _valid_bool(value.revisions_current)
        and _valid_bool(value.actor_authenticated)
        and _valid_bool(value.actor_active)
        and type(value.actor_role) is RoleRank
        and _valid_bool(value.campaign_active)
        and _valid_bool(value.actor_campaign_authorized)
        and _valid_bool(value.approval_present)
        and _valid_bool(value.approval_current)
        and _valid_bool(value.approval_exactly_bound)
        and _valid_capabilities(value.granted_capabilities)
        and _valid_bool(value.destination_extraction_complete)
        and _valid_bool(value.destinations_in_scope)
        and _valid_bool(value.credential_authority_resolved)
        and _valid_bool(value.credential_authority_current)
        and _valid_bool(value.opaque_handles_only)
        and _valid_bool(value.permitted_handle_kinds_only)
        and _valid_bool(value.raw_credentials_absent)
        and _valid_bool(value.ambient_credentials_absent)
        and _valid_bool(value.budget_authority_resolved)
        and _valid_bool(value.budget_authority_current)
        and _valid_bool(value.budget_capacity_available)
    )


def _valid_input(value: object) -> bool:
    return (
        type(value) is PolicyInputV1
        and _valid_request(value.request)
        and _valid_descriptor(value.descriptor)
        and _valid_authority(value.authority)
    )


def _inconsistent(value: PolicyInputV1) -> bool:
    descriptor = value.descriptor
    authority = value.authority

    descriptor_binding_without_trust = (
        descriptor.descriptor_binding_current and not descriptor.trusted_first_party_binding
    )
    preview_without_static_contract = descriptor.preview_ready and not (
        descriptor.trusted_first_party_binding
        and descriptor.descriptor_binding_current
        and descriptor.descriptor_complete
        and descriptor.static_policy_evaluable
    )
    eligible_without_live_contract = descriptor.future_gateway_eligible and not (
        descriptor.trusted_first_party_binding
        and descriptor.descriptor_binding_current
        and descriptor.descriptor_complete
        and descriptor.static_policy_evaluable
        and descriptor.lifecycle_ready
        and descriptor.result_authority_ready
        and descriptor.transport_ready
    )
    eligible_with_blockers = (
        descriptor.future_gateway_eligible and int(descriptor.blocker_bits) != 0
    )
    approval_without_presence = (
        authority.approval_current or authority.approval_exactly_bound
    ) and not authority.approval_present
    current_without_snapshots = (
        authority.revisions_current and not authority.required_snapshots_complete
    )
    active_without_authentication = authority.actor_active and not authority.actor_authenticated
    campaign_authority_without_active_campaign = (
        authority.actor_campaign_authorized and not authority.campaign_active
    )
    credential_current_without_resolution = (
        authority.credential_authority_current and not authority.credential_authority_resolved
    )
    permitted_kinds_without_opaque_handles = (
        authority.permitted_handle_kinds_only and not authority.opaque_handles_only
    )
    opaque_with_raw_or_ambient = authority.opaque_handles_only and (
        not authority.raw_credentials_absent or not authority.ambient_credentials_absent
    )
    budget_current_without_resolution = (
        authority.budget_authority_current and not authority.budget_authority_resolved
    )
    return any(
        (
            descriptor_binding_without_trust,
            preview_without_static_contract,
            eligible_without_live_contract,
            eligible_with_blockers,
            approval_without_presence,
            current_without_snapshots,
            active_without_authentication,
            campaign_authority_without_active_campaign,
            credential_current_without_resolution,
            permitted_kinds_without_opaque_handles,
            opaque_with_raw_or_ambient,
            budget_current_without_resolution,
        )
    )


def evaluate_policy(value: object) -> PolicyDecisionV1:
    """Evaluate reduced facts in one fixed order without accepting execution."""

    if not _valid_input(value):
        return _decision(PolicyVerdict.REJECTED, PolicyReason.INVALID_CONTRACT)
    if _inconsistent(value):
        return _decision(PolicyVerdict.REJECTED, PolicyReason.INCONSISTENT_CONTRACT)

    request = value.request
    descriptor = value.descriptor
    authority = value.authority

    if not (
        request.structure_valid
        and request.canonicalization_complete
        and request.unknown_fields_absent
        and request.alternate_transport_absent
        and request.bounded_shape_valid
    ):
        return _decision(PolicyVerdict.REJECTED, PolicyReason.INVALID_REQUEST)

    descriptor_reasons: list[PolicyReason] = []
    if not descriptor.trusted_first_party_binding:
        descriptor_reasons.append(PolicyReason.DESCRIPTOR_UNTRUSTED)
    if not descriptor.descriptor_binding_current:
        descriptor_reasons.append(PolicyReason.DESCRIPTOR_BINDING_INVALID)
    if not descriptor.descriptor_complete:
        descriptor_reasons.append(PolicyReason.DESCRIPTOR_INCOMPLETE)
    if not descriptor.static_policy_evaluable:
        descriptor_reasons.append(PolicyReason.STATIC_POLICY_UNAVAILABLE)
    if descriptor_reasons:
        return _decision(PolicyVerdict.REJECTED, *descriptor_reasons)

    if not authority.required_snapshots_complete:
        return _decision(
            PolicyVerdict.BLOCKED,
            PolicyReason.AUTHORITY_RESOLUTION_REQUIRED,
        )
    if not authority.revisions_current:
        return _decision(PolicyVerdict.BLOCKED, PolicyReason.STALE_AUTHORITY)

    actor_reasons: list[PolicyReason] = []
    if not authority.actor_authenticated:
        actor_reasons.append(PolicyReason.ACTOR_UNAUTHENTICATED)
    if not authority.actor_active:
        actor_reasons.append(PolicyReason.ACTOR_INACTIVE)
    if not authority.campaign_active:
        actor_reasons.append(PolicyReason.CAMPAIGN_INACTIVE)
    if not authority.actor_campaign_authorized:
        actor_reasons.append(PolicyReason.CAMPAIGN_UNAUTHORIZED)
    if actor_reasons:
        return _decision(PolicyVerdict.BLOCKED, *actor_reasons)

    access_reasons: list[PolicyReason] = []
    if authority.actor_role.value < descriptor.minimum_role.value:
        access_reasons.append(PolicyReason.INSUFFICIENT_ROLE)
    if (
        descriptor.noise_class is NoiseClass.HIGH_NOISE
        and authority.actor_role.value < RoleRank.TEAM_LEAD.value
    ):
        access_reasons.append(PolicyReason.HIGH_NOISE_ROLE_REQUIRED)
    if descriptor.approval_policy is ApprovalPolicy.ATTEMPT_BOUND:
        if not authority.approval_present:
            access_reasons.append(PolicyReason.APPROVAL_REQUIRED)
        elif not authority.approval_current:
            access_reasons.append(PolicyReason.APPROVAL_STALE)
        elif not authority.approval_exactly_bound:
            access_reasons.append(PolicyReason.APPROVAL_BINDING_INVALID)
    if access_reasons:
        return _decision(PolicyVerdict.BLOCKED, *access_reasons)

    if (
        authority.granted_capabilities & descriptor.required_capabilities
    ) != descriptor.required_capabilities:
        return _decision(PolicyVerdict.BLOCKED, PolicyReason.CAPABILITY_REQUIRED)

    if not authority.destination_extraction_complete:
        return _decision(
            PolicyVerdict.BLOCKED,
            PolicyReason.DESTINATION_RESOLUTION_REQUIRED,
        )
    if not authority.destinations_in_scope:
        return _decision(PolicyVerdict.BLOCKED, PolicyReason.DESTINATION_OUT_OF_SCOPE)

    credential_reasons: list[PolicyReason] = []
    if not authority.credential_authority_resolved:
        credential_reasons.append(PolicyReason.CREDENTIAL_AUTHORITY_REQUIRED)
    elif not authority.credential_authority_current:
        credential_reasons.append(PolicyReason.CREDENTIAL_AUTHORITY_STALE)
    if not authority.raw_credentials_absent:
        credential_reasons.append(PolicyReason.RAW_CREDENTIAL_FORBIDDEN)
    if not authority.ambient_credentials_absent:
        credential_reasons.append(PolicyReason.AMBIENT_CREDENTIAL_FORBIDDEN)
    if not authority.opaque_handles_only or not authority.permitted_handle_kinds_only:
        credential_reasons.append(PolicyReason.CREDENTIAL_HANDLE_POLICY_VIOLATION)
    if credential_reasons:
        return _decision(PolicyVerdict.BLOCKED, *credential_reasons)

    budget_reasons: list[PolicyReason] = []
    if not authority.budget_authority_resolved:
        budget_reasons.append(PolicyReason.BUDGET_AUTHORITY_REQUIRED)
    elif not authority.budget_authority_current:
        budget_reasons.append(PolicyReason.BUDGET_AUTHORITY_STALE)
    if not authority.budget_capacity_available:
        budget_reasons.append(PolicyReason.BUDGET_CAPACITY_UNAVAILABLE)
    if budget_reasons:
        return _decision(PolicyVerdict.BLOCKED, *budget_reasons)

    if int(descriptor.blocker_bits) != 0:
        return _decision(PolicyVerdict.BLOCKED, PolicyReason.DESCRIPTOR_BLOCKED)

    if request.mode is EvaluationMode.PREVIEW:
        if not descriptor.preview_ready:
            return _decision(PolicyVerdict.BLOCKED, PolicyReason.PREVIEW_NOT_READY)
        return _decision(PolicyVerdict.PREVIEW_READY)

    live_reasons: list[PolicyReason] = []
    if not descriptor.lifecycle_ready:
        live_reasons.append(PolicyReason.LIFECYCLE_NOT_READY)
    if not descriptor.result_authority_ready:
        live_reasons.append(PolicyReason.RESULT_AUTHORITY_NOT_READY)
    if not descriptor.transport_ready:
        live_reasons.append(PolicyReason.TRANSPORT_NOT_READY)
    if not descriptor.future_gateway_eligible:
        live_reasons.append(PolicyReason.FUTURE_GATEWAY_INELIGIBLE)
    if live_reasons:
        return _decision(PolicyVerdict.BLOCKED, *live_reasons)
    return _decision(PolicyVerdict.LIVE_CANDIDATE)


__all__ = [
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
]
