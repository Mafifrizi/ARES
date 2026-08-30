"""Immutable, audit-only first-party module descriptor sidecar.

Phase 5C.1 records trusted metadata without changing any live execution ingress.
Descriptors are explicit repository data: this module never imports concrete modules,
constructs modules, loads plugins, executes modules, or infers policy by category.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import types
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, get_args, get_origin

from pydantic import BaseModel, SecretStr, ValidationError

from ares.core.capabilities import Capability
from ares.modules import params as _params

CONTRACT_VERSION = "ares.module-descriptor.v2"
_MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_FIELD_PATH_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")


class ContractState(str, Enum):
    PROVEN_NONE = "proven_none"
    NOT_APPLICABLE = "not_applicable"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"
    DYNAMICALLY_UNBOUNDED = "dynamically_unbounded"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_BY_ADAPTER_GAP = "blocked_by_adapter_gap"


class ModuleCategory(str, Enum):
    AD = "ad"
    AI = "ai"
    CLOUD = "cloud"
    CREDENTIAL = "credential"
    EDR = "edr"
    EXFIL = "exfil"
    LATERAL = "lateral"
    LINUX = "linux"
    NETWORK = "network"
    OPSEC = "opsec"
    PERSISTENCE = "persistence"
    RECON = "recon"
    WINDOWS = "windows"


class OpsecClassification(str, Enum):
    SILENT = "silent"
    LOCAL = "local"
    LOW = "low"
    MEDIUM = "medium"
    HIGH_NOISE = "high_noise"


class MinimumRole(str, Enum):
    OPERATOR = "operator"
    TEAM_LEAD = "team_lead"


class ParameterType(str, Enum):
    STRING = "string"
    OPTIONAL_STRING = "optional_string"
    SECRET_STRING = "secret_string"  # noqa: S105 - metadata classification
    OPTIONAL_SECRET_STRING = "optional_secret_string"  # noqa: S105 - metadata classification
    BOOLEAN = "boolean"
    INTEGER = "integer"
    FLOAT = "float"
    STRING_LIST = "string_list"
    INTEGER_LIST = "integer_list"


class DefaultSemanticState(str, Enum):
    NO_DEFAULT = "no_default"
    DEFAULT_NONE = "default_none"
    DEFAULT_EMPTY = "default_empty"
    DEFAULT_PUBLIC_VALUE = "default_public_value"
    DEFAULT_NONEMPTY_BLOCKED = "default_nonempty_blocked"
    DEFAULT_FACTORY_UNEVALUATED_BLOCKED = "default_factory_unevaluated_blocked"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    SENSITIVE = "sensitive"
    SECRET = "secret"  # noqa: S105 - metadata classification


class DestinationKind(str, Enum):
    HOST = "host"
    DOMAIN = "domain"
    NETWORK_ENDPOINT = "network_endpoint"
    NETWORK_PORT = "network_port"
    NETWORK_PROTOCOL = "network_protocol"
    RELAY_TARGET = "relay_target"
    CALLBACK = "callback"
    CLOUD_TENANT = "cloud_tenant"
    CLOUD_SUBSCRIPTION = "cloud_subscription"
    CLOUD_PROJECT = "cloud_project"
    CLOUD_REGION = "cloud_region"
    LOCAL_FILE = "local_file"
    EXFILTRATION_PATH = "exfiltration_path"
    REMOTE_PROCESS = "remote_process"
    REMOTE_OBJECT = "remote_object"
    ACCOUNT = "account"
    SERVICE_PRINCIPAL = "service_principal"
    LLM_PROVIDER = "llm_provider"


class DestinationCardinality(str, Enum):
    SCALAR = "scalar"
    OPTIONAL = "optional"
    COLLECTION = "collection"


class CapabilityMatchSemantics(str, Enum):
    ALL_REQUIRED = "all_required"


class ScopeSemantics(str, Enum):
    PRIMARY_CAMPAIGN = "primary_campaign"
    SECONDARY_CAMPAIGN = "secondary_campaign"
    LOCAL_OPERATOR = "local_operator"
    CLOUD_BOUNDARY = "cloud_boundary"
    PROCESS_BOUNDARY = "process_boundary"
    PROVIDER_BOUNDARY = "provider_boundary"


class OpaqueCredentialKind(str, Enum):
    API_TOKEN = "api_token"  # noqa: S105 - opaque handle kind
    CLOUD_SESSION = "cloud_session"
    HASH_MATERIAL = "hash_material"
    NTLM_HASH = "ntlm_hash"
    PASSWORD = "password"  # noqa: S105 - opaque handle kind
    SNMP_COMMUNITY = "snmp_community"
    SSH_PRIVATE_KEY = "ssh_private_key"
    VAULT_RECORD = "vault_record"


class AmbientCredentialDependency(str, Enum):
    AWS_SDK_DEFAULT_CHAIN = "aws_sdk_default_chain"
    AZURE_DEFAULT_CREDENTIAL = "azure_default_credential"
    ENV_ANTHROPIC_API_KEY = "env_anthropic_api_key"
    ENV_OPENAI_API_KEY = "env_openai_api_key"
    EXECUTION_CONTEXT_BEST_CREDENTIAL = "execution_context_best_credential"
    EXECUTION_CONTEXT_VAULT = "execution_context_vault"
    GOOGLE_APPLICATION_DEFAULT_CREDENTIALS = "google_application_default_credentials"


class ExternalEffectClass(str, Enum):
    READ_ONLY = "read_only"
    CONDITIONALLY_MUTATING = "conditionally_mutating"
    MUTATING = "mutating"
    LOCAL_ANALYSIS = "local_analysis"
    PLANNING = "planning"
    BILLABLE_NONDETERMINISTIC_EGRESS = "billable_nondeterministic_egress"


class IdempotencyClass(str, Enum):
    PROVEN_IDEMPOTENT = "proven_idempotent"
    PROVEN_NON_IDEMPOTENT = "proven_non_idempotent"
    CONDITIONAL = "conditional"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"


class RetryEligibility(str, Enum):
    AFTER_REVALIDATION = "after_revalidation"
    BLOCKED_UNPROVEN_PRIOR_ATTEMPT = "blocked_unproven_prior_attempt"
    NEVER = "never"


class CancellationOwnership(str, Enum):
    OWNED = "owned"
    NOT_APPLICABLE = "not_applicable"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"


class CompensationClass(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"


class TimeoutSource(str, Enum):
    MODULE_DEFINED_BOUNDED = "module_defined_bounded"
    OBSERVED_LEGACY_ENGINE_DEFAULT = "observed_legacy_engine_default"
    UNSUPPORTED_OR_UNBOUNDED = "unsupported_or_unbounded"


class TimeoutSettlement(str, Enum):
    PROVEN = "proven"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"


class DryRunState(str, Enum):
    NATIVE_PROVEN = "native_proven"
    SHARED_ADAPTER_PROVEN = "shared_adapter_proven"
    GATEWAY_PREVIEW_ONLY = "gateway_preview_only"
    UNSUPPORTED = "unsupported"
    UNPROVEN_CURRENT_CONTRACT = "unproven_current_contract"


class DryRunGuardSemantics(str, Enum):
    CONTEXT_GETATTR_TRUTHY = "context_getattr_truthy"


class DryRunTermination(str, Enum):
    RETURN_BEFORE_EXTERNAL_EFFECT = "return_before_external_effect"


class BlockerCode(str, Enum):
    AMBIENT_CREDENTIALS_FORBIDDEN = "AMBIENT_CREDENTIALS_FORBIDDEN"
    CANCELLATION_OWNERSHIP_UNPROVEN = "CANCELLATION_OWNERSHIP_UNPROVEN"
    DESTINATION_CONTRACT_UNBOUNDED = "DYNAMIC_DESTINATION_UNBOUNDED"
    DEFAULT_FACTORY_UNEVALUATED = "DEFAULT_FACTORY_UNEVALUATED"
    LLM_EGRESS_POLICY_REQUIRED = "LLM_EGRESS_POLICY_REQUIRED"
    LIFECYCLE_CONTRACT_UNPROVEN = "LIFECYCLE_CONTRACT_UNPROVEN"
    RAW_CREDENTIAL_INPUT = "RAW_CREDENTIAL_INPUT"
    RESULT_AUTHORITY_UNPROVEN = "RESULT_AUTHORITY_UNPROVEN"
    SENSITIVE_NONEMPTY_DEFAULT = "SENSITIVE_NONEMPTY_DEFAULT"


class ReadinessCode(str, Enum):
    INVALID_DESCRIPTOR = "ARES-5C1-E01-INVALID-DESCRIPTOR"
    DESCRIPTOR_NOT_FOUND = "ARES-5C1-E02-DESCRIPTOR-NOT-FOUND"
    REGISTRY_SET_MISMATCH = "ARES-5C1-E03-REGISTRY-SET-MISMATCH"
    REGISTRY_BINDING_MISMATCH = "ARES-5C1-E04-REGISTRY-BINDING-MISMATCH"
    PARAMETER_CONTRACT_MISMATCH = "ARES-5C1-E05-PARAMETER-CONTRACT-MISMATCH"
    PARAMETERS_NOT_MAPPING = "ARES-5C1-E06-PARAMETERS-NOT-MAPPING"
    PARAMETERS_UNKNOWN_FIELD = "ARES-5C1-E07-PARAMETERS-UNKNOWN-FIELD"
    PARAMETERS_INVALID = "ARES-5C1-E08-PARAMETERS-INVALID"
    UNTRUSTED_EXTERNAL_METADATA = "ARES-5C1-E09-UNTRUSTED-EXTERNAL-METADATA"
    DRY_RUN_PROVENANCE_MISMATCH = "ARES-5C1-E10-DRY-RUN-PROVENANCE-MISMATCH"


@dataclass(frozen=True, slots=True, eq=False)
class ParameterFieldSpec:
    name: str
    canonical_type: ParameterType
    required: bool
    default_state: DefaultSemanticState
    public_default_digest: str | None = field(repr=False)
    legacy_schema_secret: bool
    sensitivity: Sensitivity
    blocker_code: BlockerCode | None
    nested_fields: tuple[ParameterFieldSpec, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_type, ParameterType):
            _invalid()
        if type(self.required) is not bool:
            _invalid()
        if not isinstance(self.default_state, DefaultSemanticState):
            _invalid()
        if type(self.legacy_schema_secret) is not bool:
            _invalid()
        if not isinstance(self.sensitivity, Sensitivity):
            _invalid()
        if not _FIELD_PATH_RE.fullmatch(self.name):
            _invalid()
        if type(self.nested_fields) is not tuple:
            _invalid()
        if self.blocker_code is not None and not isinstance(self.blocker_code, BlockerCode):
            _invalid()
        if self.required is not (self.default_state is DefaultSemanticState.NO_DEFAULT):
            _invalid()
        if self.default_state is DefaultSemanticState.DEFAULT_PUBLIC_VALUE:
            if self.sensitivity is not Sensitivity.PUBLIC:
                _invalid()
            if not _is_sha256(self.public_default_digest):
                _invalid()
        elif self.public_default_digest is not None:
            _invalid()
        nonempty_blocked = self.default_state is DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED
        factory_blocked = (
            self.default_state is DefaultSemanticState.DEFAULT_FACTORY_UNEVALUATED_BLOCKED
        )
        if nonempty_blocked is not (self.blocker_code is BlockerCode.SENSITIVE_NONEMPTY_DEFAULT):
            _invalid()
        if factory_blocked is not (self.blocker_code is BlockerCode.DEFAULT_FACTORY_UNEVALUATED):
            _invalid()
        if nonempty_blocked and self.sensitivity is Sensitivity.PUBLIC:
            _invalid()
        if self.legacy_schema_secret and self.sensitivity is not Sensitivity.SECRET:
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class DestinationSpec:
    kind: DestinationKind
    source_path: str
    cardinality: DestinationCardinality
    scope: ScopeSemantics
    state: ContractState

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DestinationKind):
            _invalid()
        if not isinstance(self.cardinality, DestinationCardinality):
            _invalid()
        if not isinstance(self.scope, ScopeSemantics):
            _invalid()
        if not isinstance(self.state, ContractState):
            _invalid()
        if not _FIELD_PATH_RE.fullmatch(self.source_path):
            _invalid()
        if self.state is not ContractState.SUPPORTED:
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class CredentialSourcePolicy:
    state: ContractState
    allowed_handle_kinds: tuple[OpaqueCredentialKind, ...]
    ambient_dependencies: tuple[AmbientCredentialDependency, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.state, ContractState):
            _invalid()
        _require_tuple(self.allowed_handle_kinds)
        _require_tuple(self.ambient_dependencies)
        if not all(isinstance(item, OpaqueCredentialKind) for item in self.allowed_handle_kinds):
            _invalid()
        if not all(
            isinstance(item, AmbientCredentialDependency) for item in self.ambient_dependencies
        ):
            _invalid()
        if len(set(self.allowed_handle_kinds)) != len(self.allowed_handle_kinds):
            _invalid()
        if len(set(self.ambient_dependencies)) != len(self.ambient_dependencies):
            _invalid()
        if self.ambient_dependencies and self.state is not ContractState.BLOCKED_BY_ADAPTER_GAP:
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class TimeoutPolicy:
    seconds: int
    source: TimeoutSource
    settlement: TimeoutSettlement

    def __post_init__(self) -> None:
        if not isinstance(self.source, TimeoutSource):
            _invalid()
        if not isinstance(self.settlement, TimeoutSettlement):
            _invalid()
        if type(self.seconds) is not int or not 1 <= self.seconds <= 86_400:
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class DryRunContract:
    state: DryRunState
    owner_module: str
    owner_class: str
    method_name: str
    guard_semantics: DryRunGuardSemantics
    termination: DryRunTermination
    provenance_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, DryRunState):
            _invalid()
        if not isinstance(self.guard_semantics, DryRunGuardSemantics):
            _invalid()
        if not isinstance(self.termination, DryRunTermination):
            _invalid()
        if self.state not in {DryRunState.NATIVE_PROVEN, DryRunState.SHARED_ADAPTER_PROVEN}:
            _invalid()
        if not self.owner_module.startswith("ares.modules."):
            _invalid()
        if not self.owner_class or "." in self.owner_class:
            _invalid()
        if self.method_name != "execute":
            _invalid()
        if not _is_sha256(self.provenance_digest):
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class ResultContract:
    findings: ContractState
    credentials: ContractState
    discovered_hosts: ContractState
    loot_artifacts: ContractState
    authoritative_evidence: ContractState

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, ContractState)
            for value in (
                self.findings,
                self.credentials,
                self.discovered_hosts,
                self.loot_artifacts,
                self.authoritative_evidence,
            )
        ):
            _invalid()
        if (
            self.authoritative_evidence is ContractState.SUPPORTED
            and ContractState.UNPROVEN_CURRENT_CONTRACT
            in {
                self.findings,
                self.credentials,
                self.discovered_hosts,
                self.loot_artifacts,
            }
        ):
            _invalid()


@dataclass(frozen=True, slots=True, eq=False)
class ModuleDescriptor:
    contract_version: str
    module_id: str
    category: ModuleCategory
    source_module: str
    source_class: str
    parameter_model: type[BaseModel] = field(repr=False, compare=False)
    parameter_model_identity: str
    parameter_fields: tuple[ParameterFieldSpec, ...]
    parameter_schema_digest: str = field(init=False)
    declared_outputs: tuple[str, ...]
    opsec: OpsecClassification
    minimum_role: MinimumRole
    explicit_attempt_approval: bool
    required_capabilities: tuple[Capability, ...]
    capability_match: CapabilityMatchSemantics
    destination_state: ContractState
    destinations: tuple[DestinationSpec, ...]
    credential_policy: CredentialSourcePolicy
    external_effect: ExternalEffectClass
    idempotency: IdempotencyClass
    retry_eligibility: RetryEligibility
    cancellation_ownership: CancellationOwnership
    compensation: CompensationClass
    timeout: TimeoutPolicy
    dry_run: DryRunContract
    result_contract: ResultContract
    descriptor_complete: bool
    future_gateway_eligible: bool
    blocker_codes: tuple[BlockerCode, ...]
    legacy_requires: tuple[str, ...]
    legacy_capabilities: tuple[Capability, ...]
    legacy_dry_run_supported: bool
    legacy_timeout_override: int | None
    semantic_digest: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        enum_values = (
            (self.category, ModuleCategory),
            (self.opsec, OpsecClassification),
            (self.minimum_role, MinimumRole),
            (self.capability_match, CapabilityMatchSemantics),
            (self.destination_state, ContractState),
            (self.external_effect, ExternalEffectClass),
            (self.idempotency, IdempotencyClass),
            (self.retry_eligibility, RetryEligibility),
            (self.cancellation_ownership, CancellationOwnership),
            (self.compensation, CompensationClass),
        )
        if not all(isinstance(value, kind) for value, kind in enum_values):
            _invalid()
        if not isinstance(self.parameter_model, type) or not issubclass(
            self.parameter_model, BaseModel
        ):
            _invalid()
        if not isinstance(self.credential_policy, CredentialSourcePolicy):
            _invalid()
        if not isinstance(self.timeout, TimeoutPolicy):
            _invalid()
        if not isinstance(self.dry_run, DryRunContract):
            _invalid()
        if not isinstance(self.result_contract, ResultContract):
            _invalid()
        if type(self.explicit_attempt_approval) is not bool:
            _invalid()
        if type(self.descriptor_complete) is not bool:
            _invalid()
        if type(self.future_gateway_eligible) is not bool:
            _invalid()
        if self.contract_version != CONTRACT_VERSION:
            _invalid()
        if not _MODULE_ID_RE.fullmatch(self.module_id):
            _invalid()
        if self.module_id.split(".", 1)[0] != self.category.value:
            _invalid()
        if not self.source_module.startswith("ares.modules."):
            _invalid()
        if not self.source_class or "." in self.source_class:
            _invalid()
        expected_model_identity = (
            f"{self.parameter_model.__module__}.{self.parameter_model.__qualname__}"
        )
        if self.parameter_model_identity != expected_model_identity:
            _invalid()
        for value in (
            self.parameter_fields,
            self.declared_outputs,
            self.required_capabilities,
            self.destinations,
            self.blocker_codes,
            self.legacy_requires,
            self.legacy_capabilities,
        ):
            _require_tuple(value)
        if not all(isinstance(item, ParameterFieldSpec) for item in self.parameter_fields):
            _invalid()
        if not all(type(item) is str and item for item in self.declared_outputs):
            _invalid()
        if not all(isinstance(item, Capability) for item in self.required_capabilities):
            _invalid()
        if not all(isinstance(item, DestinationSpec) for item in self.destinations):
            _invalid()
        if not all(isinstance(item, BlockerCode) for item in self.blocker_codes):
            _invalid()
        if not all(type(item) is str and item for item in self.legacy_requires):
            _invalid()
        if not all(isinstance(item, Capability) for item in self.legacy_capabilities):
            _invalid()
        if len({item.name for item in self.parameter_fields}) != len(self.parameter_fields):
            _invalid()
        if len(set(self.declared_outputs)) != len(self.declared_outputs):
            _invalid()
        if len(set(self.required_capabilities)) != len(self.required_capabilities):
            _invalid()
        if len(set(self.blocker_codes)) != len(self.blocker_codes):
            _invalid()
        paths = [item.source_path for item in self.destinations]
        if len(paths) != len(set(paths)):
            _invalid()
        root_fields = {item.name for item in self.parameter_fields}
        if any(item.source_path.split(".", 1)[0] not in root_fields for item in self.destinations):
            _invalid()
        if (
            self.destination_state is ContractState.DYNAMICALLY_UNBOUNDED
            and BlockerCode.DESTINATION_CONTRACT_UNBOUNDED not in self.blocker_codes
        ):
            _invalid()
        if self.credential_policy.ambient_dependencies and (
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN not in self.blocker_codes
        ):
            _invalid()
        if (
            self.external_effect
            in {
                ExternalEffectClass.MUTATING,
                ExternalEffectClass.CONDITIONALLY_MUTATING,
            }
            and self.retry_eligibility is not RetryEligibility.NEVER
        ):
            _invalid()
        if self.retry_eligibility is RetryEligibility.AFTER_REVALIDATION and (
            self.idempotency is not IdempotencyClass.PROVEN_IDEMPOTENT
            or self.cancellation_ownership is not CancellationOwnership.OWNED
            or self.timeout.settlement is not TimeoutSettlement.PROVEN
        ):
            _invalid()
        lifecycle_unproven = (
            self.idempotency is IdempotencyClass.UNPROVEN_CURRENT_CONTRACT
            or self.retry_eligibility is RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT
            or self.cancellation_ownership is CancellationOwnership.UNPROVEN_CURRENT_CONTRACT
            or self.compensation is CompensationClass.UNPROVEN_CURRENT_CONTRACT
            or self.timeout.settlement is TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        )
        if lifecycle_unproven and BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN not in self.blocker_codes:
            _invalid()
        field_blockers = {
            item.blocker_code for item in self.parameter_fields if item.blocker_code is not None
        }
        if not field_blockers.issubset(set(self.blocker_codes)):
            _invalid()
        if self.future_gateway_eligible:
            if self.blocker_codes:
                _invalid()
            if not self.descriptor_complete:
                _invalid()
            if self.cancellation_ownership is CancellationOwnership.UNPROVEN_CURRENT_CONTRACT:
                _invalid()
            if (
                self.result_contract.authoritative_evidence
                is ContractState.UNPROVEN_CURRENT_CONTRACT
            ):
                _invalid()
        if not self.descriptor_complete:
            _invalid()
        schema_digest = _parameter_schema_digest(self.parameter_fields)
        object.__setattr__(self, "parameter_schema_digest", schema_digest)
        object.__setattr__(self, "semantic_digest", _semantic_digest(self))


@dataclass(frozen=True, slots=True, eq=False)
class CanonicalParameters:
    _values: Mapping[str, Any] = field(repr=False)

    @property
    def values(self) -> Mapping[str, Any]:
        return self._values


@dataclass(frozen=True, slots=True, eq=False)
class ExtractedDestination:
    kind: DestinationKind
    source_path: str
    scope: ScopeSemantics
    value: Any = field(repr=False)


class DescriptorReadinessError(RuntimeError):
    def __init__(
        self,
        code: ReadinessCode,
        locations: Sequence[Sequence[str]] = (),
    ) -> None:
        self.code = code
        self.locations = tuple(tuple(str(part) for part in loc) for loc in locations)
        suffix = ""
        if self.locations:
            suffix = ":" + ",".join(".".join(loc) for loc in self.locations)
        super().__init__(code.value + suffix)

    def __repr__(self) -> str:
        return f"<DescriptorReadinessError code={self.code.value!r}>"


def _invalid() -> None:
    raise DescriptorReadinessError(ReadinessCode.INVALID_DESCRIPTOR)


def _require_tuple(value: object) -> None:
    if type(value) is not tuple:
        _invalid()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _enum_values(values: Sequence[Enum]) -> list[str]:
    return [item.value for item in values]


def _enum_set_values(values: Sequence[Enum]) -> list[str]:
    return sorted(item.value for item in values)


def _parameter_field_data(spec: ParameterFieldSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "canonical_type": spec.canonical_type.value,
        "required": spec.required,
        "default_state": spec.default_state.value,
        "public_default_digest": spec.public_default_digest,
        "legacy_schema_secret": spec.legacy_schema_secret,
        "sensitivity": spec.sensitivity.value,
        "blocker_code": spec.blocker_code.value if spec.blocker_code is not None else None,
        "nested_fields": [_parameter_field_data(item) for item in spec.nested_fields],
    }


def _parameter_schema_digest(fields: tuple[ParameterFieldSpec, ...]) -> str:
    payload = {
        "schema_contract": "ares.parameter-schema.v1",
        "fields": [_parameter_field_data(item) for item in fields],
    }
    return _sha256_json(payload)


def _semantic_data(descriptor: ModuleDescriptor) -> dict[str, Any]:
    result = descriptor.result_contract
    return {
        "contract_version": descriptor.contract_version,
        "module_id": descriptor.module_id,
        "category": descriptor.category.value,
        "source_module": descriptor.source_module,
        "source_class": descriptor.source_class,
        "parameter_model_identity": descriptor.parameter_model_identity,
        "parameter_fields": [_parameter_field_data(item) for item in descriptor.parameter_fields],
        "parameter_schema_digest": descriptor.parameter_schema_digest,
        "declared_outputs": list(descriptor.declared_outputs),
        "opsec": descriptor.opsec.value,
        "minimum_role": descriptor.minimum_role.value,
        "explicit_attempt_approval": descriptor.explicit_attempt_approval,
        "required_capabilities": _enum_set_values(descriptor.required_capabilities),
        "capability_match": descriptor.capability_match.value,
        "destination_state": descriptor.destination_state.value,
        "destinations": [
            {
                "kind": item.kind.value,
                "source_path": item.source_path,
                "cardinality": item.cardinality.value,
                "scope": item.scope.value,
                "state": item.state.value,
            }
            for item in descriptor.destinations
        ],
        "credential_policy": {
            "state": descriptor.credential_policy.state.value,
            "allowed_handle_kinds": _enum_set_values(
                descriptor.credential_policy.allowed_handle_kinds
            ),
            "ambient_dependencies": _enum_set_values(
                descriptor.credential_policy.ambient_dependencies
            ),
        },
        "external_effect": descriptor.external_effect.value,
        "idempotency": descriptor.idempotency.value,
        "retry_eligibility": descriptor.retry_eligibility.value,
        "cancellation_ownership": descriptor.cancellation_ownership.value,
        "compensation": descriptor.compensation.value,
        "timeout": {
            "seconds": descriptor.timeout.seconds,
            "source": descriptor.timeout.source.value,
            "settlement": descriptor.timeout.settlement.value,
        },
        "dry_run": {
            "state": descriptor.dry_run.state.value,
            "owner_module": descriptor.dry_run.owner_module,
            "owner_class": descriptor.dry_run.owner_class,
            "method_name": descriptor.dry_run.method_name,
            "guard_semantics": descriptor.dry_run.guard_semantics.value,
            "termination": descriptor.dry_run.termination.value,
            "provenance_digest": descriptor.dry_run.provenance_digest,
        },
        "result_contract": {
            "findings": result.findings.value,
            "credentials": result.credentials.value,
            "discovered_hosts": result.discovered_hosts.value,
            "loot_artifacts": result.loot_artifacts.value,
            "authoritative_evidence": result.authoritative_evidence.value,
        },
        "descriptor_complete": descriptor.descriptor_complete,
        "future_gateway_eligible": descriptor.future_gateway_eligible,
        "blocker_codes": _enum_set_values(descriptor.blocker_codes),
        "legacy_requires": list(descriptor.legacy_requires),
        "legacy_capabilities": _enum_set_values(descriptor.legacy_capabilities),
        "legacy_dry_run_supported": descriptor.legacy_dry_run_supported,
        "legacy_timeout_override": descriptor.legacy_timeout_override,
    }


def _sha256_json(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _semantic_digest(descriptor: ModuleDescriptor) -> str:
    return _sha256_json(_semantic_data(descriptor))


def descriptor_semantic_digest(descriptor: ModuleDescriptor) -> str:
    return _semantic_digest(descriptor)


def _pf(
    name: str,
    canonical_type: ParameterType,
    required: bool,
    default_state: DefaultSemanticState,
    public_default_digest: str | None,
    legacy_schema_secret: bool,
    sensitivity: Sensitivity,
) -> ParameterFieldSpec:
    return ParameterFieldSpec(
        name=name,
        canonical_type=canonical_type,
        required=required,
        default_state=default_state,
        public_default_digest=public_default_digest,
        legacy_schema_secret=legacy_schema_secret,
        sensitivity=sensitivity,
        blocker_code=(
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT
            if default_state is DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED
            else (
                BlockerCode.DEFAULT_FACTORY_UNEVALUATED
                if default_state is DefaultSemanticState.DEFAULT_FACTORY_UNEVALUATED_BLOCKED
                else None
            )
        ),
        nested_fields=(),
    )


def _native_dry_run(
    owner_module: str,
    owner_class: str,
    provenance_digest: str,
) -> DryRunContract:
    return DryRunContract(
        state=DryRunState.NATIVE_PROVEN,
        owner_module=owner_module,
        owner_class=owner_class,
        method_name="execute",
        guard_semantics=DryRunGuardSemantics.CONTEXT_GETATTR_TRUTHY,
        termination=DryRunTermination.RETURN_BEFORE_EXTERNAL_EFFECT,
        provenance_digest=provenance_digest,
    )


def _shared_lateral_dry_run(provenance_digest: str) -> DryRunContract:
    return DryRunContract(
        state=DryRunState.SHARED_ADAPTER_PROVEN,
        owner_module="ares.modules.lateral.modules",
        owner_class="BaseLateralModule",
        method_name="execute",
        guard_semantics=DryRunGuardSemantics.CONTEXT_GETATTR_TRUTHY,
        termination=DryRunTermination.RETURN_BEFORE_EXTERNAL_EFFECT,
        provenance_digest=provenance_digest,
    )


def _is_canonical_dry_run_guard(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) == 3
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "ctx"
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "dry_run"
        and isinstance(node.args[2], ast.Constant)
        and node.args[2].value is False
        and not node.keywords
    )


def _dry_run_prefix_digest(method: ast.AsyncFunctionDef, guard_index: int) -> str:
    normalized = ast.dump(
        ast.Module(body=method.body[: guard_index + 1], type_ignores=[]),
        annotate_fields=True,
        include_attributes=False,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_dry_run_source(
    descriptor: ModuleDescriptor,
    source: str,
) -> DryRunContract:
    """Validate a caller-supplied source copy against fixed dry-run provenance."""
    try:
        tree = ast.parse(source)
        owner = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == descriptor.dry_run.owner_class
        )
        method = next(
            node
            for node in owner.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == descriptor.dry_run.method_name
        )
        guards = [
            (index, node)
            for index, node in enumerate(method.body)
            if isinstance(node, ast.If) and _is_canonical_dry_run_guard(node.test)
        ]
        if len(guards) != 1:
            raise ValueError
        guard_index, guard = guards[0]
        if not guard.body or not isinstance(guard.body[-1], ast.Return):
            raise ValueError
        if guard.orelse:
            raise ValueError
        if any(
            isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom, ast.With, ast.AsyncWith))
            for statement in method.body[:guard_index]
            for node in ast.walk(statement)
        ):
            raise ValueError
        observed = _dry_run_prefix_digest(method, guard_index)
        if not hmac.compare_digest(observed, descriptor.dry_run.provenance_digest):
            raise ValueError
    except (SyntaxError, StopIteration, TypeError, ValueError):
        raise DescriptorReadinessError(ReadinessCode.DRY_RUN_PROVENANCE_MISMATCH) from None
    return descriptor.dry_run


def _destination(
    kind: DestinationKind,
    source_path: str,
    cardinality: DestinationCardinality,
    scope: ScopeSemantics,
) -> DestinationSpec:
    return DestinationSpec(
        kind=kind,
        source_path=source_path,
        cardinality=cardinality,
        scope=scope,
        state=ContractState.SUPPORTED,
    )


_FIRST_PARTY_DESCRIPTORS = (
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.adcs",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.adcs",
        source_class="ADCSModule",
        parameter_model=_params.ADCSParams,
        parameter_model_identity="ares.modules.params.ADCSParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "exploit_esc1",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target_user",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=(
            "adcs_findings",
            "certificate",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "target_user",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            180, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.adcs",
            "ADCSModule",
            "275e1f9e554c9088f5e8d00265ee5e4d4fb679eb1c08599d15eb20ee561494a1",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=180,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.asreproast",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.asreproast",
        source_class="ASREPRoastModule",
        parameter_model=_params.ASREPRoastParams,
        parameter_model_identity="ares.modules.params.ASREPRoastParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "userfile",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=("asrep_hashes",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "userfile",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.asreproast",
            "ASREPRoastModule",
            "d508ca0bf293251034736418271b2e311ca733866e77cf76969caf60a54da2ef",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.coerce",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.coerce",
        source_class="CoerceModule",
        parameter_model=_params.CoerceParams,
        parameter_model_identity="ares.modules.params.CoerceParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "listener_ip",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "method",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "634635a2166efa2ae765abd31d4ae807082287e329a8a7fff42b1fb30f65087e",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("coercion_sent",),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.CALLBACK,
                "listener_ip",
                DestinationCardinality.SCALAR,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.coerce",
            "CoerceModule",
            "275e1f9e554c9088f5e8d00265ee5e4d4fb679eb1c08599d15eb20ee561494a1",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.dcsync",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.dcsync",
        source_class="DCSyncModule",
        parameter_model=_params.DCSyncParams,
        parameter_model_identity="ares.modules.params.DCSyncParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target_user",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=("ntlm_hashes",),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "target_user",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            600, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.dcsync",
            "DCSyncModule",
            "f11b9ec0905859175950fea9cf4fb931698ae5eb105f15e0645c33b549046dbc",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=("domain_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=600,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.delegation_abuse",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.delegation_abuse",
        source_class="DelegationAbuseModule",
        parameter_model=_params.DelegationAbuseParams,
        parameter_model_identity="ares.modules.params.DelegationAbuseParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "mode",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "959a8f76ca25098c19d6b6c0ddb896bcc2a8c870c27b99a395e9ff0777661fb5",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target_computer",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "impersonate_user",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "target_service",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "367d9afe6b797f3b5d8c27fe0b9cf9dc0a767ee77e75c2419527b04a063f9470",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "kerberos_ticket",
            "owned_hosts",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.HOST,
                "target_computer",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "impersonate_user",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.SERVICE_PRINCIPAL,
                "target_service",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.delegation_abuse",
            "DelegationAbuseModule",
            "275e1f9e554c9088f5e8d00265ee5e4d4fb679eb1c08599d15eb20ee561494a1",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.enum_acl",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.enum_acl",
        source_class="ADEnumACLModule",
        parameter_model=_params.DomainAuthParams,
        parameter_model_identity="ares.modules.params.DomainAuthParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("acl_findings",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.enum_acl",
            "ADEnumACLModule",
            "02ef5f9ff8ff56667867768cbec000273e451c05f6e0fa81fb57faae9445cebb",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.enum_computers",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.enum_computers",
        source_class="ADEnumComputersModule",
        parameter_model=_params.DomainAuthParams,
        parameter_model_identity="ares.modules.params.DomainAuthParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("computer_list",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.enum_computers",
            "ADEnumComputersModule",
            "da48d866376ef9e98686d4365637afb0f04a387d65f7f7378f45c4d6c50c8574",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.enum_spn",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.enum_spn",
        source_class="ADEnumSPNModule",
        parameter_model=_params.DomainAuthParams,
        parameter_model_identity="ares.modules.params.DomainAuthParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("spn_list",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.enum_spn",
            "ADEnumSPNModule",
            "2ce02df8b02a943bb23cb41f4e992fbc407652cc3ad9c03859688caecf76394a",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.enum_users",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.enum_users",
        source_class="ADEnumUsersModule",
        parameter_model=_params.DomainAuthParams,
        parameter_model_identity="ares.modules.params.DomainAuthParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("user_list",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            90, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.enum_users",
            "ADEnumUsersModule",
            "da48d866376ef9e98686d4365637afb0f04a387d65f7f7378f45c4d6c50c8574",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=90,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.kerberoast",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.kerberoast",
        source_class="KerberoastModule",
        parameter_model=_params.KerberoastParams,
        parameter_model_identity="ares.modules.params.KerberoastParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target_user",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=("kerberos_hashes",),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "target_user",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.kerberoast",
            "KerberoastModule",
            "08c71e2ca82aa26109bca68992f7041ffcbbda8d26d368733ad394185124c0a7",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("domain_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.laps_enum",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.laps_enum",
        source_class="LAPSEnumModule",
        parameter_model=_params.LAPSEnumParams,
        parameter_model_identity="ares.modules.params.LAPSEnumParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "computer_filter",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "laps_passwords",
            "valid_credentials",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            60, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.laps_enum",
            "LAPSEnumModule",
            "275e1f9e554c9088f5e8d00265ee5e4d4fb679eb1c08599d15eb20ee561494a1",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=60,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ad.sccm",
        category=ModuleCategory.AD,
        source_module="ares.modules.ad.sccm",
        source_class="SCCMModule",
        parameter_model=_params.SCCMParams,
        parameter_model_identity="ares.modules.params.SCCMParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "sccm_server",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "cleartext_credentials",
            "sccm_findings",
            "owned_hosts",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.HOST,
                "sccm_server",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.ad.sccm",
            "SCCMModule",
            "842887415782f832edeee1b60a26ee4024c13aa7d0818aad003a9ef83bfc9edc",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("domain_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="ai.autonomous_planner",
        category=ModuleCategory.AI,
        source_module="ares.modules.ai.autonomous_planner",
        source_class="AIAutonomousPlannerModule",
        parameter_model=_params.AIPlannerParams,
        parameter_model_identity="ares.modules.params.AIPlannerParams",
        parameter_fields=(
            _pf(
                "goal",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "21dcfac863f8968d3f283c833770d5f955ecfeec315c1754242e5092351228f9",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "llm_backend",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "389432cbf83f3d1b64029a75864ec96f8fd06451b4c99d7b28385d395d480bfa",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "llm_model",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "auto_approve",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "execution_plan",
            "ai_reasoning",
            "confidence_score",
            "warnings",
        ),
        opsec=OpsecClassification.LOCAL,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.LLM_PROVIDER,
                "llm_backend",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROVIDER_BOUNDARY,
            ),
            _destination(
                DestinationKind.LLM_PROVIDER,
                "llm_model",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROVIDER_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.API_TOKEN,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.ENV_ANTHROPIC_API_KEY,
                AmbientCredentialDependency.ENV_OPENAI_API_KEY,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.BILLABLE_NONDETERMINISTIC_EGRESS,
        idempotency=IdempotencyClass.PROVEN_NON_IDEMPOTENT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            180, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.ai.autonomous_planner",
            "AIAutonomousPlannerModule",
            "e3122f174386346cef9b2608a30470c5698382690cc0d35cf358ef8eb83c0de6",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.LLM_EGRESS_POLICY_REQUIRED,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=180,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.aws",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.aws",
        source_class="AWSEnumModule",
        parameter_model=_params.AWSParams,
        parameter_model_identity="ares.modules.params.AWSParams",
        parameter_fields=(
            _pf(
                "profile",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "access_key",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "secret_key",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "session_token",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "region",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "57fc100527546ef06a91ff1e3c01bd7ab0c0ddca4f2847cccf998689957783c5",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("aws_findings",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_REGION,
                "region",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.CLOUD_SESSION,),
            ambient_dependencies=(AmbientCredentialDependency.AWS_SDK_DEFAULT_CHAIN,),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.aws",
            "AWSEnumModule",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.aws_privesc",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.aws_privesc",
        source_class="AWSPrivescModule",
        parameter_model=_params.AWSPrivescParams,
        parameter_model_identity="ares.modules.params.AWSPrivescParams",
        parameter_fields=(
            _pf(
                "access_key",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "secret_key",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "session_token",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "region",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "57fc100527546ef06a91ff1e3c01bd7ab0c0ddca4f2847cccf998689957783c5",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "aws_privesc_paths",
            "aws_findings",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_REGION,
                "region",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.CLOUD_SESSION,),
            ambient_dependencies=(AmbientCredentialDependency.AWS_SDK_DEFAULT_CHAIN,),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.aws_privesc",
            "AWSPrivescModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.azure",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.azure",
        source_class="AzureModule",
        parameter_model=_params.AzureParams,
        parameter_model_identity="ares.modules.params.AzureParams",
        parameter_fields=(
            _pf(
                "subscription_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "tenant_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_secret",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
        ),
        declared_outputs=("azure_findings",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_SUBSCRIPTION,
                "subscription_id",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
            _destination(
                DestinationKind.CLOUD_TENANT,
                "tenant_id",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.CLOUD_SESSION,),
            ambient_dependencies=(AmbientCredentialDependency.AZURE_DEFAULT_CREDENTIAL,),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.azure",
            "AzureModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.azure_ad",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.azure_ad",
        source_class="AzureADModule",
        parameter_model=_params.AzureADParams,
        parameter_model_identity="ares.modules.params.AzureADParams",
        parameter_fields=(
            _pf(
                "tenant_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_secret",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "access_token",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "technique",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "959a8f76ca25098c19d6b6c0ddb896bcc2a8c870c27b99a395e9ff0777661fb5",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "access_tokens",
            "azure_ad_findings",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_TENANT,
                "tenant_id",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.API_TOKEN,
                OpaqueCredentialKind.CLOUD_SESSION,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.azure_ad",
            "AzureADModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.gcp",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.gcp",
        source_class="GCPModule",
        parameter_model=_params.GCPParams,
        parameter_model_identity="ares.modules.params.GCPParams",
        parameter_fields=(
            _pf(
                "project_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "credentials_file",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=("gcp_findings",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_PROJECT,
                "project_id",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "credentials_file",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.CLOUD_SESSION,),
            ambient_dependencies=(
                AmbientCredentialDependency.GOOGLE_APPLICATION_DEFAULT_CREDENTIALS,
            ),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.gcp",
            "GCPModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="cloud.identity_federation_abuse",
        category=ModuleCategory.CLOUD,
        source_module="ares.modules.cloud.identity_federation",
        source_class="CloudIdentityFederationModule",
        parameter_model=_params.CloudFederationParams,
        parameter_model_identity="ares.modules.params.CloudFederationParams",
        parameter_fields=(
            _pf(
                "tenant_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_id",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "client_secret",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "access_key",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "secret_key",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "adfs_url",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "krbtgt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "mode",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "959a8f76ca25098c19d6b6c0ddb896bcc2a8c870c27b99a395e9ff0777661fb5",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "federation_trusts",
            "golden_saml_paths",
            "oauth_tokens",
            "pivot_paths",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.CLOUD_TENANT,
                "tenant_id",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.CLOUD_BOUNDARY,
            ),
            _destination(
                DestinationKind.NETWORK_ENDPOINT,
                "adfs_url",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.CLOUD_SESSION,
                OpaqueCredentialKind.HASH_MATERIAL,
            ),
            ambient_dependencies=(AmbientCredentialDependency.AWS_SDK_DEFAULT_CHAIN,),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            300, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.cloud.identity_federation",
            "CloudIdentityFederationModule",
            "ab2c032fc022b8ca0b311884aecebef89064e85bcd3dfc9e07fb0b4fbad494e8",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=300,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="credential.crack",
        category=ModuleCategory.CREDENTIAL,
        source_module="ares.modules.credential.crack",
        source_class="CrackModule",
        parameter_model=_params.CredentialCrackParams,
        parameter_model_identity="ares.modules.params.CredentialCrackParams",
        parameter_fields=(
            _pf(
                "hashcat_path",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "wordlist",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "rules",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
        ),
        declared_outputs=("cracked_credentials",),
        opsec=OpsecClassification.LOCAL,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_PROCESS,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.LOCAL_FILE,
                "hashcat_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "wordlist",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "rules",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.VAULT_RECORD,),
            ambient_dependencies=(AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            3600, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.credential.crack",
            "CrackModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=("vault",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=3600,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="credential.golden_ticket",
        category=ModuleCategory.CREDENTIAL,
        source_module="ares.modules.credential.golden_ticket",
        source_class="GoldenTicketModule",
        parameter_model=_params.GoldenTicketParams,
        parameter_model_identity="ares.modules.params.GoldenTicketParams",
        parameter_fields=(
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain_sid",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "krbtgt_hash",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "target",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "golden_ticket",
            "kerberos_ticket",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=True,
        required_capabilities=(Capability.CAP_FS,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.HASH_MATERIAL,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.credential.golden_ticket",
            "GoldenTicketModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=(
            "ntlm_hashes",
            "domain_admin_creds",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="credential.pass_spray",
        category=ModuleCategory.CREDENTIAL,
        source_module="ares.modules.credential.pass_spray",
        source_class="PassSprayModule",
        parameter_model=_params.PassSprayParams,
        parameter_model_identity="ares.modules.params.PassSprayParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "users",
                ParameterType.STRING_LIST,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "passwords",
                ParameterType.STRING_LIST,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SECRET,
            ),
            _pf(
                "delay_s",
                ParameterType.FLOAT,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "d0ff5974b6aa52cf562bea5921840c032a860a91a3512f7fe8f768f6bbe005f6",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "max_per_user",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("valid_credentials",),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "users",
                DestinationCardinality.COLLECTION,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.credential.pass_spray",
            "PassSprayModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("user_list",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="credential.pass_the_hash",
        category=ModuleCategory.CREDENTIAL,
        source_module="ares.modules.credential.pass_the_hash",
        source_class="PassTheHashModule",
        parameter_model=_params.PassTheHashParams,
        parameter_model_identity="ares.modules.params.PassTheHashParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "nt_hash",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "lm_hash",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "6f75e753abd43a163cbd81ada647f1c30f8903498512ad28da7ccb61de1b7eb1",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "valid_credentials",
            "owned_hosts",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.NTLM_HASH,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.credential.pass_the_hash",
            "PassTheHashModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("ntlm_hashes",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="credential.reuse",
        category=ModuleCategory.CREDENTIAL,
        source_module="ares.modules.credential.reuse",
        source_class="CredentialReuseModule",
        parameter_model=_params.CredentialReuseParams,
        parameter_model_identity="ares.modules.params.CredentialReuseParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "protocol",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "49bc0f9e0e5dabbc974840dcb1d1cca640455ad0b9481026b61278bc117c1b6e",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "valid_credentials",
            "owned_hosts",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PROTOCOL,
                "protocol",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.VAULT_RECORD,),
            ambient_dependencies=(AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.credential.reuse",
            "CredentialReuseModule",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("target",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="edr.bypass_adaptive",
        category=ModuleCategory.EDR,
        source_module="ares.modules.edr.bypass_adaptive",
        source_class="EDRAdaptiveBypassModule",
        parameter_model=_params.EDRBypassParams,
        parameter_model_identity="ares.modules.params.EDRBypassParams",
        parameter_fields=(
            _pf(
                "edr_vendor",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "eb8bf0d80db323992f6b634aab492b1e6d9e96a8e87a511c2a0db75ab929452c",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "os_version",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "viable_techniques",
            "recommended_approach",
            "edr_vendor",
            "bypass_plan",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=True,
        required_capabilities=(),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.PLANNING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.edr.bypass_adaptive",
            "EDRAdaptiveBypassModule",
            "93703552f109e2c79bd5a9e3d3c69b69c68a88b2a11b3207355a701a6303e228",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("fingerprint_result",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=120,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="exfil.secrets_scan",
        category=ModuleCategory.EXFIL,
        source_module="ares.modules.exfil.secrets_scan",
        source_class="SecretsScan",
        parameter_model=_params.SecretsScanParams,
        parameter_model_identity="ares.modules.params.SecretsScanParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "platform",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "f32af962aa06e4f20ceda568d6493687257ce3aff79853b582d13ee6fbf5171b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "credential_list",
            "sensitive_data_found",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.exfil.secrets_scan",
            "SecretsScan",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("target",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="exfil.smb_shares",
        category=ModuleCategory.EXFIL,
        source_module="ares.modules.exfil.smb_shares",
        source_class="SmbSharesExfil",
        parameter_model=_params.SmbSharesParams,
        parameter_model_identity="ares.modules.params.SmbSharesParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "max_depth",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "file_share_list",
            "sensitive_file_paths",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.exfil.smb_shares",
            "SmbSharesExfil",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "target",
            "credential",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="exfil.staged_collection",
        category=ModuleCategory.EXFIL,
        source_module="ares.modules.exfil.staged_collection",
        source_class="StagedCollectionModule",
        parameter_model=_params.StagedCollectionParams,
        parameter_model_identity="ares.modules.params.StagedCollectionParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "destination",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "platform",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "f32af962aa06e4f20ceda568d6493687257ce3aff79853b582d13ee6fbf5171b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "max_files",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "27badc983df1780b60c2b3fa9d3a19a00e46aac798451f0febdca52920faaddf",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "sensitive_file_paths",
            "collection_inventory",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.EXFILTRATION_PATH,
                "destination",
                DestinationCardinality.SCALAR,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.exfil.staged_collection",
            "StagedCollectionModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("lateral_session",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.dcom",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.dcom",
        source_class="DCOMLateral",
        parameter_model=_params.DCOMParams,
        parameter_model_identity="ares.modules.params.DCOMParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "method",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "634635a2166efa2ae765abd31d4ae807082287e329a8a7fff42b1fb30f65087e",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "lateral_session",
            "command_output",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.mssql",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.mssql",
        source_class="MSSQLModule",
        parameter_model=_params.MSSQLParams,
        parameter_model_identity="ares.modules.params.MSSQLParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "38c02f46b57855590f8cdd17c1b2704e72c3effbb92833b46fec0f2a52cc61aa",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "technique",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "062c231b0701a24f6c35e8fbfaa7d961ad23301c293f425c4f667d293ae78d83",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "6f75e753abd43a163cbd81ada647f1c30f8903498512ad28da7ccb61de1b7eb1",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "linked",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "listener",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "command_output",
            "lateral_session",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
            _destination(
                DestinationKind.HOST,
                "linked",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.CALLBACK,
                "listener",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.lateral.mssql",
            "MSSQLModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.ntlm_relay",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.ntlm_relay",
        source_class="NTLMRelayModule",
        parameter_model=_params.NTLMRelayParams,
        parameter_model_identity="ares.modules.params.NTLMRelayParams",
        parameter_fields=(
            _pf(
                "dc",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.SECRET_STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "use_ldaps",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "targets",
                ParameterType.STRING_LIST,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "coerce_source",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "target_user",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "mode",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "1e5941238a72b1f89a5d4cfad9164d5d37f08fab209161841ebf39bf057083d4",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "relay_targets",
            "machine_account",
            "kerberos_ticket",
            "owned_hosts",
        ),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "dc",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.RELAY_TARGET,
                "targets",
                DestinationCardinality.COLLECTION,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.HOST,
                "coerce_source",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.ACCOUNT,
                "target_user",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.lateral.ntlm_relay",
            "NTLMRelayModule",
            "53d310ea0ae2802f96a806a36bc0c3f082fe2fc9d990dd32cebae74c713d5d63",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
        ),
        legacy_requires=("domain_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.psexec",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.modules",
        source_class="PsExecLateral",
        parameter_model=_params.PsExecParams,
        parameter_model_identity="ares.modules.params.PsExecParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "service_name",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "lateral_session",
            "command_output",
        ),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "smb_access",
            "local_admin_creds",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.rdp",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.modules",
        source_class="RDPLateral",
        parameter_model=_params.RDPLateralParams,
        parameter_model_identity="ares.modules.params.RDPLateralParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("lateral_session",),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "rdp_access",
            "domain_creds",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.smb_relay",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.smb_relay",
        source_class="SMBRelayAuditModule",
        parameter_model=_params.SMBRelayParams,
        parameter_model_identity="ares.modules.params.SMBRelayParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "targets",
                ParameterType.STRING_LIST,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "check_ldap",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "smb_signing_config",
            "relay_candidates",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.RELAY_TARGET,
                "targets",
                DestinationCardinality.COLLECTION,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.lateral.smb_relay",
            "SMBRelayAuditModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.ssh_pivot",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.modules",
        source_class="SSHPivot",
        parameter_model=_params.SSHPivotParams,
        parameter_model_identity="ares.modules.params.SSHPivotParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "socks_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "32eb1a8dafeb0873c8d00b0e9058c8c77ff6c6d9235b3236989c50ef63d8f9ba",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "lateral_session",
            "socks5_proxy",
            "command_output",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "socks_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "ssh_access",
            "ssh_credentials",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.winrm",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.modules",
        source_class="WinRMLateral",
        parameter_model=_params.WinRMParams,
        parameter_model_identity="ares.modules.params.WinRMParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "lateral_session",
            "command_output",
            "powershell_session",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "winrm_access",
            "domain_creds",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="lateral.wmiexec",
        category=ModuleCategory.LATERAL,
        source_module="ares.modules.lateral.modules",
        source_class="WmiExecLateral",
        parameter_model=_params.WmiExecParams,
        parameter_model_identity="ares.modules.params.WmiExecParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "lateral_session",
            "command_output",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_shared_lateral_dry_run(
            "3cdb0be1530433b93781f1cdb50fb68c34ff118d3d1e66b01f44d96f5c29d694"
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "wmi_access",
            "domain_creds",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.container",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.container",
        source_class="ContainerEscapeModule",
        parameter_model=_params.ContainerEscapeParams,
        parameter_model_identity="ares.modules.params.ContainerEscapeParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "container_escape_vectors",
            "k8s_rbac_findings",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.container",
            "ContainerEscapeModule",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.kernel_suggester",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.kernel_suggester",
        source_class="KernelSuggesterModule",
        parameter_model=_params.KernelSuggesterParams,
        parameter_model_identity="ares.modules.params.KernelSuggesterParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.kernel_suggester",
            "KernelSuggesterModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("ssh_credentials",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.ld_preload",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.ld_preload",
        source_class="LDPreloadModule",
        parameter_model=_params.LDPreloadParams,
        parameter_model_identity="ares.modules.params.LDPreloadParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.ld_preload",
            "LDPreloadModule",
            "44b752036b6fcfcc60e21edf7ca185bf1b360afcd4995cb9f9f9e466ee12b393",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.nfs_escape",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.nfs_escape",
        source_class="NFSEscapeModule",
        parameter_model=_params.NFSEscapeParams,
        parameter_model_identity="ares.modules.params.NFSEscapeParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.nfs_escape",
            "NFSEscapeModule",
            "44b752036b6fcfcc60e21edf7ca185bf1b360afcd4995cb9f9f9e466ee12b393",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.privesc",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.privesc",
        source_class="LinuxPrivescModule",
        parameter_model=_params.LinuxPrivescParams,
        parameter_model_identity="ares.modules.params.LinuxPrivescParams",
        parameter_fields=(
            _pf(
                "host",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "410dec60703f87c32cfce480d66f020b622c8ae854b4fe757e83942af1cb8678",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "ssh_user",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "ssh_key",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_pass",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "host",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "ssh_key",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.SSH_PRIVATE_KEY,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.privesc",
            "LinuxPrivescModule",
            "414218f4809f0c2aed98181967ad565617448a46bc8e0e6f887d328316348090",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="linux.service_hijack",
        category=ModuleCategory.LINUX,
        source_module="ares.modules.linux.service_hijack",
        source_class="ServiceHijackModule",
        parameter_model=_params.ServiceHijackParams,
        parameter_model_identity="ares.modules.params.ServiceHijackParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "ssh_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "785f3ec7eb32f30b90cd0fcf3657d388b5ff4297f2f9716ff66e9b69c05ddd09",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ssh_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.linux.service_hijack",
            "ServiceHijackModule",
            "44b752036b6fcfcc60e21edf7ca185bf1b360afcd4995cb9f9f9e466ee12b393",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.dns_enum",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.dns_enum",
        source_class="DnsEnumModule",
        parameter_model=_params.DNSEnumParams,
        parameter_model_identity="ares.modules.params.DNSEnumParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "brute",
                ParameterType.BOOLEAN,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "dns_records",
            "subdomains",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.dns_enum",
            "DnsEnumModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.http_fingerprint",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.http_fingerprint",
        source_class="HttpFingerprintModule",
        parameter_model=_params.HTTPFingerprintParams,
        parameter_model_identity="ares.modules.params.HTTPFingerprintParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "ports",
                ParameterType.INTEGER_LIST,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "f0805c67cbb14c13b9307dbd671aa7667a03774e9e1fc6ecd5f60fdbe85ca434",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "timeout",
                ParameterType.FLOAT,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "a19a1584344c1f3783bff51524a5a4b86f2cc09356c9dbfb6af9cd236e314362",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "web_fingerprint",
            "admin_interfaces",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ports",
                DestinationCardinality.COLLECTION,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.http_fingerprint",
            "HttpFingerprintModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.pivot",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.pivot",
        source_class="PivotModule",
        parameter_model=_params.PivotParams,
        parameter_model_identity="ares.modules.params.PivotParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "key_path",
                ParameterType.OPTIONAL_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "local_port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "32eb1a8dafeb0873c8d00b0e9058c8c77ff6c6d9235b3236989c50ef63d8f9ba",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "pivot_tunnel",
            "proxy_url",
            "proxychains_config",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_FS,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.LOCAL_FILE,
                "key_path",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.LOCAL_OPERATOR,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "local_port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.PASSWORD,
                OpaqueCredentialKind.SSH_PRIVATE_KEY,
                OpaqueCredentialKind.VAULT_RECORD,
            ),
            ambient_dependencies=(
                AmbientCredentialDependency.EXECUTION_CONTEXT_BEST_CREDENTIAL,
                AmbientCredentialDependency.EXECUTION_CONTEXT_VAULT,
            ),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            60, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.pivot",
            "PivotModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.AMBIENT_CREDENTIALS_FORBIDDEN,
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "target",
            "credential",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=60,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.port_scan",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.port_scan",
        source_class="PortScanModule",
        parameter_model=_params.PortScanParams,
        parameter_model_identity="ares.modules.params.PortScanParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "ports",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "9765135f1a2c85bb0ac28d304bffe031262a8553d1b3df1bbc32c580d828bec4",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "timeout",
                ParameterType.FLOAT,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "d0ff5974b6aa52cf562bea5921840c032a860a91a3512f7fe8f768f6bbe005f6",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "threads",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "ad57366865126e55649ecb23ae1d48887544976efea46a48eb5d85a6eeb4d306",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "open_ports",
            "service_map",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ports",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.port_scan",
            "PortScanModule",
            "a2184f29d180282b8067f2132f3bb48f46fdf45e87106b47b2fde008ff9586f0",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.service_detect",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.service_detect",
        source_class="ServiceDetectModule",
        parameter_model=_params.ServiceDetectParams,
        parameter_model_identity="ares.modules.params.ServiceDetectParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "ports",
                ParameterType.INTEGER_LIST,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "timeout",
                ParameterType.FLOAT,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "a416ea84421fa7e1351582da48235bac88380a337ec5cb5a9239dc7d57908b4b",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "service_versions",
            "vulnerable_services",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "ports",
                DestinationCardinality.COLLECTION,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.service_detect",
            "ServiceDetectModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("open_ports",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="network.snmp_enum",
        category=ModuleCategory.NETWORK,
        source_module="ares.modules.network.snmp_enum",
        source_class="SnmpEnumModule",
        parameter_model=_params.SNMPEnumParams,
        parameter_model_identity="ares.modules.params.SNMPEnumParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "port",
                ParameterType.INTEGER,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "bb668ca95563216088b98a62557fa1e26802563f3919ac78ae30533bb9ed422c",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "communities",
                ParameterType.STRING_LIST,
                False,
                DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED,
                None,
                False,
                Sensitivity.SECRET,
            ),
        ),
        declared_outputs=(
            "snmp_findings",
            "system_info",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.NETWORK_PORT,
                "port",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.SNMP_COMMUNITY,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.network.snmp_enum",
            "SnmpEnumModule",
            "a2184f29d180282b8067f2132f3bb48f46fdf45e87106b47b2fde008ff9586f0",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.SENSITIVE_NONEMPTY_DEFAULT,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="opsec.coverage_predictor",
        category=ModuleCategory.OPSEC,
        source_module="ares.modules.opsec.coverage_predictor",
        source_class="CoveragePredictorModule",
        parameter_model=_params.CoveragePredictorParams,
        parameter_model_identity="ares.modules.params.CoveragePredictorParams",
        parameter_fields=(
            _pf(
                "noise_profile",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "82fbb169e798324839513347c048ecc9c91a6574588e1760f13d6b9650c328bf",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "detection_score",
            "action_risks",
            "wait_recommendation",
            "recommendations",
        ),
        opsec=OpsecClassification.LOCAL,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.PROVEN_NONE,
        destinations=(),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.LOCAL_ANALYSIS,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            30, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.opsec.coverage_predictor",
            "CoveragePredictorModule",
            "0f0d0c72007efb36ca509f4236647b2f6f2725651834cc862a5d2ec7f8102d44",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=30,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="persistence.registry_run",
        category=ModuleCategory.PERSISTENCE,
        source_module="ares.modules.persistence.scheduled_task",
        source_class="RegistryRunKeyPersistence",
        parameter_model=_params.RegistryRunParams,
        parameter_model_identity="ares.modules.params.RegistryRunParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "key_name",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "c34df72a6e229eee966adc3d537fad3475d402af426b663e389fe0e3b113e430",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "7efa09d56921166a1c309375a37816d89e62dc305c96005a563cb4dee60c8701",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "persistence_established",
            "registry_key",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=True,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_OBJECT,
                "key_name",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.persistence.scheduled_task",
            "RegistryRunKeyPersistence",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "target",
            "credential",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="persistence.scheduled_task",
        category=ModuleCategory.PERSISTENCE,
        source_module="ares.modules.persistence.scheduled_task",
        source_class="ScheduledTaskPersistence",
        parameter_model=_params.ScheduledTaskParams,
        parameter_model_identity="ares.modules.params.ScheduledTaskParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "task_name",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "b93ba3f05ff4ef4e0efe0d867c4ff68430431ce73f8566548e305c783458ca0b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "7efa09d56921166a1c309375a37816d89e62dc305c96005a563cb4dee60c8701",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "persistence_established",
            "task_name",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=True,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_OBJECT,
                "task_name",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.persistence.scheduled_task",
            "ScheduledTaskPersistence",
            "c7842cdab3cb2b640e1c9db632fcd0adef0b7f10e4e44fbb5e3309636bb8411d",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(
            "target",
            "credential",
        ),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="persistence.wmi_subscription",
        category=ModuleCategory.PERSISTENCE,
        source_module="ares.modules.persistence.wmi_subscription",
        source_class="WMISubscriptionModule",
        parameter_model=_params.WMISubscriptionParams,
        parameter_model_identity="ares.modules.params.WMISubscriptionParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "subscription_name",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "688608c4dc3b1c7b5778a04d3db3f03ece3ccce8080574c39eaf9b82745e432b",
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "7efa09d56921166a1c309375a37816d89e62dc305c96005a563cb4dee60c8701",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("persistence_established",),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=True,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_OBJECT,
                "subscription_name",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.SECONDARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.persistence.wmi_subscription",
            "WMISubscriptionModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="recon.fingerprint",
        category=ModuleCategory.RECON,
        source_module="ares.modules.recon.fingerprint",
        source_class="FingerprintModule",
        parameter_model=_params.FingerprintParams,
        parameter_model_identity="ares.modules.params.FingerprintParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "timeout",
                ParameterType.FLOAT,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "a19a1584344c1f3783bff51524a5a4b86f2cc09356c9dbfb6af9cd236e314362",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("fingerprint_result",),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.NOT_APPLICABLE,
            allowed_handle_kinds=(),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.recon.fingerprint",
            "FingerprintModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.applocker_bypass",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.applocker_bypass",
        source_class="AppLockerBypassModule",
        parameter_model=_params.AppLockerBypassParams,
        parameter_model_identity="ares.modules.params.AppLockerBypassParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "command",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "da6c05547c11d51f5ad6e778bd8eec9332041cc50270f25c39d80a7172e623be",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "applocker_config",
            "privesc_vectors",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.REMOTE_PROCESS,
                "command",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PROCESS_BOUNDARY,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.applocker_bypass",
            "AppLockerBypassModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.dpapi",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.dpapi",
        source_class="DPAPIModule",
        parameter_model=_params.DPAPIParams,
        parameter_model_identity="ares.modules.params.DPAPIParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "targets",
                ParameterType.STRING_LIST,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "4543a85a523a40e9c7155de5a7a5ab025c8a17603579b27629f07611be77e4cd",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "cleartext_credentials",
            "browser_passwords",
        ),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            180, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.dpapi",
            "DPAPIModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=(),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=180,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.lsa_secrets",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.lsa_secrets",
        source_class="LSASecretsModule",
        parameter_model=_params.LSASecretsParams,
        parameter_model_identity="ares.modules.params.LSASecretsParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "ntlm_hashes",
            "lsa_secrets",
            "cached_credentials",
        ),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.lsa_secrets",
            "LSASecretsModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.lsass_dump",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.lsass_dump",
        source_class="LsassDumpModule",
        parameter_model=_params.LsassDumpParams,
        parameter_model_identity="ares.modules.params.LsassDumpParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "technique",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "7a8c9a7f27c2fcbeb5a516beba7e6c0f1a2887094aaa373cb942c704e99a8c04",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "ntlm_hashes",
            "kerberos_tickets",
        ),
        opsec=OpsecClassification.HIGH_NOISE,
        minimum_role=MinimumRole.TEAM_LEAD,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            300, TimeoutSource.MODULE_DEFINED_BOUNDED, TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.lsass_dump",
            "LsassDumpModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=300,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.registry_enum",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.registry_enum",
        source_class="RegistryEnumModule",
        parameter_model=_params.RegistryEnumParams,
        parameter_model_identity="ares.modules.params.RegistryEnumParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "cleartext_credentials",
            "credential_hints",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.registry_enum",
            "RegistryEnumModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.scheduled_tasks_enum",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.scheduled_tasks_enum",
        source_class="ScheduledTasksEnumModule",
        parameter_model=_params.ScheduledTasksEnumParams,
        parameter_model_identity="ares.modules.params.ScheduledTasksEnumParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "scheduled_tasks",
            "privesc_vectors",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(Capability.CAP_NET,),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.DYNAMICALLY_UNBOUNDED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.READ_ONLY,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.BLOCKED_UNPROVEN_PRIOR_ATTEMPT,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.scheduled_tasks_enum",
            "ScheduledTasksEnumModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.DESTINATION_CONTRACT_UNBOUNDED,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.token_impersonation",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.token_impersonation",
        source_class="TokenImpersonationModule",
        parameter_model=_params.TokenImpersonationParams,
        parameter_model_identity="ares.modules.params.TokenImpersonationParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=("privesc_vectors",),
        opsec=OpsecClassification.MEDIUM,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(OpaqueCredentialKind.PASSWORD,),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.token_impersonation",
            "TokenImpersonationModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("lateral_session",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
    ModuleDescriptor(
        contract_version=CONTRACT_VERSION,
        module_id="windows.uac_bypass",
        category=ModuleCategory.WINDOWS,
        source_module="ares.modules.windows.uac_bypass",
        source_class="UACBypassModule",
        parameter_model=_params.UACBypassParams,
        parameter_model_identity="ares.modules.params.UACBypassParams",
        parameter_fields=(
            _pf(
                "target",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "username",
                ParameterType.STRING,
                True,
                DefaultSemanticState.NO_DEFAULT,
                None,
                False,
                Sensitivity.SENSITIVE,
            ),
            _pf(
                "password",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "nt_hash",
                ParameterType.OPTIONAL_SECRET_STRING,
                False,
                DefaultSemanticState.DEFAULT_NONE,
                None,
                True,
                Sensitivity.SECRET,
            ),
            _pf(
                "domain",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_EMPTY,
                None,
                False,
                Sensitivity.PUBLIC,
            ),
            _pf(
                "technique",
                ParameterType.STRING,
                False,
                DefaultSemanticState.DEFAULT_PUBLIC_VALUE,
                "634635a2166efa2ae765abd31d4ae807082287e329a8a7fff42b1fb30f65087e",
                False,
                Sensitivity.PUBLIC,
            ),
        ),
        declared_outputs=(
            "uac_config",
            "privesc_vectors",
        ),
        opsec=OpsecClassification.LOW,
        minimum_role=MinimumRole.OPERATOR,
        explicit_attempt_approval=False,
        required_capabilities=(
            Capability.CAP_EXEC,
            Capability.CAP_NET,
        ),
        capability_match=CapabilityMatchSemantics.ALL_REQUIRED,
        destination_state=ContractState.SUPPORTED,
        destinations=(
            _destination(
                DestinationKind.HOST,
                "target",
                DestinationCardinality.SCALAR,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
            _destination(
                DestinationKind.DOMAIN,
                "domain",
                DestinationCardinality.OPTIONAL,
                ScopeSemantics.PRIMARY_CAMPAIGN,
            ),
        ),
        credential_policy=CredentialSourcePolicy(
            state=ContractState.BLOCKED_BY_ADAPTER_GAP,
            allowed_handle_kinds=(
                OpaqueCredentialKind.NTLM_HASH,
                OpaqueCredentialKind.PASSWORD,
            ),
            ambient_dependencies=(),
        ),
        external_effect=ExternalEffectClass.CONDITIONALLY_MUTATING,
        idempotency=IdempotencyClass.UNPROVEN_CURRENT_CONTRACT,
        retry_eligibility=RetryEligibility.NEVER,
        cancellation_ownership=CancellationOwnership.UNPROVEN_CURRENT_CONTRACT,
        compensation=CompensationClass.UNPROVEN_CURRENT_CONTRACT,
        timeout=TimeoutPolicy(
            120,
            TimeoutSource.OBSERVED_LEGACY_ENGINE_DEFAULT,
            TimeoutSettlement.UNPROVEN_CURRENT_CONTRACT,
        ),
        dry_run=_native_dry_run(
            "ares.modules.windows.uac_bypass",
            "UACBypassModule",
            "fdcf8a0744fd06f66c82898d71d1e31c34d897f7f6f05c5e2544ca48b875e9da",
        ),
        result_contract=ResultContract(
            findings=ContractState.UNPROVEN_CURRENT_CONTRACT,
            credentials=ContractState.UNPROVEN_CURRENT_CONTRACT,
            discovered_hosts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            loot_artifacts=ContractState.UNPROVEN_CURRENT_CONTRACT,
            authoritative_evidence=ContractState.UNPROVEN_CURRENT_CONTRACT,
        ),
        descriptor_complete=True,
        future_gateway_eligible=False,
        blocker_codes=(
            BlockerCode.CANCELLATION_OWNERSHIP_UNPROVEN,
            BlockerCode.RAW_CREDENTIAL_INPUT,
            BlockerCode.RESULT_AUTHORITY_UNPROVEN,
            BlockerCode.LIFECYCLE_CONTRACT_UNPROVEN,
        ),
        legacy_requires=("local_admin_creds",),
        legacy_capabilities=(),
        legacy_dry_run_supported=True,
        legacy_timeout_override=None,
    ),
)

if len(_FIRST_PARTY_DESCRIPTORS) != 62:
    _invalid()
if len({item.module_id for item in _FIRST_PARTY_DESCRIPTORS}) != 62:
    _invalid()

FIRST_PARTY_DESCRIPTORS: Mapping[str, ModuleDescriptor] = types.MappingProxyType(
    {
        item.module_id: item
        for item in sorted(_FIRST_PARTY_DESCRIPTORS, key=lambda value: value.module_id)
    }
)


def get_descriptor(module_id: str) -> ModuleDescriptor | None:
    if type(module_id) is not str:
        return None
    return FIRST_PARTY_DESCRIPTORS.get(module_id)


def require_descriptor(module_id: str) -> ModuleDescriptor:
    descriptor = get_descriptor(module_id)
    if descriptor is None:
        raise DescriptorReadinessError(ReadinessCode.DESCRIPTOR_NOT_FOUND)
    return descriptor


def _annotation_identity(annotation: object) -> ParameterType:
    if annotation is str:
        return ParameterType.STRING
    if annotation is bool:
        return ParameterType.BOOLEAN
    if annotation is int:
        return ParameterType.INTEGER
    if annotation is float:
        return ParameterType.FLOAT
    if annotation is SecretStr:
        return ParameterType.SECRET_STRING
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is list and args == (str,):
        return ParameterType.STRING_LIST
    if origin is list and args == (int,):
        return ParameterType.INTEGER_LIST
    if types.NoneType in args and len(args) == 2:
        other = args[0] if args[1] is types.NoneType else args[1]
        if other is str:
            return ParameterType.OPTIONAL_STRING
        if other is SecretStr:
            return ParameterType.OPTIONAL_SECRET_STRING
    raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)


def _canonical_default(value: object) -> object:
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if type(value) in {list, tuple}:
        return [_canonical_default(item) for item in value]
    if type(value) is dict:
        return {str(key): _canonical_default(value[key]) for key in sorted(value, key=str)}
    raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)


def _public_default_digest(value: object) -> str:
    return _sha256_json(_canonical_default(value))


def _runtime_default_state(
    field_info: Any,
    sensitivity: Sensitivity,
) -> DefaultSemanticState:
    if field_info.is_required():
        return DefaultSemanticState.NO_DEFAULT
    if field_info.default_factory is not None:
        return DefaultSemanticState.DEFAULT_FACTORY_UNEVALUATED_BLOCKED
    value = field_info.default
    if value is None:
        return DefaultSemanticState.DEFAULT_NONE
    if value == "" or (type(value) in {tuple, list, dict, set} and len(value) == 0):
        return DefaultSemanticState.DEFAULT_EMPTY
    if sensitivity is not Sensitivity.PUBLIC:
        return DefaultSemanticState.DEFAULT_NONEMPTY_BLOCKED
    return DefaultSemanticState.DEFAULT_PUBLIC_VALUE


def validate_parameter_model_bindings() -> tuple[ModuleDescriptor, ...]:
    from ares.modules.params import MODULE_PARAMS

    if set(MODULE_PARAMS) != set(FIRST_PARTY_DESCRIPTORS):
        raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
    for module_id, descriptor in FIRST_PARTY_DESCRIPTORS.items():
        model = MODULE_PARAMS.get(module_id)
        if model is not descriptor.parameter_model:
            raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
        runtime_fields = model.model_fields
        if tuple(runtime_fields) != tuple(item.name for item in descriptor.parameter_fields):
            raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
        for expected in descriptor.parameter_fields:
            actual = runtime_fields[expected.name]
            extra = actual.json_schema_extra or {}
            if _annotation_identity(actual.annotation) is not expected.canonical_type:
                raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
            if actual.is_required() is not expected.required:
                raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
            runtime_secret = bool(extra.get("secret"))
            if runtime_secret is not expected.legacy_schema_secret:
                raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
            observed_state = _runtime_default_state(actual, expected.sensitivity)
            if observed_state is not expected.default_state:
                raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
            if observed_state is DefaultSemanticState.DEFAULT_PUBLIC_VALUE:
                observed_digest = _public_default_digest(actual.default)
                if not hmac.compare_digest(
                    observed_digest,
                    expected.public_default_digest or "",
                ):
                    raise DescriptorReadinessError(ReadinessCode.PARAMETER_CONTRACT_MISMATCH)
    return _FIRST_PARTY_DESCRIPTORS


def bind_first_party_registry(registry: object) -> tuple[ModuleDescriptor, ...]:
    try:
        classes = tuple(registry.all())  # type: ignore[attr-defined]
        sources = dict(registry._sources)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        raise DescriptorReadinessError(ReadinessCode.REGISTRY_BINDING_MISMATCH) from None
    ids = [str(getattr(cls, "MODULE_ID", "")) for cls in classes]
    if any(source != "builtin" for source in sources.values()):
        raise DescriptorReadinessError(ReadinessCode.UNTRUSTED_EXTERNAL_METADATA)
    if len(ids) != len(set(ids)):
        raise DescriptorReadinessError(ReadinessCode.REGISTRY_SET_MISMATCH)
    if set(ids) != set(FIRST_PARTY_DESCRIPTORS):
        raise DescriptorReadinessError(ReadinessCode.REGISTRY_SET_MISMATCH)
    if set(sources) != set(FIRST_PARTY_DESCRIPTORS):
        raise DescriptorReadinessError(ReadinessCode.REGISTRY_SET_MISMATCH)
    validate_parameter_model_bindings()
    for cls in classes:
        module_id = str(getattr(cls, "MODULE_ID", ""))
        descriptor = FIRST_PARTY_DESCRIPTORS[module_id]
        opsec = getattr(cls, "OPSEC_LEVEL", "")
        opsec_value = opsec.value if hasattr(opsec, "value") else str(opsec)
        capabilities = tuple(
            sorted(
                (
                    item if isinstance(item, Capability) else Capability(str(item))
                    for item in (getattr(cls, "CAPABILITIES", ()) or ())
                ),
                key=lambda item: item.value,
            )
        )
        checks = (
            sources.get(module_id) == "builtin",
            cls.__module__ == descriptor.source_module,
            cls.__name__ == descriptor.source_class,
            getattr(cls, "MODULE_CATEGORY", "") == descriptor.category.value,
            opsec_value == descriptor.opsec.value,
            tuple(getattr(cls, "OUTPUTS", ()) or ()) == descriptor.declared_outputs,
            tuple(getattr(cls, "REQUIRES", ()) or ()) == descriptor.legacy_requires,
            capabilities == descriptor.legacy_capabilities,
            bool(getattr(cls, "DRY_RUN_SUPPORTED", True)) is descriptor.legacy_dry_run_supported,
            getattr(cls, "MODULE_TIMEOUT_SECONDS", None) == descriptor.legacy_timeout_override,
        )
        if not all(checks):
            raise DescriptorReadinessError(ReadinessCode.REGISTRY_BINDING_MISMATCH)
    return tuple(
        FIRST_PARTY_DESCRIPTORS[module_id] for module_id in sorted(FIRST_PARTY_DESCRIPTORS)
    )


def _unknown_nested_locations(
    value: object,
    fields: tuple[ParameterFieldSpec, ...],
    prefix: tuple[str, ...],
) -> list[tuple[str, ...]]:
    if not fields or not isinstance(value, Mapping):
        return []
    expected = {item.name: item for item in fields}
    locations = [
        prefix + ("<unknown>",) for key in value if type(key) is not str or key not in expected
    ]
    for name, spec in expected.items():
        if name in value:
            locations.extend(
                _unknown_nested_locations(
                    value[name],
                    spec.nested_fields,
                    prefix + (name,),
                )
            )
    return locations


def canonicalize_parameters(
    module_id: str,
    raw_parameters: Mapping[str, Any],
) -> CanonicalParameters:
    descriptor = require_descriptor(module_id)
    if not isinstance(raw_parameters, Mapping):
        raise DescriptorReadinessError(ReadinessCode.PARAMETERS_NOT_MAPPING)
    expected = {item.name: item for item in descriptor.parameter_fields}
    unknown = [
        ("<unknown>",) for key in raw_parameters if type(key) is not str or key not in expected
    ]
    for name, spec in expected.items():
        if name in raw_parameters:
            unknown.extend(
                _unknown_nested_locations(
                    raw_parameters[name],
                    spec.nested_fields,
                    (name,),
                )
            )
    if unknown:
        raise DescriptorReadinessError(
            ReadinessCode.PARAMETERS_UNKNOWN_FIELD,
            sorted(unknown),
        )
    copied = {name: raw_parameters[name] for name in raw_parameters}
    try:
        validated = descriptor.parameter_model.model_validate(copied)
    except ValidationError as exc:
        locations = [
            tuple(str(part) for part in error.get("loc", ()))
            for error in exc.errors(include_url=False, include_context=False)
        ]
        raise DescriptorReadinessError(
            ReadinessCode.PARAMETERS_INVALID,
            sorted(locations),
        ) from None
    values = {name: getattr(validated, name) for name in expected if hasattr(validated, name)}
    return CanonicalParameters(types.MappingProxyType(values))


def _read_destination_path(values: Mapping[str, Any], source_path: str) -> object:
    current: object = values
    for part in source_path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, BaseModel):
            if not hasattr(current, part):
                return None
            current = getattr(current, part)
        else:
            return None
    return current


def extract_destinations(
    module_id: str,
    canonical: CanonicalParameters | Mapping[str, Any],
) -> tuple[ExtractedDestination, ...]:
    descriptor = require_descriptor(module_id)
    values = canonical.values if isinstance(canonical, CanonicalParameters) else canonical
    if not isinstance(values, Mapping):
        raise DescriptorReadinessError(ReadinessCode.PARAMETERS_NOT_MAPPING)
    extracted: list[ExtractedDestination] = []
    seen: set[tuple[str, str, str]] = set()
    for spec in descriptor.destinations:
        value = _read_destination_path(values, spec.source_path)
        if value in (None, "", (), []):
            continue
        members: Sequence[object]
        if spec.cardinality is DestinationCardinality.COLLECTION:
            if not isinstance(value, (list, tuple)):
                raise DescriptorReadinessError(ReadinessCode.PARAMETERS_INVALID)
            members = value
        else:
            members = (value,)
        for member in members:
            key = (
                spec.kind.value,
                spec.scope.value,
                _sha256_json(_canonical_default(member)),
            )
            if key in seen:
                continue
            seen.add(key)
            extracted.append(
                ExtractedDestination(
                    kind=spec.kind,
                    source_path=spec.source_path,
                    scope=spec.scope,
                    value=member,
                )
            )
    return tuple(extracted)


def prepare_admission_parameters(
    module_id: str,
    raw_parameters: Mapping[str, Any],
) -> tuple[CanonicalParameters, tuple[ExtractedDestination, ...]]:
    """Prepare strict descriptor-bound values for lifecycle admission.

    Keeping parameter parsing and destination extraction inside the descriptor
    boundary prevents lifecycle persistence code from depending on the
    audit-parser entry point directly.
    """
    canonical = canonicalize_parameters(module_id, raw_parameters)
    return canonical, extract_destinations(module_id, canonical)


def readiness_summary() -> Mapping[str, object]:
    blockers: dict[str, list[str]] = {}
    for descriptor in FIRST_PARTY_DESCRIPTORS.values():
        for blocker in descriptor.blocker_codes:
            blockers.setdefault(blocker.value, []).append(descriptor.module_id)
    result: dict[str, object] = {
        "descriptor_count": len(FIRST_PARTY_DESCRIPTORS),
        "descriptor_complete_count": sum(
            item.descriptor_complete for item in FIRST_PARTY_DESCRIPTORS.values()
        ),
        "future_gateway_eligible_count": sum(
            item.future_gateway_eligible for item in FIRST_PARTY_DESCRIPTORS.values()
        ),
        "legacy_schema_secret_count": sum(
            item.legacy_schema_secret
            for descriptor in FIRST_PARTY_DESCRIPTORS.values()
            for item in descriptor.parameter_fields
        ),
        "authoritative_secret_count": sum(
            item.sensitivity is Sensitivity.SECRET
            for descriptor in FIRST_PARTY_DESCRIPTORS.values()
            for item in descriptor.parameter_fields
        ),
        "parameter_default_state_counts": types.MappingProxyType(
            {
                state.value: sum(
                    field_spec.default_state is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                    for field_spec in descriptor.parameter_fields
                )
                for state in DefaultSemanticState
            }
        ),
        "idempotency_counts": types.MappingProxyType(
            {
                state.value: sum(
                    descriptor.idempotency is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                )
                for state in IdempotencyClass
            }
        ),
        "retry_counts": types.MappingProxyType(
            {
                state.value: sum(
                    descriptor.retry_eligibility is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                )
                for state in RetryEligibility
            }
        ),
        "compensation_counts": types.MappingProxyType(
            {
                state.value: sum(
                    descriptor.compensation is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                )
                for state in CompensationClass
            }
        ),
        "timeout_source_counts": types.MappingProxyType(
            {
                state.value: sum(
                    descriptor.timeout.source is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                )
                for state in TimeoutSource
            }
        ),
        "dry_run_state_counts": types.MappingProxyType(
            {
                state.value: sum(
                    descriptor.dry_run.state is state
                    for descriptor in FIRST_PARTY_DESCRIPTORS.values()
                )
                for state in DryRunState
            }
        ),
        "blocker_counts": types.MappingProxyType(
            {code: len(module_ids) for code, module_ids in sorted(blockers.items())}
        ),
        "blocker_module_ids": types.MappingProxyType(
            {code: tuple(sorted(module_ids)) for code, module_ids in sorted(blockers.items())}
        ),
    }
    return types.MappingProxyType(result)


__all__ = [
    "AmbientCredentialDependency",
    "BlockerCode",
    "CapabilityMatchSemantics",
    "CanonicalParameters",
    "CancellationOwnership",
    "CompensationClass",
    "ContractState",
    "CredentialSourcePolicy",
    "DefaultSemanticState",
    "DestinationCardinality",
    "DestinationKind",
    "DestinationSpec",
    "DescriptorReadinessError",
    "DryRunContract",
    "DryRunGuardSemantics",
    "DryRunState",
    "DryRunTermination",
    "ExtractedDestination",
    "ExternalEffectClass",
    "FIRST_PARTY_DESCRIPTORS",
    "IdempotencyClass",
    "MinimumRole",
    "ModuleCategory",
    "ModuleDescriptor",
    "OpaqueCredentialKind",
    "OpsecClassification",
    "ParameterFieldSpec",
    "ParameterType",
    "ReadinessCode",
    "ResultContract",
    "RetryEligibility",
    "ScopeSemantics",
    "Sensitivity",
    "TimeoutPolicy",
    "TimeoutSettlement",
    "TimeoutSource",
    "bind_first_party_registry",
    "canonicalize_parameters",
    "descriptor_semantic_digest",
    "extract_destinations",
    "get_descriptor",
    "prepare_admission_parameters",
    "readiness_summary",
    "require_descriptor",
    "validate_parameter_model_bindings",
    "validate_dry_run_source",
]
