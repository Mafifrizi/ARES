"""Public ARES SDK import surface (v2 Modern Standard).

Provides everything needed for module authoring, testing, and programmatic automation:

1. Module Authoring:
    from ares.sdk import BaseModule, ares_module, ExecutionContext, ModuleResult, OpsecLevel
    from ares.sdk import ModuleParams, param, SecretParam

2. Isolated Testing & Simulation:
    from ares.sdk import ModuleTestHarness, SimulationResult

3. Programmatic API Automation:
    from ares.sdk import AresClient

The legacy ``ares.modules.sdk`` path remains 100% available for existing modules.
"""
from __future__ import annotations

# Core and legacy contracts (preserved for 100% backward compatibility)
from ares.modules.sdk import (
    AccountLocked,
    AresError,
    ArtifactStore,
    AuthenticationFailed,
    BaseModule,
    ConnectionRefused,
    ConnectionTimeout,
    CredentialArtifact,
    CredentialError,
    CredentialExpired,
    DetectionSignal,
    ExecutionContext,
    ExecutionError,
    Finding,
    HashArtifact,
    HoneypotDetected,
    HostArtifact,
    HostUnreachable,
    InsufficientPrivilege,
    InvalidContext,
    ModuleError,
    ModuleResult,
    ModuleTestHelper,
    ModuleTimeoutError,
    ModuleValidationError,
    NetworkError,
    NoCredentialsAvailable,
    OpsecError,
    OpsecLevel,
    PermissionArtifact,
    SandboxError,
    ScopeError,
    Severity,
    TechniqueLibrary,
    TechniqueMapper,
    UserArtifact,
    get_logger,
    module_metadata,
    requires_privilege,
    timeout,
    validate_module_class,
)

# v2 Modern Module Declarative & Schema Contracts
from ares.sdk.module import ares_module
from ares.sdk.params import ModuleParams, SecretParam, param, validate_params

# v2 Testing Harness
from ares.sdk.testing import ModuleTestHarness, SimulationResult

# v2 Programmatic API Client
from ares.sdk.client import (
    AresAuthenticationError,
    AresClient,
    AresClientError,
    AresNotFoundError,
    AresValidationError,
)

# Enterprise Security Pipeline & Interceptors
from ares.sdk.pipeline import (
    AdaptiveNoiseInterceptor,
    AuditProvenanceInterceptor,
    BaseExecutionInterceptor,
    ExecutionInterceptor,
    ExecutionPipeline,
    ScopeEnforcementInterceptor,
    SecretSanitizationInterceptor,
)

# Capability-Based Permissions & Sandboxing
from ares.sdk.security import (
    CapabilitySandbox,
    FilesystemPermission,
    NetworkPermission,
    ProcessPermission,
    SecurityCapabilityViolation,
    SecurityPermission,
    VaultPermission,
)

# Resilience & Circuit Breakers
from ares.sdk.resilience import (
    CircuitBreaker,
    CircuitBreakerState,
    CircuitBreakerTripped,
    LockoutCircuitBreaker,
)

# Taint Tracking & Tamper-Evident Evidence
from ares.sdk.taint import (
    EvidenceRecord,
    UntrustedTargetData,
)

# Declarative Module Contracts
from ares.sdk.contracts import (
    module_contract,
)

__all__ = [
    # Base module contracts
    "BaseModule",
    "ModuleResult",
    "OpsecLevel",
    "validate_module_class",
    "ExecutionContext",
    "ares_module",
    "module_contract",
    # Parameter schema contracts (Pydantic v2)
    "ModuleParams",
    "param",
    "SecretParam",
    "validate_params",
    # Pipeline & Interceptors
    "ExecutionPipeline",
    "ExecutionInterceptor",
    "BaseExecutionInterceptor",
    "ScopeEnforcementInterceptor",
    "AdaptiveNoiseInterceptor",
    "SecretSanitizationInterceptor",
    "AuditProvenanceInterceptor",
    # Security & Capabilities
    "SecurityPermission",
    "NetworkPermission",
    "VaultPermission",
    "FilesystemPermission",
    "ProcessPermission",
    "SecurityCapabilityViolation",
    "CapabilitySandbox",
    # Resilience & Circuit Breakers
    "CircuitBreaker",
    "CircuitBreakerState",
    "CircuitBreakerTripped",
    "LockoutCircuitBreaker",
    # Taint Tracking & Evidence
    "UntrustedTargetData",
    "EvidenceRecord",
    # Errors
    "AresError",
    "ModuleError",
    "ModuleValidationError",
    "ModuleTimeoutError",
    "NetworkError",
    "ConnectionRefused",
    "ConnectionTimeout",
    "HostUnreachable",
    "CredentialError",
    "AuthenticationFailed",
    "AccountLocked",
    "CredentialExpired",
    "NoCredentialsAvailable",
    "ExecutionError",
    "SandboxError",
    "ScopeError",
    "OpsecError",
    "DetectionSignal",
    "HoneypotDetected",
    "InsufficientPrivilege",
    "InvalidContext",
    # Campaign & telemetry
    "Finding",
    "Severity",
    "get_logger",
    "TechniqueLibrary",
    "TechniqueMapper",
    # Artifacts
    "ArtifactStore",
    "HostArtifact",
    "UserArtifact",
    "CredentialArtifact",
    "HashArtifact",
    "PermissionArtifact",
    # Decorators
    "module_metadata",
    "requires_privilege",
    "timeout",
    # Testing & simulation
    "ModuleTestHelper",
    "ModuleTestHarness",
    "SimulationResult",
    # Programmatic Client SDK
    "AresClient",
    "AresClientError",
    "AresAuthenticationError",
    "AresNotFoundError",
    "AresValidationError",
]
