"""
ARES Module SDK
One-stop import for community module authors.
Provides all base classes, helpers, and type definitions needed
to write a compliant ARES module.

Quick start:
    from ares.sdk import (
        BaseModule, ExecutionContext, ModuleResult,
        Finding, Severity, OpsecLevel,
        module_metadata, requires_privilege, timeout,
    )

    class MyModule(BaseModule):
        MODULE_ID          = "corp.my_attack"
        MODULE_NAME        = "My Attack Module"
        MODULE_CATEGORY    = "ad"
        MODULE_DESCRIPTION = "Does something interesting"
        MODULE_AUTHOR      = "alice@corp.com"
        OPSEC_LEVEL        = OpsecLevel.LOW
        REQUIRES           = ["domain_creds"]
        OUTPUTS            = ["credential"]
        MITRE_TECHNIQUES   = ["T1558.003"]

        async def validate(self, ctx: ExecutionContext) -> None:
            ctx.require("target", "domain")
            if not ctx.params.get("dc"):
                raise ModuleValidationError(
                    "Missing required param: dc",
                    module_id=self.MODULE_ID, field="dc"
                )

        async def execute(self, ctx: ExecutionContext) -> ModuleResult:
            if ctx.dry_run:
                return ModuleResult(status="dry_run", module_id=self.MODULE_ID)

            await self.before_request(ctx.target)
            # ... do attack work ...
            f = self.finding(
                title       = "Something found",
                description = "Details",
                severity    = Severity.HIGH,
                mitre_technique = "T1558.003",
                host        = ctx.target,
            )
            return ModuleResult(
                status   = "success",
                findings = [f],
                module_id = self.MODULE_ID,
            )

        async def run(self, **kwargs):
            # Legacy interface — prefer execute(ctx) instead
            ctx = ExecutionContext.for_test(**kwargs)
            result = await self.execute(ctx)
            return result.findings, result.raw
"""
from __future__ import annotations

# ── Core base ──────────────────────────────────────────────────────────────────
from ares.modules.base import (
    BaseModule,
    ModuleResult,
    OpsecLevel,
    validate_module_class,
)

# ── Context ────────────────────────────────────────────────────────────────────
from ares.core.context import ExecutionContext

# ── Errors ────────────────────────────────────────────────────────────────────
from ares.core.errors import (
    AresError,
    ModuleError,
    ModuleValidationError,
    ModuleTimeoutError,
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable,
    CredentialError,
    AuthenticationFailed,
    AccountLocked,
    CredentialExpired,
    NoCredentialsAvailable,
    ExecutionError,
    SandboxError,
    ScopeError,
    OpsecError,
    DetectionSignal,
    HoneypotDetected,
    InsufficientPrivilege,
    InvalidContext,
)

# ── Campaign types ─────────────────────────────────────────────────────────────
from ares.core.campaign import Finding, Severity

# ── Logging ───────────────────────────────────────────────────────────────────
from ares.core.logger import get_logger

# ── MITRE ─────────────────────────────────────────────────────────────────────
from ares.technique.library import TechniqueLibrary, TechniqueMapper

# ── Normalize ─────────────────────────────────────────────────────────────────
from ares.normalize.artifacts import (
    ArtifactStore,
    HostArtifact,
    UserArtifact,
    CredentialArtifact,
    HashArtifact,
    PermissionArtifact,
)

# ── Convenience types for type hints ──────────────────────────────────────────
from typing import Any
import math


# ── Decorators / helpers ──────────────────────────────────────────────────────

def module_metadata(
    module_id:   str,
    name:        str,
    category:    str,
    description: str,
    author:      str = "Community",
    opsec:       OpsecLevel = OpsecLevel.LOW,
    requires:    list[str] | None = None,
    outputs:     list[str] | None = None,
    mitre:       list[str] | None = None,
) -> Any:
    """
    Class decorator to set all module metadata cleanly.

    Usage:
        @module_metadata(
            module_id   = "corp.my_module",
            name        = "My Module",
            category    = "ad",
            description = "Does X",
            author      = "alice@corp.com",
            opsec       = OpsecLevel.LOW,
            requires    = ["domain_creds"],
            outputs     = ["user_list"],
            mitre       = ["T1087.002"],
        )
        class MyModule(BaseModule):
            ...
    """
    if not isinstance(category, str) or not category.strip():
        raise ValueError("module_metadata category must be a non-empty string")
    if not isinstance(opsec, OpsecLevel) and str(opsec) not in {level.value for level in OpsecLevel}:
        raise ValueError("module_metadata opsec must be an OpsecLevel or valid opsec level string")
    for field_name, value in (
        ("requires", requires),
        ("outputs", outputs),
        ("mitre", mitre),
    ):
        if value is None:
            continue
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"module_metadata {field_name} must be a list of strings")

    def decorator(cls: type) -> type:
        cls.MODULE_ID          = module_id
        cls.MODULE_NAME        = name
        cls.MODULE_CATEGORY    = category
        cls.MODULE_DESCRIPTION = description
        cls.MODULE_AUTHOR      = author
        cls.OPSEC_LEVEL        = opsec
        cls.REQUIRES           = requires or []
        cls.OUTPUTS            = outputs or []
        cls.MITRE_TECHNIQUES   = mitre or []

        errors = validate_module_class(cls)
        if errors:
            raise ValueError(
                f"Module class {cls.__name__!r} has validation errors: {errors}"
            )
        return cls
    return decorator


def requires_privilege(level: str) -> Any:
    """
    Class decorator: declare minimum privilege required by this module.
    Engine will suggest privilege escalation if current level is insufficient.

    Usage:
        @requires_privilege("domain_admin")
        class DCSyncModule(BaseModule):
            ...
    """
    if not isinstance(level, str) or not level.strip():
        raise ValueError("requires_privilege level must be a non-empty string")

    def decorator(cls: type) -> type:
        cls.REQUIRED_PRIVILEGE = level.strip()
        return cls
    return decorator


def timeout(seconds: int | float) -> Any:
    """
    Class decorator: override default execution timeout.

    Usage:
        @timeout(60)
        class FastModule(BaseModule):
            ...
    """
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, (int, float))
        or not math.isfinite(seconds)
        or seconds <= 0
    ):
        raise ValueError("timeout seconds must be a positive finite number")

    def decorator(cls: type) -> type:
        cls.MODULE_TIMEOUT_SECONDS = seconds
        cls.DEFAULT_TIMEOUT_S = seconds
        return cls
    return decorator


# ── TestHelper — makes unit testing modules trivial ───────────────────────────

class ModuleTestHelper:
    """
    Helper for unit-testing modules without a full engine.

    Usage:
        helper  = ModuleTestHelper(KerberoastModule)
        ctx     = helper.make_context(target="dc01", domain="CORP")
        result  = await helper.run(ctx)
        assert result.success
    """

    def __init__(self, module_class: type, scope_cidrs: list[str] | None = None) -> None:
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        from ares.core.config import AresSettings
        from ares.core.noise import NoiseController

        self.module_class = module_class
        self.settings     = AresSettings()
        # NOTE: scope defaults to 0.0.0.0/0 for test harness.
        # Override via ModuleTestHelper(scope_cidrs=[...]) in integration tests.
        _scope = [ScopeEntry(cidr=s) for s in (scope_cidrs or ["0.0.0.0/0"])]
        self.campaign     = Campaign(
            name="test-campaign", client="test",
            scope=_scope,
            noise_profile=NoiseProfile.NORMAL,
            operator="test",
        )
        self.noise        = NoiseController(self.campaign)
        self.module       = module_class(
            settings=self.settings,
            campaign=self.campaign,
            noise=self.noise,
        )

    def make_context(
        self,
        target:  str = "10.0.0.1",
        domain:  str = "",
        params:  dict[str, Any] | None = None,
        dry_run: bool = True,
        **kwargs: Any,
    ) -> ExecutionContext:
        """Build a test context for this module."""
        context_params = {**(params or {}), **kwargs}
        if dry_run:
            for requirement in getattr(self.module_class, "REQUIRES", []):
                if requirement in {"credentials", "domain_creds", "domain_admin_creds"}:
                    context_params.setdefault(requirement, True)

        return ExecutionContext.build(
            campaign   = self.campaign,
            target     = target,
            module_id  = self.module_class.MODULE_ID,
            domain     = domain,
            params     = context_params,
            dry_run    = dry_run,
        )

    async def validate(self, ctx: ExecutionContext) -> None:
        """Run validate() and surface errors clearly."""
        await self.module.validate(ctx)

    async def run(self, ctx: ExecutionContext) -> ModuleResult:
        """Run execute() and return the structured result."""
        return await self.module.execute(ctx)

    async def run_full(
        self,
        target:  str = "10.0.0.1",
        domain:  str = "",
        params:  dict[str, Any] | None = None,
        dry_run: bool = True,
    ) -> ModuleResult:
        """One-liner: build context, validate, execute, return result."""
        ctx = self.make_context(target=target, domain=domain,
                                params=params, dry_run=dry_run)
        await self.validate(ctx)
        return await self.run(ctx)

    def report(self, result: ModuleResult) -> dict[str, Any]:
        """Generate report dict for this result."""
        return self.module.report(result)

    def metadata(self) -> dict[str, Any]:
        """Return module metadata."""
        return self.module_class.metadata()

    def validate_class(self) -> list[str]:
        """Validate module class has all required attributes. Returns errors."""
        return validate_module_class(self.module_class)


# ── Public API surface ────────────────────────────────────────────────────────
__all__ = [
    # Base
    "BaseModule", "ModuleResult", "OpsecLevel", "validate_module_class",
    # Context
    "ExecutionContext",
    # Errors
    "AresError", "ModuleError", "ModuleValidationError", "ModuleTimeoutError",
    "NetworkError", "ConnectionRefused", "ConnectionTimeout", "HostUnreachable",
    "CredentialError", "AuthenticationFailed", "AccountLocked", "CredentialExpired",
    "NoCredentialsAvailable", "ExecutionError", "SandboxError",
    "ScopeError", "OpsecError", "DetectionSignal", "HoneypotDetected",
    "InsufficientPrivilege", "InvalidContext",
    # Campaign types
    "Finding", "Severity",
    # Logging
    "get_logger",
    # MITRE
    "TechniqueLibrary", "TechniqueMapper",
    # Normalize
    "ArtifactStore", "HostArtifact", "UserArtifact", "CredentialArtifact",
    "HashArtifact", "PermissionArtifact",
    # Decorators
    "module_metadata", "requires_privilege", "timeout",
    # Testing
    "ModuleTestHelper",
]
