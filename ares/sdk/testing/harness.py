"""Isolated testing harness and simulation runner for ARES modules.

Enables community module authors and core developers to test attack modules
in complete isolation with simulated scope guards, synthetic vaults, and
fluent assertion matchers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from ares.core.campaign import Campaign, Finding, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import AresError, ModuleValidationError
from ares.core.noise import NoiseController
from ares.credential.vault import Credential, CredentialVault
from ares.modules.base import BaseModule, ModuleResult

M = TypeVar("M", bound=BaseModule)


@dataclass
class SimulationResult:
    """Result envelope from a simulated module execution with fluent test assertions."""

    status: str
    module_id: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    new_credentials: list[Any] = field(default_factory=list)
    discovered_hosts: list[Any] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    context: ExecutionContext | None = None

    @property
    def success(self) -> bool:
        """Return True if execution finished successfully without unhandled errors."""
        return self.status in ("success", "done", "dry_run", "partial") and not self.error

    def assert_success(self) -> SimulationResult:
        """Assert that the simulation completed successfully."""
        assert self.success, f"Expected simulation success, got status={self.status!r}, error={self.error!r}"
        return self

    def assert_failed(self, error_contains: str | None = None) -> SimulationResult:
        """Assert that the simulation failed or reported an error."""
        assert not self.success or bool(self.error), f"Expected simulation failure, got success={self.status!r}"
        if error_contains:
            assert error_contains.lower() in str(self.error or "").lower(), (
                f"Expected error containing {error_contains!r}, got {self.error!r}"
            )
        return self

    def assert_no_errors(self) -> SimulationResult:
        """Assert that no error string is recorded."""
        assert not self.error, f"Unexpected error in simulation result: {self.error}"
        return self

    def assert_finding(
        self,
        severity: Severity | str | None = None,
        mitre: str | None = None,
        title_contains: str | None = None,
    ) -> Finding:
        """Assert that at least one emitted finding matches the given criteria.

        Returns the matching finding for further inspection.
        """
        assert self.findings, f"No findings were emitted by module {self.module_id}"

        expected_sev = (
            severity.value if isinstance(severity, Severity)
            else str(severity).lower() if severity is not None
            else None
        )

        for finding in self.findings:
            matches = True
            if expected_sev is not None:
                actual_sev = getattr(finding.severity, "value", str(finding.severity)).lower()
                if actual_sev != expected_sev:
                    matches = False
            if mitre is not None:
                technique = getattr(finding, "mitre_technique", None) or ""
                if mitre.lower() not in technique.lower():
                    matches = False
            if title_contains is not None:
                title = getattr(finding, "title", "") or ""
                if title_contains.lower() not in title.lower():
                    matches = False

            if matches:
                return finding

        criteria = []
        if expected_sev:
            criteria.append(f"severity={expected_sev}")
        if mitre:
            criteria.append(f"mitre={mitre}")
        if title_contains:
            criteria.append(f"title_contains={title_contains}")

        raise AssertionError(
            f"No finding matched criteria ({', '.join(criteria)}). "
            f"Emitted findings: {[f.title for f in self.findings]}"
        )

    def assert_credential_found(self, username: str | None = None) -> Any:
        """Assert that at least one credential was discovered."""
        assert self.new_credentials, f"No new credentials discovered by module {self.module_id}"
        if username:
            matched = any(
                username.lower() in str(getattr(c, "username", "")).lower()
                for c in self.new_credentials
            )
            assert matched, f"Credential for username {username!r} not found in {self.new_credentials}"
        return self.new_credentials[0]


class ModuleTestHarness(Generic[M]):
    """Isolated execution harness for testing and simulating ARES modules.

    Usage:
        harness = ModuleTestHarness(MyModule)
        result = await harness.simulate(params={"target": "10.0.0.1"})
        result.assert_success()
        result.assert_finding(severity=Severity.HIGH)
    """

    def __init__(
        self,
        module_cls: type[M],
        scope_cidrs: list[str] | None = None,
        default_target: str = "10.0.0.1",
        default_domain: str = "CORP.LOCAL",
    ) -> None:
        self.module_cls = module_cls
        self.scope_cidrs = scope_cidrs or ["0.0.0.0/0"]
        self.default_target = default_target
        self.default_domain = default_domain
        self.settings = AresSettings()
        self.scope = [ScopeEntry(cidr=s) for s in self.scope_cidrs]
        self.campaign = Campaign(
            name="test-harness-campaign",
            client="test",
            scope=self.scope,
            noise_profile=NoiseProfile.NORMAL,
            operator="test_operator",
        )
        self.noise = NoiseController(self.campaign)
        self.vault = CredentialVault(encryption_key="ares-test-harness-master-key-32ch")

    def make_context(
        self,
        target: str | None = None,
        domain: str | None = None,
        params: dict[str, Any] | BaseModel | None = None,
        dry_run: bool = True,
        credentials: list[Any] | None = None,
        **kwargs: Any,
    ) -> ExecutionContext:
        """Build a mock ExecutionContext configured for this module."""
        final_target = target or self.default_target
        final_domain = domain or self.default_domain

        if isinstance(params, BaseModel):
            combined_params: Any = params
        else:
            combined_params = {**(params or {}), **kwargs}

        ctx = ExecutionContext.build(
            campaign=self.campaign,
            target=final_target,
            module_id=getattr(self.module_cls, "MODULE_ID", "test.module"),
            domain=final_domain,
            params=combined_params,
            credentials=credentials or [],
            vault=self.vault,
            settings=self.settings,
            noise=self.noise,
            dry_run=dry_run,
        )
        return ctx

    async def simulate(
        self,
        params: dict[str, Any] | BaseModel | None = None,
        target: str | None = None,
        domain: str | None = None,
        dry_run: bool = True,
        credentials: list[Any] | None = None,
        **kwargs: Any,
    ) -> SimulationResult:
        """Execute validate() and execute() in the isolated test harness."""
        ctx = self.make_context(
            target=target,
            domain=domain,
            params=params,
            dry_run=dry_run,
            credentials=credentials,
            **kwargs,
        )

        module = self.module_cls(
            settings=self.settings,
            campaign=self.campaign,
            noise=self.noise,
        )

        try:
            # 1. Validate
            await module.validate(ctx)

            # 2. Execute
            res = await module.execute(ctx)

            all_findings = list(res.findings or [])
            for f in ctx.findings:
                if f not in all_findings:
                    all_findings.append(f)

            return SimulationResult(
                status=res.status,
                module_id=module.MODULE_ID,
                findings=all_findings,
                raw=res.raw,
                new_credentials=list(res.new_credentials),
                discovered_hosts=list(res.discovered_hosts),
                artifacts=dict(res.artifacts),
                error=res.error or None,
                context=ctx,
            )
        except (ModuleValidationError, AresError, Exception) as exc:
            return SimulationResult(
                status="failed",
                module_id=getattr(module, "MODULE_ID", "unknown"),
                findings=ctx.findings,
                error=str(exc),
                context=ctx,
            )


__all__ = [
    "ModuleTestHarness",
    "SimulationResult",
]
