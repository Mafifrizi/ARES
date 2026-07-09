"""
ARES Base Module
All modules inherit from BaseModule.

Metadata system enables:
  - auto dependency checking before execution
  - attack chain auto-wiring (outputs → inputs)
  - opsec level enforcement (stealth mode skips HIGH_NOISE modules)
  - engine capability querying (list all modules that output 'spn_list')

Required class attributes:
    MODULE_ID          str  — unique dotted ID, e.g. "ad.kerberoast"
    MODULE_NAME        str  — human name
    MODULE_CATEGORY    str  — "ad" | "linux" | "cloud" | "reporting"
    MODULE_DESCRIPTION str  — one-liner for CLI list

Optional class attributes (defaults shown):
    OPSEC_LEVEL        OpsecLevel  — SILENT | LOW | MEDIUM | HIGH_NOISE
    REQUIRES           list[str]   — capabilities/outputs this module needs as input
    OUTPUTS            list[str]   — what this module produces (feeds downstream modules)
    MITRE_TECHNIQUES   list[str]   — ATT&CK technique IDs
    MODULE_AUTHOR      str
    MIN_NOISE_PROFILE  str | None  — block execution below this profile
"""
from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

from ares.core.campaign import Campaign, Finding, Severity
from ares.core.config import AresSettings
from ares.core.errors import ModuleValidationError
from ares.core.logger import bind_context, clear_context, get_logger
from ares.core.noise import NoiseController
from ares.core.opsec.opsec import OpSecProfile

if TYPE_CHECKING:
    from ares.core.context import ExecutionContext

logger = get_logger("ares.module")


# ── OpSec level enum ──────────────────────────────────────────────────────────

class OpsecLevel(str, Enum):
    SILENT     = "silent"      # passive/local only, zero network traffic
    LOCAL      = "local"       # alias for SILENT — cracking, local-only ops
    LOW        = "low"         # read-only LDAP, basic API calls
    MEDIUM     = "medium"      # active queries, Kerberos TGS
    HIGH_NOISE = "high_noise"  # DCSync, brute force — blocked in stealth


# ── BaseModule ────────────────────────────────────────────────────────────────

class BaseModule(abc.ABC):
    """
    Abstract base for all ARES modules.

    Subclass and implement:
        async def run(self, **kwargs) -> tuple[list[Finding], dict[str, Any]]:
            ...

    Formal SDK contract (v0.9.0+) — see validate(), before_request(), finding().
    """

    async def validate(self, ctx: "Any") -> None:
        """
        Validate the execution context BEFORE running the module.
        Called automatically by the engine — do not call manually.
        Raise ModuleValidationError if context is insufficient.

        Default: checks target is set and all REQUIRES entries are available.
        Override to add module-specific validation (format checks, etc.).
        Do NOT make network calls here — validate() must complete in < 10s.

        Example override:
            async def validate(self, ctx):
                await super().validate(ctx)            # keep default checks
                if not ctx.params.get("dc"):
                    raise ModuleValidationError(
                        f"{self.MODULE_ID} requires 'dc' (Domain Controller IP)",
                        module_id=self.MODULE_ID, field="dc",
                    )
        """
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError

        if not isinstance(ctx, ExecutionContext):
            return  # legacy context — skip validation

        # Categories that use API credentials instead of a target IP — skip target check
        _NO_TARGET_CATEGORIES = {"cloud", "reporting", "recon"}
        if getattr(self.__class__, "MODULE_CATEGORY", "") in _NO_TARGET_CATEGORIES:
            return

        # Check target is set
        if not ctx.target:
            raise ModuleValidationError(
                f"Module {self.MODULE_ID!r} requires 'target' — "
                "set via params['target'], params['dc'], or params['host']",
                module_id=self.MODULE_ID,
                field="target",
            )

        # Check REQUIRES list — each item must be present in params or context
        requires = getattr(self.__class__, "REQUIRES", [])
        if requires:
            available: set[str] = set(ctx.params.keys())
            if ctx.target:                 available.add("target")
            if ctx.domain:                 available.add("domain")
            if getattr(ctx, "vault", None): available.add("vault")
            # credentials/domain_creds: available if vault has entries
            vault = getattr(ctx, "vault", None)
            if vault and hasattr(vault, "_store") and vault._store:
                available.add("credentials")
                available.add("domain_creds")

            # Only check "capability" requirements (lowercase, no spaces)
            # Skip output-type requirements like "spn_list" or "kerberos_hashes"
            # which are satisfied by chaining, not direct params
            hard_requires = [
                r for r in requires
                if r in ("target", "domain", "vault", "credentials",
                         "domain_creds", "domain_admin_creds")
            ]
            missing = [r for r in hard_requires if r not in available]
            if missing:
                raise ModuleValidationError(
                    f"Module {self.MODULE_ID!r} missing required inputs: {missing}",
                    module_id=self.MODULE_ID,
                    field=str(missing),
                )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """
        Execute the module using the ExecutionContext (v0.9.0+ interface).

        Default implementation delegates to run() for backwards compatibility.
        New modules should override execute() directly.

        Returns:
            ModuleResult — structured result consumed by engine
        """
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status    = "success" if findings or raw else "partial",
            findings  = findings,
            raw       = raw,
            module_id = self.MODULE_ID,
            execution_id = ctx.execution_id if hasattr(ctx, "execution_id") else "",
        )

    def report(self, result: "ModuleResult") -> dict:
        """
        Format this module's result for the report engine.
        Called by ReportGenerator when building the campaign report.

        Default: returns a structured summary dict.
        Override to add module-specific narrative or MITRE context.

        Returns:
            dict with keys: title, summary, findings, mitre, severity
        """
        from ares.technique.library import TechniqueMapper
        mapper   = TechniqueMapper()
        techs    = mapper.for_module(self.MODULE_ID)
        return {
            "module_id":   self.MODULE_ID,
            "module_name": self.MODULE_NAME,
            "title":       f"{self.MODULE_NAME} Results",
            "summary":     (
                f"{len(result.findings)} finding(s) from {self.MODULE_NAME}. "
                f"Status: {result.status}."
            ),
            "findings":    [f.to_dict() if hasattr(f, "to_dict") else {} for f in result.findings],
            "mitre":       [t.to_dict() for t in techs],
            "new_credentials": len(result.new_credentials),
            "discovered_hosts": result.discovered_hosts,
            "severity":    (
                max((f.severity.value for f in result.findings), default="info")
                if result.findings else "info"
            ),
        }


    # ── Required metadata ──────────────────────────────────────────────────
    MODULE_ID:          str = ""
    MODULE_NAME:        str = ""
    MODULE_CATEGORY:    str = ""
    MODULE_DESCRIPTION: str = ""

    # ── Optional metadata ──────────────────────────────────────────────────
    OPSEC_LEVEL:        OpsecLevel  = OpsecLevel.LOW
    REQUIRES:           list[str]   = []   # e.g. ["domain_creds", "ldap_access"]
    OUTPUTS:            list[str]   = []   # e.g. ["spn_list", "user_list"]
    MITRE_TECHNIQUES:   list[str]   = []
    MODULE_AUTHOR:      str         = "ARES Team"
    MIN_NOISE_PROFILE:  str | None  = None  # None = runs in any profile

    # Per-module timeout override (seconds). None = use engine default (120s).
    # Set higher for slow ops: dcsync on WAN, lsass_dump transfer, crack jobs.
    # Set lower for fast ops: laps_enum, enum_users on fast LAN.
    MODULE_TIMEOUT_SECONDS: int | None = None

    def __init__(
        self,
        settings:  AresSettings,
        campaign:  Campaign,
        noise:     NoiseController,
        opsec:     OpSecProfile | None = None,
    ) -> None:
        self.settings = settings
        self.campaign = campaign
        self.noise    = noise
        self.opsec    = opsec or OpSecProfile.from_noise_profile(campaign.noise_profile)
        self._findings: list[Finding] = []

    # ── Abstract interface ─────────────────────────────────────────────────

    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        """
        Execute the module.

        Returns:
            findings  — list of Finding objects (unvalidated)
            raw       — raw output dict (evidence, debug info)

        Subclasses should override this method. The default implementation
        raises NotImplementedError to catch unimplemented modules at runtime.
        """
        # Abstract method — enforced by abc.ABC inheritance on BaseModule.
        # Subclasses must override this.  Using raise rather than @abstractmethod
        # here preserves Mypy compatibility with the dynamic MODULE_ID attribute.
        raise NotImplementedError(  # abstract — subclasses must implement run()
            f"Module '{self.MODULE_ID}' must implement run()"
        )

    # ── Pre-request hook ───────────────────────────────────────────────────

    async def before_request(self, target: str, action: str = "default") -> None:
        """
        Call before every network request.
        Enforces: scope check → rate limit → opsec sleep.
        """
        self.noise.scope_guard.assert_in_scope(target)
        await self.noise.rate_limiter.acquire(action)
        await self.noise.jitter.sleep()

    # ── Error classification helper ────────────────────────────────────────

    def _classify_error(self, exc: Exception, target: str = "",
                        username: str = "") -> Exception:
        """
        Map a raw exception to an ARES typed exception so AdaptiveOpsecEngine
        can choose the correct fallback strategy.

        Usage in modules:
            except Exception as exc:
                raise self._classify_error(exc, target=target, username=username) from exc

        Mapping:
            auth/credential errors  → AuthenticationFailed
            timeout/refused         → HostUnreachable or ConnectionTimeout
            access denied/privilege → InsufficientPrivilege
            rate limiting           → RateLimited
            everything else         → NetworkError (retryable)
        """
        from ares.core.errors import (
            AuthenticationFailed, HostUnreachable, ConnectionTimeout,
            InsufficientPrivilege, RateLimited, NetworkError,
        )
        msg = str(exc).lower()

        # Authentication / credential failures
        if any(s in msg for s in (
            "logon failure", "invalid credentials", "authentication failed",
            "wrong password", "bad credentials", "status_logon_failure",
            "login failed", "invalid username", "18456",
        )):
            return AuthenticationFailed(
                f"{self.MODULE_ID} auth failed on {target}: {exc}",
                username=username, module_id=self.MODULE_ID, target=target,
            )

        # Privilege / access denied
        if any(s in msg for s in (
            "access denied", "insufficient privilege", "status_access_denied",
            "permission denied", "forbidden", "not authorized",
        )):
            return InsufficientPrivilege(
                f"{self.MODULE_ID} insufficient privilege on {target}: {exc}",
                module_id=self.MODULE_ID,
            )

        # Timeout
        if any(s in msg for s in ("timed out", "timeout", "asyncio.timeouterror")):
            return ConnectionTimeout(
                f"{self.MODULE_ID} timed out on {target}: {exc}",
                timeout_s=0, target=target, module_id=self.MODULE_ID,
            )

        # Connection refused / unreachable
        if any(s in msg for s in (
            "connection refused", "no route to host",
            "network unreachable", "host unreachable", "errno 111",
        )):
            return HostUnreachable(
                f"{self.MODULE_ID} host unreachable: {target}: {exc}",
                target=target, module_id=self.MODULE_ID,
            )

        # Rate limiting
        if any(s in msg for s in ("rate limit", "too many requests", "429", "throttl")):
            return RateLimited(f"{self.MODULE_ID} rate limited: {exc}")

        # Fallback — general network error (engine will retry)
        return NetworkError(f"{self.MODULE_ID} network error on {target}: {exc}")

    # ── Finding helper ─────────────────────────────────────────────────────

    def finding(
        self,
        title:           str,
        description:     str,
        severity:        Severity,
        mitre_technique: str | None = None,
        mitre_tactic:    str | None = None,
        evidence:        dict[str, Any] | None = None,
        remediation:     str = "",
        host:            str | None = None,
        confidence:      float = 1.0,
    ) -> Finding:
        """Create, register, and return a finding."""
        f = Finding(
            id              = str(uuid.uuid4()),
            title           = title,
            description     = description,
            severity        = severity,
            mitre_technique = mitre_technique,
            mitre_tactic    = mitre_tactic,
            evidence        = evidence or {},
            remediation     = remediation,
            host            = host,
            confidence      = confidence,
            module_id       = self.MODULE_ID,
        )
        self._findings.append(f)
        logger.info(
            "finding_created",
            module=self.MODULE_ID,
            title=title,
            severity=severity.value,
            confidence=confidence,
            mitre=mitre_technique,
        )
        return f

    # ── Metadata helpers ───────────────────────────────────────────────────

    @classmethod
    def metadata(cls) -> dict[str, Any]:
        """Return full module metadata as a dict (used by registry + API)."""
        return {
            "id":               cls.MODULE_ID,
            "name":             cls.MODULE_NAME,
            "category":         cls.MODULE_CATEGORY,
            "description":      cls.MODULE_DESCRIPTION,
            "opsec_level":      cls.OPSEC_LEVEL.value if isinstance(cls.OPSEC_LEVEL, OpsecLevel) else cls.OPSEC_LEVEL,
            "requires":         cls.REQUIRES,
            "outputs":          cls.OUTPUTS,
            "mitre":            ", ".join(cls.MITRE_TECHNIQUES),
            "mitre_list":       cls.MITRE_TECHNIQUES,
            "author":           cls.MODULE_AUTHOR,
            "min_noise_profile": cls.MIN_NOISE_PROFILE,
            "required_privilege": getattr(cls, "REQUIRED_PRIVILEGE", None),
        }

    @classmethod
    def can_run_with_noise(cls, noise_profile: str) -> bool:
        """Check if this module is safe to run at the given noise level."""
        # HIGH_NOISE modules blocked in stealth
        if cls.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE and noise_profile == "stealth":
            return False
        # Respect MIN_NOISE_PROFILE
        if cls.MIN_NOISE_PROFILE:
            order = ["stealth", "normal", "aggressive"]
            try:
                required_idx = order.index(cls.MIN_NOISE_PROFILE)
                current_idx  = order.index(noise_profile)
                return current_idx >= required_idx
            except ValueError:
                pass
        return True

    @classmethod
    def satisfies(cls, capability: str) -> bool:
        """Check if this module produces a given capability/output."""
        return capability in cls.OUTPUTS

    @classmethod
    def needs(cls, capability: str) -> bool:
        """Check if this module requires a given capability/input."""
        return capability in cls.REQUIRES

    # ── Context binding ────────────────────────────────────────────────────

    def _bind_log_context(self, target: str = "") -> None:
        """Bind module context to structlog for the duration of this run."""
        bind_context(
            module=self.MODULE_ID,
            campaign=self.campaign.id[:8],
            operator=self.campaign.operator,
            noise=self.campaign.noise_profile.value,
            target=target,
        )

    def _clear_log_context(self) -> None:
        clear_context()

    # ── Context helpers ────────────────────────────────────────────────────

    def _extract_ad_params(self, ctx: "Any") -> dict:
        """
        Extract common AD module params from ExecutionContext.
        Pulls dc, domain, username, password — trying vault first.
        Safe to call even when ctx is a bare namespace (test mode).
        """
        cred = getattr(ctx, "best_credential", lambda: None)()
        username = ctx.params.get("username") or (cred.username if cred else "")
        password = ctx.params.get("password", "")
        if cred and not password:
            vault = getattr(ctx, "vault", None)
            if vault:
                try:
                    password = vault.reveal(cred.id)
                except Exception:
                    pass
        return {
            "dc":       ctx.params.get("dc") or getattr(ctx, "target", ""),
            "domain":   getattr(ctx, "domain", "") or ctx.params.get("domain", ""),
            "username": username,
            "password": password,
        }


# ── ModuleResult ──────────────────────────────────────────────────────────────
@dataclass
class ModuleResult:
    """
    Standardized output from every module execution.
    Engine uses this to auto-continue attack chains.
    """
    status:           str                   = "success"
    findings:         list = field(default_factory=list)
    artifacts:        dict = field(default_factory=dict)
    new_credentials:  list = field(default_factory=list)
    discovered_hosts: list = field(default_factory=list)
    raw:              dict = field(default_factory=dict)
    error:            str   = ""
    module_id:        str   = ""
    execution_id:     str   = ""
    # Outcome quality — 0.0=failed/empty, 0.5=partial, 1.0=full success
    # Enables accurate learning in OutcomeKnowledgeBase (not just status string)
    outcome_quality:  float = -1.0   # -1.0 = not set by module (auto-computed)
    outcome_evidence: str   = ""     # e.g. "3 TGS tickets from corp.local"

    @property
    def effective_quality(self) -> float:
        """Returns explicitly set quality, or auto-derives from status+findings."""
        if self.outcome_quality >= 0.0:
            return self.outcome_quality
        # Auto-derive
        if self.status in ("dry_run", "skipped"):
            return 0.0
        if self.status == "failed" or self.error:
            return 0.0
        if self.status == "partial":
            return 0.5 if not self.findings else min(len(self.findings) / 3.0, 0.8)
        # status == "success"
        return 1.0 if self.findings else 0.5

    @property
    def success(self) -> bool:
        return self.status == "success"

    @property
    def has_credentials(self) -> bool:
        return len(self.new_credentials) > 0

    @property
    def has_new_hosts(self) -> bool:
        return len(self.discovered_hosts) > 0

    def to_dict(self) -> dict:
        return {
            "status":           self.status,
            "findings":         len(self.findings),
            "new_credentials":  len(self.new_credentials),
            "discovered_hosts": self.discovered_hosts,
            "error":            self.error,
            "module_id":        self.module_id,
        }


_REQUIRED_MODULE_ATTRS: list[str] = [
    "MODULE_ID", "MODULE_NAME", "MODULE_CATEGORY", "MODULE_DESCRIPTION",
]


def validate_module_class(cls: type) -> list[str]:
    """
    Validate community module class has all required metadata.
    Returns list of errors (empty = valid).
    """
    errors: list[str] = []
    for attr in _REQUIRED_MODULE_ATTRS:
        val = getattr(cls, attr, "")
        if not val:
            errors.append(f"Missing required attribute: {attr!r}")
    mid = getattr(cls, "MODULE_ID", "")
    if mid and "." not in mid:
        errors.append(f"MODULE_ID {mid!r} must use dotted format 'category.name'")
    return errors
