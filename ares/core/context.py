"""
ARES ExecutionContext
A single, typed object passed to every module execution.
Replaces the scattered (settings, campaign, noise, **kwargs) pattern.

Before (v0.8.0):
    module = KerberoastModule(settings=settings, campaign=campaign, noise=noise)
    findings, extra = await module.run(dc="dc01.corp.local", domain="CORP")

After (v0.9.0):
    ctx = ExecutionContext.build(campaign, target="dc01.corp.local",
                                  params={"domain": "CORP"})
    findings, extra = await module.run(ctx)

Benefits:
  - Modules have a stable API surface regardless of engine changes
  - Context carries all shared state: credentials, session, telemetry hook
  - Validators can inspect the context before execution
  - Replay engine can serialize/deserialize context for campaign replay
  - Testing is trivial: just build a mock context

Context lifecycle:
  Engine builds context
    → validates context (BaseModule.validate(ctx))
    → executes module (BaseModule.execute(ctx))
    → processes result (BaseModule.report(result, ctx))
    → updates session state
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ares.core.errors import InvalidContext

if TYPE_CHECKING:
    from ares.core.campaign import Campaign, NoiseProfile
    from ares.core.config import AresSettings
    from ares.core.noise import NoiseController
    from ares.core.opsec.opsec import OpSecProfile
    from ares.credential.vault import CredentialVault, Credential
    from ares.state.target_state import OperatorSession, HostState
    from ares.telemetry.collector import TelemetryCollector


@dataclass
class ExecutionContext:
    """
    Unified execution context passed to every module.
    Immutable after construction (fields are set once by the engine).

    Required fields:
        target      — IP address or hostname being attacked
        campaign_id — which campaign this belongs to
        module_id   — which module will consume this context

    Optional but strongly recommended:
        credentials     — ordered list of credentials to try
        session         — shared operator session (host states, attack history)
        params          — module-specific parameters
        operator        — operator username for audit logging
    """

    # ── Identity ──────────────────────────────────────────────────────────
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    campaign_id:  str = ""
    module_id:    str = ""
    operator:     str = "unknown"

    # ── Target ────────────────────────────────────────────────────────────
    target:       str = ""          # IP or hostname being attacked
    domain:       str = ""          # AD domain (CORP.LOCAL)
    port:         int = 0           # specific port if protocol-targeted

    # ── Parameters ────────────────────────────────────────────────────────
    params: dict[str, Any] = field(default_factory=dict)

    # ── Credentials ───────────────────────────────────────────────────────
    # Ordered by score (highest first). Module tries each in order.
    credentials:       list[Any] = field(default_factory=list)   # list[Credential]
    primary_credential: Any = None    # best credential to try first

    # ── Shared state ──────────────────────────────────────────────────────
    # These are references — mutations visible to engine after execution
    session:    Any = None    # OperatorSession
    vault:      Any = None    # CredentialVault
    artifact_store: Any = None  # ArtifactStore
    runtime_state: Any = None   # CampaignRuntimeState

    # ── Engine references ─────────────────────────────────────────────────
    settings:   Any = None    # AresSettings
    campaign:   Any = None    # Campaign
    noise:      Any = None    # NoiseController
    telemetry:  Any = None    # TelemetryCollector

    # ── OpSec ─────────────────────────────────────────────────────────────
    opsec_profile:    str = "normal"   # stealth | normal | aggressive
    max_retries:      int = 3
    timeout_s:        int = 300

    # ── Audit ─────────────────────────────────────────────────────────────
    created_at:    float = field(default_factory=time.time)
    dry_run:       bool  = False   # simulation mode — no real network calls

    # ── Metadata ──────────────────────────────────────────────────────────
    tags:    list[str] = field(default_factory=list)
    extra:   dict[str, Any] = field(default_factory=dict)

    # ── Validation ────────────────────────────────────────────────────────

    def require(self, *fields: str) -> None:
        """
        Assert that required fields are present.
        Called by BaseModule.validate() to check context completeness.

        Usage:
            ctx.require("target", "domain", "credentials")

        Raises:
            InvalidContext if any field is empty/None
        """
        for f in fields:
            val = getattr(self, f, None)
            if val is None or val == "" or val == []:
                raise InvalidContext(
                    f"ExecutionContext missing required field: {f!r}",
                    module_id=self.module_id,
                    missing_field=f,
                )

    def has(self, *fields: str) -> bool:
        """Check if optional fields are populated."""
        return all(
            getattr(self, f, None) not in (None, "", [])
            for f in fields
        )

    # ── Accessors ─────────────────────────────────────────────────────────

    def best_credential(self) -> "Credential | None":
        """Return highest-scored credential, or primary_credential if set."""
        if self.primary_credential:
            return self.primary_credential
        if self.credentials:
            return self.credentials[0]
        return None

    def host_state(self) -> "HostState | None":
        """Retrieve current host state from session, if session available."""
        if self.session and self.target:
            return self.session.get_host(self.target)
        return None

    def record_metric(self, metric: str, value: float) -> None:
        """Record an execution metric in telemetry, if collector available."""
        if self.telemetry:
            self.telemetry.record_execution(
                self.module_id, value, success=True, campaign_id=self.campaign_id
            )

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize context for audit logging and replay.
        Sensitive fields (credentials, vault) are excluded.
        """
        return {
            "execution_id": self.execution_id,
            "campaign_id":  self.campaign_id,
            "module_id":    self.module_id,
            "operator":     self.operator,
            "target":       self.target,
            "domain":       self.domain,
            "port":         self.port,
            "params":       self.params,
            "opsec_profile": self.opsec_profile,
            "dry_run":       self.dry_run,
            "created_at":    self.created_at,
            "tags":          self.tags,
            "has_credentials": len(self.credentials) > 0,
            "has_session":     self.session is not None,
            "has_artifact_store": self.artifact_store is not None,
        }

    @classmethod
    def build(
        cls,
        campaign:     Any,
        target:       str,
        module_id:    str,
        params:       dict[str, Any] | None = None,
        domain:       str = "",
        port:         int = 0,
        operator:     str = "",
        credentials:  list[Any] | None = None,
        session:      Any = None,
        vault:        Any = None,
        artifact_store: Any = None,
        runtime_state: Any = None,
        settings:     Any = None,
        noise:        Any = None,
        telemetry:    Any = None,
        opsec_profile: str = "normal",
        timeout_s:    int = 300,
        dry_run:      bool = False,
        tags:         list[str] | None = None,
    ) -> "ExecutionContext":
        """
        Factory method — preferred way to create an ExecutionContext.
        Derives campaign_id and operator from the Campaign object.
        """
        return cls(
            campaign_id    = getattr(campaign, "id", "") if campaign else "",
            module_id      = module_id,
            operator       = operator or getattr(campaign, "operator", "unknown"),
            target         = target,
            domain         = domain or (params or {}).get("domain", "") or getattr(campaign, "domain", ""),
            port           = port,
            params         = params or {},
            credentials    = credentials or [],
            session        = session,
            vault          = vault,
            artifact_store = artifact_store,
            runtime_state  = runtime_state,
            settings       = settings,
            campaign       = campaign,
            noise          = noise,
            telemetry      = telemetry,
            opsec_profile  = opsec_profile,
            timeout_s      = timeout_s,
            dry_run        = dry_run,
            tags           = tags or [],
        )

    @classmethod
    def for_test(
        cls,
        target: str = "10.0.0.1",
        module_id: str = "test.module",
        params: dict[str, Any] | None = None,
        dry_run: bool = True,
    ) -> "ExecutionContext":
        """
        Build a minimal context for unit testing.
        Sets dry_run=True so no real network calls are made.
        """
        return cls(
            target=target, module_id=module_id,
            params=params or {}, campaign_id="test",
            operator="test", dry_run=dry_run,
        )

    def __repr__(self) -> str:
        return (
            f"ExecutionContext(id={self.execution_id!r}, "
            f"module={self.module_id!r}, target={self.target!r}, "
            f"profile={self.opsec_profile!r}, dry_run={self.dry_run})"
        )
