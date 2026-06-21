"""
Campaign — tracks engagements, findings, scope, and audit trail.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator
from netaddr import IPNetwork, AddrFormatError


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class NoiseProfile(str, Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1)
    severity: Severity
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> dict:
        if isinstance(v, str):
            return {"raw": v}
        return v if isinstance(v, dict) else {}
    remediation: str = ""
    false_positive: bool = False
    validated: bool = False
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    host:        str | None = None
    module_id:   str = ""
    cvss_score:  float = Field(default=0.0, ge=0.0, le=10.0,
                               description="CVSS v3.1 Base Score (0.0–10.0)")
    cvss_vector: str = Field(default="",
                              description="CVSS v3.1 vector string")
    trace_id:    str = ""  # OpenTelemetry trace ID for correlation

    @property
    def risk_score(self) -> float:
        """
        Weighted risk = severity.score × confidence.

        This is the legacy/operational metric — higher means more urgent.
        It is used by the AttackPlanner to prioritize suggested next steps
        and in CLI/dashboard summaries.

        For compliance reporting, use Finding.cvss_score (CVSS v3 Base Score, 0–10).
        The HTML/JSON report uses cvss_score as the authoritative risk number.

        Rule of thumb:
          - risk_score  → "what should I attack next?" (engine / planner)
          - cvss_score  → "how bad is this?" (report / compliance)
        """
        return self.severity.score * self.confidence

    def ensure_cvss(self) -> "Finding":
        """Auto-compute CVSS score if not already set. Returns self."""
        from ares.core.cvss import enrich_finding_with_cvss
        return enrich_finding_with_cvss(self)

    def to_dict(self) -> dict:
        """Serialize to dict — compatible with sandbox/engine code that calls .to_dict()."""
        return self.model_dump(mode="json")

    def mark_false_positive(self, reason: str) -> None:
        self.false_positive = True
        self.evidence["fp_reason"] = reason


class CampaignStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class ScopeEntry(BaseModel):
    """Defines what is in-scope for a campaign."""
    cidr: str
    description: str = ""

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            IPNetwork(v)
        except (AddrFormatError, ValueError) as e:
            raise ValueError(f"Invalid CIDR: {v}") from e
        return v


class AuditEntry(BaseModel):
    """Immutable audit log entry — tracks every action."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    action: str
    detail: str = ""
    module_id: str | None = None


class Campaign(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, max_length=100)
    client: str = Field(default="Internal", max_length=100)
    targets: list[str] = Field(default_factory=list)

    @field_validator("targets", mode="before")
    @classmethod
    def sanitize_targets(cls, v: list) -> list[str]:
        """Sanitize targets when Campaign is loaded from DB or created directly."""
        if not v:
            return []
        from ares.core.security import sanitize_hostname
        result: list[str] = []
        for entry in v:
            if isinstance(entry, str) and entry.strip():
                clean = sanitize_hostname(entry.strip())
                result.append(clean if clean else entry.strip())
        return result
    scope: list[ScopeEntry] = Field(default_factory=list)
    status: CampaignStatus = CampaignStatus.CREATED
    noise_profile: NoiseProfile = NoiseProfile.STEALTH
    findings: list[Finding] = Field(default_factory=list)
    audit_log: list[AuditEntry] = Field(default_factory=list)
    notes: str = ""
    operator: str = "unknown"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    # ── AD campaign context ───────────────────────────────────────────────────
    domain:  str = Field(default="", description="Active Directory domain (e.g. corp.local)")
    dc:      str = Field(default="", description="Domain controller IP or hostname")

    def model_post_init(self, __context: Any) -> None:
        """Warn if operator is still the default 'unknown'."""
        if self.operator == "unknown":
            import logging as _logging
            _logging.getLogger("ares.campaign").warning(
                "campaign_operator_not_set: campaign %r was created with operator='unknown'. "
                "Set operator= when creating Campaign to ensure accurate audit logs.",
                self.name,
            )

    def add_finding(self, finding: Finding) -> None:
        if not finding.false_positive:
            # Auto-mark as validated when added by operator
            if not finding.validated:
                finding = finding.model_copy(update={"validated": True})
            self.findings.append(finding)
            self.updated_at = datetime.now(timezone.utc)
            self._audit("finding_added", f"[{finding.severity.value.upper()}] {finding.title}", finding.module_id)

    def _audit(self, action: str, detail: str = "", module_id: str | None = None) -> None:
        self.audit_log.append(AuditEntry(
            actor=self.operator,
            action=action,
            detail=detail,
            module_id=module_id,
        ))

    def is_in_scope(self, ip: str) -> bool:
        """
        Check if an IP address or hostname is within defined campaign scope.

        For hostnames: attempts DNS resolution to obtain the IP, then checks
        the resolved IP against scope CIDRs. If DNS fails, the check FAILS
        CLOSED (returns False) to prevent accidental out-of-scope execution.

        NOTE: When called from async context, DNS resolution uses
        loop.getaddrinfo() (non-blocking). Falls back to sync only in CLI context.
        """
        if not self.scope:
            return False  # No scope = nothing is in scope (safe default)
        try:
            from netaddr import IPAddress
            addr = IPAddress(ip)
            return any(addr in IPNetwork(s.cidr) for s in self.scope)
        except (AddrFormatError, ValueError):
            target = ip.strip().lower()
            explicit_hosts = {
                entry.strip().lower()
                for entry in [*self.targets, self.dc]
                if entry and entry.strip()
            }
            if target and target in explicit_hosts:
                return True

            # Not a valid IP literal — attempt DNS resolution
            import socket as _socket
            import logging as _logging
            _log = _logging.getLogger("ares.campaign")
            try:
                # Bug 3 fix: use async-safe getaddrinfo when event loop is running
                import asyncio as _asyncio
                try:
                    _loop = _asyncio.get_event_loop()
                    if _loop.is_running():
                        # Running inside async context — use run_in_executor to avoid blocking
                        import concurrent.futures as _cf
                        with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                            results = _pool.submit(
                                _socket.getaddrinfo, ip, None,
                                _socket.AF_INET, _socket.SOCK_STREAM
                            ).result(timeout=5.0)
                    else:
                        results = _socket.getaddrinfo(ip, None, _socket.AF_INET, _socket.SOCK_STREAM)
                except RuntimeError:
                    results = _socket.getaddrinfo(ip, None, _socket.AF_INET, _socket.SOCK_STREAM)
                if not results:
                    _log.warning("scope_check_dns_no_result: hostname %r resolved to nothing — BLOCKING", ip)
                    return False  # Fail closed
                resolved_ip = results[0][4][0]
                from netaddr import IPAddress as _IPAddr
                addr = _IPAddr(resolved_ip)
                in_scope = any(addr in IPNetwork(s.cidr) for s in self.scope)
                if not in_scope:
                    _log.warning(
                        "scope_check_hostname_out_of_scope: %r resolved to %s which is NOT in scope %s",
                        ip, resolved_ip, [s.cidr for s in self.scope],
                    )
                else:
                    _log.debug("scope_check_hostname_resolved: %r → %s (in scope)", ip, resolved_ip)
                return in_scope
            except _socket.gaierror as dns_exc:
                _log.warning(
                    "scope_check_dns_failed: hostname %r could not be resolved (%s) — BLOCKING "
                    "(add explicit IP to scope or ensure DNS is available)",
                    ip, str(dns_exc)[:80],
                )
                return False  # Fail closed — unresolvable hostname is not in scope

    def check(self, ip: str) -> bool:
        """Alias for is_in_scope — used by guardrail consumers."""
        return self.is_in_scope(ip)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            if not f.false_positive:
                counts[f.severity.value] += 1
        return counts

    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.validated and not f.false_positive]

    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        return sum(f.risk_score for f in self.confirmed_findings())
