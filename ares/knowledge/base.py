"""
ARES Attack Knowledge Base
Known privilege escalation paths, misconfigurations, and service exploits.
Engine queries this to suggest next steps based on discovered services.

Usage:
    kb = AttackKnowledgeBase()
    suggestions = kb.suggest(host_state)
    # → [KBEntry(title="xp_cmdshell via MSSQL", ...)]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.knowledge")


@dataclass
class KBEntry:
    """A single knowledge base entry."""
    # Core fields (new API used by tests)
    entry_id:       str = ""
    module_id:      str = ""   # primary ARES module
    description:    str = ""
    conditions:     list[str] = field(default_factory=list)  # applies_when alias
    priority:       int = 5

    # Legacy / extended fields
    title:          str = ""
    category:       str = "technique"
    applies_when:   list[str] = field(default_factory=list)
    attack_modules: list[str] = field(default_factory=list)
    mitre_ids:      list[str] = field(default_factory=list)
    severity:       str = "high"
    references:     list[str] = field(default_factory=list)
    requires_auth:  bool = True

    def __post_init__(self) -> None:
        # Sync aliases
        if not self.applies_when and self.conditions:
            self.applies_when = self.conditions
        elif not self.conditions and self.applies_when:
            self.conditions = self.applies_when
        if not self.title:
            self.title = self.module_id or self.entry_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id":     self.entry_id,
            "module_id":    self.module_id,
            "id":           self.entry_id,
            "title":        self.title,
            "category":     self.category,
            "description":  self.description,
            "severity":     self.severity,
            "modules":      self.attack_modules,
            "mitre":        self.mitre_ids,
            "conditions":   self.conditions,
            "priority":     self.priority,
            "requires_auth": self.requires_auth,
        }


_KB_ENTRIES: list[KBEntry] = [
    KBEntry(entry_id="kb-001", title="Kerberoasting", description="Extract TGS hashes from SPN accounts.",
            category="credential_abuse", applies_when=["domain_joined","has_domain_creds"],
            attack_modules=["ad.kerberoast"], mitre_ids=["T1558.003"], severity="critical"),
    KBEntry(entry_id="kb-002", title="ASREPRoasting", description="Extract AS-REP hashes without credentials.",
            category="credential_abuse", applies_when=["domain_joined"],
            attack_modules=["ad.asreproast"], mitre_ids=["T1558.004"], severity="high", requires_auth=False),
    KBEntry(entry_id="kb-003", title="SUID Privesc", description="GTFOBins SUID binary escalation.",
            category="privesc", applies_when=["linux_host"],
            attack_modules=["linux.privesc"], mitre_ids=["T1548.001"], severity="critical"),
    KBEntry(entry_id="kb-004", title="S3 Public Bucket", description="Misconfigured S3 bucket exposes data.",
            category="misconfiguration", applies_when=["aws_cloud"],
            attack_modules=["cloud.aws"], mitre_ids=["T1530"], severity="critical", requires_auth=False),
    KBEntry(entry_id="kb-005", title="DCSync", description="Replicate NTDS hashes with MS-DRSR.",
            category="credential_abuse", applies_when=["domain_admin","is_dc"],
            attack_modules=["ad.dcsync"], mitre_ids=["T1003.006"], severity="critical"),
    # ── Roadmap module KB entries ─────────────────────────────────────────
    KBEntry(
        entry_id="kb-adcs",
        title="ADCS Certificate Template Misconfiguration",
        description=(
            "Active Directory Certificate Services ESC1–ESC8 vulnerabilities allow "
            "domain users to obtain certificates as Domain Admin. ESC1 is exploitable "
            "in most AD environments with ADCS deployed."
        ),
        category="privilege_escalation",
        applies_when=["domain_joined", "has_domain_creds"],
        attack_modules=["ad.adcs"],
        mitre_ids=["T1649"],
        severity="critical",
    ),
    KBEntry(
        entry_id="kb-rbcd",
        title="Resource-Based Constrained Delegation (RBCD)",
        description=(
            "If GenericWrite or WriteDACL exists on a computer object "
            "(identified by ad.enum_acl), RBCD attack can provide local admin "
            "on that machine via S4U2Self + S4U2Proxy without any additional creds."
        ),
        category="lateral_movement",
        applies_when=["acl_genericwrite_computer", "has_domain_creds"],
        attack_modules=["ad.delegation_abuse"],
        mitre_ids=["T1558.001"],
        severity="critical",
    ),
    KBEntry(
        entry_id="kb-coerce",
        title="Authentication Coercion (PetitPotam / PrinterBug)",
        description=(
            "When an SMB relay listener is active and a DC is in scope, "
            "authentication coercion forces the DC to authenticate to the listener. "
            "Captured machine account hash can be relayed for DCSync rights."
        ),
        category="credential_abuse",
        applies_when=["smb_relay_active", "domain_joined"],
        attack_modules=["ad.coerce"],
        mitre_ids=["T1187"],
        severity="critical",
    ),
    KBEntry(
        entry_id="kb-lsass",
        title="LSASS Memory Credential Dump",
        description=(
            "When local admin or SYSTEM access is confirmed on a Windows host "
            "(via lateral.psexec/wmiexec), LSASS dump extracts all NTLM hashes "
            "and Kerberos tickets from active sessions."
        ),
        category="credential_access",
        applies_when=["local_admin_windows"],
        attack_modules=["windows.lsass_dump"],
        mitre_ids=["T1003.001"],
        severity="critical",
    ),
    KBEntry(
        entry_id="kb-dpapi",
        title="DPAPI Protected Credential Extraction",
        description=(
            "When user context or NT hash is available, DPAPI blobs can be decrypted "
            "to recover Chrome/Edge saved passwords, WiFi PSK, Windows Credential Manager "
            "entries, and RDP saved credentials."
        ),
        category="credential_access",
        applies_when=["user_context_windows"],
        attack_modules=["windows.dpapi"],
        mitre_ids=["T1555.004", "T1555.003"],
        severity="high",
    ),
]


class AttackKnowledgeBase:
    """Query the KB for relevant attack paths based on current host state."""

    def __init__(self) -> None:
        self._entries = _KB_ENTRIES
        self._tracker = OutcomeTracker()

    def record_outcome(self, module_id: str, success: bool) -> None:
        """Record a module run outcome for future planner scoring."""
        self._tracker.record(module_id, success)

    def success_rate(self, module_id: str) -> float:
        """Return historical success rate (0.0–1.0). Returns 0.5 if no history."""
        return self._tracker.success_rate(module_id)

    def outcome_stats(self, module_id: str) -> "dict[str, int | float]":
        """Return {success, total, rate} dict for a module."""
        return self._tracker.stats(module_id)

    def suggest(self, host_state: dict) -> list[KBEntry]:
        """Return KB entries applicable to the given host state."""
        applicable = []
        for entry in self._entries:
            if all(self._condition_met(cond, host_state) for cond in entry.applies_when):
                applicable.append(entry)
        return sorted(applicable, key=lambda e: {"critical":0,"high":1,"medium":2,"low":3}.get(e.severity, 4))

    @staticmethod
    def _condition_met(condition: str, state: dict) -> bool:
        return bool(state.get(condition, False))

    def get(self, entry_id: str) -> KBEntry | None:
        return next((e for e in self._entries if e.entry_id == entry_id), None)

    def all_entries(self) -> list[KBEntry]:
        return list(self._entries)


class TrafficObfuscator:
    """Domain-front or proxy traffic to avoid network-level detection."""

    def __init__(self, fronting_domain: str | None = None) -> None:
        self._fronting_domain = fronting_domain

    def obfuscate_headers(self, headers: dict) -> dict:
        if self._fronting_domain:
            headers["Host"] = self._fronting_domain
        headers["User-Agent"] = "Mozilla/5.0 (compatible; ARES/1.0)"
        return headers


class Evidence:
    """A single piece of collected evidence."""
    def __init__(self, name: str, evidence_type: str, content: Any,
                 source_module: str = "", host: str = "") -> None:
        self.name, self.evidence_type, self.content = name, evidence_type, content
        self.source_module, self.host = source_module, host


class EvidenceType:
    SCREENSHOT  = "screenshot"
    FILE        = "file"
    HASH        = "hash"
    CREDENTIAL  = "credential"
    LOG         = "log"


class EvidenceStore:
    """In-memory evidence store with campaign scoping."""

    def __init__(self) -> None:
        self._store: list[Evidence] = []

    def add(self, evidence: Evidence) -> None:
        self._store.append(evidence)
        logger.debug("evidence_added", name=evidence.name, type=evidence.evidence_type)

    def get_by_type(self, evidence_type: str) -> list[Evidence]:
        return [e for e in self._store if e.evidence_type == evidence_type]

    def all(self) -> list[Evidence]:
        return list(self._store)

    def clear(self) -> None:
        self._store.clear()


# Modules yang butuh konfirmasi eksplisit sebelum dieksekusi
_HIGH_RISK_MODULES: set[str] = {"ad.dcsync"}  # only dcsync: replicates ALL domain hashes — truly irreversible

# IP range yang selalu diblokir (cloud IMDS, loopback, link-local)
_ALWAYS_BLOCKED_CIDRS: list[str] = [
    "169.254.169.254/32",  # AWS IMDS
    "169.254.170.2/32",    # ECS credentials
    "127.0.0.0/8",         # Loopback
]


class CampaignGuardrail:
    """Hard limits to prevent accidental damage during engagements."""

    def __init__(self, scope_cidrs: list[str], max_noise: str = "normal") -> None:
        self._scope = scope_cidrs
        self._max_noise = max_noise
        self._confirmed: set[tuple[str, str]] = set()  # (module_id, target_ip)

    def check(
        self,
        module_id: str,
        target_ip: str,
        confirmed: bool = False,
    ) -> tuple[bool, str]:
        """
        Check whether module_id is allowed to run against target_ip.
        Returns (allowed: bool, reason: str).
        """
        import ipaddress

        # 1. Always-blocked sensitive ranges
        for blocked_cidr in _ALWAYS_BLOCKED_CIDRS:
            try:
                if ipaddress.ip_address(target_ip) in ipaddress.ip_network(blocked_cidr, strict=False):
                    return False, f"BLOCKED: {target_ip} is a sensitive/protected address"
            except ValueError:
                pass

        # 2. Scope check
        if self._scope:
            in_scope = False
            for cidr in self._scope:
                try:
                    if ipaddress.ip_address(target_ip) in ipaddress.ip_network(cidr, strict=False):
                        in_scope = True
                        break
                except ValueError:
                    continue
            if not in_scope:
                return False, f"OUT OF SCOPE: {target_ip} is not in allowed scope {self._scope}"

        # 3. High-risk module gate
        if module_id in _HIGH_RISK_MODULES:
            key = (module_id, target_ip)
            if not confirmed and key not in self._confirmed:
                return False, f"HIGH-RISK: {module_id} requires explicit confirmation for {target_ip}"

        return True, "OK"

    def confirm_dangerous(self, module_id: str, target_ip: str) -> None:
        """Pre-approve a high-risk module for a specific target."""
        self._confirmed.add((module_id, target_ip))

    def check_target(self, target_ip: str) -> bool:
        """Legacy: Return True if target is within scope."""
        import ipaddress
        for cidr in self._scope:
            try:
                if ipaddress.ip_address(target_ip) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return not self._scope  # If no scope defined, allow all

    def assert_in_scope(self, target_ip: str) -> None:
        if not self.check_target(target_ip):
            raise ValueError(f"Target {target_ip} is out of scope. Engagement halted.")


# ── Module scoring utilities ───────────────────────────────────────────────────

NOISE_SCORE: dict[str, int] = {
    "ad.enum_users":     1,
    "ad.enum_spn":       1,
    "ad.enum_computers": 1,
    "ad.enum_acl":       2,
    "ad.kerberoast":     2,
    "ad.asreproast":     2,
    "ad.dcsync":         4,
    "linux.privesc":     2,
    "linux.container":   2,
    "cloud.aws":         1,
    "cloud.azure":       1,
    "cloud.gcp":         1,
}

EDR_DETECTABLE: set[str] = {
    "ad.dcsync",
    "ad.kerberoast",
    "ad.asreproast",
    "linux.privesc",
}


def score_modules_for_profile(
    module_ids: list[str],
    noise_profile: str = "stealth",
) -> dict[str, int]:
    thresholds = {"stealth": 1, "normal": 2, "aggressive": 4}
    max_score = thresholds.get(noise_profile, 2)
    result: dict[str, int] = {}
    for mid in module_ids:
        score = NOISE_SCORE.get(mid, 1)
        result[mid] = score
    return result


# ── Outcome persistence ────────────────────────────────────────────────────────

import json as _json
from pathlib import Path as _Path
import time as _time

_OUTCOMES_PATH = _Path.home() / ".ares" / "kb_outcomes.json"


class OutcomeTracker:
    """
    Persist module run outcomes so the planner can learn from history.
    Storage: ~/.ares/kb_outcomes.json
    Schema:  { "<module_id>": {"success": N, "total": N} }

    Thread/process-safe via fcntl.flock() exclusive lock on write.
    On platforms without fcntl (Windows), falls back to in-memory only.
    """

    def __init__(self, path: "_Path | None" = None) -> None:
        self._path = _Path(path) if path else _OUTCOMES_PATH
        self._data: dict[str, dict[str, int]] = self._load()

    def _load(self) -> dict[str, dict[str, int]]:
        try:
            if self._path.exists():
                return _json.loads(self._path.read_text())
        except Exception:
            pass
        return {}

    def _save(self) -> None:
        """Write with exclusive file lock to prevent concurrent corruption."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Use a lock file alongside the data file
            lock_path = self._path.with_suffix(".lock")
            try:
                import fcntl
                with open(lock_path, "w") as lf:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                    try:
                        self._path.write_text(_json.dumps(self._data, indent=2))
                    finally:
                        fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            except ImportError:
                # fcntl not available (Windows) — best-effort write
                self._path.write_text(_json.dumps(self._data, indent=2))
        except Exception:
            pass

    def record(self, module_id: str, success: bool) -> None:
        rec = self._data.setdefault(module_id, {"success": 0, "total": 0})
        rec["total"] += 1
        if success:
            rec["success"] += 1
        self._save()

    def success_rate(self, module_id: str) -> float:
        rec = self._data.get(module_id)
        if not rec or rec["total"] == 0:
            return 0.5   # neutral prior — no history yet
        return rec["success"] / rec["total"]

    def stats(self, module_id: str) -> dict[str, int | float]:
        rec = self._data.get(module_id, {"success": 0, "total": 0})
        return {**rec, "rate": self.success_rate(module_id)}


# Singleton tracker attached to AttackKnowledgeBase so callers can:
#   kb = AttackKnowledgeBase()
#   kb.record_outcome("ad.kerberoast", success=True)
#   rate = kb.success_rate("ad.kerberoast")

