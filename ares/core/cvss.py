"""
CVSS v3.1 Scoring Engine for ARES

Computes Base Score from a CVSS v3.1 vector string.
Maps ARES severity labels to default CVSS vectors.
Auto-assigns scores to Finding objects.

CVSS v3.1 Base Score formula:
    ISCBase = 1 - (1-ImpactConf) × (1-ImpactInteg) × (1-ImpactAvail)
    If Scope Unchanged: ISS = 6.42 × ISCBase
    If Scope Changed:   ISS = 7.52×[ISCBase-0.029] - 3.25×[ISCBase-0.02]^15
    Exploitability = 8.22 × AV × AC × PR × UI
    If ISS ≤ 0:    BaseScore = 0
    If Scope Unchanged: BaseScore = roundup(min(ISS+Exploitability, 10))
    If Scope Changed:   BaseScore = roundup(min(1.08×(ISS+Exploitability), 10))

Reference: https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


# ── CVSS v3.1 metric tables ───────────────────────────────────────────────────

_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC  = {"L": 0.77, "H": 0.44}                           # Attack Complexity
_PR  = {                                                 # Privileges Required
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.50},
    "H": {"U": 0.27, "C": 0.50},
}
_UI  = {"N": 0.85, "R": 0.62}                           # User Interaction
_S   = {"U": "U",  "C": "C"}                            # Scope
_C_I_A = {"N": 0.00, "L": 0.22, "H": 0.56}             # Confidentiality/Integrity/Availability


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: rounds to nearest 0.1 towards positive infinity."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


def _parse_vector(vector: str) -> dict[str, str]:
    """
    Parse CVSS v3.1 vector string to component dict.
    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    """
    if not vector.startswith("CVSS:3."):
        raise ValueError(f"Not a CVSS v3.x vector: {vector!r}")
    components: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            components[k] = v
    return components


def compute_base_score(vector: str) -> float:
    """
    Compute CVSS v3.1 Base Score from vector string.
    Returns float 0.0–10.0.
    """
    try:
        c = _parse_vector(vector)
        av  = _AV[c["AV"]]
        ac  = _AC[c["AC"]]
        s   = c["S"]
        pr  = _PR[c["PR"]][s]
        ui  = _UI[c["UI"]]
        ic  = _C_I_A[c["C"]]
        ii  = _C_I_A[c["I"]]
        ia  = _C_I_A[c["A"]]

        isc_base = 1 - (1 - ic) * (1 - ii) * (1 - ia)
        if s == "U":
            iss = 6.42 * isc_base
        else:
            iss = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        if iss <= 0:
            return 0.0

        exploitability = 8.22 * av * ac * pr * ui

        if s == "U":
            base = min(iss + exploitability, 10)
        else:
            base = min(1.08 * (iss + exploitability), 10)

        return _roundup(base)

    except (KeyError, ValueError):
        return 0.0


# ── CVSS severity to rating ───────────────────────────────────────────────────

def score_to_severity(score: float) -> str:
    """Map CVSS 3.1 Base Score to severity label."""
    if score == 0.0:
        return "info"
    elif score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"


def severity_to_score_range(severity: str) -> tuple[float, float]:
    """Return (min, max) CVSS score range for a severity label."""
    return {
        "critical": (9.0, 10.0),
        "high":     (7.0, 8.9),
        "medium":   (4.0, 6.9),
        "low":      (0.1, 3.9),
        "info":     (0.0, 0.0),
    }.get(severity.lower(), (0.0, 0.0))


# ── ARES module → CVSS vector mapping ────────────────────────────────────────
# Maps MITRE technique → default CVSS v3.1 vector
# Allows findings to auto-get a CVSS score even when module doesn't provide one.

TECHNIQUE_CVSS_VECTORS: dict[str, str] = {
    # AD / Credential Access
    "T1558.003": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # Kerberoasting
    "T1558.004": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # ASREPRoasting (no creds)
    "T1003.006": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",  # DCSync (DA level)
    "T1078.002": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # Valid Accounts: Domain
    "T1110.003": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Password Spray
    "T1201":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",  # Password Policy Discovery
    # Privilege Escalation
    "T1548.001": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # SUID / Setuid
    "T1548.003": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",  # Sudo
    "T1053.003": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # Cron
    "T1574.006": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # PATH Hijacking
    # Cloud
    "T1530":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # S3 Public Bucket
    "T1078.004": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Valid Cloud Accounts
    "T1552.004": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # Credentials in Files (keys)
    "T1552.005": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # IMDS credential theft
    "T1046":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # Network Service Scan
    # Discovery
    "T1087.002": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",  # Domain Account Discovery
    "T1018":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",  # Remote System Discovery
    # ACL / Defense Evasion
    "T1222.001": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",  # WriteDACL / GenericAll
}


def get_cvss_for_finding(
    mitre_technique: str | None,
    severity: str,
    custom_vector: str | None = None,
) -> tuple[float, str]:
    """
    Compute CVSS score and vector for a finding.

    Priority:
        1. custom_vector if provided
        2. TECHNIQUE_CVSS_VECTORS lookup by MITRE technique
        3. Severity-based default vector

    Returns: (base_score, vector_string)
    """
    if custom_vector:
        try:
            return compute_base_score(custom_vector), custom_vector
        except ValueError:
            pass

    if mitre_technique and mitre_technique in TECHNIQUE_CVSS_VECTORS:
        vec = TECHNIQUE_CVSS_VECTORS[mitre_technique]
        return compute_base_score(vec), vec

    # Generate a plausible default vector from severity
    return _severity_default_vector(severity)


def _severity_default_vector(severity: str) -> tuple[float, str]:
    """Generate a conservative default CVSS vector from severity label."""
    defaults = {
        "critical": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        "high":     ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
        "medium":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
        "low":      ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
        "info":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    }
    vec, score = defaults.get(severity.lower(), defaults["info"])
    return score, vec


# ── Finding enrichment ────────────────────────────────────────────────────────

def enrich_finding_with_cvss(finding: Any) -> Any:
    """
    Add cvss_score and cvss_vector to a Finding object in-place.
    Safe to call even if finding already has CVSS data.
    """
    existing_score  = getattr(finding, "cvss_score",  0.0) or 0.0
    existing_vector = getattr(finding, "cvss_vector", "") or ""

    if existing_score > 0 and existing_vector:
        return finding  # Already has CVSS

    severity   = getattr(finding, "severity", None)
    sev_value  = severity.value if hasattr(severity, "value") else str(severity)
    technique  = getattr(finding, "mitre_technique", None)
    custom_vec = getattr(finding, "cvss_vector", None)

    score, vector = get_cvss_for_finding(technique, sev_value, custom_vec)
    finding.cvss_score  = score
    finding.cvss_vector = vector
    return finding


# ── CVSS summary for reports ──────────────────────────────────────────────────

@dataclass
class CVSSSummary:
    """Aggregated CVSS statistics for a campaign's findings."""
    total_findings:   int   = 0
    critical_count:   int   = 0
    high_count:       int   = 0
    medium_count:     int   = 0
    low_count:        int   = 0
    info_count:       int   = 0
    max_score:        float = 0.0
    avg_score:        float = 0.0
    scores:           list[float] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[Any]) -> "CVSSSummary":
        s = cls()
        s.total_findings = len(findings)
        for f in findings:
            score = getattr(f, "cvss_score", 0.0) or 0.0
            sev   = score_to_severity(score)
            s.scores.append(score)
            if sev == "critical": s.critical_count += 1
            elif sev == "high":   s.high_count    += 1
            elif sev == "medium": s.medium_count  += 1
            elif sev == "low":    s.low_count     += 1
            else:                 s.info_count    += 1
        if s.scores:
            s.max_score = max(s.scores)
            s.avg_score = round(sum(s.scores) / len(s.scores), 1)
        return s

    def risk_rating(self) -> str:
        """Overall campaign risk rating based on CVSS distribution."""
        if self.critical_count > 0:
            return "CRITICAL"
        if self.high_count > 2:
            return "HIGH"
        if self.high_count > 0 or self.medium_count > 3:
            return "MEDIUM"
        if self.medium_count > 0 or self.low_count > 0:
            return "LOW"
        return "INFORMATIONAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total":       self.total_findings,
            "critical":    self.critical_count,
            "high":        self.high_count,
            "medium":      self.medium_count,
            "low":         self.low_count,
            "info":        self.info_count,
            "max_score":   self.max_score,
            "avg_score":   self.avg_score,
            "risk_rating": self.risk_rating(),
        }


# ── Compliance Framework Mapping ──────────────────────────────────────────────
# Maps MITRE ATT&CK techniques to compliance framework controls.
# Used by report generator to auto-tag findings with relevant standards.

COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Credential Access ─────────────────────────────────────────────────────
    "T1558.003": {  # Kerberoasting
        "PCI-DSS":   ["8.2.3 (Strong Authentication)", "8.3.6 (Password Complexity)"],
        "ISO27001":  ["A.9.2.4 (Management of Secret Authentication)",
                      "A.9.4.3 (Password Management System)"],
        "NIST-CSF":  ["PR.AC-1 (Identities and Credentials)"],
        "CIS":       ["CIS 5.2 (Use Unique Passwords)"],
        "MITRE-D3FEND": ["D3-SPP (Strong Password Policy)"],
    },
    "T1558.004": {  # ASREPRoasting
        "PCI-DSS":   ["8.2.3 (Strong Authentication)"],
        "ISO27001":  ["A.9.2.4 (Secret Authentication Management)"],
        "NIST-CSF":  ["PR.AC-1 (Identities and Credentials)"],
        "CIS":       ["CIS 5.2 (Use Unique Passwords)"],
    },
    "T1003.006": {  # DCSync
        "PCI-DSS":   ["7.1 (Limit Access)", "8.1.4 (Inactive Accounts)",
                      "10.2.2 (Root/Admin Actions)"],
        "ISO27001":  ["A.9.2.3 (Privileged Access Rights)",
                      "A.12.4.3 (Administrator Logs)"],
        "NIST-CSF":  ["PR.AC-4 (Access Permissions)", "DE.CM-3 (Personnel Monitoring)"],
        "CIS":       ["CIS 4.3 (Controlled Admin Privileges)", "CIS 6.2 (Audit Log Management)"],
    },
    "T1110.003": {  # Password Spray
        "PCI-DSS":   ["8.1.6 (Account Lockout)", "8.2.3 (Strong Authentication)"],
        "ISO27001":  ["A.9.4.2 (Secure Log-on Procedures)"],
        "NIST-CSF":  ["PR.AC-7 (Authentication)"],
        "CIS":       ["CIS 4.4 (Account Lockout)", "CIS 5.2 (Unique Passwords)"],
    },
    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021.002": {  # SMB/Windows Admin Shares
        "PCI-DSS":   ["1.3.4 (Network Segmentation)", "7.1 (Limit Access)"],
        "ISO27001":  ["A.13.1.3 (Segregation in Networks)"],
        "NIST-CSF":  ["PR.AC-5 (Network Integrity)", "PR.PT-4 (Communications Protection)"],
        "CIS":       ["CIS 9.2 (Limit Open Ports)", "CIS 14.6 (Network Segmentation)"],
    },
    "T1569.002": {  # PsExec Service Execution
        "PCI-DSS":   ["1.3.4 (Network Segmentation)", "10.2.7 (Object Access)"],
        "ISO27001":  ["A.12.5.1 (Installation of Software)"],
        "NIST-CSF":  ["DE.CM-5 (Unauthorized Software Detection)"],
        "CIS":       ["CIS 2.7 (Application Whitelisting)"],
    },
    "T1557.001": {  # NTLM Relay / LLMNR Poisoning
        "PCI-DSS":   ["2.2.2 (Secure System Configuration)", "4.1 (Encryption in Transit)"],
        "ISO27001":  ["A.13.1.1 (Network Controls)", "A.10.1.1 (Cryptographic Controls)"],
        "NIST-CSF":  ["PR.DS-2 (Data-in-Transit Protection)"],
        "CIS":       ["CIS 9.4 (Disable Unnecessary Protocols)"],
    },
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1548.001": {  # SUID/Setuid
        "PCI-DSS":   ["2.2.4 (System Security Parameters)"],
        "ISO27001":  ["A.12.6.1 (Technical Vulnerability Management)"],
        "NIST-CSF":  ["PR.IP-12 (Vulnerability Management)"],
        "CIS":       ["CIS 3.3 (File System Permissions)"],
    },
    "T1548.003": {  # Sudo Abuse
        "PCI-DSS":   ["7.1 (Limit Access)", "7.2 (Access Control Systems)"],
        "ISO27001":  ["A.9.2.3 (Privileged Access Rights)"],
        "NIST-CSF":  ["PR.AC-4 (Access Permissions)"],
        "CIS":       ["CIS 4.3 (Controlled Admin Privileges)"],
    },
    # ── Cloud ─────────────────────────────────────────────────────────────────
    "T1530": {  # S3 Data from Cloud Storage
        "PCI-DSS":   ["3.4 (Render PAN Unreadable)", "7.1 (Limit Access)"],
        "ISO27001":  ["A.8.2.3 (Handling of Assets)", "A.13.2.1 (Information Transfer)"],
        "NIST-CSF":  ["PR.DS-1 (Data-at-Rest Protection)"],
        "CIS":       ["CIS 14.2 (Sensitive Data Encryption)"],
    },
    "T1078.004": {  # Valid Cloud Accounts
        "PCI-DSS":   ["8.1 (Unique User IDs)", "8.3 (MFA)"],
        "ISO27001":  ["A.9.2.1 (User Registration)", "A.9.2.5 (Review of Access Rights)"],
        "NIST-CSF":  ["PR.AC-1 (Identities and Credentials)", "PR.AC-7 (Authentication)"],
        "CIS":       ["CIS 4.5 (MFA for Admin)", "CIS 16.3 (Require MFA)"],
    },
    "T1606.002": {  # SAML Token Forgery / Golden SAML
        "PCI-DSS":   ["3.5 (Protect Cryptographic Keys)", "8.3 (MFA)"],
        "ISO27001":  ["A.10.1.2 (Key Management)", "A.9.4.2 (Secure Log-on)"],
        "NIST-CSF":  ["PR.DS-1 (Data-at-Rest)", "PR.AC-7 (Authentication)"],
        "CIS":       ["CIS 4.5 (MFA for Admin)", "CIS 14.4 (Encrypt All Sensitive Data)"],
    },
    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1562.001": {  # Disable/Modify Tools (EDR bypass)
        "PCI-DSS":   ["5.1 (Anti-malware)", "5.2 (Anti-malware Current)"],
        "ISO27001":  ["A.12.2.1 (Malware Controls)"],
        "NIST-CSF":  ["DE.CM-4 (Malicious Code Detection)"],
        "CIS":       ["CIS 8.1 (Anti-malware Software)"],
    },
    # ── Persistence ───────────────────────────────────────────────────────────
    "T1053.005": {  # Scheduled Task/Job
        "PCI-DSS":   ["10.2.7 (Object Access Attempts)", "2.2.4 (Security Parameters)"],
        "ISO27001":  ["A.12.1.2 (Change Management)"],
        "NIST-CSF":  ["DE.CM-5 (Unauthorized Software)"],
        "CIS":       ["CIS 2.7 (Application Whitelisting)", "CIS 8.5 (Audit Configuration)"],
    },
    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1046": {  # Network Service Scanning
        "PCI-DSS":   ["11.2 (Vulnerability Scans)", "1.1.6 (Insecure Services)"],
        "ISO27001":  ["A.12.6.1 (Technical Vulnerability Management)"],
        "NIST-CSF":  ["DE.CM-8 (Vulnerability Scans)"],
        "CIS":       ["CIS 9.2 (Limit Open Ports)"],
    },
    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1039": {  # Data from Network Shared Drive
        "PCI-DSS":   ["3.4 (Render PAN Unreadable)", "7.1 (Limit Access)"],
        "ISO27001":  ["A.8.2.3 (Handling of Assets)", "A.13.2.1 (Information Transfer)"],
        "NIST-CSF":  ["PR.DS-5 (Data Leak Protection)"],
        "CIS":       ["CIS 13.1 (Sensitive Data Inventory)", "CIS 14.6 (Network Segmentation)"],
    },
    # ── ACL Abuse ─────────────────────────────────────────────────────────────
    "T1222.001": {  # WriteDACL / GenericAll
        "PCI-DSS":   ["7.1 (Limit Access)", "7.2 (Access Control Systems)"],
        "ISO27001":  ["A.9.1.2 (Access to Networks)", "A.9.2.3 (Privileged Access)"],
        "NIST-CSF":  ["PR.AC-4 (Access Permissions)"],
        "CIS":       ["CIS 4.3 (Controlled Admin Privileges)"],
    },
    # ── ADCS ──────────────────────────────────────────────────────────────────
    "T1649": {  # Steal/Forge Auth Certificates
        "PCI-DSS":   ["3.5 (Protect Cryptographic Keys)", "8.3 (MFA)"],
        "ISO27001":  ["A.10.1.2 (Key Management)"],
        "NIST-CSF":  ["PR.DS-1 (Data-at-Rest Protection)"],
        "CIS":       ["CIS 14.4 (Encrypt All Sensitive Data)"],
    },
}


def get_compliance_for_technique(technique_id: str) -> dict[str, list[str]]:
    """Return compliance framework mappings for a MITRE technique."""
    return COMPLIANCE_MAP.get(technique_id, {})


def get_compliance_for_finding(finding: Any) -> dict[str, list[str]]:
    """Return compliance mappings for a Finding object."""
    technique = getattr(finding, "mitre_technique", None)
    if technique:
        return get_compliance_for_technique(technique)
    return {}


def enrich_finding_with_compliance(finding: Any) -> Any:
    """Add compliance_map field to a Finding's evidence dict."""
    mapping = get_compliance_for_finding(finding)
    if mapping:
        evidence = getattr(finding, "evidence", {})
        if isinstance(evidence, dict):
            evidence["compliance_mapping"] = mapping
    return finding
