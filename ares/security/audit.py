"""
ARES Dependency Security Auditor
Scans installed packages for known CVEs using pip-audit.
Results exposed via:
  - CLI: ares security audit
  - API: GET /security/audit  (team_lead only)
  - Scheduled: runs on engine startup (warn-only by default)

pip-audit queries the OSV (Open Source Vulnerabilities) database
and PyPI Advisory Database — no external API key needed.

Usage:
    from ares.security.audit import run_dependency_audit, AuditPolicy

    result = await run_dependency_audit()
    if result["critical_count"] > 0:
        logger.critical("CRITICAL CVEs in dependencies!")

Startup check (engine integration):
    from ares.security.audit import startup_audit
    await startup_audit(policy=AuditPolicy.WARN)  # or BLOCK_CRITICAL

Policy:
    WARN            — log vulnerabilities, continue startup
    BLOCK_CRITICAL  — abort startup if any CRITICAL CVEs found
    BLOCK_ANY       — abort startup if any CVEs found
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.security.audit")


class AuditPolicy(str, Enum):
    WARN           = "warn"
    BLOCK_CRITICAL = "block_critical"
    BLOCK_ANY      = "block_any"


class CVSSScore(str, Enum):
    CRITICAL = "critical"    # CVSS >= 9.0
    HIGH     = "high"        # CVSS >= 7.0
    MEDIUM   = "medium"      # CVSS >= 4.0
    LOW      = "low"         # CVSS < 4.0
    UNKNOWN  = "unknown"


@dataclass
class Vulnerability:
    """A known vulnerability in an installed package."""
    package:     str
    version:     str
    vuln_id:     str         # CVE-YYYY-NNNN or GHSA-...
    description: str
    severity:    CVSSScore
    fix_version: str = ""    # recommended upgrade version
    aliases:     list[str] = field(default_factory=list)
    source:      str = "osv"  # osv | pypi


@dataclass
class AuditResult:
    """Complete result of a dependency audit scan."""
    scanned_packages: int           = 0
    vulnerabilities:  list[Vulnerability] = field(default_factory=list)
    scan_duration_s:  float         = 0.0
    scanner:          str           = "pip-audit"
    scanner_version:  str           = ""
    scan_timestamp:   float         = field(default_factory=time.time)
    error:            str           = ""
    tool_available:   bool          = True

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == CVSSScore.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == CVSSScore.HIGH)

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def clean(self) -> bool:
        return len(self.vulnerabilities) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_packages": self.scanned_packages,
            "total_count":      self.total_count,
            "critical_count":   self.critical_count,
            "high_count":       self.high_count,
            "clean":            self.clean,
            "scanner":          self.scanner,
            "scanner_version":  self.scanner_version,
            "scan_timestamp":   self.scan_timestamp,
            "scan_duration_s":  round(self.scan_duration_s, 2),
            "tool_available":   self.tool_available,
            "error":            self.error,
            "vulnerabilities":  [
                {
                    "package":     v.package,
                    "version":     v.version,
                    "vuln_id":     v.vuln_id,
                    "description": v.description[:200],
                    "severity":    v.severity.value,
                    "fix_version": v.fix_version,
                    "aliases":     v.aliases,
                }
                for v in self.vulnerabilities
            ],
        }

    def summary(self) -> str:
        if not self.tool_available:
            return "pip-audit not installed. Run: pip install pip-audit"
        if self.error:
            return f"Audit failed: {self.error}"
        if self.clean:
            return f"✓ Clean — {self.scanned_packages} packages, 0 vulnerabilities"
        return (
            f"⚠ {self.total_count} vulnerabilities "
            f"({self.critical_count} critical, {self.high_count} high) "
            f"in {self.scanned_packages} packages"
        )


def _parse_pip_audit_output(raw: dict[str, Any]) -> AuditResult:
    """Parse pip-audit JSON output into AuditResult."""
    result = AuditResult()
    dependencies = raw.get("dependencies", [])
    result.scanned_packages = len(dependencies)

    for dep in dependencies:
        pkg     = dep.get("name", "")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            sev = _cvss_to_severity(vuln.get("fix_versions", []),
                                     vuln.get("id", ""),
                                     aliases=vuln.get("aliases", []))
            result.vulnerabilities.append(Vulnerability(
                package     = pkg,
                version     = version,
                vuln_id     = vuln.get("id", ""),
                description = vuln.get("description", "")[:500],
                severity    = sev,
                fix_version = (vuln.get("fix_versions") or [""])[0],
                aliases     = vuln.get("aliases", []),
            ))

    return result


def _cvss_to_severity(fix_versions: list[str], vuln_id: str,
                       aliases: list | None = None) -> CVSSScore:
    """
    Determine severity from CVSS score in pip-audit output.

    pip-audit includes CVSS scores in the aliases list as dicts:
      {"type": "cvss", "score": 9.8, "vector": "..."}
    or as part of advisory metadata.

    Falls back to vuln_id-prefix heuristic only if no score found.
    """
    # 1. Try to extract CVSS score from aliases (pip-audit >= 2.6 format)
    if aliases:
        max_score = 0.0
        for alias in aliases:
            if isinstance(alias, dict):
                score = alias.get("cvss_score") or alias.get("score") or 0.0
                try:
                    max_score = max(max_score, float(score))
                except (TypeError, ValueError):
                    pass
        if max_score > 0:
            if max_score >= 9.0:  return CVSSScore.CRITICAL
            if max_score >= 7.0:  return CVSSScore.HIGH
            if max_score >= 4.0:  return CVSSScore.MEDIUM
            return CVSSScore.LOW

    # 2. Heuristic fallback based on vuln_id prefix
    vuln_lower = vuln_id.lower()
    if "ghsa" in vuln_lower or "cve" in vuln_lower:
        return CVSSScore.HIGH   # conservative — HIGH until score confirmed
    return CVSSScore.UNKNOWN


async def run_dependency_audit(
    packages: list[str] | None = None,
    timeout_s: int = 120,
) -> dict[str, Any]:
    """
    Run pip-audit and return vulnerability report as dict.
    Suitable for direct return from FastAPI endpoint.

    Args:
        packages:  Optional list of specific packages to audit.
                   If None, scans all installed packages.
        timeout_s: Max seconds to wait for pip-audit (default 120).

    Returns:
        AuditResult.to_dict()
    """
    result = await _run_pip_audit(packages=packages, timeout_s=timeout_s)
    _log_result(result)
    return result.to_dict()


async def _run_pip_audit(
    packages:  list[str] | None = None,
    timeout_s: int = 120,
) -> AuditResult:
    """Internal: run pip-audit subprocess and parse output."""
    t0 = time.monotonic()

    # Check if pip-audit is available
    if not shutil.which("pip-audit"):
        logger.warning("pip-audit not installed — dependency audit unavailable")
        return AuditResult(
            tool_available = False,
            error          = "pip-audit not installed. Install: pip install pip-audit",
        )

    # Build command
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"]
    if packages:
        for pkg in packages:
            cmd.extend(["--package", pkg])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
    except asyncio.TimeoutError:
        logger.error("pip-audit timed out after %ds", timeout_s)
        return AuditResult(
            error          = f"pip-audit timed out after {timeout_s}s",
            scan_duration_s = timeout_s,
        )
    except Exception as exc:
        return AuditResult(error=f"Failed to run pip-audit: {exc}")

    duration = time.monotonic() - t0

    # pip-audit exits 1 when vulnerabilities found — parse output regardless
    try:
        raw_json = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return AuditResult(
            error = f"Failed to parse pip-audit output: {stderr.decode()[:300]}",
            scan_duration_s = duration,
        )

    result = _parse_pip_audit_output(raw_json)
    result.scan_duration_s = round(duration, 2)
    return result


def _log_result(result: AuditResult) -> None:
    """Log audit results at appropriate severity."""
    if not result.tool_available:
        logger.warning("dependency_audit_unavailable", reason=result.error)
        return
    if result.error:
        logger.error("dependency_audit_failed", error=result.error)
        return

    level = "info"
    if result.critical_count > 0:
        level = "critical"
    elif result.high_count > 0:
        level = "warning"

    log_fn = getattr(logger, level, logger.info)
    log_fn(
        "dependency_audit_complete",
        scanned=result.scanned_packages,
        total_vulns=result.total_count,
        critical=result.critical_count,
        high=result.high_count,
        duration_s=result.scan_duration_s,
    )
    for v in result.vulnerabilities:
        logger.warning(
            "vulnerable_dependency",
            package=v.package,
            version=v.version,
            vuln_id=v.vuln_id,
            severity=v.severity.value,
            fix_version=v.fix_version,
        )


async def startup_audit(
    policy: AuditPolicy = AuditPolicy.WARN,
) -> None:
    """
    Run audit at engine startup. Behavior controlled by policy:
      WARN           — log vulnerabilities, continue
      BLOCK_CRITICAL — raise if critical CVEs found
      BLOCK_ANY      — raise if any CVEs found
    """
    logger.info("Running startup dependency audit...")
    result = await _run_pip_audit()
    _log_result(result)

    if policy == AuditPolicy.BLOCK_CRITICAL and result.critical_count > 0:
        raise RuntimeError(
            f"Startup blocked: {result.critical_count} CRITICAL CVEs in dependencies. "
            f"Run 'ares security audit' for details."
        )
    if policy == AuditPolicy.BLOCK_ANY and result.total_count > 0:
        raise RuntimeError(
            f"Startup blocked: {result.total_count} CVEs in dependencies. "
            f"Run 'ares security audit' for details."
        )
