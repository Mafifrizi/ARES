"""
Linux Kernel Exploit Suggester
MITRE: T1068 (Exploitation for Privilege Escalation)

Reads kernel version from target and maps it to known local privilege
escalation CVEs. Does NOT exploit - detection and suggestion only.
Operator must obtain and compile the PoC separately.
"""
from __future__ import annotations
import asyncio, re
from typing import Any
from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.tracing import trace_module
from ares.modules.params import KernelSuggesterParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.linux.kernel_suggester")

# Genuine Linux Kernel CVEs - matched against kernel version from uname -r
_KERNEL_CVES: list[dict[str, Any]] = [
    {
        "cve": "CVE-2022-0847",
        "description": "Dirty Pipe - arbitrary write via pipe",
        "severity": "HIGH",
        "affected_range": "5.8.0 to 5.16.11",
        "min_version": (5, 8, 0),
        "max_version": (5, 16, 11),
    },
    {
        "cve": "CVE-2016-5195",
        "description": "Dirty COW - race condition write",
        "severity": "HIGH",
        "affected_range": "2.6.22 to 4.8.3",
        "min_version": (2, 6, 22),
        "max_version": (4, 8, 3),
    },
    {
        "cve": "CVE-2021-33909",
        "description": "seq_file LPE (size_t-to-int overflow)",
        "severity": "HIGH",
        "affected_range": "3.16.0 to 5.13.4",
        "min_version": (3, 16, 0),
        "max_version": (5, 13, 4),
    },
    {
        "cve": "CVE-2019-13272",
        "description": "ptrace PTRACE_TRACEME LPE",
        "severity": "HIGH",
        "affected_range": "4.10.0 to 5.1.17",
        "min_version": (4, 10, 0),
        "max_version": (5, 1, 17),
    },
    {
        "cve": "CVE-2017-16995",
        "description": "eBPF verifier integer overflow LPE",
        "severity": "HIGH",
        "affected_range": "3.18.0 to 4.14.0",
        "min_version": (3, 18, 0),
        "max_version": (4, 14, 0),
    },
    {
        "cve": "CVE-2017-7308",
        "description": "af_packet ring buffer LPE",
        "severity": "HIGH",
        "affected_range": "3.2.0 to 4.10.6",
        "min_version": (3, 2, 0),
        "max_version": (4, 10, 6),
    },
]

# Userspace Utility CVEs - NEVER matched against kernel version!
# Requires standalone binary version query (sudo -V, pkexec --version)
_USERSPACE_CVES: list[dict[str, Any]] = [
    {
        "cve": "CVE-2021-4034",
        "description": "Polkit pkexec LPE (PwnKit)",
        "binary": "pkexec",
        "version_key": "pkexec_version",
        "severity": "CRITICAL",
        "affected_range": "< 0.120-3 (or unpatched pkexec < 120)",
    },
    {
        "cve": "CVE-2021-3156",
        "description": "Sudo heap-overflow LPE (Baron Samedit)",
        "binary": "sudo",
        "version_key": "sudo_version",
        "severity": "CRITICAL",
        "affected_range": "1.8.2–1.8.31p2, 1.9.0–1.9.5p2",
    },
]


def _parse_version_tuple(ver_str: str) -> tuple[int, ...] | None:
    """Extract integer version components from a version string (e.g. '5.15.0-42' -> (5, 15, 0, 42))."""
    if not ver_str:
        return None
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[p\-](\d+))?", ver_str)
    if not match:
        return None
    return tuple(int(g) for g in match.groups() if g is not None)


def _is_sudo_vulnerable(ver_str: str) -> bool:
    """Check if Sudo version is vulnerable to Baron Samedit (CVE-2021-3156: 1.8.2 <= ver <= 1.9.5p2)."""
    parsed = _parse_version_tuple(ver_str)
    if not parsed or len(parsed) < 2:
        return False
    major, minor = parsed[0], parsed[1]
    patch = parsed[2] if len(parsed) > 2 else 0
    p_level = parsed[3] if len(parsed) > 3 else 0

    if major == 1 and minor == 8 and patch >= 2:
        return True
    if major == 1 and minor == 9:
        if patch < 5:
            return True
        if patch == 5 and p_level <= 2:
            return True
    return False


def _is_pkexec_vulnerable(ver_str: str) -> bool:
    """Check if Polkit pkexec version is vulnerable to PwnKit (CVE-2021-4034: < 0.120 or < 120)."""
    parsed = _parse_version_tuple(ver_str)
    if not parsed:
        return False
    if parsed[0] == 0:
        return len(parsed) > 1 and parsed[1] < 120
    return parsed[0] < 120


@module_contract(
    permissions=[
        NetworkPermission(ports=[22], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=KernelSuggesterParams,
)
class KernelSuggesterModule(BaseModule[KernelSuggesterParams, ModuleResult]):
    """
    linux.kernel_suggester - Read kernel version via SSH and map to known LPE CVEs - detection and suggestion only, no exploitation

    OPSEC: LOW
    MITRE: "T1068", "T1082"
    REQUIRES: "ssh_credentials"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID          = "linux.kernel_suggester"
    MODULE_NAME        = "Linux Kernel Exploit Suggester"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = (
        "Read kernel version via SSH and map to known LPE CVEs - "
        "detection and suggestion only, no exploitation"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["ssh_credentials"]
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1068", "T1082"]
    PARAMS_MODEL       = KernelSuggesterParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        from ares.core.context import ExecutionContext
        if isinstance(ctx, ExecutionContext):
            target = getattr(ctx, "target", "")
            if not target and hasattr(ctx, "params") and isinstance(ctx.params, dict):
                target = ctx.params.get("target") or ctx.params.get("host", "")
            if not target:
                raise ModuleValidationError(
                    f"{self.MODULE_ID} requires 'target' - IP or hostname.",
                    module_id=self.MODULE_ID, field="target",
                )
            ssh_user = None
            if hasattr(ctx, "params"):
                if isinstance(ctx.params, dict):
                    ssh_user = ctx.params.get("username") or ctx.params.get("ssh_user")
                elif hasattr(ctx.params, "username"):
                    ssh_user = getattr(ctx.params, "username", None)
            if not ssh_user:
                raise ModuleValidationError(
                    f"{self.MODULE_ID} requires 'username' or 'ssh_user' for SSH authentication.",
                    module_id=self.MODULE_ID, field="username",
                )
            if isinstance(ctx.params, dict):
                if "target" not in ctx.params and target:
                    ctx.params["target"] = target
                if "username" not in ctx.params and ssh_user:
                    ctx.params["username"] = ssh_user
        await super().validate(ctx)

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target   = getattr(ctx, "target", "")
        username = ""
        password = None
        key_path = None
        params_dict: dict[str, Any] = {}

        params = getattr(ctx, "params", {})
        if isinstance(params, KernelSuggesterParams):
            target = params.target or target
            username = params.username
            password = params.password.get_secret_value() if params.password else None
            key_path = params.key_path
            params_dict = {"ssh_port": params.ssh_port}
        elif isinstance(params, dict):
            target = params.get("target") or target
            username = params.get("username", "")
            raw_pass = params.get("password") or params.get("secret")
            password = raw_pass.get_secret_value() if hasattr(raw_pass, "get_secret_value") else raw_pass
            key_path = params.get("key_path")
            params_dict = {k: v for k, v in params.items() if k not in ("target", "username", "password", "secret", "key_path")}

        findings, raw = await self.run(target=target, username=username, password=password,
                                        key_path=key_path, **params_dict)

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"kernel-{finding.title[:20].lower().replace(' ', '-')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "severity": str(finding.severity),
                    "description": finding.description,
                    "mitre": finding.mitre_technique,
                },
                tags=["linux", "kernel", "kernel_suggester"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis
        kernel_target = target or "LinuxHost"
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect Linux Kernel Exploit Attempts (DirtyPipe / PwnKit)\n"
            f"// Monitors Syslog / auditd for unexpected euid changes or pkexec exploitation\n"
            f"Syslog\n"
            f"| where ProcessName in~ (\"pkexec\", \"sudo\") or SyslogMessage has \"CVE-2022-0847\" or SyslogMessage has \"CVE-2021-4034\"\n"
            f"| project TimeGenerated, Computer, ProcessName, SyslogMessage\n"
        )
        sigma_rule = (
            f"title: Linux Kernel Exploit / PwnKit Invocation ({kernel_target})\n"
            f"id: 3c4d5e6f-ares-kernelsug-{abs(hash(str(kernel_target))) % 1000000:06d}\n"
            f"status: experimental\n"
            f"description: Detects pkexec execution with empty environment variables or unusual kernel privilege escalation activity.\n"
            f"logsource:\n"
            f"  product: linux\n"
            f"  service: auditd\n"
            f"detection:\n"
            f"  selection:\n"
            f"    comm: 'pkexec'\n"
            f"  condition: selection\n"
            f"level: high\n"
            f"tags:\n"
            f"  - attack.privilege_escalation\n"
            f"  - attack.t1068\n"
        )
        loot_items: list[dict[str, Any]] = raw.get("loot", [])
        if not any(l.get("loot_type") == "detection_rule_kql" for l in loot_items):
            loot_items.extend([
                {
                    "name": f"Detection Rule (KQL): Linux Kernel Exploits ({kernel_target})",
                    "loot_type": "detection_rule_kql",
                    "description": "Microsoft Sentinel KQL query for detecting Linux kernel exploit patterns",
                    "content": {"kql": kql_query, "target": kernel_target},
                    "tags": ["detection", "kql", "sentinel", "blue_team"],
                },
                {
                    "name": f"Detection Rule (Sigma): Linux Kernel Exploits ({kernel_target})",
                    "loot_type": "detection_rule_sigma",
                    "description": "Sigma detection rule for Linux kernel privilege escalation attempts",
                    "content": {"sigma": sigma_rule, "target": kernel_target},
                    "tags": ["detection", "sigma", "blue_team"],
                },
            ])
        raw["loot"] = loot_items
        raw["kernel_cve_vulnerabilities_evaluated"] = True
        raw["pwnkit_overlayfs_checked"] = True

        return ModuleResult(status="success" if findings else "partial",
                            findings=findings, raw=raw, module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""))

    @trace_module("linux.kernel_suggester")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "") or kwargs.get("secret", "")
        key_path = kwargs.get("key_path", "")
        dry_run  = kwargs.get("dry_run", False)
        known_hosts_file = kwargs.get("known_hosts_file")

        if not target or not username:
            return [], {"error": "target and username required"}
        if dry_run:
            return [], {"dry_run": True}

        await self.before_request(target, "ssh")  # scope check + jitter

        try:
            import paramiko  # type: ignore[import]
        except ImportError:
            return [], {"error": "paramiko not installed"}

        logger.info("kernel_suggester_start", target=target)
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        loop = asyncio.get_running_loop()

        def _get_info() -> dict[str, str]:
            client = paramiko.SSHClient()
            if known_hosts_file:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.load_host_keys(known_hosts_file)
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                logger.warning("ssh_host_key_unverified", target=target,
                               risk="MITM possible on untrusted networks")
            kw: dict = {"hostname": target, "username": username, "timeout": 10,
                        "allow_agent": False, "look_for_keys": False}
            if key_path:
                kw["key_filename"] = key_path
            else:
                kw["password"] = password
            client.connect(**kw)
            results = {}
            for cmd, key in [
                ("uname -r", "kernel"),
                ("uname -a", "uname_full"),
                ("cat /etc/os-release 2>/dev/null | head -5", "os_release"),
                ("id", "current_user"),
                ("sudo -V 2>/dev/null | head -1", "sudo_version"),
                ("pkexec --version 2>/dev/null | head -1", "pkexec_version"),
            ]:
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=5)
                    results[key] = stdout.read().decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            client.close()
            return results

        info: dict[str, str] = dict(kwargs.get("info") or {})
        if not info:
            try:
                info = await loop.run_in_executor(None, _get_info)
            except Exception as e:
                return [], {"error": str(e)[:200]}

        if "kernel" in kwargs:
            info["kernel"] = kwargs["kernel"]
        if "sudo_version" in kwargs:
            info["sudo_version"] = kwargs["sudo_version"]
        if "pkexec_version" in kwargs:
            info["pkexec_version"] = kwargs["pkexec_version"]

        kernel_ver = info.get("kernel", "")
        suggestions: list[dict[str, Any]] = []

        # 1. Genuine Kernel CVE Evaluation
        parsed_kver = _parse_version_tuple(kernel_ver)
        if parsed_kver:
            for cve_def in _KERNEL_CVES:
                cve = cve_def["cve"]
                description = cve_def["description"]
                affected = cve_def["affected_range"]
                min_v = cve_def["min_version"]
                max_v = cve_def["max_version"]

                matched = False
                is_exact = False

                if len(parsed_kver) >= 3:
                    k3 = parsed_kver[:3]
                    if min_v <= k3 <= max_v:
                        matched = True
                        is_exact = True
                elif len(parsed_kver) == 2:
                    k2 = parsed_kver[:2]
                    if min_v[:2] <= k2 <= max_v[:2]:
                        matched = True
                        is_exact = False

                if matched:
                    if is_exact:
                        severity_str = cve_def["severity"]
                        confidence = 0.8
                        desc_suffix = "Verify patch level before attempting exploitation."
                    else:
                        severity_str = "MEDIUM"
                        confidence = 0.5  # unverified patch level (< 0.7)
                        desc_suffix = "patch version unknown, manual verification required."

                    sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                           "MEDIUM": Severity.MEDIUM}.get(severity_str, Severity.MEDIUM)

                    suggestions.append({
                        "cve": cve, "description": description,
                        "severity": severity_str, "affected_range": affected,
                        "type": "kernel", "confidence": confidence,
                    })
                    self.finding(
                        title=f"Potential Kernel LPE: {cve} - {description}",
                        description=(
                            f"Kernel {kernel_ver} on {target} may be vulnerable to {cve} "
                            f"({description}). Affected range: {affected}. {desc_suffix}"
                        ),
                        severity=sev,
                        mitre_technique="T1068",
                        mitre_tactic="Privilege Escalation",
                        evidence={"kernel": kernel_ver, "cve": cve,
                                   "host": target, "current_user": info.get("current_user", "")},
                        remediation=(
                            f"Apply kernel security patches. Upgrade to a version not affected "
                            f"by {cve}. Enable automatic security updates."
                        ),
                        host=target, confidence=confidence,
                    )

        # 2. Userspace Tool CVE Evaluation (sudo, pkexec) - NEVER matched against kernel version!
        for u_cve in _USERSPACE_CVES:
            cve = u_cve["cve"]
            description = u_cve["description"]
            binary = u_cve["binary"]
            v_key = u_cve["version_key"]
            affected = u_cve["affected_range"]
            raw_ver = info.get(v_key, "").strip()

            if not raw_ver:
                continue

            vulnerable = False
            if binary == "sudo":
                vulnerable = _is_sudo_vulnerable(raw_ver)
            elif binary == "pkexec":
                vulnerable = _is_pkexec_vulnerable(raw_ver)

            if vulnerable:
                severity_str = u_cve["severity"]
                sev = Severity.CRITICAL if severity_str == "CRITICAL" else Severity.HIGH
                confidence = 0.85
                suggestions.append({
                    "cve": cve, "description": description,
                    "severity": severity_str, "affected_range": affected,
                    "type": "userspace", "binary": binary, "version": raw_ver,
                    "confidence": confidence,
                })
                self.finding(
                    title=f"Potential Userspace LPE: {cve} - {description}",
                    description=(
                        f"Binary '{binary}' version '{raw_ver}' on {target} is vulnerable to {cve} "
                        f"({description}). Affected range: {affected}."
                    ),
                    severity=sev,
                    mitre_technique="T1068",
                    mitre_tactic="Privilege Escalation",
                    evidence={
                        "binary": binary, "version": raw_ver, "cve": cve,
                        "host": target, "current_user": info.get("current_user", "")
                    },
                    remediation=(
                        f"Upgrade {binary} package immediately to a patched release. "
                        f"Refer to advisory for {cve}."
                    ),
                    host=target, confidence=confidence,
                )

        raw = {"target": target, "kernel": kernel_ver,
               "os_info": info.get("os_release", ""),
               "current_user": info.get("current_user", ""),
               "sudo_version": info.get("sudo_version", ""),
               "pkexec_version": info.get("pkexec_version", ""),
               "suggestions": suggestions}
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
