"""
Linux Kernel Exploit Suggester
MITRE: T1068 (Exploitation for Privilege Escalation)

Reads kernel version from target and maps it to known local privilege
escalation CVEs. Does NOT exploit — detection and suggestion only.
Operator must obtain and compile the PoC separately.
"""
from __future__ import annotations
import asyncio, re
from typing import Any
from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.linux.kernel_suggester")

# kernel_version_regex → (CVE, description, severity, affected_range)
# Ranges are illustrative — real check via uname -r parsing
_KERNEL_CVES: list[tuple[str, str, str, str, str]] = [
    (r"[345]\.[0-9]+",       "CVE-2021-4034", "Polkit pkexec LPE (PwnKit)", "CRITICAL", "< 0.120-3"),
    (r"[345]\.[0-9]+",       "CVE-2021-3156", "Sudo heap-overflow LPE (Baron Samedit)", "CRITICAL", "< 1.9.5p2"),
    (r"5\.[0-9]+\.[0-9]+",   "CVE-2022-0847", "Dirty Pipe — arbitrary write via pipe", "HIGH", "5.8–5.16.11"),
    (r"[34]\.[0-9]+\.[0-9]+","CVE-2016-5195", "Dirty COW — race condition write", "HIGH", "< 4.8.3"),
    (r"5\.[0-9]+\.[0-9]+",   "CVE-2021-33909", "seq_file LPE (size_t-to-int overflow)", "HIGH", "< 5.13.4"),
    (r"[345]\.[0-9]+",       "CVE-2019-13272", "ptrace PTRACE_TRACEME LPE", "HIGH", "< 5.1.17"),
    (r"[345]\.[0-9]+",       "CVE-2017-16995", "eBPF verifier integer overflow LPE", "HIGH", "3.18–4.14"),
    (r"[345]\.[0-9]+",       "CVE-2017-7308",  "af_packet ring buffer LPE", "HIGH", "< 4.10.6"),
]

class KernelSuggesterModule(BaseModule):
    """
    linux.kernel_suggester — Read kernel version via SSH and map to known LPE CVEs — detection and suggestion only, no exploi

    OPSEC: LOW
    MITRE: "T1068", "T1082"
    REQUIRES: "ssh_credentials"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID          = "linux.kernel_suggester"
    MODULE_NAME        = "Linux Kernel Exploit Suggester"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = (
        "Read kernel version via SSH and map to known LPE CVEs — "
        "detection and suggestion only, no exploitation"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["ssh_credentials"]
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1068", "T1082"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                f"{self.MODULE_ID} requires 'target' — IP or hostname.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        key_path = ctx.params.get("key_path", "")
        params = dict(ctx.params)
        for key in ("target", "username", "password", "key_path"):
            params.pop(key, None)
        findings, raw = await self.run(target=target, username=username, password=password,
                                        key_path=key_path, **params)
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
            ]:
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=5)
                    results[key] = stdout.read().decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            client.close()
            return results

        try:
            info = await loop.run_in_executor(None, _get_info)
        except Exception as e:
            return [], {"error": str(e)[:200]}

        kernel_ver = info.get("kernel", "")
        suggestions: list[dict[str, str]] = []

        for pattern, cve, description, severity_str, affected in _KERNEL_CVES:
            if re.search(pattern, kernel_ver):
                suggestions.append({
                    "cve": cve, "description": description,
                    "severity": severity_str, "affected_range": affected,
                })
                sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM}.get(severity_str, Severity.INFO)
                self.finding(
                    title=f"Potential Kernel LPE: {cve} — {description}",
                    description=(
                        f"Kernel {kernel_ver} on {target} may be vulnerable to {cve} "
                        f"({description}). Affected range: {affected}. "
                        "Verify patch level before attempting exploitation."
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
                    host=target, confidence=0.7,
                )

        raw = {"target": target, "kernel": kernel_ver,
               "os_info": info.get("os_release", ""),
               "current_user": info.get("current_user", ""),
               "suggestions": suggestions}
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
