"""
Linux Privilege Escalation — Next-Gen Sovereign SDK v2 Implementation
Local & Remote SSH with Capability-Based Sandboxing & Merkle Audit Trails.
MITRE: T1548.001, T1053.003, T1574.006
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Awaitable, Callable

from ares.core.campaign import Finding, Severity
from ares.core.errors import AuthenticationFailed, HostUnreachable, ModuleError, ModuleValidationError
from ares.core.logger import get_logger
from ares.core.security import sanitize_hostname
from ares.core.tracing import trace_module
from ares.modules.params import LinuxPrivescParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    UntrustedTargetData,
    module_contract,
)

logger = get_logger("ares.modules.linux.privesc")

GTFOBINS_SUID = {
    "nmap", "vim", "vi", "find", "bash", "sh", "more", "less", "nano", "python", "python3",
    "python2", "perl", "ruby", "php", "awk", "gawk", "tclsh", "expect", "cp", "mv", "chmod",
    "chown", "env", "ftp", "git", "tar", "zip", "unzip", "curl", "wget", "make", "gcc", "lua",
    "node", "base64", "xxd", "od", "strace", "tee", "nice", "timeout",
}


@module_contract(
    permissions=[
        NetworkPermission(ports=[22], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=True, allowed_binaries=["/bin/bash", "find", "sudo", "systemctl", "getcap", "crontab"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=LinuxPrivescParams,
)
class LinuxPrivescModule(BaseModule[LinuxPrivescParams, ModuleResult]):
    """
    linux.privesc — SUID, sudo, cron, capabilities, writable PATH — local or remote SSH

    OPSEC: MEDIUM
    MITRE: "T1548.001", "T1053.003", "T1574.006"
    OUTPUTS: ["privesc_vectors"]
    """

    MODULE_ID          = "linux.privesc"
    MODULE_NAME        = "Linux Privilege Escalation"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = "SUID, sudo, cron, capabilities, writable PATH — local or remote SSH"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1548.001", "T1053.003", "T1574.006"]
    PARAMS_MODEL       = LinuxPrivescParams

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext

        if not isinstance(ctx, ExecutionContext):
            return

        target = getattr(ctx, "target", "")
        if not target and hasattr(ctx, "params"):
            if isinstance(ctx.params, dict):
                target = ctx.params.get("target") or ctx.params.get("host", "")
            elif hasattr(ctx.params, "host"):
                target = getattr(ctx.params, "host", "") or getattr(ctx.params, "target", "")

        if not target:
            raise ModuleValidationError(
                "linux.privesc requires 'target' — IP or hostname of Linux host.",
                module_id=self.MODULE_ID,
                field="target",
            )

        ssh_user = None
        if hasattr(ctx, "params"):
            if isinstance(ctx.params, dict):
                ssh_user = ctx.params.get("username") or ctx.params.get("ssh_user")
            elif hasattr(ctx.params, "ssh_user"):
                ssh_user = getattr(ctx.params, "ssh_user", None) or getattr(ctx.params, "username", None)

        if target != "localhost" and not ssh_user:
            raise ModuleValidationError(
                f"{self.MODULE_ID} targeting remote host '{target}' requires 'username' or 'ssh_user'. "
                "Local controller fallback is prohibited.",
                module_id=self.MODULE_ID,
                field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        host     = ctx.params.get("host") or getattr(ctx, "target", "localhost")
        ssh_user = ctx.params.get("ssh_user")
        ssh_key  = ctx.params.get("ssh_key")
        ssh_pass = ctx.params.get("ssh_pass")
        ssh_port = ctx.params.get("ssh_port", 22)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True, "host": host})

        params = getattr(ctx, "params", {})
        if isinstance(params, LinuxPrivescParams):
            host = params.host or getattr(ctx, "target", "localhost")
            ssh_user = params.ssh_user
            ssh_key = params.ssh_key
            ssh_pass = params.ssh_pass.get_secret_value() if params.ssh_pass else None
            ssh_port = params.ssh_port
        elif isinstance(params, dict):
            host = params.get("host") or params.get("target") or getattr(ctx, "target", "localhost")
            ssh_user = params.get("username") or params.get("ssh_user")
            ssh_key = params.get("key_path") or params.get("ssh_key")
            raw_pass = params.get("password") or params.get("secret") or params.get("ssh_pass")
            ssh_pass = raw_pass.get_secret_value() if hasattr(raw_pass, "get_secret_value") else raw_pass
            ssh_port = int(params.get("ssh_port", 22))
        else:
            host = getattr(ctx, "target", "localhost")
            ssh_user = None
            ssh_key = None
            ssh_pass = None
            ssh_port = 22

        findings, raw = await self.run(
            host=host,
            ssh_user=ssh_user,
            ssh_key=ssh_key,
            ssh_pass=ssh_pass,
            ssh_port=ssh_port,
        )

        # Cryptographic Evidence Chain with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"privesc-{finding.title[:20].lower().replace(' ', '-')}",
                source_target=host,
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "severity": str(finding.severity),
                    "description": finding.description,
                    "mitre": finding.mitre_technique,
                },
                tags=["linux", "privesc"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("linux.privesc")
    async def run(
        self,
        host: str = "localhost",
        ssh_user: str | None = None,
        ssh_key: str | None = None,
        ssh_pass: str | None = None,
        ssh_port: int = 22,
        **kwargs: Any,
    ) -> tuple[list[Finding], dict[str, Any]]:
        is_remote = ssh_user is not None and host != "localhost"
        if is_remote:
            host = sanitize_hostname(host)
            await self.before_request(host, "ssh")
            logger.info("linux_privesc_start", host=host, mode="remote", user=ssh_user)
            run_cmd = await self._make_ssh_runner(host, ssh_user, ssh_key, ssh_pass, ssh_port)
        elif host == "localhost":
            logger.info("linux_privesc_start", host="localhost", mode="local")
            run_cmd = self._run_local
        else:
            logger.error("linux_privesc_rejected_remote_without_credentials", host=host)
            return [], {"error": f"remote target '{host}' requires ssh_user; local fallback prohibited"}

        checks = [
            ("suid", self._check_suid(run_cmd)),
            ("sudo", self._check_sudo(run_cmd)),
            ("cron", self._check_cron(run_cmd)),
            ("capabilities", self._check_capabilities(run_cmd)),
            ("writable_path", self._check_writable_path(run_cmd)),
            ("world_writable", self._check_world_writable(run_cmd)),
        ]
        raw: dict[str, Any] = {"host": host, "remote": is_remote}
        results = await asyncio.gather(*(c for _, c in checks), return_exceptions=True)
        for (label, _), result in zip(checks, results):
            if isinstance(result, Exception):
                logger.warning("privesc_check_failed", check=label, error=str(result))
            else:
                # Wrap target output in UntrustedTargetData taint barrier
                if isinstance(result, list):
                    raw[label] = [UntrustedTargetData(str(x), source=host).value for x in result]
                else:
                    raw[label] = result

        self._analyze(raw)
        logger.info("linux_privesc_done", host=host, findings=len(self._findings))
        raw["privesc_vectors"] = self._findings
        return self._findings, raw

    async def _make_ssh_runner(
        self, host: str, user: str, key_path: str | None, password: str | None, port: int
    ) -> Callable[[str], Awaitable[str]]:
        try:
            import asyncssh
        except ImportError:
            raise ModuleError("asyncssh not installed", module_id=self.MODULE_ID)

        kw: dict[str, Any] = {"host": host, "port": port, "username": user, "known_hosts": None}
        if key_path and os.path.exists(key_path):
            kw["client_keys"] = [key_path]
        elif password:
            kw["password"] = password

        try:
            conn = await asyncssh.connect(**kw)
        except Exception as exc:
            err = str(exc).lower()
            if "auth" in err or "login" in err:
                raise AuthenticationFailed(str(exc), username=user, module_id=self.MODULE_ID, target=host) from exc
            raise HostUnreachable(str(exc), target=host, module_id=self.MODULE_ID) from exc

        async def ssh_run(cmd: str) -> str:
            result = await conn.run(cmd, check=False)
            output = (result.stdout or "").strip()
            return UntrustedTargetData(output, source=host).value

        return ssh_run

    @staticmethod
    async def _run_local(cmd: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "/bin/bash",
            "-c",
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout = b""
        raw_output = (stdout or b"").decode(errors="replace").strip()
        return UntrustedTargetData(raw_output, source="localhost").value

    async def _check_suid(self, run: Callable[[str], Awaitable[str]]) -> list[str]:
        output = await run("find / -perm -4000 -type f 2>/dev/null")
        return [line for line in output.splitlines() if line.strip()]

    async def _check_sudo(self, run: Callable[[str], Awaitable[str]]) -> list[str]:
        output = await run("sudo -l 2>/dev/null")
        return [line for line in output.splitlines() if line.strip()]

    async def _check_cron(self, run: Callable[[str], Awaitable[str]]) -> dict[str, Any]:
        crontabs: list[str] = []
        for src in ["crontab -l 2>/dev/null", "cat /etc/crontab 2>/dev/null", "ls /etc/cron.d/ 2>/dev/null"]:
            out = await run(src)
            if out and "no crontab" not in out.lower():
                crontabs.append(out)
        return {"crontabs": crontabs}

    async def _check_capabilities(self, run: Callable[[str], Awaitable[str]] | None = None) -> list[str]:
        if run is None:
            return []
        output = await run("getcap -r / 2>/dev/null")
        return [line for line in output.splitlines() if line.strip()]

    async def _check_writable_path(self, run: Any = None) -> list[str]:
        path_env = os.environ.get("PATH", "")
        writable: list[str] = []
        for directory in path_env.split(":"):
            if directory and os.path.isdir(directory) and os.access(directory, os.W_OK):
                writable.append(directory)
        return writable

    async def _check_world_writable_sensitive(self, run: Any = None) -> list[str]:
        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
        writable: list[str] = []
        for path in sensitive_paths:
            if os.path.exists(path) and os.access(path, os.W_OK):
                writable.append(path)

        if writable:
            self.finding(
                title=f"World-writable sensitive files: {', '.join(writable[:3])}",
                description=f"Found {len(writable)} sensitive path(s) writable: {writable}",
                severity=Severity.CRITICAL,
                mitre_technique="T1548.001",
                mitre_tactic="Privilege Escalation",
                evidence={"writable_paths": writable},
                remediation="Remove world-write permissions from sensitive system files.",
            )
        return writable

    async def _check_world_writable(self, run: Any = None) -> list[str]:
        return await self._check_world_writable_sensitive(run=run)

    def _analyze(self, raw: dict[str, Any]) -> None:
        suid_bins = raw.get("suid", [])
        exploitable = [
            {
                "path": p,
                "binary": os.path.basename(p).split()[0],
                "gtfobins": f"https://gtfobins.github.io/gtfobins/{os.path.basename(p).split()[0]}/#suid",
            }
            for p in suid_bins
            if os.path.basename(p).split()[0] in GTFOBINS_SUID
        ]
        if exploitable:
            self.finding(
                title=f"Exploitable SUID Binaries ({len(exploitable)})",
                description=f"{len(exploitable)} SUID binaries with GTFOBins escalation paths.",
                severity=Severity.CRITICAL,
                mitre_technique="T1548.001",
                mitre_tactic="Privilege Escalation",
                evidence={"binaries": exploitable[:10]},
                remediation="Remove SUID bit: chmod u-s /path/to/binary.",
            )

        sudo_rules = raw.get("sudo", [])
        if any("ALL" in line and "NOPASSWD" in line for line in sudo_rules):
            self.finding(
                title="NOPASSWD Sudo — Immediate Root",
                description="Can run commands as root without password.",
                severity=Severity.CRITICAL,
                mitre_technique="T1548.003",
                mitre_tactic="Privilege Escalation",
                evidence={"rules": [line for line in sudo_rules if "NOPASSWD" in line][:5]},
                remediation="Remove NOPASSWD from sudoers. Restrict sudo to specific commands.",
            )

        caps = raw.get("capabilities", [])
        dangerous_caps = {"cap_setuid", "cap_setgid", "cap_sys_ptrace", "cap_dac_override", "cap_net_raw"}
        found_caps = [
            {"binary": line.split()[0], "cap": c}
            for line in caps
            for c in dangerous_caps
            if c in line.lower()
        ]
        if found_caps:
            self.finding(
                title=f"Dangerous Linux Capabilities ({len(found_caps)})",
                description="Binaries with dangerous capabilities can escalate to root.",
                severity=Severity.HIGH,
                mitre_technique="T1548.001",
                mitre_tactic="Privilege Escalation",
                evidence={"capabilities": found_caps},
                remediation="setcap -r /path/to/binary",
            )

        writable = raw.get("writable_path", [])
        if writable:
            self.finding(
                title=f"Writable PATH Dirs ({len(writable)})",
                description="Current user can write to $PATH dirs — PATH hijacking possible.",
                severity=Severity.HIGH,
                mitre_technique="T1574.006",
                mitre_tactic="Privilege Escalation",
                evidence={"directories": writable},
                remediation="Remove write permissions from PATH directories.",
            )
