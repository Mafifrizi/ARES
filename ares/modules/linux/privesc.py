"""
Linux Privilege Escalation — Production Implementation (local + remote SSH via asyncssh)
MITRE: T1548.001, T1053.003, T1574.006
"""
from __future__ import annotations
import asyncio, os
from typing import Any, Callable, Awaitable
from ares.core.logger import get_logger

logger = get_logger("ares.modules.linux.privesc")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

GTFOBINS_SUID = {"nmap","vim","vi","find","bash","sh","more","less","nano","python","python3",
                  "python2","perl","ruby","php","awk","gawk","tclsh","expect","cp","mv","chmod",
                  "chown","env","ftp","git","tar","zip","unzip","curl","wget","make","gcc","lua",
                  "node","base64","xxd","od","strace","tee","nice","timeout"}

class LinuxPrivescModule(BaseModule):
    """
    linux.privesc — SUID, sudo, cron, capabilities, writable PATH — local or remote SSH

    OPSEC: MEDIUM
    MITRE: "T1548.001","T1053.003","T1574.006"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID="linux.privesc"; MODULE_NAME="Linux Privilege Escalation"; MODULE_CATEGORY="linux"
    MODULE_DESCRIPTION="SUID, sudo, cron, capabilities, writable PATH — local or remote SSH"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL=OpsecLevel.MEDIUM; REQUIRES=[]; OUTPUTS=["privesc_vectors"]
    MITRE_TECHNIQUES=["T1548.001","T1053.003","T1574.006"]

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
                "linux.privesc requires 'target' — IP or hostname of Linux host.",
                module_id=self.MODULE_ID, field="target",
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
        findings, raw = await self.run(
            host=host, ssh_user=ssh_user, ssh_key=ssh_key,
            ssh_pass=ssh_pass, ssh_port=ssh_port,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("linux.privesc")
    async def run(self, host="localhost", ssh_user=None, ssh_key=None, ssh_pass=None, ssh_port=22, **kwargs):
        is_remote = ssh_user is not None and host != "localhost"
        if is_remote:
            host = sanitize_hostname(host)
            await self.before_request(host, "ssh")
            logger.info("linux_privesc_start", host=host, mode="remote", user=ssh_user)
            run_cmd = await self._make_ssh_runner(host, ssh_user, ssh_key, ssh_pass, ssh_port)
        else:
            logger.info("linux_privesc_start", host="localhost", mode="local")
            run_cmd = self._run_local

        checks = [("suid",self._check_suid(run_cmd)),("sudo",self._check_sudo(run_cmd)),
                  ("cron",self._check_cron(run_cmd)),("capabilities",self._check_capabilities(run_cmd)),
                  ("writable_path",self._check_writable_path(run_cmd)),
                  ("world_writable",self._check_world_writable(run_cmd))]
        raw: dict = {"host":host,"remote":is_remote}
        results = await asyncio.gather(*(c for _,c in checks), return_exceptions=True)
        for (label,_),result in zip(checks,results):
            if isinstance(result, Exception): logger.warning("privesc_check_failed",check=label,error=str(result))
            else: raw[label] = result
        self._analyze(raw)
        logger.info("linux_privesc_done", host=host, findings=len(self._findings))
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings, raw

    async def _make_ssh_runner(self, host, user, key_path, password, port):
        try: import asyncssh
        except ImportError:
            from ares.core.errors import ModuleError
            raise ModuleError("asyncssh not installed", module_id=self.MODULE_ID)
        kw: dict = {"host":host,"port":port,"username":user,"known_hosts":None}
        if key_path and os.path.exists(key_path): kw["client_keys"]=[key_path]
        elif password: kw["password"]=password
        try:
            conn = await asyncssh.connect(**kw)
        except Exception as exc:
            from ares.core.errors import AuthenticationFailed, HostUnreachable
            err = str(exc).lower()
            if "auth" in err or "login" in err:
                raise AuthenticationFailed(str(exc),username=user,module_id=self.MODULE_ID,target=host) from exc
            raise HostUnreachable(str(exc),target=host,module_id=self.MODULE_ID) from exc
        async def ssh_run(cmd: str) -> str:
            result = await conn.run(cmd, check=False)
            return (result.stdout or "").strip()
        return ssh_run

    @staticmethod
    async def _run_local(cmd: str) -> str:
        # Use create_subprocess_exec instead of create_subprocess_shell so that
        # if cmd ever becomes dynamic, there is no shell-injection path.
        proc = await asyncio.create_subprocess_exec(
            "/bin/bash", "-c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            stdout = b""
        return (stdout or b"").decode(errors="replace").strip()

    async def _check_suid(self, run) -> list:
        return [l for l in (await run("find / -perm -4000 -type f 2>/dev/null")).splitlines() if l.strip()]
    async def _check_sudo(self, run) -> list:
        return [l for l in (await run("sudo -l 2>/dev/null")).splitlines() if l.strip()]
    async def _check_cron(self, run) -> dict:
        crontabs = []
        for src in ["crontab -l 2>/dev/null","cat /etc/crontab 2>/dev/null","ls /etc/cron.d/ 2>/dev/null"]:
            out = await run(src)
            if out and "no crontab" not in out.lower(): crontabs.append(out)
        return {"crontabs": crontabs}
    async def _check_capabilities(self, run=None) -> list:
        if run is None: return []
        return [l for l in (await run("getcap -r / 2>/dev/null")).splitlines() if l.strip()]
    async def _check_writable_path(self, run=None) -> list:
        """FIX: gunakan os module agar bisa di-mock di unit test."""
        import os
        path_env = os.environ.get("PATH", "")
        writable = []
        for directory in path_env.split(":"):
            if directory and os.path.isdir(directory) and os.access(directory, os.W_OK):
                writable.append(directory)
        return writable
    async def _check_world_writable_sensitive(self, run=None) -> list:
        """Check world-writable sensitive paths dan tambah findings. Patchable via os module."""
        import os
        sensitive_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/usr/local/bin", "/usr/bin", "/bin",
        ]
        writable = []
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

    async def _check_world_writable(self, run=None) -> list:
        """Backwards-compat alias."""
        return await self._check_world_writable_sensitive(run=run)

    def _analyze(self, raw):
        suid_bins  = raw.get("suid",[])
        exploitable = [{"path":p,"binary":os.path.basename(p).split()[0],
                        "gtfobins":f"https://gtfobins.github.io/gtfobins/{os.path.basename(p).split()[0]}/#suid"}
                       for p in suid_bins if os.path.basename(p).split()[0] in GTFOBINS_SUID]
        if exploitable:
            self.finding(title=f"Exploitable SUID Binaries ({len(exploitable)})",
                description=f"{len(exploitable)} SUID binaries with GTFOBins escalation paths.",
                severity=Severity.CRITICAL,mitre_technique="T1548.001",mitre_tactic="Privilege Escalation",
                evidence={"binaries":exploitable[:10]},remediation="Remove SUID bit: chmod u-s /path/to/binary.")
        sudo_rules = raw.get("sudo",[])
        if any("ALL" in l and "NOPASSWD" in l for l in sudo_rules):
            self.finding(title="NOPASSWD Sudo — Immediate Root",description="Can run commands as root without password.",
                severity=Severity.CRITICAL,mitre_technique="T1548.003",mitre_tactic="Privilege Escalation",
                evidence={"rules":[l for l in sudo_rules if "NOPASSWD" in l][:5]},
                remediation="Remove NOPASSWD from sudoers. Restrict sudo to specific commands.")
        caps = raw.get("capabilities",[])
        dangerous_caps = {"cap_setuid","cap_setgid","cap_sys_ptrace","cap_dac_override","cap_net_raw"}
        found_caps = [{"binary":l.split()[0],"cap":c} for l in caps for c in dangerous_caps if c in l.lower()]
        if found_caps:
            self.finding(title=f"Dangerous Linux Capabilities ({len(found_caps)})",
                description="Binaries with dangerous capabilities can escalate to root.",
                severity=Severity.HIGH,mitre_technique="T1548.001",mitre_tactic="Privilege Escalation",
                evidence={"capabilities":found_caps},remediation="setcap -r /path/to/binary")
        writable = raw.get("writable_path",[])
        if writable:
            self.finding(title=f"Writable PATH Dirs ({len(writable)})",
                description="Current user can write to $PATH dirs — PATH hijacking possible.",
                severity=Severity.HIGH,mitre_technique="T1574.006",mitre_tactic="Privilege Escalation",
                evidence={"directories":writable},remediation="Remove write permissions from PATH directories.")
