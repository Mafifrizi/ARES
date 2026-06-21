"""
Linux Service Binary Hijack Detection
MITRE: T1574.010 (Services File Permissions Weakness)

Detects system services where the binary (ExecStart) is writable
by the current user — replacing it executes arbitrary code the
next time the service restarts or the system reboots.

Checks:
  1. systemd unit files (.service) in /etc/systemd/system/,
     /lib/systemd/system/, /usr/lib/systemd/system/
  2. SysV init scripts in /etc/init.d/
  3. For each service, parse ExecStart= path and test writability

Also checks:
  4. Writable service unit files themselves
     (modifying the unit file is equivalent to modifying the binary)
  5. Services running as root with binaries in user-writable locations

Detection only — no service files or binaries are modified.
All checks are read-only (stat, test -w).

OPSEC: LOW — reads unit files, no process execution or service interaction.
"""
from __future__ import annotations

import asyncio
import os
import re
import shlex
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.linux.service_hijack")

# Directories containing systemd unit files
_SYSTEMD_DIRS: list[str] = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/usr/local/lib/systemd/system",
]

# Max services to check (avoid very long scans)
_MAX_SERVICES = 60

# User-controlled path indicators — binaries here are suspicious
_USER_WRITABLE_PATHS: list[str] = [
    "/tmp/",
    "/var/tmp/",
    "/home/",
    "/dev/shm/",
]


def _parse_exec_start(unit_content: str) -> list[str]:
    """
    Extract ExecStart= paths from a systemd unit file.
    Returns list of binary paths (first token, stripped of leading - or @).
    """
    paths: list[str] = []
    for line in unit_content.splitlines():
        line = line.strip()
        if not line.startswith("ExecStart="):
            continue
        value = line[len("ExecStart="):].strip()
        if not value or value in ("-", "@"):
            continue
        # Strip leading - (ignore failure) or @ (use execve directly)
        value = value.lstrip("-@").strip()
        if not value:
            continue
        # First token is the binary path
        binary = value.split()[0] if value else ""
        # Strip shell-style env prefix (VAR=val /path/to/bin)
        if "=" in binary and not binary.startswith("/"):
            parts = value.split()
            binary = next((p for p in parts if p.startswith("/")), "")
        if binary and binary.startswith("/"):
            paths.append(binary)
    return paths


class ServiceHijackModule(BaseModule):
    """
    linux.service_hijack — Detect systemd/init services with writable binaries or unit files — replacing the binary escalat

    OPSEC: LOW
    MITRE: "T1574.010", "T1082"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID          = "linux.service_hijack"
    MODULE_NAME        = "Service Binary Hijack Detection"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = (
        "Detect systemd/init services with writable binaries or unit files — "
        "replacing the binary escalates privileges at next service restart"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1574.010", "T1082"]

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
        host     = ctx.params.get("host") or getattr(ctx, "target", "localhost")
        ssh_user = ctx.params.get("ssh_user")
        ssh_key  = ctx.params.get("ssh_key")
        ssh_pass = ctx.params.get("ssh_pass") or ctx.params.get("password", "")
        ssh_port = ctx.params.get("ssh_port", 22)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "host": host},
            )
        findings, raw = await self.run(
            host=host, ssh_user=ssh_user, ssh_key=ssh_key,
            ssh_pass=ssh_pass, ssh_port=ssh_port,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("linux.service_hijack")
    async def run(
        self,
        host: str = "localhost",
        ssh_user: str | None = None,
        ssh_key:  str | None = None,
        ssh_pass: str | None = None,
        ssh_port: int = 22,
        **kwargs: Any,
    ) -> tuple[list[Finding], dict[str, Any]]:

        is_remote = ssh_user is not None and host != "localhost"

        if is_remote:
            host = sanitize_hostname(host)
            await self.before_request(host, "ssh")
            logger.info("service_hijack_start", host=host, mode="remote", user=ssh_user)
            run_cmd = await self._make_ssh_runner(host, ssh_user, ssh_key, ssh_pass, ssh_port)
        else:
            logger.info("service_hijack_start", host="localhost", mode="local")
            run_cmd = self._run_local

        # ── 1. Collect .service unit files ────────────────────────────────
        find_cmd = (
            "find "
            + " ".join(f"'{d}'" for d in _SYSTEMD_DIRS)
            + f" -name '*.service' -type f 2>/dev/null | head -{_MAX_SERVICES}"
        )
        unit_files_raw = await run_cmd(find_cmd)
        unit_files_raw = unit_files_raw if isinstance(unit_files_raw, str) else ""
        unit_files = [u.strip() for u in unit_files_raw.splitlines() if u.strip()]

        # Also collect init.d scripts
        initd_raw = await run_cmd("ls /etc/init.d/ 2>/dev/null")
        initd_raw = initd_raw if isinstance(initd_raw, str) else ""
        initd_scripts = [
            f"/etc/init.d/{s.strip()}"
            for s in initd_raw.splitlines()
            if s.strip() and not s.strip().startswith(".")
        ]

        writable_binaries:   list[dict[str, str]] = []
        writable_unit_files: list[dict[str, str]] = []
        suspicious_paths:    list[dict[str, str]] = []
        checked = 0

        # ── 2. Check each systemd unit file ───────────────────────────────
        for unit_path in unit_files:
            if checked >= _MAX_SERVICES:
                break
            checked += 1

            # Read unit file content
            content = await run_cmd(f"cat {shlex.quote(unit_path)} 2>/dev/null")
            content = content if isinstance(content, str) else ""
            if not content:
                continue

            # Check if the unit file itself is writable
            unit_writable = await run_cmd(
                f"[ -w {shlex.quote(unit_path)} ] && echo writable"
            )
            unit_writable = unit_writable if isinstance(unit_writable, str) else ""
            if "writable" in unit_writable:
                writable_unit_files.append({
                    "unit": unit_path,
                    "reason": "Unit file writable — modify ExecStart to run arbitrary command",
                })

            # Extract ExecStart paths and check writability
            exec_paths = _parse_exec_start(content)
            for binary in exec_paths:
                # Check for user-writable temp/home paths
                if any(binary.startswith(p) for p in _USER_WRITABLE_PATHS):
                    # Extract User= line to determine service privilege level
                    user_match = re.search(r'^User=(.+)$', content, re.MULTILINE)
                    service_user = user_match.group(1).strip() if user_match else "root"
                    suspicious_paths.append({
                        "unit":    unit_path,
                        "binary":  binary,
                        "runs_as": service_user,
                    })
                    continue

                # Check if binary is writable
                bin_writable = await run_cmd(
                    f"[ -f {shlex.quote(binary)} ] && [ -w {shlex.quote(binary)} ] && echo writable"
                )
                bin_writable = bin_writable if isinstance(bin_writable, str) else ""
                if "writable" in bin_writable:
                    user_match = re.search(r'^User=(.+)$', content, re.MULTILINE)
                    service_user = user_match.group(1).strip() if user_match else "root"
                    writable_binaries.append({
                        "unit":    unit_path,
                        "binary":  binary,
                        "runs_as": service_user,
                    })
            await self.noise.jitter.sleep()

        # ── 3. Check init.d scripts for writability ────────────────────────
        writable_initd: list[str] = []
        for script in initd_scripts[:20]:
            check = await run_cmd(
                f"[ -f {shlex.quote(script)} ] && [ -w {shlex.quote(script)} ] && echo writable"
            )
            check = check if isinstance(check, str) else ""
            if "writable" in check:
                writable_initd.append(script)

        # ── Generate findings ──────────────────────────────────────────────

        if writable_binaries:
            self.finding(
                title=(
                    f"Service Binary Writable on {host} "
                    f"({len(writable_binaries)} service(s))"
                ),
                description=(
                    f"{len(writable_binaries)} service binary/binaries are writable "
                    f"by the current user on {host}. "
                    "Replacing a service binary with a malicious executable "
                    "will run it under the service's privilege level "
                    "(usually root) at the next service restart or system reboot."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1574.010",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":    host,
                    "vectors": writable_binaries,
                    "exploitation": (
                        "1. Backup original binary: cp <binary> /tmp/original. "
                        "2. Replace with payload: cp /tmp/payload <binary>. "
                        "3. Wait for service restart or reboot. "
                        "4. Payload executes under service user context."
                    ),
                },
                remediation=(
                    "Fix binary permissions: chown root:root <binary> && chmod 755 <binary>. "
                    "Audit service binaries regularly: "
                    "find /usr /opt -name '*.service' -exec grep ExecStart= {} \\; "
                    "| awk '{print $2}' | xargs ls -la. "
                    "Use systemd's ProtectSystem=strict to prevent runtime modification."
                ),
                host=host, confidence=1.0,
            )

        if writable_unit_files:
            self.finding(
                title=(
                    f"Writable systemd Unit Files on {host} "
                    f"({len(writable_unit_files)} file(s))"
                ),
                description=(
                    f"{len(writable_unit_files)} systemd unit file(s) on {host} "
                    "are writable by the current user. "
                    "Modifying the ExecStart= directive and reloading systemd "
                    "achieves code execution under that service's user context."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1574.010",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":       host,
                    "unit_files": writable_unit_files,
                    "exploitation": (
                        "1. Edit unit file ExecStart=/tmp/payload. "
                        "2. Run: systemctl daemon-reload && systemctl restart <service>. "
                        "3. Payload runs as the service's User= account."
                    ),
                },
                remediation=(
                    "Fix unit file permissions: chmod 644 <unit_file>. "
                    "Only root should write systemd unit files. "
                    "Monitor unit file changes with auditd: "
                    "-w /etc/systemd/system -p wa -k systemd_unit_change"
                ),
                host=host, confidence=1.0,
            )

        if suspicious_paths:
            self.finding(
                title=(
                    f"Services with Binaries in User-Writable Paths on {host} "
                    f"({len(suspicious_paths)} service(s))"
                ),
                description=(
                    f"{len(suspicious_paths)} service(s) on {host} execute binaries "
                    "from user-writable directories (/tmp, /home, /var/tmp, /dev/shm). "
                    "These paths are trivially writable by unprivileged users — "
                    "placing a file with the expected name in these directories "
                    "causes the service to execute it."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1574.010",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":    host,
                    "vectors": suspicious_paths,
                },
                remediation=(
                    "Move service binaries to protected system directories "
                    "(e.g. /usr/local/bin or /opt/<service>/bin). "
                    "Never run services from /tmp or user home directories."
                ),
                host=host, confidence=0.95,
            )

        if writable_initd:
            self.finding(
                title=(
                    f"Writable SysV Init Scripts on {host} "
                    f"({len(writable_initd)} script(s))"
                ),
                description=(
                    f"{len(writable_initd)} SysV init script(s) in /etc/init.d/ "
                    f"are writable on {host}: {', '.join(writable_initd[:5])}. "
                    "These scripts run as root at boot time and during service "
                    "start/stop operations."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1574.010",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":    host,
                    "scripts": writable_initd,
                },
                remediation=(
                    "Fix permissions: chmod 755 /etc/init.d/<script> && "
                    "chown root:root /etc/init.d/<script>."
                ),
                host=host, confidence=1.0,
            )

        raw = {
            "host":               host,
            "units_checked":      checked,
            "writable_binaries":  writable_binaries,
            "writable_unit_files": writable_unit_files,
            "suspicious_paths":   suspicious_paths,
            "writable_initd":     writable_initd,
        }
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw

    # ── SSH / local runner helpers — identical pattern to linux.privesc ────

    async def _make_ssh_runner(
        self,
        host: str,
        user: str,
        key_path: str | None,
        password: str | None,
        port: int,
    ) -> Any:
        try:
            import asyncssh  # type: ignore[import]
        except ImportError:
            from ares.core.errors import ModuleError
            raise ModuleError("asyncssh not installed — pip install asyncssh",
                              module_id=self.MODULE_ID)

        kw: dict = {"host": host, "port": port, "username": user, "known_hosts": None}
        if key_path and os.path.exists(key_path):
            kw["client_keys"] = [key_path]
        elif password:
            kw["password"] = password

        try:
            conn = await asyncssh.connect(**kw)
        except Exception as exc:
            from ares.core.errors import AuthenticationFailed, HostUnreachable
            err = str(exc).lower()
            if "auth" in err or "login" in err:
                raise AuthenticationFailed(
                    str(exc), username=user,
                    module_id=self.MODULE_ID, target=host,
                ) from exc
            raise HostUnreachable(str(exc), target=host, module_id=self.MODULE_ID) from exc

        async def ssh_run(cmd: str) -> str:
            result = await conn.run(cmd, check=False)
            return (result.stdout or "").strip()

        return ssh_run

    @staticmethod
    async def _run_local(cmd: str) -> str:
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
