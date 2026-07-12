"""
Linux LD_PRELOAD / Library Hijack Detection
MITRE: T1574.006 (Dynamic Linker Hijacking)

Detects conditions that allow library hijacking via:
  1. LD_PRELOAD allowed in sudoers (env_keep += LD_PRELOAD)
     — run arbitrary code as sudo target user via preloaded .so
  2. RPATH pointing to writable directories in SUID/sudo binaries
     — attacker-controlled .so loaded before system libraries
  3. Writable directories in /etc/ld.so.conf or ld.so.conf.d/
     — affects all dynamically linked binaries run by any user
  4. Writable /etc/ld.so.preload
     — forces preload of attacker .so for every dynamic binary

Detection only — no .so files are created or injected.
All checks run via SSH or local shell, read-only commands.

OPSEC: LOW — reads config files and runs readelf/ldd on existing binaries.
"""
from __future__ import annotations

import asyncio
import os
import shlex
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.linux.ld_preload")

# SUID binaries worth checking for writable RPATH
_RPATH_CHECK_DEPTH = 20    # max SUID binaries to check RPATH on

# Commands used for detection
_CMD_SUDOERS_LDPRELOAD = (
    "sudo -l 2>/dev/null | grep -i 'LD_PRELOAD\\|env_keep'"
)
_CMD_LD_PRELOAD_FILE = (
    "ls -la /etc/ld.so.preload 2>/dev/null && cat /etc/ld.so.preload 2>/dev/null"
)
_CMD_LD_CONF_PATHS = (
    "cat /etc/ld.so.conf 2>/dev/null; "
    "cat /etc/ld.so.conf.d/*.conf 2>/dev/null"
)
_CMD_SUID_BINS = (
    "find / -perm -4000 -type f 2>/dev/null | head -30"
)


class LDPreloadModule(BaseModule):
    """
    linux.ld_preload — Detect LD_PRELOAD in sudoers, writable RPATH in SUID binaries, and writable ld.so config paths —

    OPSEC: LOW
    MITRE: "T1574.006", "T1082"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID          = "linux.ld_preload"
    MODULE_NAME        = "LD_PRELOAD / Library Hijack Detection"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = (
        "Detect LD_PRELOAD in sudoers, writable RPATH in SUID binaries, "
        "and writable ld.so config paths — library hijack escalation vectors"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1574.006", "T1082"]

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
        host     = ctx.params.get("target") or ctx.params.get("host") or getattr(ctx, "target", "localhost")
        ssh_user = ctx.params.get("username") or ctx.params.get("ssh_user")
        ssh_key  = ctx.params.get("key_path") or ctx.params.get("ssh_key")
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

    @trace_module("linux.ld_preload")
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
            logger.info("ld_preload_start", host=host, mode="remote", user=ssh_user)
            run_cmd = await self._make_ssh_runner(host, ssh_user, ssh_key, ssh_pass, ssh_port)
        else:
            logger.info("ld_preload_start", host="localhost", mode="local")
            run_cmd = self._run_local

        # Run checks in parallel
        (
            sudoers_out,
            preload_file_out,
            ld_conf_out,
            suid_bins_out,
        ) = await asyncio.gather(
            run_cmd(_CMD_SUDOERS_LDPRELOAD),
            run_cmd(_CMD_LD_PRELOAD_FILE),
            run_cmd(_CMD_LD_CONF_PATHS),
            run_cmd(_CMD_SUID_BINS),
            return_exceptions=True,
        )

        def _safe(v: Any) -> str:
            return v if isinstance(v, str) else ""

        sudoers_out      = _safe(sudoers_out)
        preload_file_out = _safe(preload_file_out)
        ld_conf_out      = _safe(ld_conf_out)
        suid_bins_out    = _safe(suid_bins_out)

        # ── Check 1: LD_PRELOAD in sudoers env_keep ────────────────────────
        if sudoers_out and "ld_preload" in sudoers_out.lower():
            self.finding(
                title=f"LD_PRELOAD Preserved in Sudoers on {host}",
                description=(
                    f"The sudoers configuration on {host} preserves the LD_PRELOAD "
                    "environment variable (env_keep += LD_PRELOAD). "
                    "An attacker can compile a malicious shared library, set "
                    "LD_PRELOAD to point to it, and run any command allowed by "
                    "sudo — causing the library to execute as the sudo target user "
                    "(often root) before the actual command runs."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1574.006",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":           host,
                    "sudoers_output": sudoers_out[:300],
                    "exploitation": (
                        "1. Compile: gcc -shared -fPIC -o /tmp/evil.so evil.c. "
                        "2. Set: export LD_PRELOAD=/tmp/evil.so. "
                        "3. Run any allowed sudo command — evil.so executes as root."
                    ),
                },
                remediation=(
                    "Remove LD_PRELOAD from env_keep in /etc/sudoers. "
                    "Add 'Defaults env_reset' and 'Defaults!env_reset env_keep=' "
                    "to explicitly control preserved variables. "
                    "Use 'visudo' to edit sudoers safely."
                ),
                host=host, confidence=1.0,
            )

        # ── Check 2: Writable /etc/ld.so.preload ──────────────────────────
        if preload_file_out:
            # File exists — check if writable by current user
            writable_preload = await run_cmd(
                "[ -w /etc/ld.so.preload ] && echo writable || echo readonly"
            ) if not isinstance(preload_file_out, Exception) else ""
            writable_preload = writable_preload if isinstance(writable_preload, str) else ""

            if "writable" in writable_preload:
                self.finding(
                    title=f"/etc/ld.so.preload is Writable on {host}",
                    description=(
                        f"/etc/ld.so.preload exists and is writable on {host}. "
                        "This file forces the dynamic linker to preload listed "
                        "shared libraries for EVERY dynamically linked binary run "
                        "by any user, including root. "
                        "Writing a malicious .so path here achieves system-wide "
                        "code execution as any user running any binary."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1574.006",
                    mitre_tactic="Privilege Escalation",
                    evidence={
                        "host":              host,
                        "file":              "/etc/ld.so.preload",
                        "current_contents":  preload_file_out[:200],
                        "exploitation": (
                            "1. Compile malicious .so: gcc -shared -fPIC -o /tmp/evil.so evil.c. "
                            "2. Add to preload: echo '/tmp/evil.so' >> /etc/ld.so.preload. "
                            "3. Next time any privileged binary runs, evil.so executes first."
                        ),
                    },
                    remediation=(
                        "Set correct permissions on /etc/ld.so.preload: "
                        "chown root:root /etc/ld.so.preload && chmod 644 /etc/ld.so.preload. "
                        "Verify contents are expected. "
                        "Monitor this file with auditd: "
                        "-w /etc/ld.so.preload -p wa -k ld_preload"
                    ),
                    host=host, confidence=1.0,
                )

        # ── Check 3: Writable directories in ld.so.conf ───────────────────
        if ld_conf_out:
            lib_dirs: list[str] = []
            for line in ld_conf_out.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line.startswith("/"):
                    lib_dirs.append(line)

            writable_lib_dirs: list[str] = []
            for ldir in lib_dirs[:20]:   # check first 20
                check = await run_cmd(
                    f"[ -d {shlex.quote(ldir)} ] && [ -w {shlex.quote(ldir)} ] && echo writable"
                )
                check = check if isinstance(check, str) else ""
                if "writable" in check:
                    writable_lib_dirs.append(ldir)

            if writable_lib_dirs:
                self.finding(
                    title=(
                        f"Writable Library Path in ld.so.conf on {host} "
                        f"({len(writable_lib_dirs)} dir(s))"
                    ),
                    description=(
                        f"The following directories are listed in /etc/ld.so.conf "
                        f"and are writable by the current user on {host}: "
                        f"{', '.join(writable_lib_dirs)}. "
                        "Placing a malicious .so with the same name as a real library "
                        "in these directories will cause it to be loaded instead of "
                        "the real library for any dynamically linked binary."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1574.006",
                    mitre_tactic="Privilege Escalation",
                    evidence={
                        "host":              host,
                        "writable_dirs":     writable_lib_dirs,
                        "all_lib_dirs":      lib_dirs[:10],
                    },
                    remediation=(
                        "Remove write permissions from library directories: "
                        "chmod 755 <dir> && chown root:root <dir>. "
                        "Run ldconfig after any legitimate library change. "
                        "Use AppArmor or SELinux to restrict library loading."
                    ),
                    host=host, confidence=0.95,
                )

        # ── Check 4: SUID binaries with writable RPATH ────────────────────
        suid_bins = [
            b.strip() for b in suid_bins_out.splitlines() if b.strip()
        ]
        writable_rpath_bins: list[dict[str, str]] = []

        for binary in suid_bins[:_RPATH_CHECK_DEPTH]:
            # Read RPATH/RUNPATH from the binary
            rpath_out = await run_cmd(
                f"readelf -d {shlex.quote(binary)} 2>/dev/null | "
                "grep -E '(RPATH|RUNPATH)'"
            )
            rpath_out = rpath_out if isinstance(rpath_out, str) else ""
            if not rpath_out:
                continue

            # Extract paths from RPATH output
            # Typical: 0x000000000000000f (RPATH) Library rpath: [/opt/lib:/usr/local/lib]
            import re
            match = re.search(r'\[(.+?)\]', rpath_out)
            if not match:
                continue
            rpath_dirs = [d.strip() for d in match.group(1).split(":") if d.strip()]

            for rdir in rpath_dirs:
                writable = await run_cmd(
                    f"[ -d {shlex.quote(rdir)} ] && [ -w {shlex.quote(rdir)} ] && echo writable"
                )
                writable = writable if isinstance(writable, str) else ""
                if "writable" in writable:
                    writable_rpath_bins.append({
                        "binary":       binary,
                        "rpath":        match.group(1),
                        "writable_dir": rdir,
                    })

        if writable_rpath_bins:
            self.finding(
                title=(
                    f"SUID Binary with Writable RPATH on {host} "
                    f"({len(writable_rpath_bins)} binary/binaries)"
                ),
                description=(
                    f"{len(writable_rpath_bins)} SUID binary/binaries on {host} "
                    "have RPATH pointing to directories writable by the current user. "
                    "By placing a malicious .so in the writable RPATH directory "
                    "with the same name as a library the binary loads, "
                    "the malicious library executes as the SUID binary owner (often root)."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1574.006",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":    host,
                    "vectors": writable_rpath_bins,
                    "exploitation": (
                        "1. Run ldd <suid_binary> to find loaded libraries. "
                        "2. Compile a fake version of one library as a shared object. "
                        "3. Place it in the writable RPATH dir with the exact library name. "
                        "4. Execute the SUID binary — your .so runs as root."
                    ),
                },
                remediation=(
                    "Recompile the binary without a hardcoded RPATH, or ensure "
                    "RPATH only points to root-owned directories. "
                    "Use patchelf --remove-rpath to strip RPATH. "
                    "Verify with: readelf -d <binary> | grep -E '(RPATH|RUNPATH)'"
                ),
                host=host, confidence=0.9,
            )

        raw = {
            "host":                   host,
            "sudoers_ldpreload":      sudoers_out,
            "ld_so_preload":          preload_file_out,
            "ld_conf_dirs":           ld_conf_out,
            "suid_bins_checked":      len(suid_bins[:_RPATH_CHECK_DEPTH]),
            "writable_rpath_vectors": writable_rpath_bins,
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
