"""
Linux NFS Misconfiguration — no_root_squash Detection
MITRE: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

Checks NFS exports on the target for the no_root_squash option.
When no_root_squash is set, a remote root user mounting that export
retains root privileges on the NFS share — allowing SUID binary
creation or direct overwrite of sensitive files like /etc/passwd.

Two execution paths:
  Remote (SSH) — connects via asyncssh, reads /etc/exports and
                 mounted NFS shares from /proc/mounts
  Local        — reads directly from /etc/exports and /proc/mounts

This module is DETECTION ONLY.
It reports misconfigured exports and the exploitation path.
It does NOT mount anything or create any files on the target.

OPSEC: LOW — reads config files via SSH, no network scanning.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.linux.nfs_escape")

# Dangerous NFS export options
_DANGEROUS_OPTIONS: list[tuple[str, str, str]] = [
    (
        "no_root_squash",
        "Root on client retains root on the NFS share",
        "CRITICAL",
    ),
    (
        "no_all_squash",
        "All UIDs/GIDs are preserved — non-root users may also gain elevated access",
        "HIGH",
    ),
    (
        "insecure",
        "Allows connections from unprivileged ports (>1024) — easier to connect",
        "MEDIUM",
    ),
    (
        "rw",
        "Export is writable — required for file placement attacks",
        "INFO",
    ),
]


def _parse_exports(exports_content: str) -> list[dict[str, Any]]:
    """
    Parse /etc/exports content into structured list.
    Each entry: {path, clients: [{host, options}]}
    Handles continuation lines (backslash) and inline comments.
    """
    entries: list[dict[str, Any]] = []
    lines   = exports_content.splitlines()

    # Join continuation lines
    joined: list[str] = []
    buf = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            buf += stripped
            joined.append(buf.strip())
            buf = ""
    if buf.strip():
        joined.append(buf.strip())

    for line in joined:
        parts = line.split()
        if not parts:
            continue
        path    = parts[0]
        clients = []
        for part in parts[1:]:
            if "(" in part:
                host    = part[:part.index("(")]
                opts_str = part[part.index("(")+1:].rstrip(")")
                opts    = [o.strip() for o in opts_str.split(",") if o.strip()]
            else:
                host = part
                opts = []
            clients.append({"host": host or "*", "options": opts})
        entries.append({"path": path, "clients": clients})

    return entries


class NFSEscapeModule(BaseModule):
    """
    linux.nfs_escape — Detect NFS exports with no_root_squash — allows root on attacker machine to write SUID binaries 

    OPSEC: LOW
    MITRE: "T1548.001", "T1082"
    OUTPUTS:  "privesc_vectors"
    """
    MODULE_ID          = "linux.nfs_escape"
    MODULE_NAME        = "NFS no_root_squash Detection"
    MODULE_CATEGORY    = "linux"
    MODULE_DESCRIPTION = (
        "Detect NFS exports with no_root_squash — allows root on attacker "
        "machine to write SUID binaries to the share for privilege escalation"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1548.001", "T1082"]

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

    @trace_module("linux.nfs_escape")
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
            host     = sanitize_hostname(host)
            await self.before_request(host, "ssh")
            logger.info("nfs_escape_start", host=host, mode="remote", user=ssh_user)
            run_cmd = await self._make_ssh_runner(host, ssh_user, ssh_key, ssh_pass, ssh_port)
        else:
            logger.info("nfs_escape_start", host="localhost", mode="local")
            run_cmd = self._run_local

        # Gather NFS data in parallel
        exports_raw, mounts_raw, showmount_raw, nfs_conf_raw = await asyncio.gather(
            run_cmd("cat /etc/exports 2>/dev/null"),
            run_cmd("cat /proc/mounts 2>/dev/null | grep nfs"),
            run_cmd("showmount -e localhost 2>/dev/null"),
            run_cmd("cat /etc/nfs.conf 2>/dev/null | head -30"),
            return_exceptions=True,
        )

        # Safely coerce exceptions to empty string
        def _safe(v: Any) -> str:
            return v if isinstance(v, str) else ""

        exports_raw  = _safe(exports_raw)
        mounts_raw   = _safe(mounts_raw)
        showmount_raw = _safe(showmount_raw)
        nfs_conf_raw = _safe(nfs_conf_raw)

        entries = _parse_exports(exports_raw)

        # ── Analyse each export entry ──────────────────────────────────────
        for entry in entries:
            path    = entry["path"]
            clients = entry["clients"]

            for client in clients:
                opts           = [o.lower() for o in client.get("options", [])]
                client_host    = client.get("host", "*")
                is_writable    = "rw" in opts
                no_root_squash = "no_root_squash" in opts
                no_all_squash  = "no_all_squash" in opts
                insecure       = "insecure" in opts

                if no_root_squash:
                    self.finding(
                        title=f"NFS no_root_squash on {path} (host={client_host})",
                        description=(
                            f"NFS export {path!r} on {host} is configured with "
                            f"no_root_squash for client {client_host!r}. "
                            "Any client connecting as root retains root privileges "
                            "on the share. "
                            + (
                                "The export is also writable (rw). "
                                "An attacker with root on a client machine can mount "
                                "this share and copy a SUID /bin/bash binary, then "
                                "execute it from a low-priv shell on the NFS server "
                                "to escalate to root."
                                if is_writable else
                                "The export is read-only — no_root_squash is less "
                                "immediately exploitable but still a misconfiguration."
                            )
                        ),
                        severity=Severity.CRITICAL if is_writable else Severity.HIGH,
                        mitre_technique="T1548.001",
                        mitre_tactic="Privilege Escalation",
                        evidence={
                            "host":           host,
                            "export_path":    path,
                            "client":         client_host,
                            "options":        client.get("options", []),
                            "writable":       is_writable,
                            "exploitation":   (
                                f"1. Mount {path} on attacker machine as root. "
                                "2. Copy /bin/bash to the share and set SUID: "
                                "cp /bin/bash /mnt/share/ && chmod +s /mnt/share/bash. "
                                "3. On the NFS server (as low-priv user): "
                                f"/mnt_nfs{path}/bash -p  (opens root shell)."
                            ) if is_writable else "read-only export — limited impact",
                        },
                        remediation=(
                            f"Remove no_root_squash from {path} export in /etc/exports. "
                            "Use root_squash (default) to map remote root to nfsnobody. "
                            "Restrict NFS exports to specific IP ranges, not wildcards. "
                            "Run: exportfs -ra after editing /etc/exports."
                        ),
                        host=host, confidence=1.0,
                    )

                elif no_all_squash:
                    self.finding(
                        title=f"NFS no_all_squash on {path} (host={client_host})",
                        description=(
                            f"NFS export {path!r} on {host} has no_all_squash for "
                            f"client {client_host!r}. "
                            "UIDs from the client are passed through to the server — "
                            "if the client has a UID matching a privileged user on "
                            "the server, it gains their access."
                        ),
                        severity=Severity.HIGH if is_writable else Severity.MEDIUM,
                        mitre_technique="T1548.001",
                        mitre_tactic="Privilege Escalation",
                        evidence={
                            "host":        host,
                            "export_path": path,
                            "client":      client_host,
                            "options":     client.get("options", []),
                            "writable":    is_writable,
                        },
                        remediation=(
                            "Add all_squash to the export options to map all remote "
                            "UIDs to anonuid/anongid. "
                            "Example: /share *(rw,sync,all_squash,anonuid=65534,anongid=65534)"
                        ),
                        host=host, confidence=0.9,
                    )

        # ── Finding: NFS server running but no dangerous exports ───────────
        nfs_running = bool(exports_raw.strip()) or bool(mounts_raw.strip())
        if nfs_running and not self._findings:
            logger.info("nfs_escape_no_dangerous_exports", host=host,
                        export_count=len(entries))

        raw = {
            "host":           host,
            "exports_raw":    exports_raw,
            "exports_parsed": entries,
            "nfs_mounts":     mounts_raw,
            "showmount":      showmount_raw,
            "nfs_conf":       nfs_conf_raw,
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
