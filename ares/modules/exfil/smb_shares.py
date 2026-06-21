"""
ARES Exfil Module — SMB Share Enumeration & Staging (T1039 / T1021.002)

Enumerates accessible SMB shares with impacket SMBConnection:
  1. connect() to target on port 445
  2. listShares() — get all share names
  3. listPath(share, "*") — recursively scan each share for sensitive filenames
  4. logoff() — clean disconnect

MITRE ATT&CK:
  T1039  — Data from Network Shared Drive
  T1021.002 — Remote Services: SMB/Windows Admin Shares
"""
from __future__ import annotations

import fnmatch
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.logger import get_logger, audit
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.exfil.smb_shares")

_SENSITIVE_PATTERNS: list[str] = [
    "*.config", "web.config", "appsettings*.json",
    "*.kdbx", "*.pfx", "*.key", "*.pem", "*.p12",
    "id_rsa", "id_ecdsa", "id_ed25519",
    "password*", "passwords*", "credential*", "creds*",
    "secret*", "secrets*", "*.env", ".env",
    "NTDS.dit", "SAM", "SYSTEM", "SECURITY",
    "*.rdp", "*.ppk", "*.ovpn",
]
_SKIP_SHARES: set[str] = {"IPC$", "PRINT$", "print$"}


def _is_sensitive(filename: str) -> bool:
    name = filename.lower()
    return any(fnmatch.fnmatch(name, p.lower()) for p in _SENSITIVE_PATTERNS)


def _list_share_recursive(conn: Any, share: str, path: str = "*",
                           max_depth: int = 4, depth: int = 0) -> list[str]:
    if depth > max_depth:
        return []
    hits: list[str] = []
    try:
        entries = conn.listPath(share, path)
    except Exception:
        return hits
    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue
        if entry.is_directory() and depth < max_depth:
            sub = path.rstrip("*").rstrip("\\") + f"\\{name}\\*"
            hits.extend(_list_share_recursive(conn, share, sub, max_depth, depth + 1))
        elif not entry.is_directory() and _is_sensitive(name):
            base = path.rstrip("*").rstrip("\\")
            hits.append(f"\\\\{conn.getRemoteName()}\\{share}{base}\\{name}")
    return hits


class SmbSharesExfil(BaseModule):
    """
    exfil.smb_shares — Enumerate accessible SMB shares and scan for sensitive files including configs, keys, and credential

    OPSEC: MEDIUM
    MITRE: "T1039", "T1021.002"
    REQUIRES: "target", "credential"
    OUTPUTS:  "file_share_list", "sensitive_file_paths"
    """
    MODULE_ID        = "exfil.smb_shares"
    MODULE_NAME      = "SMB Share Enumeration"
    MODULE_CATEGORY  = "exfil"
    MODULE_DESCRIPTION = "Enumerate accessible SMB shares and scan for sensitive files including configs, keys, and credentials"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    REQUIRES         = ["target", "credential"]
    OUTPUTS          = ["file_share_list", "sensitive_file_paths"]
    MITRE_TECHNIQUES = ["T1039", "T1021.002"]

    OPSEC_LEVEL      = OpsecLevel.MEDIUM

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
                "exfil.smb_shares requires 'target' — IP of Windows/Samba host.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params)
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("exfil.smb_shares")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        ctx       = kwargs.get("ctx") or kwargs
        target    = ctx.get("target", "")
        dry_run   = ctx.get("dry_run", False)   # Fixed: was True
        username  = ctx.get("username", "")
        password  = ctx.get("password", "")
        domain    = ctx.get("domain", "")
        max_depth = int(ctx.get("max_depth", 3))

        if not target:
            return [], {"error": "no_target"}

        logger.info("smb_shares_enum", target=target, dry_run=dry_run)
        audit("smb_shares_enum", actor=username or "operator", source="operator",
              target=target, technique="T1039")

        if dry_run:
            mock_shares = ["SYSVOL", "NETLOGON", "C$", "IPC$", "Data"]
            mock_files  = [f"\\\\{target}\\Data\\credentials.xlsx",
                           f"\\\\{target}\\Data\\web.config"]
            self.finding(
                title       = f"Sensitive files found on SMB shares ({target})",
                description = (f"Shares enumerated: {', '.join(mock_shares)}. "
                               f"Sensitive files found: {len(mock_files)}"),
                severity    = Severity.HIGH, confidence=0.85,
                mitre_technique="T1039", mitre_tactic="Collection",
                remediation="Restrict SMB share permissions. Enable SMB auditing.",
                host=target,
            )
            return self._findings[:], {"dry_run": True, "file_share_list": mock_shares,
                 "sensitive_file_paths": mock_files, "sensitive_data_found": True}

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket_not_installed"}

        if not username:
            return [], {"error": "no_credential_username"}

        await self.before_request(target, "default")

        import asyncio as _asyncio
        loop = _asyncio.get_running_loop()

        def _smb_enum_sync() -> tuple[list[str], list[str]]:
            """
            All blocking SMB operations in one sync function — runs in executor.
            Wrapping in run_in_executor prevents freezing the event loop during
            SMBConnection.login(), listShares(), and recursive listPath() calls.
            """
            conn = None
            try:
                conn = SMBConnection(target, target, sess_port=445, timeout=10)
                conn.login(username, password, domain)

                share_list: list[str] = []
                try:
                    for s in conn.listShares():
                        share_list.append(s["shi1_netname"][:-1])
                except Exception as exc:
                    logger.warning("smb_list_shares_failed", target=target,
                                   error=str(exc)[:80])

                all_hits: list[str] = []
                for share in share_list:
                    if share in _SKIP_SHARES:
                        continue
                    try:
                        hits = _list_share_recursive(conn, share, "*",
                                                     max_depth=max_depth)
                        all_hits.extend(hits)
                        logger.debug("smb_share_scanned", share=share, hits=len(hits))
                    except Exception as exc:
                        logger.debug("smb_share_scan_error", share=share,
                                     error=str(exc)[:80])

                return share_list, all_hits
            finally:
                if conn:
                    try:
                        conn.logoff()
                    except Exception:
                        pass

        try:
            share_list, all_hits = await loop.run_in_executor(None, _smb_enum_sync)
        except Exception as exc:
            raise self._classify_error(exc) from exc

        if all_hits:
            self.finding(
                title       = f"Sensitive files on SMB shares ({target})",
                description = (
                    f"Enumerated {len(share_list)} shares. "
                    f"Found {len(all_hits)} sensitive file(s):\n"
                    + "\n".join(all_hits[:20])
                    + (f"\n...and {len(all_hits)-20} more" if len(all_hits) > 20 else "")
                ),
                severity=Severity.HIGH, confidence=0.90,
                mitre_technique="T1039", mitre_tactic="Collection",
                evidence={"sensitive_files": all_hits[:50]},
                remediation=(
                    "Restrict share permissions. Enable SMB auditing. "
                    "Rotate any credentials found in config files."
                ),
                host=target,
            )

        return self._findings[:], {
            "file_share_list":      share_list,
            "sensitive_file_paths": all_hits,
            "sensitive_data_found": bool(all_hits),
            "shares_scanned":       len(share_list),
            "files_found":          len(all_hits),
        }
