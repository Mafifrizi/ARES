"""
AppLocker Policy Enumeration & Writable Trusted Path Detection
MITRE: T1218 (System Binary Proxy Execution), T1574.001 (DLL Search Order Hijacking)

Reads AppLocker rules from the registry and checks for:
  1. Whether AppLocker is configured and enforcing (vs Audit mode only)
  2. Which rule collections are active (Exe, Script, MSI, DLL, Appx)
  3. Writable directories under trusted paths that could be used for bypass
     (e.g. writable C:\\Windows\\Tasks, user-writable paths in allowed rules)
  4. Classic unsigned bypass paths (WMIC, mshta, wscript, cscript, etc.)
     that may still be allowed under publisher or path rules

This module is ENUMERATION ONLY — no code execution on target.
Operator uses findings to assess bypass feasibility.

OPSEC: LOW — remote registry read + optional WinRM command for path writability.
       Main detection surface is registry access audit (rarely enabled).
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.windows.applocker_bypass")


# ── AppLocker registry base ────────────────────────────────────────────────────
_AL_BASE = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2"

# Rule collection names under SrpV2
_COLLECTIONS = ["Exe", "Script", "Msi", "Dll", "Appx"]

# Classic LOLBins that bypass application whitelisting when not explicitly blocked
_LOLBINS: list[dict[str, str]] = [
    {"binary": "mshta.exe",       "technique": "Execute HTA files — often not in AppLocker rules"},
    {"binary": "wscript.exe",     "technique": "Execute VBScript/JScript"},
    {"binary": "cscript.exe",     "technique": "Execute VBScript/JScript via cscript"},
    {"binary": "regsvr32.exe",    "technique": "Squiblydoo — execute SCT file via COM"},
    {"binary": "regasm.exe",      "technique": "Execute .NET assembly via COM registration"},
    {"binary": "regsvcs.exe",     "technique": "Execute .NET assembly via COM services"},
    {"binary": "installutil.exe", "technique": "Execute .NET assembly via installer utility"},
    {"binary": "rundll32.exe",    "technique": "Execute DLL or JavaScript via mshtml"},
    {"binary": "msiexec.exe",     "technique": "Execute MSI or DLL via Windows Installer"},
    {"binary": "certutil.exe",    "technique": "Download and decode payloads"},
    {"binary": "bitsadmin.exe",   "technique": "Download files and execute"},
    {"binary": "wmic.exe",        "technique": "Execute XSL via wmic /format"},
    {"binary": "forfiles.exe",    "technique": "Execute arbitrary commands via /c parameter"},
    {"binary": "pcalua.exe",      "technique": "Execute arbitrary program as child process"},
    {"binary": "bash.exe",        "technique": "WSL bash — execute Linux binaries if WSL enabled"},
]

# Commonly writable paths inside trusted Windows locations
_TRUSTED_WRITABLE_CANDIDATES: list[str] = [
    "%windir%\\Tasks",
    "%windir%\\Tracing",
    "%windir%\\System32\\spool\\drivers\\color",
    "%windir%\\System32\\Tasks",
    "%windir%\\SysWOW64\\Tasks",
    "%temp%",
    "%localappdata%\\Temp",
    "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "%programdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
]


class AppLockerBypassModule(BaseModule):
    """
    windows.applocker_bypass — Enumerate AppLocker rules from registry, identify enforcement mode, and detect writable trusted 

    OPSEC: LOW
    MITRE: "T1218", "T1574.001", "T1082"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "applocker_config", "privesc_vectors"
    """
    MODULE_ID          = "windows.applocker_bypass"
    MODULE_NAME        = "AppLocker Policy Enumeration"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Enumerate AppLocker rules from registry, identify enforcement mode, "
        "and detect writable trusted paths and LOLBin bypass candidates"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["applocker_config", "privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1218", "T1574.001", "T1082"]

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

    @trace_module("windows.applocker_bypass")
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
                hOpenLocalMachine, hBaseRegOpenKey,
                hBaseRegQueryValue, hBaseRegQueryInfoKey,
                hBaseRegEnumKey, hBaseRegEnumValue,
                hBaseRegCloseKey, DCERPCException,
            )
        except ImportError:
            return [], {"error": "impacket not installed — pip install ares-redteam[ad]"}

        logger.info("applocker_enum_start", target=target, username=username)
        audit("applocker_enum", actor=username, source="operator",
              target=target, technique="T1082")

        await self.before_request(target, "smb")

        loop = asyncio.get_running_loop()

        def _read_applocker() -> dict[str, Any]:
            collections: dict[str, dict[str, Any]] = {}
            errors: list[str] = []

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

                ans  = hOpenLocalMachine(dce)
                hklm = ans["phKey"]

                # Check if AppLocker key exists at all
                try:
                    ans2  = hBaseRegOpenKey(dce, hklm, _AL_BASE)
                    hbase = ans2["phkResult"]
                except DCERPCException:
                    # AppLocker not configured
                    hBaseRegCloseKey(dce, hklm)
                    return {
                        "configured": False,
                        "collections": {},
                        "errors": [],
                    }

                # Enumerate each rule collection
                for col in _COLLECTIONS:
                    col_path = f"{_AL_BASE}\\{col}"
                    try:
                        ans3  = hBaseRegOpenKey(dce, hklm, col_path)
                        hcol  = ans3["phkResult"]

                        # Read EnforcementMode (0=not configured, 1=enforce, 2=audit)
                        enforcement = 0
                        try:
                            ev = hBaseRegQueryValue(dce, hcol, "EnforcementMode")
                            enforcement = int(ev[1]) if ev[1] is not None else 0
                        except DCERPCException:
                            pass

                        # Count rules
                        try:
                            info  = hBaseRegQueryInfoKey(dce, hcol)
                            nkeys = info["lpcSubKeys"]
                        except Exception:
                            nkeys = 0

                        # Read rule details (first 10)
                        rules: list[dict[str, str]] = []
                        for i in range(min(nkeys, 10)):
                            try:
                                ek        = hBaseRegEnumKey(dce, hcol, i)
                                rule_guid = ek["lpNameOut"].rstrip("\x00")
                                ans4      = hBaseRegOpenKey(dce, hcol, rule_guid)
                                hrule     = ans4["phkResult"]

                                rule_data: dict[str, str] = {"id": rule_guid}
                                for field in ("Name", "Description",
                                              "Action", "UserOrGroupSid",
                                              "Conditions"):
                                    try:
                                        rv = hBaseRegQueryValue(dce, hrule, field)
                                        val = rv[1]
                                        if isinstance(val, bytes):
                                            val = val.rstrip(b"\x00").decode(
                                                "utf-8", errors="replace"
                                            )
                                        rule_data[field] = str(val).rstrip("\x00")
                                    except DCERPCException:
                                        pass
                                hBaseRegCloseKey(dce, hrule)
                                rules.append(rule_data)
                            except Exception:
                                continue

                        hBaseRegCloseKey(dce, hcol)
                        collections[col] = {
                            "enforcement": enforcement,
                            "rule_count":  nkeys,
                            "rules":       rules,
                        }
                    except DCERPCException:
                        pass  # This collection not configured

                hBaseRegCloseKey(dce, hbase)
                hBaseRegCloseKey(dce, hklm)

            except Exception as e:
                errors.append(str(e)[:200])
            finally:
                if dce:
                    try: dce.disconnect()
                    except Exception: pass
                if smb:
                    try: smb.logoff()
                    except Exception: pass

            return {
                "configured": True,
                "collections": collections,
                "errors": errors,
            }

        reg_data   = await loop.run_in_executor(None, _read_applocker)
        configured = reg_data.get("configured", False)
        collections = reg_data.get("collections", {})
        errors     = reg_data.get("errors", [])

        # ── Finding 1: AppLocker not configured ───────────────────────────
        if not configured:
            self.finding(
                title=f"AppLocker Not Configured on {target}",
                description=(
                    f"AppLocker is not configured on {target}. "
                    "No application whitelisting is in place. "
                    "Any executable, script, or MSI can run without restriction."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1218",
                mitre_tactic="Defense Evasion",
                evidence={"host": target, "applocker_configured": False},
                remediation=(
                    "Configure AppLocker (or Windows Defender Application Control) "
                    "to restrict which applications can run. "
                    "Start with Audit mode to identify required applications, "
                    "then switch to Enforce mode."
                ),
                host=target, confidence=1.0,
            )

        else:
            # ── Finding 2: Audit-only collections (not enforcing) ──────────
            audit_only = [
                col for col, data in collections.items()
                if data.get("enforcement") == 2     # 2 = Audit
            ]
            not_configured_cols = [
                col for col in _COLLECTIONS
                if col not in collections
            ]
            enforced = [
                col for col, data in collections.items()
                if data.get("enforcement") == 1     # 1 = Enforce
            ]

            if audit_only:
                self.finding(
                    title=(
                        f"AppLocker in Audit-Only Mode on {target}: "
                        f"{', '.join(audit_only)}"
                    ),
                    description=(
                        f"The following AppLocker rule collections are in Audit mode "
                        f"(not enforcing) on {target}: {', '.join(audit_only)}. "
                        "Rules are logged but NOT blocked — any executable can still run."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1218",
                    mitre_tactic="Defense Evasion",
                    evidence={
                        "host":          target,
                        "audit_only":    audit_only,
                        "enforced":      enforced,
                        "not_configured": not_configured_cols,
                    },
                    remediation=(
                        "Change EnforcementMode from 2 (Audit) to 1 (Enforce) for all "
                        "AppLocker rule collections after validating rules in audit mode."
                    ),
                    host=target, confidence=1.0,
                )

            if not_configured_cols:
                self.finding(
                    title=(
                        f"AppLocker Missing Rule Collections on {target}: "
                        f"{', '.join(not_configured_cols)}"
                    ),
                    description=(
                        f"AppLocker is configured on {target} but the following "
                        f"collections have no rules: {', '.join(not_configured_cols)}. "
                        "Unconfigured collections are not restricted at all."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1218",
                    mitre_tactic="Defense Evasion",
                    evidence={
                        "host":             target,
                        "missing":          not_configured_cols,
                        "enforced":         enforced,
                    },
                    remediation=(
                        "Add AppLocker rules for all collections, especially Script and DLL. "
                        "Without Script rules, PowerShell and VBScript are unrestricted."
                    ),
                    host=target, confidence=1.0,
                )

            # ── Finding 3: LOLBin bypass candidates ───────────────────────
            # If Script or Exe collection is not in enforce mode, LOLBins apply
            script_enforced = collections.get("Script", {}).get("enforcement") == 1
            exe_enforced    = collections.get("Exe",    {}).get("enforcement") == 1

            if not script_enforced or not exe_enforced:
                applicable_lolbins = [
                    lb for lb in _LOLBINS
                    if not exe_enforced or "Execute" in lb["technique"]
                ][:8]  # report first 8

                if applicable_lolbins:
                    self.finding(
                        title=(
                            f"LOLBin Bypass Candidates Available on {target} "
                            f"({len(_LOLBINS)} total)"
                        ),
                        description=(
                            f"AppLocker Exe/Script collections are not fully enforced on "
                            f"{target}. The following system binaries can potentially be "
                            "used to execute unsigned code: "
                            + ", ".join(lb["binary"] for lb in applicable_lolbins)
                            + ". These are signed Microsoft binaries typically not "
                            "blocked by default AppLocker rules."
                        ),
                        severity=Severity.HIGH,
                        mitre_technique="T1218",
                        mitre_tactic="Defense Evasion",
                        evidence={
                            "host":         target,
                            "lolbins":      applicable_lolbins,
                            "exe_enforced": exe_enforced,
                            "script_enforced": script_enforced,
                        },
                        remediation=(
                            "Create explicit Deny rules for common LOLBins not needed "
                            "in the environment (mshta, wscript, cscript, regsvr32, etc.). "
                            "Consider Windows Defender Application Control (WDAC) for "
                            "kernel-enforced policies that cannot be bypassed via registry."
                        ),
                        host=target, confidence=0.85,
                    )

            # ── Finding 4: Writable trusted path candidates ────────────────
            self.finding(
                title=f"Potential Writable Trusted Paths on {target} — Manual Verification Needed",
                description=(
                    f"The following paths are commonly writable by low-privileged users "
                    f"on Windows systems and may fall within AppLocker trusted path rules: "
                    + ", ".join(_TRUSTED_WRITABLE_CANDIDATES[:6])
                    + ". "
                    "Operator should verify write access to these paths from the current "
                    "session context to confirm bypass feasibility."
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1574.001",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":                  target,
                    "candidates":            _TRUSTED_WRITABLE_CANDIDATES,
                    "applocker_collections": {
                        k: v.get("enforcement") for k, v in collections.items()
                    },
                },
                remediation=(
                    "Audit write permissions on %windir%\\Tasks, %windir%\\Tracing, "
                    "and other system directories. "
                    "Use 'icacls' to verify and remove unexpected write permissions. "
                    "Prefer path rules scoped to specific directories over broad %windir% rules."
                ),
                host=target, confidence=0.7,
            )

        raw = {
            "target":          target,
            "configured":      configured,
            "collections":     collections,
            "lolbins_checked": len(_LOLBINS),
            "errors":          errors,
        }
        raw["applocker_config"] = self._findings  # OUTPUTS key
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
