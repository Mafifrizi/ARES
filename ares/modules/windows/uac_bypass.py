"""
Windows UAC Configuration Audit & Bypass Technique Enumeration
MITRE: T1548.002 (Bypass User Account Control)

Connects to target via impacket remote registry to read UAC configuration:
  - EnableLUA         — whether UAC is enabled at all
  - ConsentPromptBehaviorAdmin  — UAC consent level (0–5)
  - PromptOnSecureDesktop       — whether secure desktop is used

Based on OS version and UAC level, reports which bypass techniques
are applicable (fodhelper, sdclt, eventvwr, etc.).

This module is DETECTION AND ENUMERATION ONLY.
It does NOT perform any bypass or privilege escalation.
Operator must assess findings and decide on further action.

OPSEC: LOW — reads registry remotely, no process execution on target.
Generates: Event 4688 (process creation, if auditing enabled) when
impacket opens SMB connection. No more.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.windows.uac_bypass")


# ── UAC consent level descriptions ────────────────────────────────────────────
_CONSENT_LEVEL: dict[int, tuple[str, str]] = {
    0: ("No UAC prompt — silently elevates",              "CRITICAL"),
    1: ("Prompt for credentials on secure desktop",       "MEDIUM"),
    2: ("Prompt for consent on secure desktop",           "MEDIUM"),
    3: ("Prompt for credentials (no secure desktop)",     "HIGH"),
    4: ("Prompt for consent (no secure desktop)",         "HIGH"),
    5: ("Default — prompt only for non-Windows binaries", "HIGH"),
}

# ── Bypass techniques per Windows version & UAC level ─────────────────────────
# Keyed by (os_major, os_minor, build_min) → list of applicable technique names
# Only techniques that bypass UAC WITHOUT requiring a prompt or credential.
# Source: https://attack.mitre.org/techniques/T1548/002/
_BYPASS_TECHNIQUES: list[dict[str, Any]] = [
    {
        "name":         "fodhelper.exe",
        "description":  "Auto-elevated COM object abuse via HKCU\\Software\\Classes\\ms-settings",
        "os_min_build": 14393,   # Windows 10 1607+
        "max_consent":  5,        # works at all default UAC levels
        "mitre":        "T1548.002",
        "reference":    "https://attack.mitre.org/techniques/T1548/002/",
    },
    {
        "name":         "sdclt.exe",
        "description":  "sdclt.exe IsolatedCommand registry key bypass",
        "os_min_build": 14393,
        "max_consent":  5,
        "mitre":        "T1548.002",
        "reference":    "https://attack.mitre.org/techniques/T1548/002/",
    },
    {
        "name":         "eventvwr.exe",
        "description":  "Event Viewer COM object HKCU registry hijack",
        "os_min_build": 7600,    # Windows 7+
        "max_consent":  5,
        "mitre":        "T1548.002",
        "reference":    "https://attack.mitre.org/techniques/T1548/002/",
    },
    {
        "name":         "cmstp.exe",
        "description":  "CMSTP auto-elevated INF file execution",
        "os_min_build": 7600,
        "max_consent":  4,        # does not work when consent level ≤ 2 (secure desktop)
        "mitre":        "T1548.002",
        "reference":    "https://attack.mitre.org/techniques/T1548/002/",
    },
    {
        "name":         "DISMHost / CompMgmtLauncher",
        "description":  "Auto-elevated binary hijack via writable PATH or DLL",
        "os_min_build": 9200,    # Windows 8+
        "max_consent":  5,
        "mitre":        "T1548.002",
        "reference":    "https://attack.mitre.org/techniques/T1548/002/",
    },
]


class UACBypassModule(BaseModule):
    """
    windows.uac_bypass — Read UAC configuration via remote registry and enumerate applicable bypass techniques — detectio

    OPSEC: LOW
    MITRE: "T1548.002", "T1082"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "uac_config", "privesc_vectors"
    """
    MODULE_ID          = "windows.uac_bypass"
    MODULE_NAME        = "UAC Configuration Audit"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Read UAC configuration via remote registry and enumerate "
        "applicable bypass techniques — detection and enumeration only"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["uac_config", "privesc_vectors"]
    MITRE_TECHNIQUES   = ["T1548.002", "T1082"]

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

    @trace_module("windows.uac_bypass")
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
                hOpenLocalMachine, hBaseRegOpenKey, hBaseRegQueryValue,
                hBaseRegCloseKey,
            )
        except ImportError:
            return [], {"error": "impacket not installed — pip install ares-redteam[ad]"}

        logger.info("uac_bypass_audit_start", target=target, username=username)
        audit("uac_audit", actor=username, source="operator",
              target=target, technique="T1082")

        await self.before_request(target, "smb")

        uac_data:  dict[str, Any] = {}
        os_info:   dict[str, Any] = {}
        loop = asyncio.get_running_loop()

        def _read_registry() -> dict[str, Any]:
            """Read UAC and OS version settings via remote registry."""
            result: dict[str, Any] = {
                "uac": {}, "os": {}, "errors": []
            }
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

                # ── Read UAC settings ──────────────────────────────────────
                uac_reg_path = (
                    "SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System"
                )
                try:
                    ans    = hOpenLocalMachine(dce)
                    hklm   = ans["phKey"]
                    ans2   = hBaseRegOpenKey(dce, hklm, uac_reg_path)
                    hkey   = ans2["phkResult"]

                    for val_name in (
                        "EnableLUA",
                        "ConsentPromptBehaviorAdmin",
                        "PromptOnSecureDesktop",
                        "EnableVirtualization",
                        "FilterAdministratorToken",
                    ):
                        try:
                            ans3 = hBaseRegQueryValue(dce, hkey, val_name)
                            result["uac"][val_name] = ans3[1]
                        except Exception:
                            pass

                    hBaseRegCloseKey(dce, hkey)
                    hBaseRegCloseKey(dce, hklm)
                except Exception as e:
                    result["errors"].append(f"UAC registry: {e!s:.100}")

                # ── Read OS version via registry ───────────────────────────
                os_reg_path = (
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                )
                try:
                    ans    = hOpenLocalMachine(dce)
                    hklm   = ans["phKey"]
                    ans2   = hBaseRegOpenKey(dce, hklm, os_reg_path)
                    hkey   = ans2["phkResult"]

                    for val_name in (
                        "CurrentBuildNumber",
                        "CurrentVersion",
                        "ProductName",
                        "ReleaseId",
                        "DisplayVersion",
                    ):
                        try:
                            ans3 = hBaseRegQueryValue(dce, hkey, val_name)
                            result["os"][val_name] = ans3[1]
                        except Exception:
                            pass

                    hBaseRegCloseKey(dce, hkey)
                    hBaseRegCloseKey(dce, hklm)
                except Exception as e:
                    result["errors"].append(f"OS registry: {e!s:.100}")

            except Exception as e:
                result["errors"].append(str(e)[:200])
            finally:
                if dce:
                    try: dce.disconnect()
                    except Exception: pass
                if smb:
                    try: smb.logoff()
                    except Exception: pass
            return result

        reg_data = await loop.run_in_executor(None, _read_registry)
        uac_data = reg_data.get("uac", {})
        os_info  = reg_data.get("os", {})
        errors   = reg_data.get("errors", [])

        # ── Analyse UAC configuration ──────────────────────────────────────
        uac_enabled    = bool(uac_data.get("EnableLUA", 1))
        consent_level  = int(uac_data.get("ConsentPromptBehaviorAdmin", 5))
        secure_desktop = bool(uac_data.get("PromptOnSecureDesktop", 1))

        try:
            build = int(os_info.get("CurrentBuildNumber", "0"))
        except (ValueError, TypeError):
            build = 0

        product = os_info.get("ProductName", "Unknown Windows")

        # ── Finding 1: UAC disabled entirely ──────────────────────────────
        if not uac_enabled:
            self.finding(
                title=f"UAC Disabled on {target}",
                description=(
                    f"User Account Control (UAC) is completely disabled on {target} "
                    f"({product}). "
                    "Any process run by a local administrator already runs with "
                    "full elevation — no bypass needed. "
                    "This is a severe misconfiguration on any server or workstation."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1548.002",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":          target,
                    "EnableLUA":     uac_enabled,
                    "os":            product,
                    "build":         build,
                },
                remediation=(
                    "Enable UAC: Set HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System\\EnableLUA = 1 "
                    "and reboot. "
                    "Group Policy: Computer Configuration → Windows Settings → "
                    "Security Settings → Local Policies → Security Options → "
                    "'User Account Control: Run all administrators in Admin Approval Mode'"
                ),
                host=target, confidence=1.0,
            )

        # ── Finding 2: UAC level assessment ───────────────────────────────
        elif uac_enabled and consent_level in _CONSENT_LEVEL:
            desc_text, sev_str = _CONSENT_LEVEL[consent_level]
            sev_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH":     Severity.HIGH,
                "MEDIUM":   Severity.MEDIUM,
            }
            sev = sev_map.get(sev_str, Severity.MEDIUM)

            # Secure desktop off = easier to spoof prompt
            extra = ""
            if not secure_desktop:
                extra = (
                    " PromptOnSecureDesktop is DISABLED — "
                    "UAC prompt appears on regular desktop, "
                    "making it susceptible to UI spoofing attacks."
                )

            self.finding(
                title=(
                    f"UAC Level {consent_level} on {target}: "
                    f"{desc_text.split(' — ')[0]}"
                ),
                description=(
                    f"{target} ({product} build {build}) has UAC enabled "
                    f"at ConsentPromptBehaviorAdmin={consent_level}: {desc_text}.{extra}"
                ),
                severity=sev,
                mitre_technique="T1548.002",
                mitre_tactic="Privilege Escalation",
                evidence={
                    "host":                        target,
                    "EnableLUA":                   uac_enabled,
                    "ConsentPromptBehaviorAdmin":   consent_level,
                    "PromptOnSecureDesktop":        secure_desktop,
                    "os":                          product,
                    "build":                       build,
                },
                remediation=(
                    "Set ConsentPromptBehaviorAdmin=2 and PromptOnSecureDesktop=1 "
                    "for the most secure UAC configuration. "
                    "Consider using Protected Users security group for admins."
                ),
                host=target, confidence=1.0,
            )

        # ── Finding 3: Enumerate applicable bypass techniques ──────────────
        if uac_enabled and build > 0:
            applicable = [
                t for t in _BYPASS_TECHNIQUES
                if build >= t["os_min_build"]
                and consent_level <= t["max_consent"]
            ]
            if applicable:
                technique_names = [t["name"] for t in applicable]
                self.finding(
                    title=(
                        f"{len(applicable)} UAC Bypass Technique(s) Applicable "
                        f"on {target} (build {build})"
                    ),
                    description=(
                        f"Based on OS build {build} ({product}) and UAC level "
                        f"{consent_level}, the following bypass techniques are "
                        f"applicable: {', '.join(technique_names)}. "
                        "These techniques allow elevation from a standard admin "
                        "account to a high-integrity process without a UAC prompt."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1548.002",
                    mitre_tactic="Privilege Escalation",
                    evidence={
                        "host":        target,
                        "os_build":    build,
                        "uac_level":   consent_level,
                        "techniques":  applicable,
                    },
                    remediation=(
                        "Set UAC to 'Always notify' (ConsentPromptBehaviorAdmin=2) "
                        "and enable Secure Desktop (PromptOnSecureDesktop=1). "
                        "Patch Windows regularly — many bypass techniques are "
                        "periodically patched by Microsoft."
                    ),
                    host=target, confidence=0.9,
                )

        raw = {
            "target":          target,
            "os":              os_info,
            "uac_config":      uac_data,
            "uac_enabled":     uac_enabled,
            "consent_level":   consent_level,
            "secure_desktop":  secure_desktop,
            "os_build":        build,
            "errors":          errors,
        }
        raw["privesc_vectors"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
