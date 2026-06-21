"""
SNMP Enumeration — Community String Testing + OID Walk
MITRE: T1046, T1590

Tests common SNMP community strings (v1/v2c) and enumerates system information
via SNMP GET/WALK on standard OIDs:
  sysDescr, sysName, sysLocation, sysContact,
  ifTable (network interfaces), hrSWRunTable (running processes),
  hrStorageTable (disk info)

Flags:
  - Default community string "public" or "private" — HIGH severity
  - System info disclosure — MEDIUM
  - Network interface enumeration — INFO

Requires: pip install ares-redteam[network] (adds pysnmp)

OpSec: LOW — SNMP UDP is low-noise but creates log entries on managed devices.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.snmp_enum")

# Community strings to test, ordered by likelihood
_COMMUNITY_STRINGS: list[str] = [
    "public", "private", "community", "manager",
    "admin", "cisco", "monitor", "snmp", "default",
    "read", "write", "access", "guest", "network",
    "security", "system", "secret", "pass", "1234",
]

# Standard OIDs for system enumeration
_OID_MAP: dict[str, str] = {
    "1.3.6.1.2.1.1.1.0":  "sysDescr",       # System description
    "1.3.6.1.2.1.1.3.0":  "sysUpTime",      # Uptime
    "1.3.6.1.2.1.1.4.0":  "sysContact",     # Admin contact
    "1.3.6.1.2.1.1.5.0":  "sysName",        # Hostname
    "1.3.6.1.2.1.1.6.0":  "sysLocation",    # Physical location
    "1.3.6.1.2.1.1.2.0":  "sysObjectID",    # Vendor OID
}

# OID prefixes for table walks
_WALK_OIDS: dict[str, str] = {
    "1.3.6.1.2.1.2.2.1.2":  "ifDescr",         # Interface names
    "1.3.6.1.2.1.2.2.1.3":  "ifType",           # Interface types
    "1.3.6.1.2.1.25.4.2.1.2": "hrSWRunName",   # Running processes
    "1.3.6.1.2.1.25.2.3.1.3": "hrStorageDescr", # Storage descriptions
}


def _snmp_get_sync(host: str, community: str, port: int,
                    oids: list[str], timeout: int = 3) -> dict[str, str]:
    """
    Synchronous pysnmp GET for a list of OIDs.
    Returns dict {oid_name: value}. Empty dict if community wrong or host unreachable.
    """
    try:
        from pysnmp.hlapi import (  # type: ignore[import]
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        return {"_error": "pysnmp not installed — run: pip install pysnmp"}

    results: dict[str, str] = {}
    engine = SnmpEngine()
    for oid in oids:
        error_indication, error_status, _, var_binds = next(
            getCmd(
                engine,
                CommunityData(community, mpModel=1),  # mpModel=1 = SNMPv2c
                UdpTransportTarget((host, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )
        if error_indication or error_status:
            continue
        for var_bind in var_binds:
            label = _OID_MAP.get(oid, oid.split(".")[-1])
            results[label] = str(var_bind[1])
    return results


def _snmp_walk_sync(host: str, community: str, port: int,
                     oid_prefix: str, label: str,
                     max_rows: int = 30, timeout: int = 3) -> list[str]:
    """
    Synchronous pysnmp WALK for a table OID prefix.
    Returns list of string values (up to max_rows).
    """
    try:
        from pysnmp.hlapi import (  # type: ignore[import]
            nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        return []

    rows: list[str] = []
    engine = SnmpEngine()
    for error_indication, error_status, _, var_binds in nextCmd(
        engine,
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, port), timeout=timeout, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid_prefix)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            break
        for var_bind in var_binds:
            val = str(var_bind[1]).strip()
            if val and val not in rows:
                rows.append(val)
        if len(rows) >= max_rows:
            break
    return rows


class SnmpEnumModule(BaseModule):
    """
    network.snmp_enum — Test common SNMP community strings and enumerate system info via OID walk — identifies default c

    OPSEC: LOW
    MITRE: "T1046", "T1590"
    OUTPUTS:  "snmp_findings", "system_info"
    """
    MODULE_ID          = "network.snmp_enum"
    MODULE_NAME        = "SNMP Enumeration"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "Test common SNMP community strings and enumerate system info via OID walk — "
        "identifies default credentials, system details, interfaces, and running processes"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["snmp_findings", "system_info"]
    MITRE_TECHNIQUES   = ["T1046", "T1590"]

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
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True,
                                     "target": getattr(ctx, "target", "")})
        target = getattr(ctx, "target", ctx.params.get("target", ""))
        findings, raw = await self.run(target=target, **ctx.params)
        return ModuleResult(
            status="success" if (findings or raw.get("valid_communities")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.snmp_enum")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target      = kwargs.get("target", "")
        port        = int(kwargs.get("snmp_port", 161))
        dry_run     = kwargs.get("dry_run", False)
        communities = kwargs.get("communities") or _COMMUNITY_STRINGS
        do_walk     = kwargs.get("walk", True)    # Walk tables for deeper enum

        if not target:
            return [], {"error": "no_target"}
        if dry_run:
            return [], {"dry_run": True, "target": target}

        await self.before_request(target, "snmp")  # scope check + jitter

        logger.info("snmp_enum_start", target=target, port=port,
                    community_count=len(communities))
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        loop = asyncio.get_running_loop()
        valid_communities: list[dict[str, Any]] = []
        system_info: dict[str, Any] = {}

        # ── Test each community string ─────────────────────────────────────────
        for community in communities:
            await self.noise.jitter.sleep()
            result = await loop.run_in_executor(
                None,
                lambda c=community: _snmp_get_sync(
                    target, c, port, list(_OID_MAP.keys())
                )
            )

            if result.get("_error"):
                # pysnmp not installed — stop here
                return [], {"error": result["_error"]}

            if not result:
                continue  # Community string wrong or host unreachable

            # Valid community string found
            entry: dict[str, Any] = {
                "community":   community,
                "system_info": result,
            }

            # ── Walk tables for deeper enumeration ─────────────────────────────
            if do_walk:
                for oid_prefix, label in _WALK_OIDS.items():
                    rows = await loop.run_in_executor(
                        None,
                        lambda op=oid_prefix, lbl=label: _snmp_walk_sync(
                            target, community, port, op, lbl
                        )
                    )
                    if rows:
                        entry[label] = rows

            valid_communities.append(entry)
            system_info = result  # Use last valid community's info for summary
            logger.info("snmp_valid_community",
                        target=target, community=community,
                        sys_name=result.get("sysName", "?"))

            # Emit finding
            is_default = community.lower() in ("public", "private")
            sev = Severity.HIGH if is_default else Severity.MEDIUM
            self.finding(
                title=f"SNMP Valid Community String '{community}' on {target}:{port}",
                description=(
                    f"SNMP community string '{community}' is accepted by {target}. "
                    f"{'This is a DEFAULT community string.' if is_default else ''} "
                    f"System: {result.get('sysName', 'unknown')} — "
                    f"{result.get('sysDescr', '')[:150]}"
                ),
                severity=sev,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence={
                    "host":        target,
                    "port":        port,
                    "community":   community,
                    "is_default":  is_default,
                    "system_info": result,
                },
                remediation=(
                    "Change all SNMP community strings from default values. "
                    "Use long random strings (20+ chars). "
                    "Upgrade to SNMPv3 with authentication and privacy (AES). "
                    "Restrict SNMP access by source IP via ACL. "
                    "If SNMP is not needed, disable the service entirely."
                ),
                host=target,
                confidence=1.0,
            )

            # Don't spray all community strings if we found one
            # (stay low-noise — operator can re-run with specific communities if needed)
            break

        # ── System info finding if sysLocation/sysContact found ───────────────
        if system_info.get("sysLocation") or system_info.get("sysContact"):
            self.finding(
                title=f"SNMP System Information Disclosed: {system_info.get('sysName', target)}",
                description=(
                    "SNMP enumeration revealed system details that assist in targeting. "
                    f"Name: {system_info.get('sysName', 'unknown')} | "
                    f"Location: {system_info.get('sysLocation', 'unknown')} | "
                    f"Contact: {system_info.get('sysContact', 'unknown')}"
                ),
                severity=Severity.LOW,
                mitre_technique="T1590",
                mitre_tactic="Reconnaissance",
                evidence={"host": target, "system_info": system_info},
                remediation=(
                    "Remove sysLocation and sysContact from SNMP configuration if not required. "
                    "Ensure sysDescr does not disclose OS version or vendor information."
                ),
                host=target,
                confidence=0.95,
            )

        raw = {
            "target":             target,
            "port":               port,
            "valid_communities":  valid_communities,
            "system_info":        system_info,
            "communities_tested": len(communities),
        }
        raw["snmp_findings"] = self._findings  # OUTPUTS key
        return self._findings[:], raw
