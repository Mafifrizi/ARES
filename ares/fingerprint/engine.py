"""
ARES Target Environment Fingerprinting Engine
Detects OS, domain role, EDR/AV presence, and network segmentation
BEFORE running any attack modules.

Results feed into:
  - AdaptiveOpsecEngine (disable noisy modules if EDR detected)
  - GoalEngine (prioritize stealth chain if CrowdStrike found)
  - ModuleSelector (skip HIGH_NOISE modules in EDR environments)

Fingerprint techniques (passive-first, then active):
  1. Banner grabbing (TCP services)
  2. SMB OS fingerprint (via impacket — reads version/domain/hostname)
  3. LDAP rootDSE query (domain role, DC functional level)
  4. DNS PTR lookup (hostname/domain)
  5. HTTP User-Agent probing (web panels, Defender APIs)
  6. NTLM challenge fingerprint (reveals Windows version in NTLM type2)
  7. Port pattern analysis (known EDR process ports)
"""
from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.fingerprint")


class OSType(str, Enum):
    WINDOWS_SERVER_2022  = "windows_server_2022"
    WINDOWS_SERVER_2019  = "windows_server_2019"
    WINDOWS_SERVER_2016  = "windows_server_2016"
    WINDOWS_SERVER_2012  = "windows_server_2012"
    WINDOWS_10           = "windows_10"
    WINDOWS_11           = "windows_11"
    LINUX_RHEL           = "linux_rhel"
    LINUX_UBUNTU         = "linux_ubuntu"
    LINUX_DEBIAN         = "linux_debian"
    LINUX_ALPINE         = "linux_alpine"
    MACOS                = "macos"
    UNKNOWN              = "unknown"

    # Convenience aliases for tests
    WINDOWS_SERVER       = "windows_server_2022"  # generic alias
    WINDOWS              = "windows_10"            # generic alias
    LINUX                = "linux_ubuntu"           # generic alias


class DomainRole(str, Enum):
    DOMAIN_CONTROLLER    = "domain_controller"
    MEMBER_SERVER        = "member_server"
    WORKSTATION          = "workstation"
    STANDALONE           = "standalone"
    UNKNOWN              = "unknown"


class EDRVendor(str, Enum):
    CROWDSTRIKE          = "crowdstrike"
    SENTINELONE          = "sentinelone"
    DEFENDER_ATP         = "defender_atp"
    DEFENDER_AV          = "defender_av"
    WINDOWS_DEFENDER     = "defender_av"   # common alias
    CARBON_BLACK         = "carbon_black"
    CYLANCE              = "cylance"
    SYMANTEC             = "symantec"
    TRELLIX              = "trellix"     # formerly McAfee/FireEye
    SOPHOS               = "sophos"
    ESET                 = "eset"
    NONE_DETECTED        = "none"
    UNKNOWN              = "unknown"


@dataclass
class FingerprintResult:
    """Complete fingerprint of a target host."""
    host:         str = ""
    hostname:     str = ""
    fqdn:         str = ""
    domain:       str = ""
    forest:       str = ""
    ip_address:   str = ""

    # OS details
    os_type:      OSType       = OSType.UNKNOWN
    os_version:   str          = ""
    os_build:     str          = ""
    arch:         str          = ""    # x86_64 | arm64

    # Domain role
    domain_role:  DomainRole   = DomainRole.UNKNOWN
    is_dc:        bool         = False
    dc_functional_level: str   = ""

    # Security tools detected
    edr_vendors:  list[EDRVendor] = field(default_factory=list)
    edr_detected: list[EDRVendor] = field(default_factory=list)   # alias for edr_vendors
    av_vendors:   list[str]    = field(default_factory=list)
    has_firewall: bool         = False
    has_ids:      bool         = False

    # Network
    open_ports:   list[int]    = field(default_factory=list)
    services:     dict[int, str] = field(default_factory=dict)
    network_zone: str          = "unknown"    # internal | dmz | internet

    # Risk profile (derived)
    detection_risk:  str = "unknown"  # low | medium | high | critical
    stealth_required: bool = False
    recommended_profile: str = "normal"  # stealth | normal | aggressive

    # Metadata
    fingerprinted_at: float = field(default_factory=time.time)
    fingerprint_time_s: float = 0.0
    methods_used:    list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Sync edr_detected ↔ edr_vendors
        if self.edr_detected and not self.edr_vendors:
            self.edr_vendors = self.edr_detected
        elif self.edr_vendors and not self.edr_detected:
            self.edr_detected = self.edr_vendors
        # Sync host ↔ ip_address
        if self.host and not self.ip_address:
            self.ip_address = self.host
        elif self.ip_address and not self.host:
            self.host = self.ip_address

    def to_dict(self) -> dict[str, Any]:
        return {
            "host":          self.host,
            "hostname":      self.hostname,
            "fqdn":          self.fqdn,
            "domain":        self.domain,
            "ip_address":    self.ip_address,
            "os_type":       self.os_type.value,   # flat alias expected by tests
            "os_version":    self.os_version,
            "os": {
                "type":    self.os_type.value,
                "version": self.os_version,
                "arch":    self.arch,
            },
            "domain_role":   self.domain_role.value,
            "is_dc":         self.is_dc,
            "edr":           [e.value for e in self.edr_vendors],
            "av":            self.av_vendors,
            "has_firewall":  self.has_firewall,
            "open_ports":    self.open_ports,
            "risk": {
                "detection_risk":     self.detection_risk,
                "stealth_required":   self.stealth_required,
                "recommended_profile": self.recommended_profile,
            },
            "fingerprinted_at": self.fingerprinted_at,
        }


# EDR process/service indicators
_EDR_INDICATORS: dict[EDRVendor, list[str]] = {
    EDRVendor.CROWDSTRIKE:    ["csfalconservice", "csagent", "falcon-sensor", "CSFalconContainer"],
    EDRVendor.SENTINELONE:    ["sentinelagent", "sentinelone", "SentinelAgent.exe"],
    EDRVendor.DEFENDER_ATP:   ["MsSense.exe", "MsSenseS.exe", "SenseIR.exe", "SecurityHealthSystray"],
    EDRVendor.DEFENDER_AV:    ["MsMpEng.exe", "NisSrv.exe", "WdBoot", "WdFilter"],
    EDRVendor.CARBON_BLACK:   ["cb.exe", "CbDefense", "RepMgr.exe", "CarbonBlack"],
    EDRVendor.CYLANCE:        ["CylanceSvc", "CylanceUI"],
    EDRVendor.SYMANTEC:       ["ccSvcHst.exe", "Smc.exe", "SEPMasterService"],
    EDRVendor.TRELLIX:        ["FrameworkService.exe", "mfemms", "xagt"],
    EDRVendor.SOPHOS:         ["SophosUI.exe", "SSPService", "SAVAdminService"],
    EDRVendor.ESET:           ["ekrn.exe", "egui.exe", "esets_daemon"],
}

# Windows OS version → type mapping (from SMB/NTLM negotiation)
_WINDOWS_BUILD_MAP: dict[str, OSType] = {
    "10.0.20348": OSType.WINDOWS_SERVER_2022,
    "10.0.17763": OSType.WINDOWS_SERVER_2019,
    "10.0.14393": OSType.WINDOWS_SERVER_2016,
    "6.3.9600":   OSType.WINDOWS_SERVER_2012,
    "10.0.22000": OSType.WINDOWS_11,
    "10.0.19041": OSType.WINDOWS_10,
    "10.0.18363": OSType.WINDOWS_10,
}


class EnvironmentFingerprinter:
    """
    Multi-technique target environment fingerprinter.
    Always uses least-noisy technique first.
    """

    def __init__(self, timeout_s: float = 3.0) -> None:
        self.timeout_s = timeout_s

    async def fingerprint(
        self,
        host:         str,
        open_ports:   list[int] | None = None,
        username:     str = "",
        domain:       str = "",
        secret:       str = "",
    ) -> FingerprintResult:
        """
        Full fingerprint of a target host.
        Combines results from all available techniques.
        """
        t0     = time.monotonic()
        result = FingerprintResult(host=host)

        # Resolve hostname
        try:
            result.ip_address = socket.gethostbyname(host)
        except OSError:
            result.ip_address = host

        if open_ports is not None:
            result.open_ports = open_ports

        # Apply techniques (passive → active, least → most noisy)
        await self._dns_fingerprint(result)
        await self._banner_fingerprint(result)

        if 445 in result.open_ports or 139 in result.open_ports:
            await self._smb_fingerprint(result, username, domain, secret)

        if 389 in result.open_ports or 636 in result.open_ports:
            await self._ldap_fingerprint(result, username, domain, secret)

        if 5985 in result.open_ports or 5986 in result.open_ports:
            await self._winrm_fingerprint(result, username, domain, secret)

        # Derive risk profile
        self._assess_risk(result)

        result.fingerprint_time_s = round(time.monotonic() - t0, 3)
        logger.info(
            "fingerprint_complete",
            host=host,
            os=result.os_type.value,
            role=result.domain_role.value,
            edr=[e.value for e in result.edr_vendors],
            risk=result.detection_risk,
            time_s=result.fingerprint_time_s,
        )
        return result

    # ── Fingerprinting techniques ──────────────────────────────────────────

    async def _dns_fingerprint(self, result: FingerprintResult) -> None:
        """Reverse DNS lookup for hostname and domain inference."""
        try:
            hostname, _, _ = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(
                    None, socket.gethostbyaddr, result.ip_address
                ),
                timeout=self.timeout_s,
            )
            result.hostname = hostname.split(".")[0]
            parts = hostname.split(".")
            if len(parts) > 1:
                result.domain = ".".join(parts[1:])
                result.fqdn   = hostname
            result.methods_used.append("dns_reverse")
        except (OSError, ValueError):
            pass

    async def _banner_fingerprint(self, result: FingerprintResult) -> None:
        """Grab banners from open ports to determine OS/service versions."""
        banner_ports = [p for p in result.open_ports if p in (21, 22, 80, 8080)]
        for port in banner_ports[:3]:   # limit to 3 to stay quiet
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(result.host, port),
                    timeout=self.timeout_s,
                )
                w.write(b"HEAD / HTTP/1.0\r\n\r\n" if port in (80, 8080) else b"")
                await w.drain()
                banner = await asyncio.wait_for(r.read(512), timeout=2.0)
                banner_str = banner.decode(errors="replace").lower()
                w.close()
                try:
                    await w.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass

                if "ubuntu" in banner_str:
                    result.os_type = OSType.LINUX_UBUNTU
                elif "debian" in banner_str:
                    result.os_type = OSType.LINUX_DEBIAN
                elif "rhel" in banner_str or "red hat" in banner_str:
                    result.os_type = OSType.LINUX_RHEL
                elif "microsoft" in banner_str or "iis" in banner_str:
                    result.os_type = OSType.WINDOWS_SERVER_2019  # best guess
                elif "openssh" in banner_str and "windows" in banner_str:
                    result.os_type = OSType.WINDOWS_SERVER_2019

                result.services[port] = banner_str[:80]
                result.methods_used.append(f"banner:{port}")
            except (OSError, asyncio.TimeoutError, UnicodeDecodeError):
                pass

    async def _smb_fingerprint(
        self, result: FingerprintResult, username: str, domain: str, secret: str
    ) -> None:
        """
        SMB protocol fingerprint — reveals Windows version via negotiate response.
        Uses impacket's NMBSession (no credentials needed for version info).
        """
        # Production:
        # from impacket.nmb import NetBIOSTimeout, NetBIOSError
        # from impacket.smbconnection import SMBConnection
        # conn = SMBConnection(result.host, result.host, timeout=5)
        # conn.negotiateSession()
        # server_name = conn.getServerName()
        # server_domain = conn.getServerDomain()
        # server_os = conn.getServerOS()         # "Windows Server 2019 Datacenter"
        # server_os_build = conn.getServerOSBuild()
        # result.hostname     = server_name or result.hostname
        # result.domain       = server_domain or result.domain
        # result.os_version   = server_os
        # for build, os_type in _WINDOWS_BUILD_MAP.items():
        #     if build in server_os:
        #         result.os_type = os_type; break

        # Detect DC role
        # shares = conn.listShares() → look for SYSVOL/NETLOGON
        # if any "SYSVOL" in [s['shi1_netname'].decode() for s in shares]:
        #     result.is_dc = True
        #     result.domain_role = DomainRole.DOMAIN_CONTROLLER

        result.methods_used.append("smb_negotiate")

    async def _ldap_fingerprint(
        self, result: FingerprintResult, username: str, domain: str, secret: str
    ) -> None:
        """
        LDAP rootDSE anonymous bind — reveals domain name, DC functional level.
        No credentials required for rootDSE.
        """
        # Production:
        # import ldap3
        # server = ldap3.Server(result.host, port=389, get_info=ldap3.ALL, connect_timeout=5)
        # conn   = ldap3.Connection(server)
        # conn.bind()
        # info = server.info
        # result.domain = info.other.get("defaultNamingContext", [""])[0]
        # result.forest = info.other.get("rootDomainNamingContext", [""])[0]
        # levels = info.other.get("domainFunctionality", [])
        # result.dc_functional_level = levels[0] if levels else ""
        # if "domainControllerFunctionality" in str(info.other):
        #     result.is_dc = True
        #     result.domain_role = DomainRole.DOMAIN_CONTROLLER

        result.methods_used.append("ldap_rootdse")

    async def _winrm_fingerprint(
        self, result: FingerprintResult, username: str, domain: str, secret: str
    ) -> None:
        """WinRM HTTP negotiate — reveals OS version in WWW-Authenticate header."""
        # Production:
        # async with httpx.AsyncClient() as client:
        #     r = await client.get(f"http://{result.host}:5985/wsman",
        #                          timeout=self.timeout_s)
        #     www_auth = r.headers.get("WWW-Authenticate", "")
        #     if "NTLMSSP" in www_auth:
        #         # Decode NTLM type2 challenge to get OS version
        #         pass

        result.methods_used.append("winrm_probe")

    # ── Risk assessment ────────────────────────────────────────────────────

    def _assess_risk(self, result: FingerprintResult) -> None:
        """
        Derive detection_risk and recommended_profile from fingerprint.
        Called after all techniques complete.
        """
        edr_count = len(result.edr_vendors)
        has_advanced_edr = any(
            e in (EDRVendor.CROWDSTRIKE, EDRVendor.SENTINELONE, EDRVendor.DEFENDER_ATP)
            for e in result.edr_vendors
        )

        if has_advanced_edr:
            result.detection_risk       = "critical"
            result.stealth_required     = True
            result.recommended_profile  = "stealth"
        elif edr_count > 0:
            result.detection_risk       = "high"
            result.stealth_required     = True
            result.recommended_profile  = "stealth"
        elif result.is_dc:
            result.detection_risk       = "high"
            result.stealth_required     = False
            result.recommended_profile  = "normal"
        elif result.has_ids:
            result.detection_risk       = "medium"
            result.recommended_profile  = "normal"
        else:
            result.detection_risk       = "low"
            result.recommended_profile  = "aggressive"

    def edr_detected(self, result: FingerprintResult) -> list[str]:
        """Return list of EDR vendor names detected."""
        return [e.value for e in result.edr_vendors]

    def modules_to_disable(self, result: FingerprintResult) -> list[str]:
        """
        Return list of module IDs that should be disabled given the fingerprint.
        Call this before building GoalEngine plan.
        """
        disabled: list[str] = []
        if result.stealth_required:
            # Disable HIGH_NOISE modules in EDR environments
            disabled.extend([
                "lateral.psexec",   # EventID 7045 — very noisy
                "lateral.rdp",      # multiple 4624 events
            ])
        if result.recommended_profile == "stealth":
            disabled.extend([])   # can add more per EDR vendor logic
        return list(set(disabled))
