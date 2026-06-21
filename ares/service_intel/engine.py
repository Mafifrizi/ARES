"""
ARES Service Intelligence Engine
Discovers open ports, maps them to services, recommends attack modules.

Port → Service → Attack Module mapping:

  port 22   → ssh    → lateral.ssh_pivot, linux.privesc
  port 80   → http   → web recon modules
  port 135  → msrpc  → ad.enum_users (DCOM)
  port 139  → netbios-ssn → ad.enum_users, lateral.psexec
  port 389  → ldap   → ad.enum_users, ad.enum_spn, ad.enum_acl
  port 443  → https  → cloud modules, web recon
  port 445  → smb    → lateral.psexec, lateral.wmiexec, ad.enum_users
  port 636  → ldaps  → ad.enum_users (secure)
  port 1433 → mssql  → credential reuse
  port 1521 → oracle → credential reuse
  port 3306 → mysql  → credential reuse
  port 3389 → rdp    → lateral.rdp
  port 5432 → postgres → credential reuse
  port 5985 → winrm  → lateral.winrm
  port 5986 → winrm-ssl → lateral.winrm
  port 6379 → redis  → data exfil
  port 8080 → http-alt → web recon
  port 8443 → https-alt → web recon
  port 27017 → mongodb → credential reuse, data exfil

Usage:
    intel = ServiceIntelEngine()
    scan_result = await intel.scan_host("10.0.0.1")
    modules = intel.recommend_modules(scan_result)
"""
from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from ares.core.logger import get_logger
from ares.state.target_state import HostState, ServiceEntry

logger = get_logger("ares.service_intel")


# ── Service mapping ────────────────────────────────────────────────────────────

@dataclass
class ServiceProfile:
    """Profile of a known service with associated attack modules."""
    service_name:    str = ""
    port:            int = 0        # primary port for this service
    protocol:        str = "tcp"    # tcp | udp
    description:     str = ""
    attack_modules:  list[str] = field(default_factory=list)  # module IDs that can attack this service
    cred_types:      list[str] = field(default_factory=list)  # credential types that work here
    opsec_risk:      str = "medium"  # low | medium | high — how noisy attacking this is
    mitre_techniques: list[str] = field(default_factory=list)


# Master port → service → modules map
PORT_SERVICE_MAP: dict[int, ServiceProfile] = {
    21: ServiceProfile(
        service_name="ftp", description="File Transfer Protocol",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="low", mitre_techniques=["T1021.005"],
    ),
    22: ServiceProfile(
        service_name="ssh", description="Secure Shell",
        attack_modules=["lateral.ssh_pivot", "linux.privesc"],
        cred_types=["cleartext", "ssh_key"],
        opsec_risk="low", mitre_techniques=["T1021.004"],
    ),
    23: ServiceProfile(
        service_name="telnet", description="Telnet (legacy)",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="low", mitre_techniques=["T1021"],
    ),
    80: ServiceProfile(
        service_name="http", description="HTTP web server",
        attack_modules=[], cred_types=["cleartext", "cookie", "jwt"],
        opsec_risk="low", mitre_techniques=["T1190"],
    ),
    135: ServiceProfile(
        service_name="msrpc", description="Microsoft RPC / DCOM",
        attack_modules=["ad.enum_users", "lateral.wmiexec"],
        cred_types=["ntlm", "cleartext"],
        opsec_risk="medium", mitre_techniques=["T1047", "T1135"],
    ),
    139: ServiceProfile(
        service_name="netbios-ssn", description="NetBIOS Session Service",
        attack_modules=["lateral.psexec", "ad.enum_users"],
        cred_types=["ntlm", "cleartext"],
        opsec_risk="medium", mitre_techniques=["T1021.002"],
    ),
    389: ServiceProfile(
        service_name="ldap", description="Active Directory LDAP",
        attack_modules=["ad.enum_users", "ad.enum_spn", "ad.enum_acl", "ad.enum_computers"],
        cred_types=["cleartext", "ntlm"],
        opsec_risk="low", mitre_techniques=["T1087.002", "T1201"],
    ),
    443: ServiceProfile(
        service_name="https", description="HTTPS web server",
        attack_modules=[], cred_types=["cleartext", "cookie", "jwt", "certificate"],
        opsec_risk="low", mitre_techniques=["T1190"],
    ),
    445: ServiceProfile(
        service_name="smb", description="SMB / CIFS file sharing",
        attack_modules=["lateral.psexec", "lateral.wmiexec", "ad.enum_users", "ad.enum_computers"],
        cred_types=["ntlm", "cleartext"],
        opsec_risk="medium", mitre_techniques=["T1021.002", "T1135"],
    ),
    636: ServiceProfile(
        service_name="ldaps", description="Active Directory LDAPS (secure)",
        attack_modules=["ad.enum_users", "ad.enum_spn", "ad.enum_acl"],
        cred_types=["cleartext", "ntlm", "certificate"],
        opsec_risk="low", mitre_techniques=["T1087.002"],
    ),
    1433: ServiceProfile(
        service_name="mssql", description="Microsoft SQL Server",
        attack_modules=[], cred_types=["cleartext", "ntlm"],
        opsec_risk="medium", mitre_techniques=["T1505.001"],
    ),
    1521: ServiceProfile(
        service_name="oracle", description="Oracle Database",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="medium", mitre_techniques=[],
    ),
    3306: ServiceProfile(
        service_name="mysql", description="MySQL Database",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="medium", mitre_techniques=[],
    ),
    3389: ServiceProfile(
        service_name="rdp", description="Remote Desktop Protocol",
        attack_modules=["lateral.rdp"],
        cred_types=["cleartext", "ntlm"],
        opsec_risk="high", mitre_techniques=["T1021.001"],
    ),
    5432: ServiceProfile(
        service_name="postgresql", description="PostgreSQL Database",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="medium", mitre_techniques=[],
    ),
    5985: ServiceProfile(
        service_name="winrm", description="WinRM / PowerShell Remoting (HTTP)",
        attack_modules=["lateral.winrm"],
        cred_types=["cleartext", "ntlm"],
        opsec_risk="medium", mitre_techniques=["T1021.006"],
    ),
    5986: ServiceProfile(
        service_name="winrm-ssl", description="WinRM / PowerShell Remoting (HTTPS)",
        attack_modules=["lateral.winrm"],
        cred_types=["cleartext", "ntlm", "certificate"],
        opsec_risk="medium", mitre_techniques=["T1021.006"],
    ),
    6379: ServiceProfile(
        service_name="redis", description="Redis (often unauthenticated)",
        attack_modules=[], cred_types=[],
        opsec_risk="low", mitre_techniques=["T1005"],
    ),
    8080: ServiceProfile(
        service_name="http-alt", description="HTTP alternate port",
        attack_modules=[], cred_types=["cleartext", "cookie", "jwt"],
        opsec_risk="low", mitre_techniques=["T1190"],
    ),
    8443: ServiceProfile(
        service_name="https-alt", description="HTTPS alternate port",
        attack_modules=[], cred_types=["cleartext", "cookie", "jwt"],
        opsec_risk="low", mitre_techniques=["T1190"],
    ),
    27017: ServiceProfile(
        service_name="mongodb", description="MongoDB (often unauthenticated)",
        attack_modules=[], cred_types=["cleartext"],
        opsec_risk="low", mitre_techniques=["T1005"],
    ),
    88: ServiceProfile(
        service_name="kerberos", description="Kerberos KDC",
        attack_modules=["ad.kerberoast", "ad.asreproast"],
        cred_types=["krb5_tgs", "krb5_asrep", "krb5_tgt"],
        opsec_risk="medium", mitre_techniques=["T1558.003", "T1558.004"],
    ),
    464: ServiceProfile(
        service_name="kpasswd", description="Kerberos password change",
        attack_modules=[], cred_types=[],
        opsec_risk="low", mitre_techniques=[],
    ),
    3268: ServiceProfile(
        service_name="ldap-gc", description="AD Global Catalog LDAP",
        attack_modules=["ad.enum_users", "ad.enum_spn"],
        cred_types=["cleartext", "ntlm"],
        opsec_risk="low", mitre_techniques=["T1087.002"],
    ),
}


@dataclass
class PortScanResult:
    host:       str
    open_ports: list[int]     = field(default_factory=list)
    services:   dict[int, ServiceProfile] = field(default_factory=dict)
    scan_time_s: float = 0.0
    error:      str   = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host":   self.host,
            "ports":  self.open_ports,
            "services": {
                str(p): {"name": s.service_name, "modules": s.attack_modules}
                for p, s in self.services.items()
            },
        }


# ── Service Intel Engine ───────────────────────────────────────────────────────

class ServiceIntelEngine:
    """
    Port scanner + service mapper + module recommender.

    connect_scan() is fast but noisy.
    syn_scan()     requires root + scapy (opsec-preferred, harder to detect).

    For production engagements, use nmap via subprocess for reliability.
    """

    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443,
        445, 464, 636, 993, 995, 1433, 1521, 3268, 3306, 3389, 5432,
        5985, 5986, 6379, 8080, 8443, 27017,
    ]

    DC_PORTS = [88, 135, 139, 389, 445, 464, 636, 3268, 3269]

    def __init__(self, timeout_s: float = 1.5, max_parallel: int = 100) -> None:
        self.timeout_s    = timeout_s
        self.max_parallel = max_parallel

    async def scan_host(
        self,
        host:  str,
        ports: list[int] | None = None,
        jitter_ms: int = 0,
    ) -> PortScanResult:
        """
        Async TCP connect scan. Fast, no root required.
        Set jitter_ms > 0 for stealth.
        """
        ports = ports or self.DEFAULT_PORTS
        result = PortScanResult(host=host)
        sem    = asyncio.Semaphore(self.max_parallel)
        t0     = time.monotonic()

        async def check_port(port: int) -> None:
            async with sem:
                if jitter_ms:
                    import random
                    await asyncio.sleep(random.uniform(0, jitter_ms / 1000))
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.timeout_s,
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, asyncio.TimeoutError):
                        pass
                    result.open_ports.append(port)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass
                except Exception as exc:
                    logger.debug("port_scan_error", host=host, port=port, error=str(exc)[:50])

        await asyncio.gather(*[check_port(p) for p in ports])

        result.open_ports.sort()
        result.scan_time_s = round(time.monotonic() - t0, 3)

        # Map to service profiles
        for port in result.open_ports:
            if port in PORT_SERVICE_MAP:
                result.services[port] = PORT_SERVICE_MAP[port]

        logger.info(
            "port_scan_complete",
            host=host,
            open_ports=len(result.open_ports),
            scan_time_s=result.scan_time_s,
        )
        return result

    async def scan_hosts(
        self,
        hosts:     list[str],
        ports:     list[int] | None = None,
        max_hosts: int = 20,
    ) -> list[PortScanResult]:
        """Scan multiple hosts in parallel."""
        sem = asyncio.Semaphore(max_hosts)

        async def scan_one(host: str) -> PortScanResult:
            async with sem:
                return await self.scan_host(host, ports)

        return await asyncio.gather(*[scan_one(h) for h in hosts])

    def recommend_modules(
        self,
        scan:            PortScanResult,
        available_creds: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recommend attack modules for a scan result.
        Returns list of {module_id, port, service, reason, opsec_risk}.
        """
        available_creds = available_creds or []
        seen:   set[str] = set()
        result: list[dict[str, Any]] = []

        for port, svc in scan.services.items():
            for module_id in svc.attack_modules:
                if module_id in seen:
                    continue
                seen.add(module_id)

                # Only recommend cred-dependent modules if we have creds
                needs_creds = bool(svc.cred_types)
                has_creds   = bool(available_creds)
                if needs_creds and not has_creds:
                    continue

                result.append({
                    "module_id":  module_id,
                    "port":       port,
                    "service":    svc.service_name,
                    "reason":     f"Port {port}/{svc.service_name} open on {scan.host}",
                    "opsec_risk": svc.opsec_risk,
                    "mitre":      svc.mitre_techniques,
                })

        # Sort: low opsec risk first
        opsec_order = {"low": 0, "medium": 1, "high": 2}
        result.sort(key=lambda r: opsec_order.get(r["opsec_risk"], 3))
        return result

    def update_host_state(self, host: HostState, scan: PortScanResult) -> None:
        """Populate a HostState object with scan results."""
        host.open_ports = scan.open_ports
        for port, svc in scan.services.items():
            host.add_service(port, svc.service_name)

        # Detect DC by port pattern
        dc_score = sum(1 for p in self.DC_PORTS if p in scan.open_ports)
        if dc_score >= 5:
            host.is_dc = True
            host.tags.append("domain_controller")
            logger.info("dc_detected", host=host.ip_address, dc_port_score=dc_score)

    def is_likely_dc(self, scan: PortScanResult) -> bool:
        """Heuristic DC detection from open ports."""
        return sum(1 for p in self.DC_PORTS if p in scan.open_ports) >= 4
