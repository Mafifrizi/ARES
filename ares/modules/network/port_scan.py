"""
Network Port Scanner — Production Implementation
MITRE: T1046 (Network Service Discovery)

TCP connect scan with asyncio — no raw sockets, no root required.
Respects NoiseController rate limits and opsec profile.
Results feed ServiceIntelEngine for automatic module recommendation.

OpSec notes:
  - MEDIUM: generates connection attempts to every scanned port
  - Stealth profile reduces concurrency and adds jitter
  - Does NOT do SYN/half-open scan (requires root, higher noise)
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.port_scan")

# Common ports scanned by default (top-100 most relevant for red team)
_DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389, 4443,
    5432, 5985, 5986, 6379, 7001, 8080, 8443, 8888, 9200, 9300, 27017,
    50000, 50070, 61616,
]

# Port → service name (for display only, not security-sensitive)
_PORT_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp-submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2375: "docker-http", 2376: "docker-tls",
    3306: "mysql", 3389: "rdp", 4443: "https-alt", 5432: "postgresql",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis",
    7001: "weblogic", 8080: "http-alt", 8443: "https-alt",
    8888: "http-jupyter", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    27017: "mongodb", 50000: "db2", 50070: "hdfs-namenode",
    61616: "activemq",
}

# Services that suggest high-value attack paths
_HIGH_VALUE_SERVICES: dict[int, str] = {
    88:   "Kerberos — DC present, AD attack surface",
    389:  "LDAP — AD enumeration (enum_users, enum_spn, dcsync)",
    445:  "SMB — lateral movement (psexec, wmiexec) + credential access",
    636:  "LDAPS — secure AD enumeration",
    1433: "MSSQL — credential reuse + potential xp_cmdshell RCE",
    3389: "RDP — lateral movement target",
    5985: "WinRM HTTP — lateral movement (winrm module)",
    5986: "WinRM HTTPS — lateral movement (winrm module)",
    27017: "MongoDB — likely unauthenticated, data exfil opportunity",
    9200: "Elasticsearch — likely unauthenticated, data exfil opportunity",
    6379: "Redis — likely unauthenticated, potential RCE via module loading",
    2375: "Docker daemon HTTP — unauthenticated container escape",
}


async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Attempt TCP connect. Returns True if port is open."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


class PortScanModule(BaseModule):
    """
    network.port_scan — Async TCP connect scan — identifies open ports and maps them to services and recommended attack 

    OPSEC: MEDIUM
    MITRE: "T1046"
    OUTPUTS:  "open_ports", "service_map"
    """
    MODULE_ID          = "network.port_scan"
    MODULE_NAME        = "TCP Port Scanner"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "Async TCP connect scan — identifies open ports and maps them to "
        "services and recommended attack modules"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["open_ports", "service_map"]
    MITRE_TECHNIQUES   = ["T1046"]

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
                "network.port_scan requires 'target' — IP or CIDR to scan.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True, "target": getattr(ctx, "target", "")})
        findings, raw = await self.run(**ctx.params,
                                        target=getattr(ctx, "target", ctx.params.get("target", "")))
        return ModuleResult(
            status="success" if (findings or raw.get("open_ports")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.port_scan")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        ports    = kwargs.get("ports", _DEFAULT_PORTS)
        dry_run  = kwargs.get("dry_run", False)
        timeout  = float(kwargs.get("timeout", 2.0))
        # Concurrency: stealth=10, normal=50, aggressive=200
        noise_profile = getattr(self.noise, "profile_name", "normal") \
                        if self.noise else "normal"
        max_concurrent = {"stealth": 10, "normal": 50, "aggressive": 200}.get(
            noise_profile, 50
        )

        if not target:
            return [], {"error": "no_target"}

        if dry_run:
            return [], {"dry_run": True, "would_scan": len(ports), "target": target}

        await self.before_request(target, "tcp_scan")  # scope check + jitter

        logger.info("port_scan_start", target=target, port_count=len(ports),
                    concurrency=max_concurrent)
        t0 = time.monotonic()

        # Rate-limit the scan
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        # Run concurrent TCP probes
        semaphore = asyncio.Semaphore(max_concurrent)

        async def probe(port: int) -> tuple[int, bool]:
            async with semaphore:
                return port, await _tcp_connect(target, port, timeout)

        results = await asyncio.gather(*[probe(p) for p in ports])
        open_ports = [p for p, is_open in results if is_open]
        scan_ms    = round((time.monotonic() - t0) * 1000, 1)

        logger.info("port_scan_done", target=target,
                    open=len(open_ports), total=len(ports), ms=scan_ms)

        # Build service map and findings
        service_map: dict[int, str] = {
            p: _PORT_NAMES.get(p, f"unknown-{p}") for p in open_ports
        }
        findings: list[Finding] = []

        # Finding for each high-value port
        for port in open_ports:
            if port in _HIGH_VALUE_SERVICES:
                svc = _PORT_NAMES.get(port, str(port))
                hint = _HIGH_VALUE_SERVICES[port]
                self.finding(
                    title=f"High-Value Service Open: {svc.upper()} (port {port})",
                    description=(
                        f"Port {port}/{svc} is open on {target}. {hint}. "
                        "This service should be targeted for further enumeration."
                    ),
                    severity=Severity.INFO,
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    evidence={"host": target, "port": port, "service": svc},
                    remediation=(
                        "Ensure this service is intended to be accessible from the "
                        "operator's position. Apply least-privilege network segmentation."
                    ),
                    host=target,
                    confidence=1.0,
                )

        # Summary finding if many interesting ports open
        if len(open_ports) >= 3:
            self.finding(
                title=f"Attack Surface: {len(open_ports)} Open Ports on {target}",
                description=(
                    f"{len(open_ports)} TCP ports are open on {target}: "
                    f"{', '.join(f'{p}/{_PORT_NAMES.get(p, str(p))}' for p in sorted(open_ports))}."
                ),
                severity=Severity.INFO,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence={"host": target, "open_ports": open_ports, "service_map": service_map},
                remediation=(
                    "Review all open ports against network diagrams and business requirements. "
                    "Close or firewall any service not required for operations."
                ),
                host=target,
                confidence=1.0,
            )

        # Feed results into HostState if session available
        # (ServiceIntelEngine picks this up for module recommendations)
        findings_out = self._findings[:]
        raw = {
            "target":       target,
            "open_ports":   open_ports,
            "service_map":  service_map,
            "total_scanned": len(ports),
            "scan_ms":      scan_ms,
        }
        return findings_out, raw
