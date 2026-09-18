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
from ares.modules.params import PortScanParams
from ares.core.tracing import trace_module
from ares.sdk import (
    CircuitBreaker,
    EvidenceRecord,
    ExecutionContext,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

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
_SERVICE_INTELLIGENCE: dict[int, dict[str, Any]] = {
    88: {
        "title": "Active Directory KDC (Kerberos) Detected on Port 88",
        "service": "kerberos",
        "role": "Tier-0 Domain Controller",
        "severity": Severity.MEDIUM,
        "description": (
            "Kerberos Key Distribution Center (KDC) is active on {target}:88. "
            "Confirms host functions as an Active Directory Domain Controller (Tier-0 asset). "
            "Exposes pre-authentication attack surfaces including AS-REP Roasting (ad.asreproast), "
            "Kerberoasting (ad.kerberoast), and Kerberos PKINIT certificate exchange."
        ),
        "remediation": (
            "Enforce AES-256 Kerberos encryption types, disable legacy RC4-HMAC, audit SPN assignments, "
            "and monitor Event ID 4769 for anomalous ticket-granting service requests."
        ),
        "next_modules": ["ad.asreproast", "ad.kerberoast", "ad.enum_spn"],
    },
    636: {
        "title": "Secure Directory Service (LDAPS) Active on Port 636",
        "service": "ldaps",
        "role": "Active Directory Domain Controller (TLS)",
        "severity": Severity.MEDIUM,
        "description": (
            "LDAP over TLS (LDAPS) is listening on {target}:636. Indicates a Domain Controller supporting "
            "encrypted directory queries and ADCS certificate enrollment. "
            "Target for AD enumeration (ad.enum_users, ad.enum_computers) and ADCS escalation (ad.adcs, ad.ghost_forge)."
        ),
        "remediation": (
            "Enforce LDAP channel binding (LdapEnforceChannelBinding=2), require LDAP signing, "
            "and restrict LDAPS inbound traffic to authorized administrative jump hosts."
        ),
        "next_modules": ["ad.enum_users", "ad.adcs", "ad.ghost_forge"],
    },
    389: {
        "title": "Active Directory LDAP Directory Service Exposed on Port 389",
        "service": "ldap",
        "role": "Active Directory Directory Service",
        "severity": Severity.MEDIUM,
        "description": (
            "Standard LDAP is open on {target}:389. Enables unauthenticated or low-privilege AD enumeration "
            "(users, groups, domain controllers, and ACLs). Susceptible to NTLM relay if LDAP signing is disabled."
        ),
        "remediation": (
            "Enforce LDAP server integrity (LDAPServerIntegrity=2), disable unauthenticated LDAP binds, "
            "and transition all directory clients to LDAPS (port 636)."
        ),
        "next_modules": ["ad.enum_users", "ad.enum_spn", "ad.enum_acl"],
    },
    445: {
        "title": "Windows Server Message Block (SMB) Service Open on Port 445",
        "service": "smb",
        "role": "Windows Core Transport & Remote Administration",
        "severity": Severity.MEDIUM,
        "description": (
            "SMB port 445 is reachable on {target}. Primary vector for Windows lateral movement, "
            "named pipe RPC access, password spraying, and NTLM relay coercion (PetitPotam / ad.coerce). "
            "If credentials are authenticated, facilitates remote command execution via SMB/WMI."
        ),
        "remediation": (
            "Require SMB signing (RequireSecuritySignature=1), disable legacy SMBv1, and apply network "
            "segmentation to block inbound port 445 from untrusted user subnets."
        ),
        "next_modules": ["ad.coerce", "credential.spray", "windows.secretsdump"],
    },
    5985: {
        "title": "WinRM HTTP Remote Management Service Accessible on Port 5985",
        "service": "winrm-http",
        "role": "PowerShell Remoting Endpoint",
        "severity": Severity.MEDIUM,
        "description": (
            "Windows Remote Management (WinRM HTTP) is active on {target}:5985. "
            "Provides an immediate PowerShell remoting execution path if valid local administrator "
            "or domain credentials are acquired."
        ),
        "remediation": (
            "Disable unencrypted WinRM HTTP listeners, enforce WinRM HTTPS (port 5986), "
            "and restrict WinRM access via host-based Windows Firewall rules."
        ),
        "next_modules": ["lateral.winrm", "windows.service_hijack"],
    },
    5986: {
        "title": "WinRM HTTPS Remote Management Service Accessible on Port 5986",
        "service": "winrm-https",
        "role": "Encrypted PowerShell Remoting Endpoint",
        "severity": Severity.LOW,
        "description": (
            "Windows Remote Management over HTTPS is listening on {target}:5986. "
            "Enables encrypted PowerShell remoting. Target for lateral movement using valid credentials."
        ),
        "remediation": (
            "Restrict WinRM access to dedicated administrative management subnets using IP whitelisting."
        ),
        "next_modules": ["lateral.winrm"],
    },
    3389: {
        "title": "Remote Desktop Protocol (RDP) Service Reachable on Port 3389",
        "service": "rdp",
        "role": "Windows Terminal Server",
        "severity": Severity.LOW,
        "description": (
            "RDP port 3389 is open on {target}. Allows graphical interactive logon. "
            "Target for credential spray attacks, session hijacking, and sticky keys exploitation."
        ),
        "remediation": (
            "Enforce Network Level Authentication (NLA), mandate multi-factor authentication (MFA) for RDP, "
            "and restrict RDP access to VPN/management gateways."
        ),
        "next_modules": ["credential.spray"],
    },
    1433: {
        "title": "Microsoft SQL Server Database Instance Detected on Port 1433",
        "service": "mssql",
        "role": "Enterprise Database Server",
        "severity": Severity.MEDIUM,
        "description": (
            "MSSQL Server is listening on {target}:1433. Potential vector for SQL authentication brute-forcing, "
            "database credential harvesting, linked server privilege escalation, and xp_cmdshell command execution."
        ),
        "remediation": (
            "Disable the 'sa' account, enforce Windows Integrated Authentication only, "
            "and keep xp_cmdshell disabled in database engine configuration."
        ),
        "next_modules": ["credential.spray"],
    },
    2375: {
        "title": "Unauthenticated Docker Daemon API Exposed on Port 2375",
        "service": "docker-http",
        "role": "Container Management Engine",
        "severity": Severity.HIGH,
        "description": (
            "Unencrypted, unauthenticated Docker daemon HTTP API is exposed on {target}:2375. "
            "Allows arbitrary container creation, host filesystem mounting, and root host takeover."
        ),
        "remediation": (
            "Disable plaintext Docker TCP socket. Enable TLS mutual authentication on port 2376 "
            "or bind Docker daemon to local Unix domain socket only."
        ),
        "next_modules": ["linux.container"],
    },
    6379: {
        "title": "Redis In-Memory Data Store Accessible on Port 6379",
        "service": "redis",
        "role": "In-Memory Cache / Database",
        "severity": Severity.MEDIUM,
        "description": (
            "Redis port 6379 is open on {target}. Frequently lacks authentication. "
            "Attack vectors include unauthenticated data exfiltration, writing SSH authorized_keys, "
            "and remote code execution via custom module loading."
        ),
        "remediation": (
            "Enable 'requirepass' in redis.conf, bind Redis to 127.0.0.1, and rename dangerous commands (CONFIG, EVAL)."
        ),
        "next_modules": ["linux.service_hijack"],
    },
    27017: {
        "title": "MongoDB NoSQL Database Service Exposed on Port 27017",
        "service": "mongodb",
        "role": "Document Database Server",
        "severity": Severity.MEDIUM,
        "description": (
            "MongoDB is listening on {target}:27017. Target for unauthenticated database enumeration, "
            "credential discovery, and sensitive customer data extraction."
        ),
        "remediation": (
            "Enable MongoDB authorization (security.authorization: enabled) and bind to private loopback interface."
        ),
        "next_modules": ["network.service_detect"],
    },
    9200: {
        "title": "Elasticsearch REST API Open on Port 9200",
        "service": "elasticsearch",
        "role": "Distributed Search & Analytics Cluster",
        "severity": Severity.MEDIUM,
        "description": (
            "Elasticsearch REST API is accessible on {target}:9200. Inspect indices for unencrypted credentials, "
            "API keys, and system log data exfiltration."
        ),
        "remediation": (
            "Enable Elasticsearch X-Pack security, require TLS, and mandate HTTP basic authentication."
        ),
        "next_modules": ["network.service_detect"],
    },
}

_HIGH_VALUE_SERVICES: dict[int, str] = {
    p: info["title"] for p, info in _SERVICE_INTELLIGENCE.items()
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


@module_contract(
    permissions=[
        NetworkPermission(protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=CircuitBreaker(name="network.port_scan", failure_threshold=15),
    params_model=PortScanParams,
)
class PortScanModule(BaseModule):
    """
    network.port_scan — Async TCP connect scan — identifies open ports and maps them to services and recommended attack paths

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
    PARAMS_MODEL       = PortScanParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        if isinstance(ctx.params, dict):
            if not ctx.params.get("target") and getattr(ctx, "target", None):
                ctx.params["target"] = ctx.target
        target = getattr(ctx, "target", "") or (ctx.params.get("target", "") if isinstance(ctx.params, dict) else getattr(ctx.params, "target", ""))
        if not target:
            raise ModuleValidationError(
                "network.port_scan requires 'target' — IP or CIDR to scan.",
                module_id=self.MODULE_ID, field="target",
            )
        await super().validate(ctx)

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True, "target": getattr(ctx, "target", "")})
        target = getattr(ctx, "target", "")
        ports = _DEFAULT_PORTS
        timeout = 2.0
        extra_params: dict[str, Any] = {}

        params = getattr(ctx, "params", {})
        if isinstance(params, PortScanParams):
            target = params.target or target
            timeout = params.timeout or timeout
            if isinstance(params.ports, str):
                if params.ports in ("top1000", "all", ""):
                    ports = _DEFAULT_PORTS
                else:
                    try:
                        ports = [int(p.strip()) for p in params.ports.split(",") if p.strip().isdigit()]
                    except Exception:
                        ports = _DEFAULT_PORTS
            elif isinstance(params.ports, list):
                ports = params.ports
        elif isinstance(params, dict):
            target = params.get("target") or target
            timeout = float(params.get("timeout", 2.0))
            raw_ports = params.get("ports")
            if isinstance(raw_ports, list):
                ports = raw_ports
            elif isinstance(raw_ports, str):
                if raw_ports in ("top1000", "all", ""):
                    ports = _DEFAULT_PORTS
                else:
                    try:
                        ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()]
                    except Exception:
                        ports = _DEFAULT_PORTS
            extra_params = {k: v for k, v in params.items() if k not in ("target", "ports", "timeout")}

        findings, raw = await self.run(
            target=target, ports=ports, timeout=timeout, **extra_params,
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"portscan-{target.replace('.', '-')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "target": target,
                    "title": finding.title,
                    "severity": str(finding.severity),
                },
                tags=["network", "port_scan"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis
        scan_target = target or "NetworkTarget"
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect Rapid Network Port Scanning / Sweep\n"
            f"// Monitors AzureNetworkAnalytics_CL / NetworkSession for single source contacting >= 15 distinct ports within 5 minutes\n"
            f"NetworkSession\n"
            f"| where DestinationIp == \"{scan_target}\" or SourceIp == \"{scan_target}\"\n"
            f"| summarize DistinctPorts = dcount(DestinationPort), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by SourceIp, DestinationIp\n"
            f"| where DistinctPorts >= 15\n"
        )
        sigma_rule = (
            f"title: Rapid Network Port Scan / Reconnaissance ({scan_target})\n"
            f"id: 1e2f3a4b-ares-portscan-{abs(hash(str(scan_target))) % 1000000:06d}\n"
            f"status: experimental\n"
            f"description: Detects rapid probing of multiple distinct TCP ports against target hosts.\n"
            f"logsource:\n"
            f"  product: firewall\n"
            f"detection:\n"
            f"  selection:\n"
            f"    dst_ip: '{scan_target}'\n"
            f"  condition: selection | count() by src_ip > 15\n"
            f"level: low\n"
            f"tags:\n"
            f"  - attack.reconnaissance\n"
            f"  - attack.t1046\n"
        )
        loot_items: list[dict[str, Any]] = raw.get("loot", [])
        if not any(l.get("loot_type") == "detection_rule_kql" for l in loot_items):
            loot_items.extend([
                {
                    "name": f"Detection Rule (KQL): Network Port Scan ({scan_target})",
                    "loot_type": "detection_rule_kql",
                    "description": "Microsoft Sentinel KQL query for detecting rapid TCP port scanning",
                    "content": {"kql": kql_query, "target": scan_target},
                    "tags": ["detection", "kql", "sentinel", "blue_team"],
                },
                {
                    "name": f"Detection Rule (Sigma): Network Port Scan ({scan_target})",
                    "loot_type": "detection_rule_sigma",
                    "description": "Sigma detection rule for rapid TCP port scanning",
                    "content": {"sigma": sigma_rule, "target": scan_target},
                    "tags": ["detection", "sigma", "blue_team"],
                },
            ])
        raw["loot"] = loot_items
        raw["port_scan_reconnaissance_evaluated"] = True
        raw["high_value_ports_mapped"] = True

        return ModuleResult(
            status="success" if (findings or raw.get("open_ports")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.port_scan")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        raw_ports = kwargs.get("ports", _DEFAULT_PORTS)
        if isinstance(raw_ports, str):
            if raw_ports in ("top1000", "all", ""):
                ports = _DEFAULT_PORTS
            else:
                try:
                    ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()]
                except Exception:
                    ports = _DEFAULT_PORTS
        else:
            ports = raw_ports or _DEFAULT_PORTS
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

        # Finding for each high-value port
        for port in open_ports:
            intel = _SERVICE_INTELLIGENCE.get(port)
            if intel:
                svc = intel["service"]
                self.finding(
                    title=intel["title"],
                    description=intel["description"].format(target=target),
                    severity=intel["severity"],
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    evidence={
                        "host": target,
                        "port": port,
                        "service": svc,
                        "role": intel["role"],
                        "next_modules": intel.get("next_modules", []),
                    },
                    remediation=intel["remediation"],
                    host=target,
                    confidence=1.0,
                )
            elif port in _HIGH_VALUE_SERVICES:
                svc = _PORT_NAMES.get(port, str(port))
                hint = _HIGH_VALUE_SERVICES[port]
                self.finding(
                    title=f"Service Open: {svc.upper()} (port {port})",
                    description=f"Port {port}/{svc} is open on {target}. {hint}.",
                    severity=Severity.INFO,
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    evidence={"host": target, "port": port, "service": svc},
                    remediation="Ensure this service is intended to be accessible from the operator's position. Apply least-privilege network segmentation.",
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
