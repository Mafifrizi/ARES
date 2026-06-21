"""
Network Service Detection — Banner Grabbing + Version Fingerprinting
MITRE: T1046, T1590.004

Connects to open ports, reads banner/response, identifies:
  - Service name and version
  - TLS/SSL details
  - Authentication methods offered
  - Known vulnerable versions
"""
from __future__ import annotations

import asyncio
import ssl
import re
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.service_detect")

# Probes to send to services for banner extraction
_PROBES: dict[str, bytes] = {
    "http":  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ftp":   b"",       # FTP sends banner on connect
    "smtp":  b"",       # SMTP sends banner on connect
    "ssh":   b"",       # SSH sends banner on connect
    "redis": b"*1\r\n$4\r\nINFO\r\n",
    "mongodb": b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
               b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
               b"\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
    "generic": b"",
}

# Version patterns — (service, pattern, severity, cve_hint)
_VULN_PATTERNS: list[tuple[str, str, str, str]] = [
    ("openssh",   r"OpenSSH[_\s]([0-9]\.[0-9])",   "INFO",     ""),
    ("vsftpd",    r"vsftpd\s([0-9]\.[0-9]\.[0-9])", "MEDIUM",   "CVE-2011-2523 if 2.3.4"),
    ("proftpd",   r"ProFTPD\s([0-9]\.[0-9])",       "INFO",     ""),
    ("apache",    r"Apache[/\s]([0-9]+\.[0-9]+)",   "INFO",     ""),
    ("nginx",     r"nginx[/\s]([0-9]+\.[0-9]+)",    "INFO",     ""),
    ("iis",       r"Microsoft-IIS[/\s]([0-9]+\.[0-9]+)", "INFO", ""),
    ("redis",     r"redis_version:([0-9]+\.[0-9]+)", "MEDIUM",  "Check for no-auth"),
    ("mongodb",   r"\"version\"",                   "MEDIUM",   "Check for no-auth"),
    ("elasticsearch", r"\"number\":\"([0-9]+\.[0-9]+)", "MEDIUM", "Check for no-auth"),
]


async def _grab_banner(host: str, port: int, timeout: float = 4.0,
                       use_tls: bool = False) -> str:
    """Connect to port, optionally TLS-wrap, read banner bytes."""
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        # Determine probe based on port
        port_probe_map = {80: "http", 8080: "http", 8443: "http", 443: "http",
                          8888: "http", 21: "ftp", 25: "smtp", 22: "ssh",
                          6379: "redis", 27017: "mongodb"}
        probe_key = port_probe_map.get(port, "generic")
        probe     = _PROBES.get(probe_key, b"")
        if probe:
            writer.write(probe)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="replace").strip()[:1000]

    except Exception:
        return ""


class ServiceDetectModule(BaseModule):
    """
    network.service_detect — Banner grabbing and version fingerprinting on open ports — identifies service versions and flags

    OPSEC: LOW
    MITRE: "T1046", "T1590.004"
    REQUIRES: "open_ports"
    OUTPUTS:  "service_versions", "vulnerable_services"
    """
    MODULE_ID          = "network.service_detect"
    MODULE_NAME        = "Service Detection"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "Banner grabbing and version fingerprinting on open ports — "
        "identifies service versions and flags potentially vulnerable services"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = ["open_ports"]
    OUTPUTS            = ["service_versions", "vulnerable_services"]
    MITRE_TECHNIQUES   = ["T1046", "T1590.004"]

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
                                raw={"dry_run": True})
        target = getattr(ctx, "target", ctx.params.get("target", ""))
        ports  = ctx.params.get("ports", [])
        findings, raw = await self.run(target=target, ports=ports, **ctx.params)
        return ModuleResult(
            status="success" if (findings or raw.get("service_versions")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.service_detect")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target  = kwargs.get("target", "")
        ports   = kwargs.get("ports") or []
        dry_run = kwargs.get("dry_run", False)

        if not target:
            return [], {"error": "no_target"}
        if not ports:
            return [], {"error": "no_ports_provided", "hint":
                        "Run network.port_scan first to populate open_ports"}
        if dry_run:
            return [], {"dry_run": True, "target": target}

        await self.before_request(target, "tcp")  # scope check + jitter

        logger.info("service_detect_start", target=target, ports=ports)
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        service_versions: dict[int, dict[str, str]] = {}
        vuln_services: list[dict[str, Any]] = []

        async def probe_port(port: int) -> None:
            await self.noise.jitter.sleep()
            # Decide TLS
            use_tls = port in (443, 636, 993, 995, 8443, 5986)
            banner  = await _grab_banner(target, port, use_tls=use_tls)
            if not banner:
                # Try TLS on non-standard ports if plain failed
                if not use_tls:
                    banner = await _grab_banner(target, port, use_tls=True)

            if not banner:
                return

            entry: dict[str, str] = {"banner": banner[:200]}

            # Fingerprint against known patterns
            for svc_name, pattern, severity, cve_hint in _VULN_PATTERNS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else "detected"
                    entry["service"] = svc_name
                    entry["version"] = version
                    if cve_hint:
                        entry["cve_hint"] = cve_hint
                        vuln_services.append({
                            "host": target, "port": port, "service": svc_name,
                            "version": version, "cve_hint": cve_hint,
                            "severity": severity,
                        })
                    break

            service_versions[port] = entry

        # Probe all ports with bounded concurrency
        semaphore = asyncio.Semaphore(10)
        async def bounded(port: int) -> None:
            async with semaphore:
                await probe_port(port)

        await asyncio.gather(*[bounded(p) for p in ports])

        # Findings for vulnerable/interesting services
        for vs in vuln_services:
            sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM}.get(vs["severity"], Severity.INFO)
            self.finding(
                title=f"Service Version Identified: {vs['service'].upper()} {vs['version']} on port {vs['port']}",
                description=(
                    f"{vs['service']} {vs['version']} running on {target}:{vs['port']}. "
                    f"{vs.get('cve_hint', 'Check for known CVEs for this version.')}"
                ),
                severity=sev,
                mitre_technique="T1046",
                mitre_tactic="Discovery",
                evidence=vs,
                remediation=(
                    f"Update {vs['service']} to the latest stable version. "
                    "Apply vendor security patches promptly."
                ),
                host=target,
                confidence=0.9,
            )

        raw = {
            "target":           target,
            "service_versions": {str(k): v for k, v in service_versions.items()},
            "vulnerable_services": vuln_services,
        }
        return self._findings[:], raw
