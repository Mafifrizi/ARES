"""
DNS Enumeration — Zone Transfer, Subdomain Brute, Record Enum
MITRE: T1590.002

Attempts:
  1. AXFR zone transfer (misconfigured DNS servers leak entire zone)
  2. Common subdomain brute force
  3. Standard record enumeration (MX, NS, TXT, SOA, PTR)
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.dns_enum")

# Common subdomains to brute-force
_COMMON_SUBDOMAINS: list[str] = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "vpn", "remote",
    "owa", "webmail", "exchange", "autodiscover", "lyncdiscover",
    "admin", "portal", "intranet", "extranet", "internal",
    "dev", "staging", "test", "qa", "uat", "prod",
    "api", "api-dev", "api-staging", "app", "apps",
    "git", "gitlab", "github", "bitbucket", "jira", "confluence",
    "jenkins", "ci", "cd", "build", "deploy",
    "db", "database", "sql", "mysql", "postgres", "mongo",
    "redis", "elasticsearch", "kibana", "grafana", "prometheus",
    "backup", "files", "share", "nfs", "nas", "storage",
    "dc", "dc01", "dc02", "ad", "ldap",
    "rdp", "remote", "citrix", "horizon",
    "proxy", "gateway", "fw", "firewall", "router",
    "monitor", "monitoring", "nagios", "zabbix",
    "ns", "ns1", "ns2", "mx", "mx1", "mx2",
    "secure", "login", "sso", "auth",
]

# Record types to enumerate
_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]


class DnsEnumModule(BaseModule):
    """
    network.dns_enum — DNS zone transfer attempt, subdomain brute force, and record enumeration — maps DNS infrastructu

    OPSEC: LOW
    MITRE: "T1590.002"
    OUTPUTS:  "dns_records", "subdomains"
    """
    MODULE_ID          = "network.dns_enum"
    MODULE_NAME        = "DNS Enumeration"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "DNS zone transfer attempt, subdomain brute force, and record enumeration — "
        "maps DNS infrastructure and finds internal hostnames"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["dns_records", "subdomains"]
    MITRE_TECHNIQUES   = ["T1590.002"]

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
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target = getattr(ctx, "target", ctx.params.get("target", ""))
        domain = ctx.params.get("domain") or target
        params = dict(ctx.params)
        params.pop("target", None)
        params.pop("domain", None)
        findings, raw = await self.run(target=target, domain=domain, **params)
        return ModuleResult(
            status="success" if (findings or raw.get("dns_records")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.dns_enum")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target  = kwargs.get("target", "")
        domain  = kwargs.get("domain") or target
        dry_run = kwargs.get("dry_run", False)
        brute   = kwargs.get("brute_force", True)

        if not domain:
            return [], {"error": "no_domain"}
        if dry_run:
            return [], {"dry_run": True}

        await self.before_request(target, "dns")  # scope check + jitter

        try:
            import dns.resolver       # type: ignore[import]
            import dns.zone           # type: ignore[import]
            import dns.query          # type: ignore[import]
            import dns.exception      # type: ignore[import]
        except ImportError:
            return [], {"error": "dnspython not installed — run: pip install dnspython"}

        logger.info("dns_enum_start", domain=domain)
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        import asyncio as _asyncio
        loop = _asyncio.get_running_loop()

        dns_records: dict[str, list[str]] = {}
        subdomains_found: list[dict[str, Any]] = []
        zone_transfer_data: list[str] = []

        resolver = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 5

        # ── 1. Standard record enumeration — blocking, wrapped in executor ──────
        def _resolve_records() -> dict[str, list[str]]:
            results: dict[str, list[str]] = {}
            for rtype in _RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    results[rtype] = [str(r) for r in answers]
                except Exception:
                    pass
            return results

        dns_records = await loop.run_in_executor(None, _resolve_records)

        # ── 2. Zone transfer attempt — blocking, wrapped in executor ─────────────
        ns_servers: list[str] = dns_records.get("NS", [])

        def _try_axfr(ns_host: str) -> list[str]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
                return [str(n) for n in zone.nodes.keys()]
            except Exception:
                return []

        for ns in ns_servers[:3]:
            ns_clean = ns.rstrip(".")
            records  = await loop.run_in_executor(None, _try_axfr, ns_clean)
            if records:
                zone_transfer_data = records
                self.finding(
                    title=f"DNS Zone Transfer Allowed on {ns_clean}",
                    description=(
                        f"The nameserver {ns_clean} allowed a full zone transfer (AXFR) "
                        f"for {domain}. This exposes the complete DNS zone with "
                        f"{len(zone_transfer_data)} records — all internal hostnames and IPs."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1590.002",
                    mitre_tactic="Reconnaissance",
                    evidence={
                        "nameserver": ns_clean,
                        "domain":     domain,
                        "record_count": len(zone_transfer_data),
                        "sample_records": zone_transfer_data[:20],
                    },
                    remediation=(
                        "Configure DNS server to restrict AXFR to authorized secondary "
                        "nameservers only. In BIND: allow-transfer { secondary_ns_ip; }; "
                        "In Windows DNS: disable zone transfer or restrict to named servers."
                    ),
                    host=ns_clean, confidence=1.0,
                )
                break

        # ── 3. Subdomain brute force ────────────────────────────────────────────
        if brute and not zone_transfer_data:
            sem = asyncio.Semaphore(20)

            async def resolve_sub(sub: str) -> None:
                fqdn = f"{sub}.{domain}"
                async with sem:
                    await self.noise.jitter.sleep()
                    try:
                        answers = await loop.run_in_executor(
                            None, lambda f=fqdn: resolver.resolve(f, "A")
                        )
                        ips = [str(r) for r in answers]
                        subdomains_found.append({"fqdn": fqdn, "ips": ips})
                    except Exception:
                        pass
                        pass

            await asyncio.gather(*[resolve_sub(s) for s in _COMMON_SUBDOMAINS])

        # Finding for discovered subdomains
        if subdomains_found:
            self.finding(
                title=f"DNS Subdomain Enumeration: {len(subdomains_found)} Subdomains Found",
                description=(
                    f"Subdomain brute force identified {len(subdomains_found)} active subdomains "
                    f"of {domain}. Each subdomain may be an additional attack target."
                ),
                severity=Severity.INFO,
                mitre_technique="T1590.002",
                mitre_tactic="Reconnaissance",
                evidence={"domain": domain, "subdomains": subdomains_found},
                remediation=(
                    "Review all discovered subdomains. Remove or decommission unused ones. "
                    "Ensure all subdomains are accounted for in asset inventory."
                ),
                host=domain, confidence=0.95,
            )

        # Finding for TXT records containing interesting data
        for txt in dns_records.get("TXT", []):
            import re
            if re.search(r"v=spf1|DKIM|DMARC|google-site-verification|"
                         r"atlassian-domain|MS=ms|docusign", txt, re.IGNORECASE):
                pass  # Normal SPF/DMARC records — not findings
            elif re.search(r"password|secret|token|key|credential", txt, re.IGNORECASE):
                self.finding(
                    title=f"Sensitive Data in DNS TXT Record for {domain}",
                    description=(
                        f"A DNS TXT record for {domain} appears to contain sensitive keywords. "
                        f"TXT content: {txt[:200]}"
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1590.002",
                    mitre_tactic="Reconnaissance",
                    evidence={"domain": domain, "txt_record": txt},
                    remediation="Remove sensitive data from DNS TXT records immediately.",
                    host=domain, confidence=0.7,
                )

        raw = {
            "domain":          domain,
            "dns_records":     dns_records,
            "subdomains":      subdomains_found,
            "zone_transfer":   zone_transfer_data,
        }
        return self._findings[:], raw
