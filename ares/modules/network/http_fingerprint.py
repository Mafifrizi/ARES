"""
HTTP Fingerprinting — Web Server, Framework, CMS Detection
MITRE: T1592.002, T1046

Identifies: server software, web framework, CMS, admin interfaces,
exposed API endpoints, version disclosure in headers/responses.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from ares.core.logger import get_logger
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.network.http_fingerprint")

# Paths that indicate admin interfaces or sensitive endpoints
_SENSITIVE_PATHS: list[tuple[str, str]] = [
    ("/admin",              "Admin interface"),
    ("/admin/login",        "Admin login"),
    ("/.env",               "Environment file — may expose secrets"),
    ("/.git/HEAD",          "Git repository exposed"),
    ("/wp-admin/",          "WordPress admin panel"),
    ("/wp-login.php",       "WordPress login"),
    ("/phpmyadmin/",        "phpMyAdmin database manager"),
    ("/manager/html",       "Tomcat Manager"),
    ("/api/v1/",            "API endpoint"),
    ("/api/swagger.json",   "Swagger/OpenAPI spec — enumerate endpoints"),
    ("/swagger-ui.html",    "Swagger UI"),
    ("/actuator",           "Spring Boot Actuator — may expose internals"),
    ("/actuator/env",       "Spring Boot env — may expose credentials"),
    ("/console",            "Admin console"),
    ("/jenkins",            "Jenkins CI"),
    ("/solr/",              "Apache Solr admin"),
    ("/kibana",             "Kibana dashboard"),
    ("/grafana",            "Grafana dashboard"),
    ("/.htpasswd",          "Apache password file"),
    ("/server-status",      "Apache server status"),
    ("/elmah.axd",          "ELMAH error log — .NET"),
    ("/trace.axd",          "ASP.NET trace — may expose internals"),
]

# Server/framework fingerprints in response headers
_HEADER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("server",          r"Apache[/\s]([0-9.]+)",  "Apache"),
    ("server",          r"nginx[/\s]([0-9.]+)",   "nginx"),
    ("server",          r"Microsoft-IIS[/\s]([0-9.]+)", "IIS"),
    ("server",          r"Jetty[/\s]([0-9.]+)",   "Jetty"),
    ("server",          r"Tomcat",                 "Apache Tomcat"),
    ("x-powered-by",    r"PHP[/\s]([0-9.]+)",     "PHP"),
    ("x-powered-by",    r"ASP\.NET",              "ASP.NET"),
    ("x-aspnet-version", r"([0-9.]+)",            "ASP.NET"),
    ("x-generator",     r"(.*)",                  "Generator"),
    ("x-drupal-cache",  r"",                      "Drupal CMS"),
    ("x-wordpress",     r"",                      "WordPress"),
]


class HttpFingerprintModule(BaseModule):
    """
    network.http_fingerprint — Fingerprint web servers and applications — detect server software, frameworks, CMS, admin interf

    OPSEC: LOW
    MITRE: "T1592.002", T1046 := "T1046"
    OUTPUTS:  "web_fingerprint", "admin_interfaces"
    """
    MODULE_ID          = "network.http_fingerprint"
    MODULE_NAME        = "HTTP Fingerprinting"
    MODULE_CATEGORY    = "network"
    MODULE_DESCRIPTION = (
        "Fingerprint web servers and applications — detect server software, "
        "frameworks, CMS, admin interfaces, and exposed sensitive paths"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["web_fingerprint", "admin_interfaces"]
    MITRE_TECHNIQUES   = ["T1592.002", T1046 := "T1046"]

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
        params = dict(ctx.params)
        params.pop("target", None)
        findings, raw = await self.run(target=target, **params)
        return ModuleResult(
            status="success" if (findings or raw.get("web_fingerprint")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("network.http_fingerprint")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target    = kwargs.get("target", "")
        ports     = kwargs.get("ports") or kwargs.get("http_ports") or [80, 443, 8080, 8443, 8888]
        dry_run   = kwargs.get("dry_run", False)

        if not target:
            return [], {"error": "no_target"}
        if dry_run:
            return [], {"dry_run": True}

        await self.before_request(target, "http")  # scope check + jitter

        try:
            import httpx
        except ImportError:
            return [], {"error": "httpx not installed — run: pip install httpx"}

        logger.info("http_fingerprint_start", target=target, ports=ports)
        await self.noise.rate_limiter.acquire("network_scan")
        await self.noise.jitter.sleep()

        web_fingerprint: dict[str, Any] = {}
        admin_interfaces: list[dict[str, Any]] = []

        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{target}:{port}"

            try:
                async with httpx.AsyncClient(
                    timeout=6.0, verify=False,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ) as client:
                    r = await client.get(f"{base_url}/")
            except Exception:
                continue

            # Fingerprint from headers
            tech_stack: list[str] = []
            version_disclosures: dict[str, str] = {}
            for header_name, pattern, label in _HEADER_FINGERPRINTS:
                val = r.headers.get(header_name, "")
                if not val:
                    continue
                if pattern:
                    m = re.search(pattern, val, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.lastindex else val
                        tech_stack.append(f"{label}/{version}")
                        version_disclosures[label] = version
                else:
                    tech_stack.append(label)

            # Fingerprint from response body
            body = r.text[:5000]
            body_fingerprints = [
                (r"wp-content|wp-includes", "WordPress"),
                (r"Joomla", "Joomla"),
                (r"Drupal\.settings", "Drupal"),
                (r"window\.django", "Django"),
                (r"laravel_session|laravel_token", "Laravel"),
                (r"<title>[^<]*GitLab", "GitLab"),
                (r"Jenkins", "Jenkins"),
                (r"Grafana", "Grafana"),
            ]
            for pattern, label in body_fingerprints:
                if re.search(pattern, body, re.IGNORECASE):
                    tech_stack.append(label)

            web_fingerprint[f"{port}"] = {
                "url":                 base_url,
                "status_code":         r.status_code,
                "tech_stack":          list(set(tech_stack)),
                "version_disclosures": version_disclosures,
                "server":              r.headers.get("server", ""),
                "x_powered_by":        r.headers.get("x-powered-by", ""),
            }

            # Findings for version disclosures
            for tech, ver in version_disclosures.items():
                self.finding(
                    title=f"Version Disclosure: {tech} {ver} on {target}:{port}",
                    description=(
                        f"The server discloses {tech} version {ver} in response headers. "
                        "Version disclosure helps attackers target known CVEs."
                    ),
                    severity=Severity.LOW,
                    mitre_technique="T1592.002",
                    mitre_tactic="Reconnaissance",
                    evidence={"host": target, "port": port, "tech": tech, "version": ver},
                    remediation=(
                        f"Remove or suppress version information from {tech} response headers. "
                        "Configure server to send generic 'Server: webserver' header."
                    ),
                    host=target, confidence=0.95,
                )

            # Check sensitive paths
            await self.noise.jitter.sleep()
            for path, description in _SENSITIVE_PATHS[:8]:  # limit to 8 per port
                try:
                    pr = await client.head(f"{base_url}{path}", timeout=3.0)
                    if pr.status_code in (200, 302, 301, 403):
                        entry = {
                            "url":         f"{base_url}{path}",
                            "status_code": pr.status_code,
                            "description": description,
                        }
                        admin_interfaces.append(entry)
                        sev = Severity.HIGH if pr.status_code == 200 else Severity.MEDIUM
                        self.finding(
                            title=f"Sensitive Path Accessible: {path} on {target}:{port}",
                            description=(
                                f"{description} found at {base_url}{path} "
                                f"(HTTP {pr.status_code}). "
                                "This endpoint may expose sensitive functionality or data."
                            ),
                            severity=sev,
                            mitre_technique="T1592.002",
                            mitre_tactic="Reconnaissance",
                            evidence=entry,
                            remediation=(
                                "Restrict access to administrative interfaces by IP. "
                                "Remove debug/development endpoints from production. "
                                "Ensure admin interfaces require strong authentication."
                            ),
                            host=target, confidence=0.9,
                        )
                except Exception:
                    continue

        raw = {
            "target":           target,
            "web_fingerprint":  web_fingerprint,
            "admin_interfaces": admin_interfaces,
        }
        return self._findings[:], raw
