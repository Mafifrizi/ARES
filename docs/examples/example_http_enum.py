"""
ARES Example Module — HTTP Service Enumeration
A minimal, fully commented example of the ARES public module SDK.

Copy this file as a starting point for your own module.
Run the test at the bottom with: pytest docs/examples/example_http_enum.py -v

Installing:
    ares module install ./example_http_enum.py
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.errors import (
    ConnectionRefused,
    ConnectionTimeout,
    ModuleValidationError,
)
from ares.sdk import BaseModule, ExecutionContext, Finding, ModuleResult, OpsecLevel, Severity


class HttpEnumModule(BaseModule):
    """
    Enumerate HTTP/HTTPS services on a target host.
    Detects: server software, interesting headers, directory listing,
    default credentials on admin panels.
    """

    # ── Required: engine uses these for validation, registry, and reports ──
    MODULE_ID          = "web.http_enum"
    MODULE_NAME        = "HTTP Service Enumeration"
    MODULE_CATEGORY    = "web"
    MODULE_DESCRIPTION = "Fingerprint HTTP/HTTPS, detect server version and misconfigs"

    # ── OpSec: how noisy is this module? ──────────────────────────────────
    # LOW = read-only HTTP requests. No login attempts here.
    OPSEC_LEVEL = OpsecLevel.LOW

    # ── Dependency declarations ───────────────────────────────────────────
    # REQUIRES: what this module needs FROM previous modules
    # OUTPUTS:  what this module produces FOR downstream modules
    REQUIRES = ["port_80_open"]          # only run if HTTP port is known open
    OUTPUTS  = ["http_service_info"]     # consumed by e.g. web.sqli_scan

    # ── MITRE ATT&CK mapping ──────────────────────────────────────────────
    MITRE_TECHNIQUES = ["T1190"]         # Exploit Public-Facing Application

    MODULE_AUTHOR = "ARES Team <team@ares-framework.io>"

    # ─────────────────────────────────────────────────────────────────────
    # SDK Contract: three methods you should override
    # ─────────────────────────────────────────────────────────────────────

    async def validate(self, ctx: ExecutionContext) -> None:
        """
        Called BEFORE execute(). Check that the context is complete.
        Raise ModuleValidationError for anything that would prevent execution.
        """
        # target is always required
        ctx.require("target")

        # Set defaults for optional params
        if "port" not in ctx.params:
            ctx.params["port"] = 80
        if "https" not in ctx.params:
            ctx.params["https"] = ctx.params["port"] == 443
        if "timeout_s" not in ctx.params:
            ctx.params["timeout_s"] = 5

        # Validate value ranges
        port = ctx.params["port"]
        if not (1 <= port <= 65535):
            raise ModuleValidationError(
                f"Invalid port: {port}. Must be 1–65535.",
                module_id=self.MODULE_ID,
                field="port",
            )

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        """
        Run the enumeration. All network calls go here.

        Key rules:
          - Always call before_request() to enforce scope + rate limiting
          - Always check ctx.dry_run and return stub data if True
          - Raise ARES errors (not generic exceptions) so the engine
            can make smart retry/fallback decisions
        """
        target  = ctx.target
        port    = ctx.params.get("port", 80)
        https   = ctx.params.get("https", False)
        scheme  = "https" if https else "http"
        url     = f"{scheme}://{target}:{port}"

        result = ModuleResult(
            module_id    = self.MODULE_ID,
            execution_id = ctx.execution_id,
        )

        # ── Rate limit + scope enforcement (always call this) ──
        await self.before_request(target, action="http_get")

        # ── Simulation mode (dry_run=True) ─────────────────────
        if ctx.dry_run:
            result.status   = "success"
            result.artifacts = {
                "url":     url,
                "server":  "nginx/1.24.0",
                "headers": {"X-Powered-By": "PHP/8.1"},
                "title":   "Welcome to nginx!",
                "simulated": True,
            }
            return result

        # ── Real execution ──────────────────────────────────────
        try:
            info = await self._fetch_headers(target, port, https, ctx)

            # Create a finding if anything interesting detected
            interesting = []
            server = info.get("server", "")
            if server:
                interesting.append(f"Server: {server}")
            if info.get("x_powered_by"):
                interesting.append(f"X-Powered-By: {info['x_powered_by']}")
            if info.get("directory_listing"):
                interesting.append("Directory listing enabled")

            if interesting:
                f = self.finding(
                    title       = f"HTTP service on {target}:{port}",
                    description = f"HTTP server detected at {url}. " + " | ".join(interesting),
                    severity    = Severity.LOW,
                    mitre_technique = "T1190",
                    host        = target,
                    evidence    = info,
                )
                result.findings.append(f)

            result.status    = "success"
            result.artifacts = info

        except ConnectionRefusedError:
            # Engine will try fallback (e.g. different port)
            raise ConnectionRefused(
                f"Port {port} refused on {target}",
                module_id=self.MODULE_ID,
                target=target,
                port=port,
            )
        except asyncio.TimeoutError:
            raise ConnectionTimeout(
                f"HTTP timeout after {ctx.params.get('timeout_s', 5)}s on {url}",
                module_id=self.MODULE_ID,
                target=target,
                timeout_s=ctx.params.get("timeout_s", 5),
            )

        return result

    def report(self, result: ModuleResult) -> dict:
        """
        Format this module's result for the campaign report.
        Called by ReportGenerator. Extend the default dict with narrative.
        """
        base = super().report(result)   # get standard structure from BaseModule
        base["narrative"] = (
            "HTTP service enumeration identified web servers and their configurations. "
            "Review for outdated server versions, exposed admin panels, and directory listings."
        )
        base["recommendations"] = [
            "Disable server version disclosure (ServerTokens Prod in Apache, server_tokens off in nginx)",
            "Remove X-Powered-By headers",
            "Disable directory listing",
            "Upgrade server software to latest stable version",
        ]
        return base

    # ── Private helpers ──────────────────────────────────────────────────
    # Keep these private (prefix _). They won't be called by the engine.

    async def _fetch_headers(
        self, target: str, port: int, https: bool, ctx: ExecutionContext
    ) -> dict[str, Any]:
        """
        Fetch HTTP headers and page title from the target.
        Production: use httpx or aiohttp.
        """
        timeout_s = ctx.params.get("timeout_s", 5)

        # Real implementation using httpx (async):
        #
        # import httpx
        # scheme = "https" if https else "http"
        # async with httpx.AsyncClient(verify=False, timeout=timeout_s) as client:
        #     r = await client.get(f"{scheme}://{target}:{port}/",
        #                          follow_redirects=True)
        #     return {
        #         "url":           str(r.url),
        #         "status_code":   r.status_code,
        #         "server":        r.headers.get("server", ""),
        #         "x_powered_by":  r.headers.get("x-powered-by", ""),
        #         "content_type":  r.headers.get("content-type", ""),
        #         "title":         self._extract_title(r.text),
        #         "redirect_chain": [str(h.url) for h in r.history],
        #     }

        # Stub for now:
        return {
            "url":          f"{'https' if https else 'http'}://{target}:{port}/",
            "status_code":  200,
            "server":       "",
            "x_powered_by": "",
        }

    @staticmethod
    def _extract_title(html: str) -> str:
        import re
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        return m.group(1).strip() if m else ""


# ─────────────────────────────────────────────────────────────────────────────
# Tests — run with: pytest docs/examples/example_http_enum.py -v
# ─────────────────────────────────────────────────────────────────────────────

import pytest


@pytest.fixture
def module():
    """Build a module instance using test helpers."""
    from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
    from ares.core.config import AresSettings
    from ares.core.noise import NoiseController
    campaign = Campaign(
        name="example-test", scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    return HttpEnumModule(
        settings=AresSettings(),
        campaign=campaign,
        noise=NoiseController(campaign),
    )


@pytest.mark.asyncio
async def test_validate_sets_defaults(module) -> None:
    ctx = ExecutionContext.for_test(target="10.0.0.1")
    await module.validate(ctx)
    assert ctx.params["port"] == 80          # default set
    assert ctx.params["https"] is False


@pytest.mark.asyncio
async def test_validate_rejects_invalid_port(module) -> None:
    ctx = ExecutionContext.for_test(target="10.0.0.1", params={"port": 99999})
    with pytest.raises(ModuleValidationError) as exc_info:
        await module.validate(ctx)
    assert "port" in exc_info.value.field


@pytest.mark.asyncio
async def test_validate_requires_target(module) -> None:
    from ares.core.errors import InvalidContext
    ctx = ExecutionContext.for_test(target="")
    with pytest.raises(InvalidContext):
        await module.validate(ctx)


@pytest.mark.asyncio
async def test_execute_dry_run(module) -> None:
    ctx = ExecutionContext.for_test(
        target="10.0.0.1",
        params={"port": 80},
        dry_run=True,
    )
    result = await module.execute(ctx)
    assert result.success
    assert result.artifacts.get("simulated") is True
    assert result.module_id == "web.http_enum"


def test_report_has_narrative(module) -> None:
    result = ModuleResult(status="success", module_id="web.http_enum")
    report = module.report(result)
    assert "narrative"        in report
    assert "recommendations"  in report
    assert len(report["recommendations"]) > 0


def test_module_metadata_valid() -> None:
    from ares.sdk import validate_module_class
    errors = validate_module_class(HttpEnumModule)
    assert errors == [], f"Metadata errors: {errors}"


def test_module_satisfies_output() -> None:
    assert HttpEnumModule.satisfies("http_service_info")
    assert not HttpEnumModule.satisfies("kerberos_hashes")


def test_module_needs_input() -> None:
    assert HttpEnumModule.needs("port_80_open")
    assert not HttpEnumModule.needs("domain_creds")
