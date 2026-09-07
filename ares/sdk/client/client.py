"""Programmatic Python Client SDK for ARES API Server (v6.0.0+).

Provides an asynchronous client to orchestrate campaigns, run attack modules,
query findings and attack graphs, and stream real-time execution events.

Usage:
    from ares.sdk import AresClient

    async with AresClient(base_url="http://127.0.0.1:8000", api_key="ares_key_...") as ares:
        campaign = await ares.campaigns.create(name="RedOps-2026", scope=["10.10.0.0/24"])
        print(f"Created campaign: {campaign['id']}")

        modules = await ares.modules.list()
        result = await ares.modules.run("ad.kerberoast", target="dc01.corp.local")
"""
from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import urlparse

import httpx

try:
    import websockets
except ImportError:
    websockets = None  # type: ignore[assignment]


class AresClientError(Exception):
    """Base exception for ARES client errors."""


class AresAuthenticationError(AresClientError):
    """Raised when authentication fails (HTTP 401/403)."""


class AresNotFoundError(AresClientError):
    """Raised when the requested resource is not found (HTTP 404)."""


class AresValidationError(AresClientError):
    """Raised when request payload validation fails (HTTP 422)."""


class _CampaignsResource:
    """Operations on ARES campaigns."""

    def __init__(self, client: AresClient) -> None:
        self._c = client

    async def list(self, page: int = 1, per_page: int = 50) -> list[dict[str, Any]]:
        """List campaigns with pagination."""
        res = await self._c._get("/campaigns", params={"page": page, "per_page": per_page})
        return res if isinstance(res, list) else res.get("items", [])

    async def create(
        self,
        name: str,
        scope: list[str],
        client: str = "internal",
        noise_profile: str = "normal",
        domain: str = "",
        operator: str = "api_client",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new campaign."""
        payload = {
            "name": name,
            "scope": scope,
            "client": client,
            "noise_profile": noise_profile,
            "domain": domain,
            "operator": operator,
            "tags": tags or [],
        }
        return await self._c._post("/campaigns", json_data=payload)

    async def get(self, campaign_id: str) -> dict[str, Any]:
        """Get campaign details by ID."""
        return await self._c._get(f"/campaigns/{campaign_id}")

    async def delete(self, campaign_id: str) -> bool:
        """Delete a campaign by ID."""
        res = await self._c._delete(f"/campaigns/{campaign_id}")
        return bool(res.get("deleted", True))

    async def findings(
        self,
        campaign_id: str,
        page: int = 1,
        per_page: int = 100,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """List findings for a campaign."""
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if severity:
            params["severity"] = severity
        res = await self._c._get(f"/campaigns/{campaign_id}/findings", params=params)
        return res if isinstance(res, list) else res.get("items", [])

    async def hosts(self, campaign_id: str) -> list[dict[str, Any]]:
        """List discovered hosts for a campaign."""
        res = await self._c._get(f"/campaigns/{campaign_id}/hosts")
        return res if isinstance(res, list) else res.get("items", [])

    async def credentials(self, campaign_id: str) -> list[dict[str, Any]]:
        """List recovered credentials for a campaign."""
        res = await self._c._get(f"/campaigns/{campaign_id}/credentials")
        return res if isinstance(res, list) else res.get("items", [])

    async def graph(self, campaign_id: str) -> dict[str, Any]:
        """Retrieve the attack graph visualization payload for a campaign."""
        return await self._c._get(f"/campaigns/{campaign_id}/graph")


class _ModulesResource:
    """Operations on ARES offensive modules."""

    def __init__(self, client: AresClient) -> None:
        self._c = client

    async def list(self) -> list[dict[str, Any]]:
        """List all available attack modules and their metadata schemas."""
        res = await self._c._get("/modules")
        return res if isinstance(res, list) else res.get("items", [])

    async def get(self, module_id: str) -> dict[str, Any]:
        """Get descriptor and parameter schema for a specific module."""
        return await self._c._get(f"/modules/{module_id}")

    async def run(
        self,
        module_id: str,
        target: str = "10.0.0.1",
        params: dict[str, Any] | None = None,
        campaign_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Dispatch a module for execution."""
        payload = {
            "target": target,
            "params": params or {},
            "dry_run": dry_run,
        }
        if campaign_id:
            payload["campaign_id"] = campaign_id
        return await self._c._post(f"/modules/{module_id}/run", json_data=payload)


class _TelemetryResource:
    """Real-time event streaming via WebSockets."""

    def __init__(self, client: AresClient) -> None:
        self._c = client

    async def stream_events(self, campaign_id: str) -> AsyncGenerator[dict[str, Any], None]:
        """Stream real-time campaign execution events over WebSocket."""
        if websockets is None:
            raise AresClientError("websockets library is required for event streaming. Install via: pip install websockets")

        parsed = urlparse(self._c.base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{parsed.netloc}/ws/campaigns/{campaign_id}/events"

        headers = {}
        if self._c.api_key:
            headers["X-API-Key"] = self._c.api_key
        elif self._c.token:
            headers["Authorization"] = f"Bearer {self._c.token}"

        async with websockets.connect(ws_url, extra_headers=headers) as ws:
            async for message in ws:
                if isinstance(message, bytes):
                    message = message.decode("utf-8")
                try:
                    yield json.loads(message)
                except Exception:
                    yield {"raw": message}


class AresClient:
    """Asynchronous programmatic Python client for ARES.

    Usage:
        async with AresClient(base_url="http://127.0.0.1:8000", api_key="...") as client:
            status = await client.health()
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.token = token
        self.timeout = timeout
        self._transport = transport

        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        elif token:
            headers["Authorization"] = f"Bearer {token}"

        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

        self.campaigns = _CampaignsResource(self)
        self.modules = _ModulesResource(self)
        self.telemetry = _TelemetryResource(self)

    async def __aenter__(self) -> AresClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client session."""
        await self._http.aclose()

    async def health(self) -> dict[str, Any]:
        """Check server connectivity and health."""
        return await self._get("/health")

    # ── Internal HTTP request dispatchers ─────────────────────────────────

    def _handle_error(self, response: httpx.Response) -> None:
        if response.is_success:
            return
        status = response.status_code
        try:
            err_data = response.json()
            message = err_data.get("detail") or err_data.get("message") or response.text
        except Exception:
            message = response.text or f"HTTP {status}"

        if status in (401, 403):
            raise AresAuthenticationError(f"Authentication failed ({status}): {message}")
        if status == 404:
            raise AresNotFoundError(f"Resource not found ({status}): {message}")
        if status == 422:
            raise AresValidationError(f"Validation error ({status}): {message}")
        raise AresClientError(f"API request failed ({status}): {message}")

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        res = await self._http.get(path, params=params)
        self._handle_error(res)
        return res.json()

    async def _post(self, path: str, json_data: dict[str, Any] | None = None) -> Any:
        res = await self._http.post(path, json=json_data)
        self._handle_error(res)
        return res.json()

    async def _delete(self, path: str) -> Any:
        res = await self._http.delete(path)
        self._handle_error(res)
        return res.json()


__all__ = [
    "AresClient",
    "AresClientError",
    "AresAuthenticationError",
    "AresNotFoundError",
    "AresValidationError",
]
