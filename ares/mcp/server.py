"""ARES Sovereign MCP Server Engine.

Coordinates protocol negotiation, tool execution, resource streaming,
prompt management, and the 7 Unbreakable Security Guarantees.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine

from ares.mcp.prompts import McpPromptRegistry
from ares.mcp.protocol import (
    ErrorCode,
    InitializeResult,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
    LATEST_PROTOCOL_VERSION,
)
from ares.mcp.resources import McpResourceRegistry
from ares.mcp.security import ConfirmationTokenManager, McpRateLimiter
from ares.mcp.tools import McpToolRegistry

logger = logging.getLogger("ares.mcp.server")


class AresMcpServer:
    """Central Sovereign MCP Server for ARES."""

    def __init__(
        self,
        db: Any | None = None,
        ws_broadcast: Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]] | None = None,
        secret_key: str | None = None,
        rate_per_minute: float = 60.0,
    ) -> None:
        self.db = db
        self.ws_broadcast = ws_broadcast
        self.token_manager = ConfirmationTokenManager(secret_key=secret_key)
        self.rate_limiter = McpRateLimiter(rate_per_minute=rate_per_minute)

        self.tool_registry = McpToolRegistry(
            token_manager=self.token_manager,
            db=self.db,
            ws_broadcast=self.ws_broadcast,
        )
        self.resource_registry = McpResourceRegistry(db=self.db)
        self.prompt_registry = McpPromptRegistry()

        self._initialized = False

    async def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle incoming JSON-RPC request or notification."""
        # 1. Check Rate Limiter
        if not self.rate_limiter.allow():
            req_id = message.get("id")
            return JSONRPCResponse(
                id=req_id,
                error=JSONRPCError(
                    code=ErrorCode.RATE_LIMITED.value,
                    message="Rate limit exceeded. Slow down requests.",
                ),
            ).model_dump(exclude_none=True)

        # 2. Parse request
        try:
            req = JSONRPCRequest.model_validate(message)
        except Exception as e:
            return JSONRPCResponse(
                id=message.get("id"),
                error=JSONRPCError(code=ErrorCode.INVALID_REQUEST.value, message=f"Invalid JSON-RPC request: {e}"),
            ).model_dump(exclude_none=True)

        method = req.method
        params = req.params or {}

        # 3. Notification Handling (no id, returns None)
        if req.id is None:
            if method == "notifications/initialized":
                self._initialized = True
                logger.info("MCP Client connection initialized successfully.")
            return None

        # 4. Request Dispatching
        try:
            if method == "initialize":
                result = InitializeResult(
                    protocolVersion=params.get("protocolVersion", LATEST_PROTOCOL_VERSION)
                )
                self._initialized = True
                return JSONRPCResponse(id=req.id, result=result.model_dump()).model_dump(exclude_none=True)

            if method == "ping":
                return JSONRPCResponse(id=req.id, result={}).model_dump(exclude_none=True)

            # Tools
            if method == "tools/list":
                tools = self.tool_registry.list_tools()
                return JSONRPCResponse(
                    id=req.id,
                    result={"tools": [t.model_dump() for t in tools]},
                ).model_dump(exclude_none=True)

            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                if not tool_name:
                    return JSONRPCResponse(
                        id=req.id,
                        error=JSONRPCError(code=ErrorCode.INVALID_PARAMS.value, message="Missing 'name' in tools/call"),
                    ).model_dump(exclude_none=True)

                res = await self.tool_registry.call_tool(tool_name, tool_args)
                return JSONRPCResponse(id=req.id, result=res.model_dump()).model_dump(exclude_none=True)

            # Resources
            if method == "resources/list":
                resources = self.resource_registry.list_resources()
                return JSONRPCResponse(
                    id=req.id,
                    result={"resources": [r.model_dump() for r in resources]},
                ).model_dump(exclude_none=True)

            if method == "resources/read":
                uri = params.get("uri")
                if not uri:
                    return JSONRPCResponse(
                        id=req.id,
                        error=JSONRPCError(code=ErrorCode.INVALID_PARAMS.value, message="Missing 'uri' in resources/read"),
                    ).model_dump(exclude_none=True)

                res_result = await self.resource_registry.read_resource(uri)
                return JSONRPCResponse(id=req.id, result=res_result.model_dump()).model_dump(exclude_none=True)

            # Prompts
            if method == "prompts/list":
                prompts = self.prompt_registry.list_prompts()
                return JSONRPCResponse(
                    id=req.id,
                    result={"prompts": [p.model_dump() for p in prompts]},
                ).model_dump(exclude_none=True)

            if method == "prompts/get":
                prompt_name = params.get("name")
                prompt_args = params.get("arguments", {})
                if not prompt_name:
                    return JSONRPCResponse(
                        id=req.id,
                        error=JSONRPCError(code=ErrorCode.INVALID_PARAMS.value, message="Missing 'name' in prompts/get"),
                    ).model_dump(exclude_none=True)

                p_result = await self.prompt_registry.get_prompt(prompt_name, prompt_args)
                return JSONRPCResponse(id=req.id, result=p_result.model_dump()).model_dump(exclude_none=True)

            # Unknown Method
            return JSONRPCResponse(
                id=req.id,
                error=JSONRPCError(code=ErrorCode.METHOD_NOT_FOUND.value, message=f"Method not found: '{method}'"),
            ).model_dump(exclude_none=True)

        except Exception as e:
            logger.exception("Internal error handling method %s: %s", method, e)
            return JSONRPCResponse(
                id=req.id,
                error=JSONRPCError(code=ErrorCode.INTERNAL_ERROR.value, message=f"Internal MCP server error: {e}"),
            ).model_dump(exclude_none=True)
