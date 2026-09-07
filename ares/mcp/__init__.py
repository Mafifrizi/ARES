"""ARES Sovereign Security-First Model Context Protocol (MCP) Package.

Universal AI Gateway for Claude Desktop, Cursor IDE, Windsurf, VS Code (Cline),
Zed, Open-WebUI, LibreChat, LangChain, LlamaIndex, CrewAI, AutoGen, and Local LLMs (Ollama).
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.mcp.export import export_gemini_tools, export_json_schema, export_openai_tools
from ares.mcp.protocol import CallToolResult, InitializeResult, Tool
from ares.mcp.security import (
    ConfirmationTokenManager,
    McpRateLimiter,
    McpScopeGate,
    McpSecurityViolation,
    McpTaintSanitizer,
    SecretMasker,
)
from ares.mcp.server import AresMcpServer
from ares.mcp.transport.sse import create_sse_app
from ares.mcp.transport.stdio import StdioTransport


async def run_stdio_server(db: Any | None = None, secret_key: str | None = None) -> None:
    """Convenience entry point to run ARES MCP server over stdio."""
    server = AresMcpServer(db=db, secret_key=secret_key)
    transport = StdioTransport(server)
    await transport.run()


__all__ = [
    "AresMcpServer",
    "StdioTransport",
    "create_sse_app",
    "ConfirmationTokenManager",
    "McpScopeGate",
    "McpTaintSanitizer",
    "SecretMasker",
    "McpRateLimiter",
    "McpSecurityViolation",
    "Tool",
    "CallToolResult",
    "InitializeResult",
    "export_openai_tools",
    "export_gemini_tools",
    "export_json_schema",
    "run_stdio_server",
]
