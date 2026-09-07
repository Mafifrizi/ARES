"""Model Context Protocol (MCP) JSON-RPC 2.0 Schemas & Types.

Strict implementation of the Anthropic Model Context Protocol specification (2024-11-05).
Zero external dependency: uses standard Python typing and Pydantic v2.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field

LATEST_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = ["2024-11-05", "2024-10-07"]


class ErrorCode(int, Enum):
    """Standard JSON-RPC 2.0 and MCP error codes."""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # MCP Custom Application Errors (-32000 to -32099)
    UNAUTHORIZED = -32001
    SCOPE_VIOLATION = -32002
    CONFIRMATION_REQUIRED = -32003
    CIRCUIT_BREAKER_OPEN = -32004
    RATE_LIMITED = -32005


class JSONRPCError(BaseModel):
    """JSON-RPC 2.0 Error object."""
    code: int
    message: str
    data: Any | None = None


class JSONRPCRequest(BaseModel):
    """JSON-RPC 2.0 Request."""
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 Response."""
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    result: Any | None = None
    error: JSONRPCError | None = None


class JSONRPCNotification(BaseModel):
    """JSON-RPC 2.0 Notification (no id)."""
    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: dict[str, Any] | None = None


# ── MCP Protocol Negotiation ──────────────────────────────────────────────

class ClientInfo(BaseModel):
    name: str
    version: str = "1.0.0"


class InitializeRequestParams(BaseModel):
    protocolVersion: str = LATEST_PROTOCOL_VERSION
    capabilities: dict[str, Any] = Field(default_factory=dict)
    clientInfo: ClientInfo = Field(default_factory=lambda: ClientInfo(name="generic-mcp-client"))


class ServerCapabilities(BaseModel):
    tools: dict[str, Any] = Field(default_factory=lambda: {"listChanged": False})
    resources: dict[str, Any] = Field(default_factory=lambda: {"subscribe": False, "listChanged": False})
    prompts: dict[str, Any] = Field(default_factory=lambda: {"listChanged": False})
    logging: dict[str, Any] = Field(default_factory=dict)


class ServerInfo(BaseModel):
    name: str = "ares-mcp-server"
    version: str = "6.0.0"
    description: str = "ARES Sovereign Security-First Offensive Simulation Gateway"


class InitializeResult(BaseModel):
    protocolVersion: str = LATEST_PROTOCOL_VERSION
    capabilities: ServerCapabilities = Field(default_factory=ServerCapabilities)
    serverInfo: ServerInfo = Field(default_factory=ServerInfo)
    instructions: str = (
        "ARES Sovereign Security-First MCP Server. "
        "Enforces pre-flight ScopeGuard, cryptographic two-tier confirmation tokens, "
        "anti-prompt-injection taint tracking, and Active Directory lockout circuit breaking. "
        "Tier-1 read-only and simulation tools run freely. "
        "Tier-2 active execution requires an explicit confirmation_token produced by a dry-run."
    )


# ── MCP Tool Primitives ───────────────────────────────────────────────────

class ToolInputSchema(BaseModel):
    type: Literal["object"] = "object"
    properties: dict[str, Any] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)


class Tool(BaseModel):
    name: str
    description: str
    inputSchema: ToolInputSchema


class TextContent(BaseModel):
    type: Literal["text"] = "text"
    text: str


class CallToolResult(BaseModel):
    content: list[TextContent]
    isError: bool = False


# ── MCP Resource Primitives ───────────────────────────────────────────────

class Resource(BaseModel):
    uri: str
    name: str
    description: str = ""
    mimeType: str = "application/json"


class ResourceContents(BaseModel):
    uri: str
    mimeType: str = "application/json"
    text: str


class ReadResourceResult(BaseModel):
    contents: list[ResourceContents]


# ── MCP Prompt Primitives ─────────────────────────────────────────────────

class PromptArgument(BaseModel):
    name: str
    description: str = ""
    required: bool = False


class Prompt(BaseModel):
    name: str
    description: str = ""
    arguments: list[PromptArgument] = Field(default_factory=list)


class PromptMessage(BaseModel):
    role: Literal["user", "assistant"] = "user"
    content: TextContent


class GetPromptResult(BaseModel):
    description: str = ""
    messages: list[PromptMessage]
