"""ARES MCP Universal Multi-Format Tool Exporter.

Enables systems that do not yet support native MCP (such as raw OpenAI SDK,
Google Gemini SDK, LangChain, AutoGen, and CrewAI) to consume ARES operational
tools seamlessly.
"""
from __future__ import annotations

from typing import Any
from ares.mcp.protocol import Tool


def export_openai_tools(tools: list[Tool]) -> list[dict[str, Any]]:
    """Convert MCP tools into standard OpenAI Tools (Function Calling) format."""
    openai_tools = []
    for tool in tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": {
                    "type": tool.inputSchema.type,
                    "properties": tool.inputSchema.properties,
                    "required": tool.inputSchema.required,
                },
            },
        })
    return openai_tools


def export_gemini_tools(tools: list[Tool]) -> list[dict[str, Any]]:
    """Convert MCP tools into Google Gemini Function Calling format."""
    gemini_declarations = []
    for tool in tools:
        gemini_declarations.append({
            "name": tool.name,
            "description": tool.description,
            "parameters": {
                "type": tool.inputSchema.type.upper(),
                "properties": tool.inputSchema.properties,
                "required": tool.inputSchema.required,
            },
        })
    return gemini_declarations


def export_json_schema(tools: list[Tool]) -> dict[str, Any]:
    """Export complete tool inventory as a single JSON Schema object."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AresMcpToolInventory",
        "type": "object",
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.inputSchema.model_dump(),
            }
            for t in tools
        ],
    }


def generate_langchain_snippet() -> str:
    """Generate Python code snippet to bind ARES MCP server to LangChain."""
    return """# LangChain MCP Adapter for ARES
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI

async def main():
    async with MultiServerMCPClient(
        {
            "ares": {
                "command": "ares",
                "args": ["mcp", "stdio"],
                "transport": "stdio",
            }
        }
    ) as client:
        tools = client.get_tools()
        model = ChatOpenAI(model="gpt-4o").bind_tools(tools)
        response = await model.ainvoke("List findings on campaign Lab-01")
        print(response)
"""
