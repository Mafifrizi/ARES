"""ARES MCP Asynchronous Stdio Transport.

Implements line-delimited JSON-RPC 2.0 streaming over standard input and output.
Guarantees clean stdout: all logging and diagnostics are diverted to stderr.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ares.mcp.server import AresMcpServer

logger = logging.getLogger("ares.mcp.stdio")


class StdioTransport:
    """Standard input/output stream transport for MCP."""

    def __init__(self, server: AresMcpServer) -> None:
        self.server = server
        self._running = False

    async def run(self) -> None:
        """Run the main event loop reading from stdin and writing to stdout."""
        self._running = True
        sys.stderr.write("[ARES-MCP] Stdio Transport Initialized. Listening on stdin...\n")
        sys.stderr.flush()

        loop = asyncio.get_running_loop()

        while self._running:
            try:
                # Read line asynchronously using to_thread for cross-platform reliability (Windows/Linux/macOS)
                line = await asyncio.to_thread(sys.stdin.readline)
                if not line:
                    # EOF received, client closed connection
                    sys.stderr.write("[ARES-MCP] EOF received on stdin. Shutting down.\n")
                    break

                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    payload = json.loads(line_str)
                except json.JSONDecodeError as e:
                    err_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                    }
                    self._send(err_response)
                    continue

                # Process message through MCP Server
                response = await self.server.handle_message(payload)
                if response is not None:
                    self._send(response)

            except asyncio.CancelledError:
                break
            except Exception as e:
                sys.stderr.write(f"[ARES-MCP] Unexpected transport error: {e}\n")
                sys.stderr.flush()

        self._running = False

    def _send(self, data: dict[str, Any]) -> None:
        """Send JSON-RPC payload to stdout."""
        try:
            line = json.dumps(data)
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[ARES-MCP] Error writing to stdout: {e}\n")
            sys.stderr.flush()

    def stop(self) -> None:
        self._running = False
