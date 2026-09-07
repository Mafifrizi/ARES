"""
ARES MCP Event Bus.
Provides sub-millisecond, non-blocking UDP loopback event telemetry
between the MCP stdio/SSE server and local TUI terminal monitors.
"""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_EVENT_PORT = 27890
DEFAULT_EVENT_HOST = "127.0.0.1"
TOKEN_STATUS_FILE = Path.home() / ".ares" / "mcp_token_status.json"


class McpEventBus:
    """Non-blocking event emitter for MCP server telemetry."""

    @staticmethod
    def emit(event_type: str, data: Dict[str, Any]) -> None:
        """Emit telemetry event to local monitor over UDP loopback."""
        payload = {
            "timestamp": time.strftime("%H:%M:%S"),
            "type": event_type,
            "data": data,
        }
        try:
            raw = json.dumps(payload).encode("utf-8")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(raw, (DEFAULT_EVENT_HOST, DEFAULT_EVENT_PORT))
            sock.close()
        except Exception:
            pass  # Silent drop if no listener or network exception

    @staticmethod
    def set_token_decision(token: str, decision: str) -> None:
        """Record operator decision (APPROVED or REJECTED) for a token."""
        TOKEN_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "token": token,
            "decision": decision,
            "timestamp": time.strftime("%H:%M:%S"),
        }
        try:
            with open(TOKEN_STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def get_token_decision(token: str) -> Optional[str]:
        """Read operator decision for a token."""
        if not TOKEN_STATUS_FILE.exists():
            return None
        try:
            with open(TOKEN_STATUS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("token") == token:
                return data.get("decision")
        except Exception:
            pass
        return None


class McpEventListener:
    """Non-blocking UDP receiver for terminal monitor."""

    def __init__(self, host: str = DEFAULT_EVENT_HOST, port: int = DEFAULT_EVENT_PORT) -> None:
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self._bind()

    def _bind(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.setblocking(False)
        except Exception:
            self.sock = None

    def poll_events(self) -> List[Dict[str, Any]]:
        """Poll incoming UDP events without blocking."""
        events: List[Dict[str, Any]] = []
        if not self.sock:
            return events

        while True:
            try:
                data, _ = self.sock.recvfrom(65535)
                event = json.loads(data.decode("utf-8"))
                events.append(event)
            except (BlockingIOError, socket.error):
                break
            except Exception:
                break
        return events

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
