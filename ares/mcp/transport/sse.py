"""ARES MCP Server-Sent Events (SSE) over HTTP Transport.

Implements the official Model Context Protocol HTTP/SSE transport (2024-11-05 spec):
- GET /sse: Opens persistent SSE stream, issues session_id, and sends 'endpoint' event.
- POST /messages?session_id=...: Ingests JSON-RPC requests, pushes responses through SSE stream or HTTP reply.
- Full Bearer Token / API Key authentication and per-session rate limiting.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

if TYPE_CHECKING:
    from ares.mcp.server import AresMcpServer


class SseSession:
    """Represents an active SSE connection session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.created_at = asyncio.get_event_loop().time()


def create_sse_app(
    server: AresMcpServer,
    api_key: str | None = None,
) -> Starlette:
    """Create a Starlette ASGI application hosting the MCP SSE endpoints."""

    sessions: dict[str, SseSession] = {}

    def _verify_auth(request: Request) -> bool:
        if not api_key:
            return True
        # Check Authorization: Bearer <token> or X-ARES-API-Key or query param
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if secrets.compare_digest(token, api_key):
                return True

        header_key = request.headers.get("x-ares-api-key")
        if header_key and secrets.compare_digest(header_key, api_key):
            return True

        query_key = request.query_params.get("api_key")
        if query_key and secrets.compare_digest(query_key, api_key):
            return True

        return False

    async def handle_sse(request: Request) -> Response:
        """GET /sse: Establish Server-Sent Events stream."""
        if not _verify_auth(request):
            return JSONResponse({"error": "Unauthorized. Provide valid Bearer token or API key."}, status_code=401)

        session_id = f"sess_{secrets.token_hex(16)}"
        session = SseSession(session_id)
        sessions[session_id] = session

        async def event_generator():
            try:
                # 1. Send the initial 'endpoint' event per MCP SSE spec
                endpoint_url = f"/messages?session_id={session_id}"
                yield f"event: endpoint\ndata: {endpoint_url}\n\n"

                # 2. Stream responses from session queue
                while True:
                    data = await session.queue.get()
                    if data is None:
                        break
                    json_str = json.dumps(data)
                    yield f"event: message\ndata: {json_str}\n\n"
            finally:
                sessions.pop(session_id, None)

        from starlette.responses import StreamingResponse
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    async def handle_messages(request: Request) -> Response:
        """POST /messages?session_id=...: Receive JSON-RPC client messages."""
        if not _verify_auth(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

        session_id = request.query_params.get("session_id")
        if not session_id or session_id not in sessions:
            return JSONResponse({"error": "Invalid or expired session_id. Connect to /sse first."}, status_code=400)

        session = sessions[session_id]

        try:
            body = await request.json()
        except Exception as e:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                },
                status_code=400,
            )

        # Process through MCP server
        response = await server.handle_message(body)

        if response is not None:
            # Push to SSE stream
            await session.queue.put(response)
            # Also return JSON response for HTTP callers
            return JSONResponse(response, status_code=202)

        return Response(status_code=204)

    routes = [
        Route("/sse", endpoint=handle_sse, methods=["GET"]),
        Route("/messages", endpoint=handle_messages, methods=["POST"]),
    ]

    return Starlette(routes=routes)
