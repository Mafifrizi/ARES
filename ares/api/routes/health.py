from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from ares.__version__ import __version__ as _ares_version

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    db_ok = getattr(request.app.state, "db", None) is not None
    return {
        "status": "ok" if db_ok else "degraded",
        "version": _ares_version,
        "db": "connected" if db_ok else "unavailable",
    }
