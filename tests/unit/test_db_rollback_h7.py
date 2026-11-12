"""AUDIT run-1 H7: an unhandled error must not leave the shared SQLite
connection mid-transaction; the generic exception handler rolls it back."""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_generic_exception_handler_rolls_back_shared_connection():
    from ares.api.server import generic_exception_handler

    conn = MagicMock()
    conn.rollback = AsyncMock()
    db = MagicMock()
    db.conn = conn

    request = MagicMock()
    request.app.state.db = db
    request.url.path = "/campaigns"
    request.method = "POST"

    resp = await generic_exception_handler(request, RuntimeError("boom"))
    assert resp.status_code == 500
    conn.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_generic_exception_handler_tolerates_missing_db():
    from ares.api.server import generic_exception_handler

    request = MagicMock()
    request.app.state.db = None
    request.url.path = "/x"
    request.method = "GET"
    # Must not raise even when no DB / no conn is available.
    resp = await generic_exception_handler(request, RuntimeError("boom"))
    assert resp.status_code == 500
