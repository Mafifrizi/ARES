from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.modules.network.service_detect import _grab_banner


@pytest.mark.asyncio
async def test_service_detect_socket_cleanup_on_timeout():
    """MOD-060: socket writer is closed and wait_closed is called even if TimeoutError occurs during read."""
    mock_reader = AsyncMock()
    mock_reader.read.side_effect = asyncio.TimeoutError("Read timed out")

    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    async def fake_open_connection(*args, **kwargs):
        return mock_reader, mock_writer

    with patch("asyncio.open_connection", side_effect=fake_open_connection):
        banner = await _grab_banner("10.0.0.1", 80, timeout=1.0)
        assert banner == ""
        assert mock_writer.close.called
        assert mock_writer.wait_closed.called


@pytest.mark.asyncio
async def test_service_detect_socket_cleanup_on_normal_read():
    """MOD-060: socket writer is closed cleanly on normal read completion."""
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"

    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    async def fake_open_connection(*args, **kwargs):
        return mock_reader, mock_writer

    with patch("asyncio.open_connection", side_effect=fake_open_connection):
        banner = await _grab_banner("10.0.0.1", 22, timeout=1.0)
        assert "SSH-2.0-OpenSSH_8.9p1" in banner
        assert mock_writer.close.called
        assert mock_writer.wait_closed.called
