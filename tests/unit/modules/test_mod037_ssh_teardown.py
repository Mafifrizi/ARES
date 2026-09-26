"""
Tests for MOD-037: SSH Connection Leak in 4 Linux Modules.
Ensures asyncssh connections are closed in finally block across:
- ares.modules.linux.privesc (LinuxPrivescModule)
- ares.modules.linux.service_hijack (ServiceHijackModule)
- ares.modules.linux.ld_preload (LDPreloadModule)
- ares.modules.linux.nfs_escape (NFSEscapeModule)
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.errors import HostUnreachable
from ares.core.noise import NoiseController
from ares.modules.linux.ld_preload import LDPreloadModule
from ares.modules.linux.nfs_escape import NFSEscapeModule
from ares.modules.linux.privesc import LinuxPrivescModule
from ares.modules.linux.service_hijack import ServiceHijackModule


MODULE_CLASSES = [
    LinuxPrivescModule,
    ServiceHijackModule,
    LDPreloadModule,
    NFSEscapeModule,
]


def _make_module(cls: type) -> tuple:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="MOD-037-Test",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile("normal"),
    )
    noise = NoiseController(campaign)
    module = cls(settings=settings, campaign=campaign, noise=noise)
    return module, campaign


@pytest.mark.parametrize("mod_cls", MODULE_CLASSES)
@pytest.mark.asyncio
async def test_ssh_connection_closed_on_normal_execution(mod_cls):
    """Test: koneksi asyncssh ditutup setelah eksekusi normal selesai."""
    module, _ = _make_module(mod_cls)

    mock_conn = MagicMock()
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_conn.run = AsyncMock(return_value=mock_result)

    with patch.dict("sys.modules", {"asyncssh": MagicMock(connect=AsyncMock(return_value=mock_conn))}):
        findings, raw = await module.run(
            host="10.0.0.5",
            ssh_user="testuser",
            ssh_pass="secret123",
        )

    assert mock_conn.close.called, f"{mod_cls.__name__} did not call conn.close() on normal completion"


@pytest.mark.parametrize("mod_cls", MODULE_CLASSES)
@pytest.mark.asyncio
async def test_ssh_connection_closed_on_mid_operation_exception(mod_cls):
    """Test: koneksi asyncssh ditutup kalau exception terjadi di tengah operasi."""
    module, _ = _make_module(mod_cls)

    mock_conn = MagicMock()
    mock_conn.close = MagicMock()
    mock_conn.wait_closed = AsyncMock()

    # Raise an exception when running commands over SSH
    mock_conn.run = AsyncMock(side_effect=RuntimeError("Simulated mid-operation network crash"))

    with patch.dict("sys.modules", {"asyncssh": MagicMock(connect=AsyncMock(return_value=mock_conn))}):
        try:
            await module.run(
                host="10.0.0.5",
                ssh_user="testuser",
                ssh_pass="secret123",
            )
        except Exception:
            pass  # Some modules catch exceptions in gather, others re-raise

    assert mock_conn.close.called, f"{mod_cls.__name__} did not call conn.close() when exception occurred"


@pytest.mark.parametrize("mod_cls", MODULE_CLASSES)
@pytest.mark.asyncio
async def test_ssh_connection_closed_on_unreachable_target(mod_cls):
    """Test: kalau target unreachable (exception di connect sendiri), finally tetap aman."""
    module, _ = _make_module(mod_cls)

    mock_asyncssh = MagicMock()
    mock_asyncssh.connect = AsyncMock(side_effect=OSError("Connection refused to target"))

    with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
        with pytest.raises(HostUnreachable):
            await module.run(
                host="10.0.0.5",
                ssh_user="testuser",
                ssh_pass="secret123",
            )
