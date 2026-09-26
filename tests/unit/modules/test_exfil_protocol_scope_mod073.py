"""
Tests for MOD-073: Scope Guard / Rate Limiter protocol string in before_request().
Verifies exfil.secrets_scan and exfil.smb_shares use explicit protocol strings ('ssh', 'smb')
instead of the uncalibrated 'default'.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.exfil.secrets_scan import SecretsScan
from ares.modules.exfil.smb_shares import SmbSharesExfil


def _make_deps():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Exfil-Protocol-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return settings, campaign, noise


@pytest.mark.asyncio
async def test_secrets_scan_uses_ssh_protocol_for_linux():
    """Verify secrets_scan passes 'ssh' to before_request for Linux scans."""
    settings, campaign, noise = _make_deps()
    mod = SecretsScan(settings=settings, campaign=campaign, noise=noise)

    mock_before_req = AsyncMock()
    with patch.object(mod, "before_request", mock_before_req):
        with patch("ares.modules.exfil.secrets_scan._ssh_scan", return_value=[]):
            await mod.run(
                target="192.168.1.100",
                username="root",
                platform="linux",
            )

    mock_before_req.assert_awaited_once_with("192.168.1.100", "ssh")


@pytest.mark.asyncio
async def test_secrets_scan_uses_smb_protocol_for_windows():
    """Verify secrets_scan passes 'smb' to before_request for Windows scans."""
    settings, campaign, noise = _make_deps()
    mod = SecretsScan(settings=settings, campaign=campaign, noise=noise)

    mock_before_req = AsyncMock()
    with patch.object(mod, "before_request", mock_before_req):
        with patch("ares.modules.exfil.secrets_scan._wmi_scan", return_value=[]):
            await mod.run(
                target="192.168.1.101",
                username="Administrator",
                platform="windows",
            )

    mock_before_req.assert_awaited_once_with("192.168.1.101", "smb")


@pytest.mark.asyncio
async def test_smb_shares_uses_smb_protocol():
    """Verify smb_shares passes 'smb' to before_request."""
    import sys
    settings, campaign, noise = _make_deps()
    mod = SmbSharesExfil(settings=settings, campaign=campaign, noise=noise)

    mock_before_req = AsyncMock()
    mock_smb_module = MagicMock()
    with patch.dict(sys.modules, {"impacket": MagicMock(), "impacket.smbconnection": mock_smb_module}):
        with patch.object(mod, "before_request", mock_before_req):
            with patch("asyncio.get_running_loop") as mock_loop:
                fake_loop = MagicMock()
                mock_loop.return_value = fake_loop
                fake_loop.run_in_executor = AsyncMock(return_value=([], []))

                await mod.run(
                    target="192.168.1.102",
                    username="Administrator",
                )

    mock_before_req.assert_awaited_once_with("192.168.1.102", "smb")
