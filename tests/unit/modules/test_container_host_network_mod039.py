"""
Tests for MOD-039: Container host_network weak heuristic replacement.
Verifies:
1. Container with standard interfaces (lo, eth0) does not produce false positive finding.
2. Verified host network via netns inode comparison produces high confidence finding (0.95).
3. Host interface detection (ens, docker0) produces potential finding with confidence < 0.5.
"""

from unittest.mock import MagicMock, mock_open, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux.container import ContainerEscapeModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Container-MOD039-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return ContainerEscapeModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_standard_container_no_false_positive():
    """Container with standard lo and eth0 does not trigger host network finding."""
    mod = _make_module()

    mock_dev_data = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 12345678    1000    0    0    0     0          0         0 12345678    1000    0    0    0     0       0          0\n"
        "  eth0: 98765432    5000    0    0    0     0          0         0 98765432    5000    0    0    0     0       0          0\n"
    )

    with patch("os.stat", side_effect=OSError("Permission denied")), \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=mock_dev_data)):

        res = await mod._check_host_network()

        assert res["host_network_detected"] is False
        assert len(mod._findings) == 0


@pytest.mark.asyncio
async def test_verified_host_network_netns_inode_match():
    """Netns inode match produces verified host network finding with 0.95 confidence."""
    mod = _make_module()

    mock_stat = MagicMock()
    mock_stat.st_ino = 4026531992

    with patch("os.stat", return_value=mock_stat), \
         patch("os.path.exists", return_value=False):

        res = await mod._check_host_network()

        assert res["host_network_detected"] is True
        assert res["verified"] is True
        assert len(mod._findings) == 1
        finding = mod._findings[0]
        assert "Host Network Namespace" in finding.title
        assert finding.confidence == 0.95


@pytest.mark.asyncio
async def test_host_interfaces_detected_calibrated_confidence():
    """Host interfaces (ens33, docker0) detected produces potential finding with confidence < 0.5."""
    mod = _make_module()

    mock_dev_data = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n"
        " ens33: 5000 50 0 0 0 0 0 0 5000 50 0 0 0 0 0 0\n"
        "docker0: 2000 20 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
    )

    with patch("os.stat", side_effect=OSError("Permission denied")), \
         patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=mock_dev_data)):

        res = await mod._check_host_network()

        assert res["host_network_detected"] is True
        assert res["verified"] is False
        assert len(mod._findings) == 1
        finding = mod._findings[0]
        assert "Potential" in finding.title
        assert finding.confidence < 0.5
