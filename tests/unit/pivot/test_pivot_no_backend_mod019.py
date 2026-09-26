"""
Tests for MOD-019: network.pivot & PivotManager phantom active status fix.
Verifies:
1. ModuleExecutionError is raised when neither asyncssh nor ssh binary is available.
2. TunnelState never becomes ACTIVE without a successful backend connection.
3. PivotModule does not publish a successful SOCKS5 pivot finding if backend is unavailable.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.errors import ModuleExecutionError
from ares.core.noise import NoiseController
from ares.modules.network.pivot import PivotModule
from ares.pivot.infrastructure import PivotManager, TunnelState


def _make_pivot_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Pivot-MOD019-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return PivotModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_socks5_no_backend_raises_module_execution_error():
    """Verify establish_socks5 raises ModuleExecutionError when no backend is present."""
    pm = PivotManager(operator="test_op")

    with patch.dict("sys.modules", {"asyncssh": None}), \
         patch("shutil.which", return_value=None):
        with pytest.raises(ModuleExecutionError) as exc_info:
            await pm.establish_socks5(
                pivot_host="10.0.0.5",
                username="root",
                secret="pass",
                local_port=1080,
            )
        assert "No SSH backend available" in str(exc_info.value)

    # TunnelState must never be ACTIVE
    assert pm.active_tunnels() == []


@pytest.mark.asyncio
async def test_local_forward_no_backend_raises_module_execution_error():
    """Verify establish_local_forward raises ModuleExecutionError when no backend is present."""
    pm = PivotManager(operator="test_op")

    with patch.dict("sys.modules", {"asyncssh": None}), \
         patch("shutil.which", return_value=None):
        with pytest.raises(ModuleExecutionError) as exc_info:
            await pm.establish_local_forward(
                pivot_host="10.0.0.5",
                username="root",
                secret="pass",
                remote_host="10.0.0.20",
                remote_port=80,
                local_port=8080,
            )
        assert "No SSH backend available" in str(exc_info.value)

    assert pm.active_tunnels() == []


@pytest.mark.asyncio
async def test_pivot_module_run_no_backend_no_phantom_finding():
    """Verify PivotModule.run raises ModuleExecutionError and emits no phantom active finding."""
    mod = _make_pivot_module()

    with patch.dict("sys.modules", {"asyncssh": None}), \
         patch("shutil.which", return_value=None):
        with pytest.raises(ModuleExecutionError):
            await mod.run(
                target="10.0.0.5",
                username="root",
                secret="password",
                local_port=1080,
            )

    # No findings should have been recorded as active SOCKS5
    active_findings = [f for f in mod._findings if "SOCKS5 Pivot Established" in f.title]
    assert len(active_findings) == 0
