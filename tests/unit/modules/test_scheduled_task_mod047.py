from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.persistence.scheduled_task import (
    RegistryRunKeyPersistence,
    _rrp_set_run_key,
)


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Scheduled-Task-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return RegistryRunKeyPersistence(settings=settings, campaign=campaign, noise=noise)


def test_rrp_handle_cleanup_on_error():
    """MOD-047: rrp handles and dce connection are cleaned up in finally even on error."""
    mock_dce = MagicMock()
    mock_transport = MagicMock()
    mock_transport.get_dce_rpc.return_value = mock_dce

    mock_rrp = MagicMock()
    mock_rrp.hOpenLocalMachine.return_value = {"phKey": "ROOT_HANDLE_123"}
    mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": "RUN_KEY_HANDLE_456"}
    # Fail at SetValue
    mock_rrp.hBaseRegSetValue.side_effect = RuntimeError("Failed writing registry value")

    mock_v5 = MagicMock()
    mock_v5.transport.DCERPCTransportFactory.return_value = mock_transport
    mock_v5.rrp = mock_rrp
    mock_v5.dtypes.MAXIMUM_ALLOWED = 0x02000000

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": mock_v5,
        "impacket.dcerpc.v5.transport": mock_v5.transport,
        "impacket.dcerpc.v5.rrp": mock_rrp,
        "impacket.dcerpc.v5.dtypes": mock_v5.dtypes,
    }

    with patch.dict("sys.modules", mock_modules):
        with pytest.raises(RuntimeError, match="Failed writing registry value"):
            _rrp_set_run_key("10.0.0.5", "admin", "pass", "corp.local", "AresAgent", "payload.exe")

    # Verify both handles were closed and dce disconnected
    mock_rrp.hBaseRegCloseKey.assert_any_call(mock_dce, "RUN_KEY_HANDLE_456")
    mock_rrp.hBaseRegCloseKey.assert_any_call(mock_dce, "ROOT_HANDLE_123")
    mock_dce.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_registry_run_key_default_dry_run_is_false():
    """MOD-047: default dry_run is False, so non-dry-run path is attempted."""
    mod = _make_module()

    mock_rrp_set = MagicMock()
    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.rrp": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules), \
         patch("ares.modules.persistence.scheduled_task._rrp_set_run_key", mock_rrp_set):
        findings, raw = await mod.run(
            target="10.0.0.5",
            username="admin",
            password="pass",
            domain="corp.local",
            value_name="TestVal",
            payload="test.exe",
        )

    # Because dry_run is False, _rrp_set_run_key should be called
    mock_rrp_set.assert_called_once_with("10.0.0.5", "admin", "pass", "corp.local", "TestVal", "test.exe")
    assert raw.get("dry_run") is not True
    assert raw["persistence_established"] is True
