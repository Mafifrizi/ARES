from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.persistence.wmi_subscription import WMISubscriptionModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="WMI-Subscription-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return WMISubscriptionModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_wmi_subscription_cleanup_deletes_binding_and_objects():
    """MOD-048: cleanup deletes __FilterToConsumerBinding, consumer, and filter."""
    mod = _make_module()

    mock_dcom = MagicMock()
    mock_login = MagicMock()
    mock_services = MagicMock()

    mock_dcom.CoCreateInstanceEx.return_value = MagicMock()
    mock_dcom_cls = MagicMock(return_value=mock_dcom)

    mock_wmimod = MagicMock()
    mock_wmimod.IWbemLevel1Login.return_value = mock_login
    mock_login.NTLMLogin.return_value = mock_services

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.dcomrt": MagicMock(DCOMConnection=mock_dcom_cls),
        "impacket.dcerpc.v5.dcom": MagicMock(wmi=mock_wmimod),
        "impacket.dcerpc.v5.dtypes": MagicMock(NULL=None),
    }

    with patch.dict("sys.modules", mock_modules):
        res = await mod.cleanup("10.0.0.5", "admin", "pass", "corp.local", "TestPersistence")

    assert res["success"] is True
    assert "__FilterToConsumerBinding/TestPersistenceBinding" in res["message"]
    assert "CommandLineEventConsumer/TestPersistenceConsumer" in res["message"]
    assert "__EventFilter/TestPersistenceFilter" in res["message"]

    deleted_paths = [call.args[0] for call in mock_services.DeleteInstance.call_args_list]
    assert len(deleted_paths) == 3
    # Check that binding path was deleted
    assert any("__FilterToConsumerBinding.Filter=" in p and "Consumer=" in p for p in deleted_paths)
    assert any("CommandLineEventConsumer.Name=\"TestPersistenceConsumer\"" in p for p in deleted_paths)
    assert any("__EventFilter.Name=\"TestPersistenceFilter\"" in p for p in deleted_paths)
    mock_dcom.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_wmi_subscription_persistence_established_truthiness():
    """MOD-048: raw['persistence_established'] is empty string on installation failure."""
    mod = _make_module()

    mock_dcom_cls = MagicMock(side_effect=ConnectionRefusedError("Failed"))
    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.dcomrt": MagicMock(DCOMConnection=mock_dcom_cls),
        "impacket.dcerpc.v5.dcom": MagicMock(),
        "impacket.dcerpc.v5.dtypes": MagicMock(NULL=None),
    }

    with patch.dict("sys.modules", mock_modules):
        findings, raw = await mod.run(
            target="10.0.0.5",
            username="admin",
            password="pass",
            domain="corp.local",
            command="notepad.exe",
            subscription_name="FailSub",
        )

    assert raw["success"] is False
    assert raw["persistence_established"] == ""
    assert len(findings) == 0
