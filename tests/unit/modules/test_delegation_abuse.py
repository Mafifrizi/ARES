from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.ad.delegation_abuse import DelegationAbuseModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Delegation-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return DelegationAbuseModule(settings=settings, campaign=campaign, noise=noise)


def test_rbcd_attack_populates_ccache():
    mod = _make_module()

    mock_ccache_instance = MagicMock()
    mock_ccache_cls = MagicMock(return_value=mock_ccache_instance)

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.krb5": MagicMock(),
        "impacket.krb5.kerberosv5": MagicMock(),
        "impacket.krb5.types": MagicMock(),
        "impacket.krb5.constants": MagicMock(),
        "impacket.krb5.ccache": MagicMock(CCache=mock_ccache_cls),
    }

    mock_modules["impacket.krb5.kerberosv5"].getKerberosTGT.return_value = (
        b"tgt", "cipher", None, b"sk"
    )
    mock_modules["impacket.krb5.kerberosv5"].getKerberosTGS.side_effect = [
        (b"tgs_s4u", "tgs_cipher", None, b"tgs_sk"),
        (b"final_tgs", "cipher2", b"old_key", b"new_key"),
    ]

    with patch.dict("sys.modules", mock_modules):
        ccache_path = mod._rbcd_attack_sync(
            dc="10.0.0.1",
            domain="corp.local",
            username="fake_svc$",
            password="Password123",
            target_computer="DC01$",
            impersonate_user="Administrator",
            target_service="cifs",
        )

        assert ccache_path != ""
        mock_ccache_instance.fromTGS.assert_called_once_with(
            b"final_tgs", b"old_key", b"new_key"
        )
        mock_ccache_instance.saveFile.assert_called_once_with(ccache_path)
        if os.path.exists(ccache_path):
            os.unlink(ccache_path)


def test_rbcd_attack_error_classification_handles_target():
    mod = _make_module()

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.krb5": MagicMock(),
        "impacket.krb5.kerberosv5": MagicMock(),
        "impacket.krb5.types": MagicMock(),
        "impacket.krb5.constants": MagicMock(),
        "impacket.krb5.ccache": MagicMock(),
    }
    mock_modules["impacket.krb5.kerberosv5"].getKerberosTGT.side_effect = ConnectionResetError("DC closed connection")

    with patch.dict("sys.modules", mock_modules):
        with pytest.raises(Exception) as exc_info:
            mod._rbcd_attack_sync(
                dc="10.0.0.1",
                domain="corp.local",
                username="fake_svc$",
                password="Password123",
                target_computer="DC01$",
                impersonate_user="Administrator",
                target_service="cifs",
            )
        # Should not raise UnboundLocalError / NameError: target
        assert "target" not in str(exc_info.value).lower() or "dc closed connection" in str(exc_info.value).lower()
