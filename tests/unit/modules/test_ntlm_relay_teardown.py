from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.lateral.ntlm_relay import NTLMRelayModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="NTLM-Relay-Teardown-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return NTLMRelayModule(settings=settings, campaign=campaign, noise=noise)


def _setup_ldap_mock(initial_dacl_bytes=b"ORIGINAL_DACL_SD"):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_conn.bound = True
    mock_conn.result = {"result": 0, "description": "success"}

    target_entry = MagicMock()
    target_entry.distinguishedName = "CN=TARGET-SRV,CN=Computers,DC=CORP,DC=LOCAL"
    if initial_dacl_bytes is not None:
        target_entry.msDS_AllowedToActOnBehalfOfOtherIdentity.raw_values = [initial_dacl_bytes]
    else:
        target_entry.msDS_AllowedToActOnBehalfOfOtherIdentity.raw_values = []

    def mock_search(base, filter_str, attributes=None):
        if "dNSHostName" in filter_str:
            mock_conn.entries = [target_entry]
        elif "sAMAccountName=" in filter_str:
            machine_entry = MagicMock()
            machine_entry.objectSid.raw_values = [b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"]
            mock_conn.entries = [machine_entry]
        else:
            mock_conn.entries = []

    mock_conn.search.side_effect = mock_search

    mock_ldap3 = MagicMock()
    mock_ldap3.Connection.return_value = mock_conn
    mock_ldap3.NTLM = "NTLM"
    mock_ldap3.AUTO_BIND_NONE = "AUTO_BIND_NONE"
    mock_ldap3.MODIFY_REPLACE = "MODIFY_REPLACE"
    mock_ldap3.MODIFY_DELETE = "MODIFY_DELETE"

    return mock_conn, mock_ldap3


@pytest.mark.asyncio
async def test_rbcd_teardown_on_success():
    """MOD-012: machine account deleted and original DACL restored after successful RBCD attack."""
    mod = _make_module()
    mock_conn, mock_ldap3 = _setup_ldap_mock(initial_dacl_bytes=b"INITIAL_DACL_BYTES")

    mock_modules = {
        "ldap3": mock_ldap3,
        "impacket": MagicMock(),
        "impacket.ldap": MagicMock(),
        "impacket.ldap.ldap": MagicMock(),
        "impacket.ldap.ldapasn1": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules), \
         patch.object(mod, "_s4u_attack", return_value="/tmp/test.ccache"):
        res = await mod._rbcd_attack(
            dc="10.0.0.1",
            domain="corp.local",
            username="attacker",
            password="Password123!",
            target_host="target.corp.local",
            target_user="Administrator",
        )

    assert res.success is True
    # Verify machine account was deleted
    expected_dn = f"CN={res.machine_account.rstrip('$')},CN=Computers,DC=CORP,DC=LOCAL"
    mock_conn.delete.assert_called_once_with(expected_dn)

    # Verify DACL was restored to initial value
    modify_calls = mock_conn.modify.call_args_list
    assert len(modify_calls) >= 2  # first set delegation, then restore
    restore_call = modify_calls[-1]
    assert restore_call.args[0] == "CN=TARGET-SRV,CN=Computers,DC=CORP,DC=LOCAL"
    changes = restore_call.args[1]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
    assert changes[0][0] == "MODIFY_REPLACE"
    assert changes[0][1] == [b"INITIAL_DACL_BYTES"]
    mock_conn.unbind.assert_called_once()


@pytest.mark.asyncio
async def test_rbcd_teardown_on_failure_in_middle():
    """MOD-012: machine account deleted and DACL restored even when S4U fails or raises."""
    mod = _make_module()
    mock_conn, mock_ldap3 = _setup_ldap_mock(initial_dacl_bytes=None)

    mock_modules = {
        "ldap3": mock_ldap3,
        "impacket": MagicMock(),
        "impacket.ldap": MagicMock(),
        "impacket.ldap.ldap": MagicMock(),
        "impacket.ldap.ldapasn1": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules), \
         patch.object(mod, "_s4u_attack", side_effect=RuntimeError("KDC unreachable during S4U")):
        res = await mod._rbcd_attack(
            dc="10.0.0.1",
            domain="corp.local",
            username="attacker",
            password="Password123!",
            target_host="target.corp.local",
            target_user="Administrator",
        )

    assert res.success is False
    assert "KDC unreachable" in res.error

    # Machine account must still be deleted
    expected_dn = f"CN={res.machine_account.rstrip('$')},CN=Computers,DC=CORP,DC=LOCAL"
    mock_conn.delete.assert_called_once_with(expected_dn)

    # When initial DACL was None, MODIFY_DELETE must be called
    modify_calls = mock_conn.modify.call_args_list
    restore_call = modify_calls[-1]
    changes = restore_call.args[1]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
    assert changes[0][0] == "MODIFY_DELETE"
    mock_conn.unbind.assert_called_once()
