"""Unit test for MOD-057: normalize LDAP bind format in enum_acl and laps_enum using build_ad_bind_plan."""
from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.ad.dependencies import build_ad_bind_plan
from ares.modules.ad.enum_acl import ADEnumACLModule
from ares.modules.ad.laps_enum import LAPSEnumModule


def _make_module(cls):
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="AD-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


def test_build_ad_bind_plan_formats():
    """Verify build_ad_bind_plan handles UPN, NetBIOS, and plain username."""
    # UPN
    upn_plan = build_ad_bind_plan("alice@corp.local", "corp.local")
    assert upn_plan.mode == "simple"
    assert upn_plan.user == "alice@corp.local"
    assert upn_plan.username_format == "upn"

    # NetBIOS
    netbios_plan = build_ad_bind_plan("CORP\\alice", "corp.local")
    assert netbios_plan.mode == "ntlm"
    assert netbios_plan.user == "CORP\\alice"
    assert netbios_plan.username_format == "netbios"

    # Plain with domain
    plain_plan = build_ad_bind_plan("alice", "corp.local")
    assert plain_plan.mode == "simple"
    assert plain_plan.user == "alice@corp.local"
    assert plain_plan.username_format == "plain_to_upn"


@patch("ldap3.Connection")
@patch("ldap3.Server")
def test_enum_acl_uses_build_ad_bind_plan(mock_server, mock_connection):
    """MOD-057: enum_acl._enum_acls_sync uses build_ad_bind_plan rather than raw string concat."""
    conn_instance = MagicMock()
    conn_instance.bind.return_value = True
    conn_instance.entries = []
    conn_instance.result = {}
    mock_connection.return_value = conn_instance

    module = _make_module(ADEnumACLModule)

    # Test with UPN: should use simple bind and alice@corp.local, NOT CORP.LOCAL\alice@corp.local
    module._enum_acls_sync(
        dc="10.0.0.1",
        username="alice@corp.local",
        password="Password123!",
        domain="corp.local",
    )

    mock_connection.assert_called()
    call_kwargs = mock_connection.call_args[1]
    assert call_kwargs["user"] == "alice@corp.local"
    # For UPN, simple bind is used (no NTLM in kwargs)
    assert "authentication" not in call_kwargs


@patch("ldap3.Connection")
@patch("ldap3.Server")
def test_laps_enum_uses_build_ad_bind_plan(mock_server, mock_connection):
    """MOD-057: laps_enum._query_laps_sync uses build_ad_bind_plan rather than raw string concat."""
    conn_instance = MagicMock()
    conn_instance.bind.return_value = True
    conn_instance.entries = []
    conn_instance.result = {}
    mock_connection.return_value = conn_instance

    module = _make_module(LAPSEnumModule)

    # Test with NetBIOS: should use NTLM authentication
    entries = module._query_laps_sync(
        dc="10.0.0.1",
        username="CORP\\admin",
        password="Password123!",
        domain="corp.local",
    )

    mock_connection.assert_called()
    call_kwargs = mock_connection.call_args[1]
    assert call_kwargs["user"] == "CORP\\admin"
    from ldap3 import NTLM
    assert call_kwargs.get("authentication") == NTLM
