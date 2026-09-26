import sys
import types
from unittest.mock import MagicMock
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


def _install_mock_ldap3(monkeypatch):
    """Install mock ldap3 modules in sys.modules for test environments lacking optional ldap3."""
    ldap3_mod = types.ModuleType("ldap3")
    ldap3_mod.AUTO_BIND_NONE = "AUTO_BIND_NONE"
    ldap3_mod.ALL = "ALL"
    ldap3_mod.NTLM = "NTLM"
    ldap3_mod.SUBTREE = "SUBTREE"

    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_conn.entries = []
    mock_conn.result = {}

    mock_connection_cls = MagicMock(return_value=mock_conn)
    mock_server_cls = MagicMock()
    mock_tls_cls = MagicMock()

    ldap3_mod.Connection = mock_connection_cls
    ldap3_mod.Server = mock_server_cls
    ldap3_mod.Tls = mock_tls_cls
    ldap3_mod.CERT_NONE = 0

    ldap3_core = types.ModuleType("ldap3.core")
    ldap3_exceptions = types.ModuleType("ldap3.core.exceptions")
    ldap3_exceptions.LDAPBindError = type("LDAPBindError", (Exception,), {})
    ldap3_mod.core = ldap3_core
    ldap3_core.exceptions = ldap3_exceptions

    monkeypatch.setitem(sys.modules, "ldap3", ldap3_mod)
    monkeypatch.setitem(sys.modules, "ldap3.core", ldap3_core)
    monkeypatch.setitem(sys.modules, "ldap3.core.exceptions", ldap3_exceptions)

    return mock_connection_cls, mock_conn


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


def test_enum_acl_uses_build_ad_bind_plan(monkeypatch):
    """MOD-057: enum_acl._enum_acls_sync uses build_ad_bind_plan rather than raw string concat."""
    mock_connection_cls, mock_conn = _install_mock_ldap3(monkeypatch)

    module = _make_module(ADEnumACLModule)

    # Test with UPN: should use simple bind and alice@corp.local, NOT CORP.LOCAL\\alice@corp.local
    module._enum_acls_sync(
        dc="10.0.0.1",
        username="alice@corp.local",
        password="Password123!",
        domain="corp.local",
    )

    mock_connection_cls.assert_called()
    call_kwargs = mock_connection_cls.call_args[1]
    assert call_kwargs["user"] == "alice@corp.local"
    # For UPN, simple bind is used (no NTLM in kwargs)
    assert "authentication" not in call_kwargs


def test_laps_enum_uses_build_ad_bind_plan(monkeypatch):
    """MOD-057: laps_enum._query_laps_sync uses build_ad_bind_plan rather than raw string concat."""
    mock_connection_cls, mock_conn = _install_mock_ldap3(monkeypatch)

    module = _make_module(LAPSEnumModule)

    # Test with NetBIOS: should use NTLM authentication
    module._query_laps_sync(
        dc="10.0.0.1",
        username="CORP\\admin",
        password="Password123!",
        domain="corp.local",
    )

    mock_connection_cls.assert_called()
    call_kwargs = mock_connection_cls.call_args[1]
    assert call_kwargs["user"] == "CORP\\admin"
    assert call_kwargs.get("authentication") == "NTLM"
