from __future__ import annotations

import sys
import time
import types

import pytest

from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError, NetworkError
from tests.unit.modules.test_modules import _make_module


def _install_fake_ldap3(monkeypatch, *, bind_outcomes=None):
    bind_outcomes = list(bind_outcomes or [True])

    class LDAPBindError(Exception):
        pass

    class FakeTls:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class FakeServer:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class FakeConnection:
        calls: list[dict] = []

        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.result = {}
            self.entries = []
            FakeConnection.calls.append(kwargs)

        def bind(self):
            outcome = bind_outcomes.pop(0) if bind_outcomes else True
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, tuple):
                ok, result = outcome
                self.result = result
                return ok
            if outcome is False:
                self.result = {"result": 49, "description": "invalidCredentials"}
                return False
            return True

        def search(self, *args, **kwargs):
            self.result = {
                "controls": {
                    "1.2.840.113556.1.4.319": {"value": {"cookie": b""}}
                }
            }
            self.entries = []
            return True

        def unbind(self):
            return True

    ldap3_mod = types.ModuleType("ldap3")
    ldap3_mod.AUTO_BIND_NONE = "AUTO_BIND_NONE"
    ldap3_mod.ALL = "ALL"
    ldap3_mod.NTLM = "NTLM"
    ldap3_mod.SUBTREE = "SUBTREE"
    ldap3_mod.Connection = FakeConnection
    ldap3_mod.Server = FakeServer
    ldap3_mod.Tls = FakeTls
    ldap3_mod.CERT_NONE = 0

    ldap3_core = types.ModuleType("ldap3.core")
    ldap3_exceptions = types.ModuleType("ldap3.core.exceptions")
    ldap3_exceptions.LDAPBindError = LDAPBindError
    ldap3_mod.core = ldap3_core
    ldap3_core.exceptions = ldap3_exceptions

    monkeypatch.setitem(sys.modules, "ldap3", ldap3_mod)
    monkeypatch.setitem(sys.modules, "ldap3.core", ldap3_core)
    monkeypatch.setitem(sys.modules, "ldap3.core.exceptions", ldap3_exceptions)
    return FakeConnection


def _install_fake_kerberos(monkeypatch, *, tgt_error=None, tgs_delay=0):
    def get_kerberos_tgt(**kwargs):
        if tgt_error is not None:
            raise tgt_error
        return b"tgt", "cipher", b"old_session", b"session"

    def get_kerberos_tgs(**kwargs):
        if tgs_delay:
            time.sleep(tgs_delay)
        return b"tgs", "tgs_cipher", b"old", b"tgs_session"

    class _PrincipalNameTypeValue:
        def __init__(self, value):
            self.value = value

    class _PrincipalNameType:
        NT_PRINCIPAL = _PrincipalNameTypeValue(1)
        NT_SRV_INST = _PrincipalNameTypeValue(2)

    class Principal:
        def __init__(self, name, type):
            self.name = name
            self.type = type

    impacket = types.ModuleType("impacket")
    krb5 = types.ModuleType("impacket.krb5")
    kerberosv5 = types.ModuleType("impacket.krb5.kerberosv5")
    kerberosv5.getKerberosTGT = get_kerberos_tgt
    kerberosv5.getKerberosTGS = get_kerberos_tgs
    types_mod = types.ModuleType("impacket.krb5.types")
    types_mod.Principal = Principal
    constants_mod = types.ModuleType("impacket.krb5.constants")
    constants_mod.PrincipalNameType = _PrincipalNameType
    impacket.krb5 = krb5
    krb5.kerberosv5 = kerberosv5
    krb5.types = types_mod
    krb5.constants = constants_mod

    monkeypatch.setitem(sys.modules, "impacket", impacket)
    monkeypatch.setitem(sys.modules, "impacket.krb5", krb5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.kerberosv5", kerberosv5)
    monkeypatch.setitem(sys.modules, "impacket.krb5.types", types_mod)
    monkeypatch.setitem(sys.modules, "impacket.krb5.constants", constants_mod)
    monkeypatch.setitem(sys.modules, "pyasn1", types.ModuleType("pyasn1"))
    monkeypatch.setitem(sys.modules, "pyasn1_modules", types.ModuleType("pyasn1_modules"))


def test_ad_username_sanitizer_preserves_upn_and_explicit_netbios():
    from ares.modules.ad.dependencies import sanitize_ad_username

    assert sanitize_ad_username("alice@lab.local") == "alice@lab.local"
    assert sanitize_ad_username("LAB\\alice") == "LAB\\alice"
    assert sanitize_ad_username("LAB\\alice*") == "LAB\\alice"


@pytest.mark.asyncio
async def test_asreproast_dry_run_does_not_bind_or_request_kerberos(monkeypatch):
    from ares.modules.ad.asreproast import ASREPRoastModule

    async def fail_ldap(*args, **kwargs):
        raise AssertionError("dry-run must not bind LDAP")

    monkeypatch.setattr(ASREPRoastModule, "_ldap_get_nopreauth", fail_ldap)
    module, _ = _make_module(ASREPRoastModule)
    ctx = ExecutionContext.for_test(
        module_id="ad.asreproast",
        params={
            "dc": "10.0.0.5",
            "domain": "lab.local",
            "username": "alice@lab.local",
            "password": "Password1!",
        },
        dry_run=True,
    )

    result = await module.execute(ctx)

    assert result.status == "dry_run"
    assert result.raw["bind_mode"] == "simple"
    assert result.raw["username_format"] == "upn"
    assert result.raw["would_bind_ldap"] is False
    assert result.raw["would_request_kerberos"] is False


@pytest.mark.asyncio
async def test_kerberoast_dry_run_does_not_request_tgt_or_spns(monkeypatch):
    from ares.modules.ad.kerberoast import KerberoastModule

    async def fail_tickets(*args, **kwargs):
        raise AssertionError("dry-run must not request Kerberos tickets")

    monkeypatch.setattr(KerberoastModule, "_request_tickets", fail_tickets)
    module, _ = _make_module(KerberoastModule)
    ctx = ExecutionContext.for_test(
        module_id="ad.kerberoast",
        params={
            "dc": "10.0.0.5",
            "domain": "lab.local",
            "username": "alice@lab.local",
            "password": "Password1!",
            "target_user": "HTTP/web.lab.local",
        },
        dry_run=True,
    )

    result = await module.execute(ctx)

    assert result.status == "dry_run"
    assert result.raw["bind_mode"] == "simple"
    assert result.raw["username_format"] == "upn"
    assert result.raw["would_bind_ldap"] is False
    assert result.raw["would_request_kerberos"] is False


@pytest.mark.asyncio
async def test_asreproast_upn_uses_simple_ldap_bind(monkeypatch):
    from ares.modules.ad.asreproast import ASREPRoastModule

    fake_connection = _install_fake_ldap3(monkeypatch)
    module, _ = _make_module(ASREPRoastModule)

    targets = await module._ldap_get_nopreauth(
        "10.0.0.5",
        "lab.local",
        "alice@lab.local",
        "Password1!",
    )

    assert targets == []
    assert fake_connection.calls[0]["user"] == "alice@lab.local"
    assert "authentication" not in fake_connection.calls[0]


@pytest.mark.asyncio
async def test_asreproast_netbios_ntlm_md4_error_is_actionable_abort(monkeypatch):
    from ares.modules.ad.asreproast import ASREPRoastModule

    fake_connection = _install_fake_ldap3(
        monkeypatch,
        bind_outcomes=[ValueError("unsupported hash type MD4")],
    )
    module, _ = _make_module(ASREPRoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module._ldap_get_nopreauth(
            "10.0.0.5",
            "lab.local",
            "LAB\\alice",
            "Password1!",
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "username"
    assert not isinstance(exc_info.value, NetworkError)
    assert "NTLM bind is unavailable" in message
    assert "alice@lab.local" in message
    assert "Password1!" not in message
    assert fake_connection.calls[0]["authentication"] == "NTLM"


def test_enum_spn_upn_uses_simple_ldap_bind(monkeypatch):
    from ares.modules.ad.enum_spn import ADEnumSPNModule

    fake_connection = _install_fake_ldap3(monkeypatch)
    module, _ = _make_module(ADEnumSPNModule)

    spns = module._fetch_spns_sync(
        "10.0.0.5",
        "alice@lab.local",
        "Password1!",
        "lab.local",
    )

    assert spns == []
    assert fake_connection.calls[0]["user"] == "alice@lab.local"
    assert "authentication" not in fake_connection.calls[0]


def test_enum_spn_invalid_credentials_abort_not_network(monkeypatch):
    from ares.modules.ad.enum_spn import ADEnumSPNModule

    _install_fake_ldap3(monkeypatch, bind_outcomes=[False])
    module, _ = _make_module(ADEnumSPNModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        module._fetch_spns_sync(
            "10.0.0.5",
            "alice@lab.local",
            "WrongPassword1!",
            "lab.local",
        )

    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "username"
    assert not isinstance(exc_info.value, NetworkError)
    assert "invalid LDAP credentials" in str(exc_info.value)
    assert "WrongPassword1!" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kerberoast_invalid_tgt_credentials_are_nonretryable(monkeypatch):
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch, tgt_error=Exception("KDC_ERR_PREAUTH_FAILED"))
    module, _ = _make_module(KerberoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "WrongPassword1!",
            "lab.local",
            "HTTP/web.lab.local",
        )

    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "username"
    assert not isinstance(exc_info.value, NetworkError)
    assert "invalid credentials" in str(exc_info.value)
    assert "WrongPassword1!" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kerberoast_spn_lookup_consumes_enum_spn_output_key(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.enum_spn import ADEnumSPNModule
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch)

    async def fake_enum_spn_run(*args, **kwargs):
        return [], {"spn_list": [{"spn_list": ["HTTP/web.lab.local"]}]}

    monkeypatch.setattr(ADEnumSPNModule, "run", fake_enum_spn_run)
    monkeypatch.setattr(
        kerberoast_mod,
        "_format_krb5tgs_hash",
        lambda *args, **kwargs: "$krb5tgs$23$fake",
    )
    module, _ = _make_module(KerberoastModule)

    hashes, accounts = await module._request_tickets(
        "10.0.0.5",
        "alice@lab.local",
        "Password1!",
        "lab.local",
        None,
    )

    assert hashes == ["$krb5tgs$23$fake"]
    assert accounts[0]["spn"] == "HTTP/web.lab.local"


@pytest.mark.asyncio
async def test_kerberoast_tgs_timeout_after_spn_enumeration_is_actionable(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.enum_spn import ADEnumSPNModule
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch, tgs_delay=0.05)
    monkeypatch.setattr(kerberoast_mod, "KERBEROS_TGS_TIMEOUT_SECONDS", 0.01)

    async def fake_enum_spn_run(*args, **kwargs):
        return [], {
            "spn_list": [
                {"name": "svc-web", "spn_list": ["HTTP/web.lab.local"]},
                {"name": "svc-sql", "spn_list": ["MSSQLSvc/sql.lab.local"]},
            ]
        }

    monkeypatch.setattr(ADEnumSPNModule, "run", fake_enum_spn_run)
    module, _ = _make_module(KerberoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "Password1!",
            "lab.local",
            None,
        )

    assert exc_info.value.action == "abort"
    assert "LDAP/SPN enumeration succeeded and found 2 Kerberoastable candidate account(s)" in str(exc_info.value)
    assert "Kerberos TGS request timed out before a hash was confirmed" in str(exc_info.value)
    assert "Password1!" not in str(exc_info.value)
