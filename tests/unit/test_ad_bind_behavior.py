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


def _install_fake_kerberos(monkeypatch, *, tgt_error=None):
    def get_kerberos_tgt(**kwargs):
        if tgt_error is not None:
            raise tgt_error
        return b"tgt", "cipher", b"old_session", b"session"

    def get_kerberos_tgs(**kwargs):
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


def _blocking_tgs_worker(connection, *args):
    time.sleep(5)


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


def test_asreproast_capture_uses_impacket_no_preauth_api(monkeypatch):
    import ares.modules.ad.asreproast as asreproast_mod

    _install_fake_kerberos(monkeypatch)
    import impacket.krb5.kerberosv5 as kerberosv5

    captured = {}

    def fake_get_kerberos_tgt(client, password, domain, lmhash, nthash, **kwargs):
        captured.update(
            client=client,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            **kwargs,
        )
        return b"raw-asrep", None, None, None

    monkeypatch.setattr(kerberosv5, "getKerberosTGT", fake_get_kerberos_tgt)

    raw = asreproast_mod._capture_asrep_raw(
        "10.0.0.5", "lab.local", "legacy-nonpreauth"
    )

    assert raw == b"raw-asrep"
    assert captured["password"] == ""
    assert captured["domain"] == "lab.local"
    assert captured["kdcHost"] == "10.0.0.5"
    assert captured["requestPAC"] is True
    assert captured["kerberoast_no_preauth"] is True


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


def test_enum_users_invalid_credentials_abort_not_network(monkeypatch):
    from ares.modules.ad.enum_users import ADEnumUsersModule

    _install_fake_ldap3(monkeypatch, bind_outcomes=[False])
    module, _ = _make_module(ADEnumUsersModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        module._ldap_query_sync(
            "10.0.0.5",
            "alice@lab.local",
            "WrongPassword1!",
            "lab.local",
            False,
            50,
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "username"
    assert "invalid LDAP credentials" in message
    assert "WrongPassword1!" not in message


def test_enum_users_network_bind_failure_is_actionable(monkeypatch):
    from ares.modules.ad.enum_users import ADEnumUsersModule

    _install_fake_ldap3(
        monkeypatch,
        bind_outcomes=[OSError("socket connection error while opening")],
    )
    module, _ = _make_module(ADEnumUsersModule)

    with pytest.raises(NetworkError) as exc_info:
        module._ldap_query_sync(
            "10.0.0.5",
            "alice@lab.local",
            "Password1!",
            "lab.local",
            False,
            50,
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "retry"
    assert "network/connectivity failure" in message
    assert "use_ldaps=false" in message
    assert "389" in message and "636" in message
    assert "Password1!" not in message


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
async def test_kerberoast_wrong_realm_is_nonretryable(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch, tgt_error=Exception("KDC_ERR_WRONG_REALM"))
    module, _ = _make_module(KerberoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "UserLab!2026",
            "10.0.0.5",
            None,
        )

    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "domain"
    assert str(exc_info.value) == kerberoast_mod.format_kerberos_realm_mismatch()
    assert "UserLab!2026" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kerberoast_clock_skew_is_nonretryable(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(
        monkeypatch,
        tgt_error=Exception("KRB_AP_ERR_SKEW(Clock skew too great)"),
    )
    module, _ = _make_module(KerberoastModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "Password1!",
            "lab.local",
            "HTTP/web.lab.local",
        )

    assert exc_info.value.action == "abort"
    assert exc_info.value.field == "time"
    assert str(exc_info.value) == kerberoast_mod.format_kerberos_clock_skew()
    assert "Password1!" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kerberoast_spn_lookup_consumes_enum_spn_output_key(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.enum_spn import ADEnumSPNModule
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch)

    async def fake_tgs_process(**kwargs):
        return b"tgs"

    monkeypatch.setattr(kerberoast_mod, "_run_tgs_request_process", fake_tgs_process)

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

    _install_fake_kerberos(monkeypatch)
    monkeypatch.setattr(kerberoast_mod, "KERBEROS_TGS_TIMEOUT_SECONDS", 0.01)

    async def fake_enum_spn_run(*args, **kwargs):
        return [], {
            "spn_list": [
                {"name": "svc-web", "spn_list": ["HTTP/web.lab.local"]},
                {"name": "svc-sql", "spn_list": ["MSSQLSvc/sql.lab.local"]},
            ]
        }

    monkeypatch.setattr(ADEnumSPNModule, "run", fake_enum_spn_run)
    real_process = kerberoast_mod._run_tgs_request_process

    async def blocking_tgs_process(**kwargs):
        return await real_process(worker=_blocking_tgs_worker, **kwargs)

    monkeypatch.setattr(kerberoast_mod, "_run_tgs_request_process", blocking_tgs_process)
    module, _ = _make_module(KerberoastModule)

    started = time.monotonic()
    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "Password1!",
            "lab.local",
            None,
        )
    assert time.monotonic() - started < 1.0

    assert exc_info.value.action == "abort"
    assert "LDAP/SPN enumeration succeeded and found 2 Kerberoastable candidate account(s)" in str(exc_info.value)
    assert "Kerberos TGS request timed out before a hash was confirmed" in str(exc_info.value)
    assert "Password1!" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_kerberoast_tgs_collection_window_precedes_engine_timeout(monkeypatch):
    import ares.modules.ad.kerberoast as kerberoast_mod
    from ares.modules.ad.enum_spn import ADEnumSPNModule
    from ares.modules.ad.kerberoast import KerberoastModule

    _install_fake_kerberos(monkeypatch)
    monkeypatch.setattr(kerberoast_mod, "KERBEROS_TGS_TIMEOUT_SECONDS", 0.01)

    async def fake_enum_spn_run(*args, **kwargs):
        return [], {
            "spn_list": [
                {"name": "svc-web", "spn_list": ["HTTP/web.lab.local"]},
                {"name": "svc-sql", "spn_list": ["MSSQLSvc/sql.lab.local"]},
                {"name": "svc-api", "spn_list": ["HTTP/api.lab.local"]},
            ]
        }

    async def slow_tgs_process(**kwargs):
        time.sleep(0.02)
        return b"tgs"

    async def no_sleep(*args):
        return None

    monkeypatch.setattr(ADEnumSPNModule, "run", fake_enum_spn_run)
    monkeypatch.setattr(kerberoast_mod, "_run_tgs_request_process", slow_tgs_process)
    monkeypatch.setattr(kerberoast_mod, "_format_krb5tgs_hash", lambda *args: "")
    module, _ = _make_module(KerberoastModule)
    monkeypatch.setattr(module.noise.jitter, "sleep", no_sleep)
    monkeypatch.setattr(kerberoast_mod.asyncio, "sleep", no_sleep)

    started = time.monotonic()
    with pytest.raises(ModuleValidationError) as exc_info:
        await module._request_tickets(
            "10.0.0.5",
            "alice@lab.local",
            "Password1!",
            "lab.local",
            None,
        )

    assert time.monotonic() - started < 0.5
    assert exc_info.value.action == "abort"
    assert "found 3 Kerberoastable candidate account(s)" in str(exc_info.value)
    assert "Kerberos TGS request timed out before a hash was confirmed" in str(exc_info.value)
    assert "Password1!" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_asreproast_candidate_hash_is_confirmed_with_high_confidence(monkeypatch):
    import ares.modules.ad.asreproast as asreproast_mod
    from ares.core.validator import build_default_validator
    from ares.modules.ad.asreproast import ASREPRoastModule

    _install_fake_kerberos(monkeypatch)
    monkeypatch.setattr(asreproast_mod, "ensure_ad_dependencies", lambda *args, **kwargs: None)
    module, _ = _make_module(ASREPRoastModule)

    async def fake_candidates(*args, **kwargs):
        return ["legacy-nonpreauth"]

    monkeypatch.setattr(module, "_ldap_get_nopreauth", fake_candidates)
    monkeypatch.setattr(
        asreproast_mod,
        "_capture_asrep_raw",
        lambda *args, **kwargs: b"raw-asrep",
    )
    monkeypatch.setattr(
        asreproast_mod,
        "_format_krb5asrep_hash",
        lambda *args, **kwargs: "$krb5asrep$23$redacted",
    )

    findings, raw = await module.run(
        dc="10.0.0.5",
        domain="lab.local",
        username="alice@lab.local",
        password="Password1!",
    )

    assert len(findings) == 1
    assert raw["asrep_hashes"] == ["$krb5asrep$23$redacted"]
    assert "Password1!" not in str(raw)
    validator = build_default_validator()
    validation = await validator.validate(findings[0], raw)
    assert validation.passed is True
    assert validation.confidence == 0.95


def _install_fake_ldap3_ssl_close(monkeypatch, error_message=None):
    class FakeTls:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class FakeServer:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            raise OSError(
                error_message
                or (
                    "socket ssl wrapping error: [WinError 10054] "
                    "An existing connection was forcibly closed by the remote host"
                )
            )

    ldap3_mod = types.ModuleType("ldap3")
    ldap3_mod.ALL = "ALL"
    ldap3_mod.NTLM = "NTLM"
    ldap3_mod.SUBTREE = "SUBTREE"
    ldap3_mod.AUTO_BIND_NO_TLS = "AUTO_BIND_NO_TLS"
    ldap3_mod.Connection = FakeConnection
    ldap3_mod.Server = FakeServer
    ldap3_mod.Tls = FakeTls
    monkeypatch.setitem(sys.modules, "ldap3", ldap3_mod)


@pytest.mark.asyncio
async def test_enum_computers_ssl_close_is_actionable_operator_error(monkeypatch):
    from ares.core.errors import ModuleValidationError
    from ares.modules.ad.enum_computers import ADEnumComputersModule

    _install_fake_ldap3_ssl_close(monkeypatch)
    module, _ = _make_module(ADEnumComputersModule)

    with pytest.raises(ModuleValidationError) as exc_info:
        await module.run(
            dc="10.0.0.5",
            domain="lab.local",
            username="alice@lab.local",
            password="Password1!",
            use_ldaps=False,
        )

    message = str(exc_info.value)
    assert exc_info.value.action == "abort"
    assert "module_error" not in message
    assert "use_ldaps=false" in message
    assert "389" in message and "636" in message
    assert "LDAP/LDAPS" in message
    assert "firewall" in message
    assert "certificate/LDAPS configuration" in message
    assert module._findings == []
    assert "Password1!" not in message


@pytest.mark.asyncio
async def test_enum_computers_config_error_does_not_retry(monkeypatch, minimal_campaign):
    from unittest.mock import AsyncMock, patch

    from ares.core.engine import AresEngine
    from ares.core.config import AresSettings
    from ares.core.noise import JitterEngine
    from ares.modules.ad.enum_computers import ADEnumComputersModule

    engine = AresEngine(settings=AresSettings())
    engine.load_modules()
    _install_fake_ldap3_ssl_close(monkeypatch)
    calls = 0

    original_fetch = ADEnumComputersModule._fetch_computers

    async def counted_fetch(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        return await original_fetch(self, *args, **kwargs)

    monkeypatch.setattr(ADEnumComputersModule, "_fetch_computers", counted_fetch)
    async def no_noise_sleep(*args, **kwargs):
        return None

    monkeypatch.setattr(JitterEngine, "sleep", no_noise_sleep)
    params = {
        "dc": "10.0.0.5",
        "domain": "lab.local",
        "username": "alice@lab.local",
        "password": "Password1!",
        "use_ldaps": False,
    }
    with patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
        result = await engine.run_module("ad.enum_computers", minimal_campaign, params)

    assert calls == 1
    assert retry_sleep.await_count == 0
    assert result.outcome == "operator_error"
    assert result.findings == []
    assert "use_ldaps=false" in result.outcome_message
    assert "389" in result.outcome_message and "636" in result.outcome_message


@pytest.mark.asyncio
async def test_enum_computers_ldaps_network_failure_is_not_module_error(
    monkeypatch, minimal_campaign
):
    from unittest.mock import AsyncMock, patch

    from ares.core.config import AresSettings
    from ares.core.engine import AresEngine
    from ares.core.noise import JitterEngine

    engine = AresEngine(settings=AresSettings())
    engine.load_modules()
    _install_fake_ldap3_ssl_close(
        monkeypatch,
        error_message=(
            "socket connection error while opening: [WinError 10060] "
            "A connection attempt failed because the connected party did not "
            "properly respond"
        ),
    )

    async def no_noise_sleep(*args, **kwargs):
        return None

    monkeypatch.setattr(JitterEngine, "sleep", no_noise_sleep)
    params = {
        "dc": "10.0.0.5",
        "domain": "lab.local",
        "username": "alice@lab.local",
        "password": "Password1!",
        "use_ldaps": True,
    }
    with patch("ares.core.engine.asyncio.sleep", new=AsyncMock()):
        result = await engine.run_module("ad.enum_computers", minimal_campaign, params)

    assert result.outcome == "network_error"
    assert result.findings == []
    assert "module_error" not in result.outcome_message
    assert "use_ldaps=true" in result.outcome_message
    assert "389" in result.outcome_message and "636" in result.outcome_message
    assert "certificate/LDAPS configuration" in result.outcome_message
    assert "Password1!" not in result.outcome_message


@pytest.mark.asyncio
async def test_asreproast_candidate_kerberos_failure_is_candidate_aware(monkeypatch):
    import ares.modules.ad.asreproast as asreproast_mod
    from ares.modules.ad.asreproast import ASREPRoastModule

    monkeypatch.setattr(asreproast_mod, "ensure_ad_dependencies", lambda *args, **kwargs: None)
    module, _ = _make_module(ASREPRoastModule)

    async def fake_candidates(*args, **kwargs):
        return ["legacy-nonpreauth"]

    def skewed_asrep(*args, **kwargs):
        raise RuntimeError(
            "Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great) "
            "password=Password1!"
        )

    monkeypatch.setattr(module, "_ldap_get_nopreauth", fake_candidates)
    monkeypatch.setattr(asreproast_mod, "_capture_asrep_raw", skewed_asrep)

    findings, raw = await module.run(
        dc="10.0.0.5",
        domain="lab.local",
        username="alice@lab.local",
        password="Password1!",
    )

    assert findings == []
    assert raw["outcome_category"] == "operator_error"
    assert "LDAP found 1 ASREPRoast candidate account(s)" in raw["outcome_message"]
    assert "KRB_AP_ERR_SKEW" in raw["outcome_message"]
    assert "Next steps:" in raw["outcome_message"]
    assert "completed_no_findings" not in raw["outcome_message"]
    assert "Password1!" not in raw["outcome_message"]
    assert "Password1!" not in raw["asrep_failure_reason"]


@pytest.mark.asyncio
async def test_asreproast_parse_failure_is_candidate_aware(monkeypatch):
    import ares.modules.ad.asreproast as asreproast_mod
    from ares.modules.ad.asreproast import ASREPRoastModule, ASREPParseError

    monkeypatch.setattr(asreproast_mod, "ensure_ad_dependencies", lambda *args, **kwargs: None)
    module, _ = _make_module(ASREPRoastModule)

    async def fake_candidates(*args, **kwargs):
        return ["legacy-nonpreauth"]

    monkeypatch.setattr(module, "_ldap_get_nopreauth", fake_candidates)
    monkeypatch.setattr(asreproast_mod, "_capture_asrep_raw", lambda *args, **kwargs: b"raw")

    def parse_failure(*args, **kwargs):
        raise ASREPParseError("AS-REP response could not be parsed (EndOfStreamError)")

    monkeypatch.setattr(
        asreproast_mod,
        "_format_krb5asrep_hash",
        parse_failure,
    )

    findings, raw = await module.run(
        dc="10.0.0.5",
        domain="lab.local",
        username="alice@lab.local",
        password="Password1!",
    )

    assert findings == []
    assert raw["outcome_category"] == "module_error"
    assert "candidate=legacy-nonpreauth" in raw["outcome_message"]
    assert "EndOfStreamError" in raw["outcome_message"]
    assert "malformed or unsupported" in raw["outcome_message"]
    assert "Next steps:" in raw["outcome_message"]
    assert "Password1!" not in raw["outcome_message"]


@pytest.mark.asyncio
async def test_asreproast_without_candidates_remains_no_findings(monkeypatch):
    import ares.modules.ad.asreproast as asreproast_mod
    from ares.modules.ad.asreproast import ASREPRoastModule

    monkeypatch.setattr(asreproast_mod, "ensure_ad_dependencies", lambda *args, **kwargs: None)
    module, _ = _make_module(ASREPRoastModule)

    async def no_candidates(*args, **kwargs):
        return []

    def unexpected_asrep(*args, **kwargs):
        raise AssertionError("AS-REP must not be requested without candidates")

    monkeypatch.setattr(module, "_ldap_get_nopreauth", no_candidates)
    monkeypatch.setattr(asreproast_mod, "_capture_asrep_raw", unexpected_asrep)

    findings, raw = await module.run(
        dc="10.0.0.5",
        domain="lab.local",
        username="alice@lab.local",
        password="Password1!",
    )

    assert findings == []
    assert raw["outcome_category"] == "completed_no_findings"
    assert "no accounts without Kerberos pre-auth were found" in raw["outcome_message"]


@pytest.mark.parametrize(
    ("error_text", "category", "reason"),
    [
        ("KRB_AP_ERR_SKEW(Clock skew too great)", "operator_error", "KRB_AP_ERR_SKEW"),
        ("KDC_ERR_WRONG_REALM", "operator_error", "KDC_ERR_WRONG_REALM"),
        ("KDC_ERR_CANNOT_POSTDATE", "operator_error", "KDC_ERR_CANNOT_POSTDATE"),
        ("KDC_ERR_PREAUTH_FAILED", "operator_error", "invalid credentials"),
        ("Kerberos request timed out", "network_error", "timed out"),
        ("unexpected parser failure", "module_error", "unexpected parser failure"),
    ],
)
def test_asreproast_request_error_classification_is_safe(error_text, category, reason):
    from ares.modules.ad.asreproast import classify_asrep_request_error

    actual_category, actual_reason = classify_asrep_request_error(
        RuntimeError(f"{error_text} password=Password1!")
    )

    assert actual_category == category
    assert reason in actual_reason
    assert "Password1!" not in actual_reason
