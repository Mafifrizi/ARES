"""AUDIT run-1 H15/H16/H17: outbound TLS verification is on by default and only
disabled behind the explicit ARES_ALLOW_INSECURE_TLS opt-in."""

import ssl

import pytest

from ares.modules import _tls_security as tlssec


@pytest.fixture
def force_insecure(monkeypatch):
    def _set(value: bool):
        monkeypatch.setattr(tlssec, "insecure_tls_allowed", lambda: value)
    return _set


def test_ldap_tls_plaintext_returns_none(force_insecure):
    force_insecure(False)
    assert tlssec.ldap_tls(False) is None


def test_ldap_tls_verifies_by_default(force_insecure):
    pytest.importorskip("ldap3")  # optional dep; not in the base test env
    force_insecure(False)
    tls = tlssec.ldap_tls(True)
    assert tls is not None
    assert tls.validate == ssl.CERT_REQUIRED


def test_ldap_tls_insecure_only_on_opt_in(force_insecure):
    pytest.importorskip("ldap3")  # optional dep; not in the base test env
    force_insecure(True)
    tls = tlssec.ldap_tls(True)
    assert tls.validate == ssl.CERT_NONE


def test_winrm_cert_validation_default_validate(force_insecure):
    force_insecure(False)
    assert tlssec.winrm_cert_validation(True) == "validate"
    force_insecure(True)
    assert tlssec.winrm_cert_validation(True) == "ignore"
    # plaintext transport is never "ignore"
    assert tlssec.winrm_cert_validation(False) == "validate"


def test_httpx_verify_default_true(force_insecure):
    force_insecure(False)
    assert tlssec.httpx_verify() is True
    force_insecure(True)
    assert tlssec.httpx_verify() is False


def test_harden_ssl_context_defaults_to_verification(force_insecure):
    force_insecure(False)
    ctx = tlssec.harden_ssl_context(ssl.create_default_context())
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True

    force_insecure(True)
    ctx2 = tlssec.harden_ssl_context(ssl.create_default_context())
    assert ctx2.verify_mode == ssl.CERT_NONE
    assert ctx2.check_hostname is False


def test_insecure_defaults_closed_on_settings_error(monkeypatch):
    # If settings cannot be resolved, we must fail closed (verification ON).
    import ares.core.config as cfg

    def _boom():
        raise RuntimeError("no settings")

    monkeypatch.setattr(cfg, "get_settings", _boom)
    assert tlssec.insecure_tls_allowed() is False
