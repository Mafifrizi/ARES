"""Shared TLS verification policy for outbound module connections.

AUDIT run-1 H15/H16/H17. Authenticated LDAPS binds, WinRM-over-HTTPS NTLM
transports and HTTPS recon previously disabled certificate verification
unconditionally, exposing the privileged credentials they carry (and the
responses they trust) to a transparent man-in-the-middle. These helpers make
verification the default and gate the insecure behaviour behind an explicit
operator opt-in (``ARES_ALLOW_INSECURE_TLS=true`` / ``settings.ares_allow_insecure_tls``),
emitting a loud warning whenever verification is actually disabled.
"""
from __future__ import annotations

import ssl
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.modules.tls")


def insecure_tls_allowed() -> bool:
    """Return True only when the operator has explicitly opted in to disabling
    TLS verification. Any failure to resolve settings fails closed (secure)."""
    try:
        from ares.core.config import get_settings

        return bool(getattr(get_settings(), "ares_allow_insecure_tls", False))
    except Exception:
        return False


def _warn_insecure(channel: str) -> None:
    logger.warning(
        "tls_verification_disabled",
        channel=channel,
        detail="ARES_ALLOW_INSECURE_TLS is set; server certificate is NOT verified. "
        "Credentials and responses on this channel are exposed to MITM.",
    )


def ldap_tls(use_ssl: bool, *, ca_certs_file: str | None = None) -> Any:
    """Build an ldap3 ``Tls`` config for a (possibly) LDAPS bind.

    Returns ``None`` for plaintext LDAP. For LDAPS the certificate is required
    and validated against the system trust store by default; verification is
    only disabled when the operator has opted in.
    """
    if not use_ssl:
        return None
    from ldap3 import Tls

    if insecure_tls_allowed():
        _warn_insecure("ldaps")
        return Tls(validate=ssl.CERT_NONE)
    return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_certs_file)


def winrm_cert_validation(use_ssl: bool) -> str:
    """Return the pywinrm ``server_cert_validation`` value for a transport.

    "validate" by default on HTTPS; "ignore" only on operator opt-in. For
    plaintext HTTP the value is irrelevant but we return "validate".
    """
    if use_ssl and insecure_tls_allowed():
        _warn_insecure("winrm")
        return "ignore"
    return "validate"


def httpx_verify() -> bool:
    """Return the ``verify`` value for an httpx client (True unless opted out)."""
    if insecure_tls_allowed():
        _warn_insecure("https")
        return False
    return True


def harden_ssl_context(ctx: ssl.SSLContext, *, channel: str = "tls") -> ssl.SSLContext:
    """Enforce verification on an ``ssl.SSLContext`` unless opted out.

    ``ssl.create_default_context()`` already verifies; this makes the policy
    explicit and only relaxes it (hostname + cert) on operator opt-in.
    """
    if insecure_tls_allowed():
        _warn_insecure(channel)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
