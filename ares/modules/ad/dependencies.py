"""Shared Active Directory optional dependency checks."""
from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from collections.abc import Iterable
from typing import Any

from ares.core.errors import ModuleValidationError, NetworkError


AD_INSTALL_HINT = (
    'Install AD dependencies with .\\.venv\\Scripts\\python.exe -m pip install -e ".[ad]" '
    'for a normal source checkout, or .\\.venv\\Scripts\\python.exe -m pip install -e ".[ad-support]" '
    "when using source/local Impacket; then restart the dashboard and rerun "
    "ares doctor --pdf-smoke."
)

AD_SUPPORT_DEPENDENCIES: tuple[tuple[str, str], ...] = (
    ("pyasn1", "pyasn1 (AD Kerberos helpers)"),
    ("pyasn1_modules", "pyasn1_modules (AD Kerberos helpers)"),
    ("ldap3", "ldap3 (AD LDAP enumeration)"),
    ("httpx_ntlm", "httpx-ntlm (ADCS HTTP enrollment)"),
)

_AD_IDENTITY_UNSAFE_CHARS = re.compile(r"[*()\x00-\x1f\x7f]")


def ensure_ad_dependencies(import_names: Iterable[str], *, module_id: str) -> None:
    """Raise a non-retryable ARES validation error for missing AD local deps."""
    for import_name in import_names:
        try:
            importlib.import_module(import_name)
        except (ImportError, OSError, RuntimeError) as exc:
            raise ModuleValidationError(
                (
                    f"{module_id} cannot run because AD dependency {import_name!r} "
                    f"is missing or broken ({exc.__class__.__name__}). {AD_INSTALL_HINT}"
                ),
                module_id=module_id,
                field=import_name,
            ) from exc


@dataclass(frozen=True)
class ADBindPlan:
    """Safe LDAP bind plan metadata shared by AD modules."""

    user: str
    mode: str
    username_format: str


def build_ad_bind_plan(username: str, domain: str) -> ADBindPlan:
    """
    Choose a deterministic LDAP bind mode from the user-supplied identity.

    UPN identities use LDAP simple bind to avoid NTLM/MD4 issues on modern
    Windows Python/OpenSSL builds. NETBIOS-style names keep NTLM explicit.
    """
    username = (username or "").strip()
    domain = (domain or "").strip()
    if "@" in username:
        return ADBindPlan(user=username, mode="simple", username_format="upn")
    if "\\" in username:
        return ADBindPlan(user=username, mode="ntlm", username_format="netbios")
    if domain:
        return ADBindPlan(
            user=f"{username}@{domain}",
            mode="simple",
            username_format="plain_to_upn",
        )
    return ADBindPlan(user=username, mode="simple", username_format="plain")


def sanitize_ad_username(value: str) -> str:
    """Strip LDAP filter metacharacters while preserving UPN and NETBIOS forms."""
    return _AD_IDENTITY_UNSAFE_CHARS.sub("", value or "")


def ad_bind_dry_run_metadata(username: str | None, domain: str | None) -> dict[str, Any]:
    """Return safe bind metadata for dry-run output."""
    if not username:
        return {
            "bind_mode": None,
            "username_format": None,
            "would_bind_ldap": False,
            "would_request_kerberos": False,
        }
    plan = build_ad_bind_plan(username, domain or "")
    return {
        "bind_mode": plan.mode,
        "username_format": plan.username_format,
        "would_bind_ldap": False,
        "would_request_kerberos": False,
    }


def _safe_exception_text(exc: BaseException) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return text[:160] if text else exc.__class__.__name__


def _is_ntlm_md4_error(exc: BaseException) -> bool:
    text = f"{exc.__class__.__name__}: {exc}".lower()
    return "unsupported hash type" in text and "md4" in text


def _is_invalid_ldap_credentials(
    exc: BaseException | None = None,
    result: dict[str, Any] | None = None,
) -> bool:
    if result:
        if result.get("result") == 49:
            return True
        combined = " ".join(
            str(result.get(key, ""))
            for key in ("description", "message", "diagnosticMessage")
        ).lower()
        if "invalidcredentials" in combined or "invalid credentials" in combined:
            return True
        if "acceptsecuritycontext" in combined and "data 52e" in combined:
            return True
    if exc is None:
        return False
    text = f"{exc.__class__.__name__}: {exc}".lower()
    return any(
        marker in text
        for marker in (
            "invalidcredentials",
            "invalid credentials",
            "ldapinvalidcredentials",
            "logon failure",
            "data 52e",
            "kdc_err_preauth_failed",
        )
    )


def classify_ad_ldap_bind_failure(
    exc: BaseException,
    *,
    module_id: str,
    dc: str,
    bind_plan: ADBindPlan,
    result: dict[str, Any] | None = None,
) -> ModuleValidationError | NetworkError:
    """Classify LDAP bind failures without exposing passwords or raw traces."""
    context = {
        "dc": dc,
        "bind_mode": bind_plan.mode,
        "username_format": bind_plan.username_format,
    }
    prefix = (
        f"{module_id} LDAP bind failed for dc {dc} using {bind_plan.mode} "
        f"(username_format={bind_plan.username_format})"
    )
    if _is_ntlm_md4_error(exc):
        context["reason"] = "ntlm_md4_unavailable"
        return ModuleValidationError(
            (
                f"{prefix}: NTLM bind is unavailable in this Python/OpenSSL "
                "environment; use UPN format such as alice@lab.local."
            ),
            module_id=module_id,
            field="username",
            target=dc,
            context=context,
        )
    if _is_invalid_ldap_credentials(exc, result):
        context["reason"] = "invalid_credentials"
        return ModuleValidationError(
            f"{prefix}: invalid LDAP credentials.",
            module_id=module_id,
            field="username",
            target=dc,
            context=context,
        )
    context["reason"] = "network_or_directory_unreachable"
    return NetworkError(
        f"{prefix}: network/connectivity failure ({_safe_exception_text(exc)}).",
        module_id=module_id,
        target=dc,
        context=context,
    )


def nonretryable_ad_auth_error(
    *,
    module_id: str,
    dc: str,
    username: str,
    domain: str,
    service: str,
) -> ModuleValidationError:
    """Return a safe, non-retryable AD authentication error."""
    plan = build_ad_bind_plan(username, domain)
    context = {
        "dc": dc,
        "service": service,
        "bind_mode": plan.mode,
        "username_format": plan.username_format,
        "reason": "invalid_credentials",
    }
    return ModuleValidationError(
        (
            f"{module_id} {service} authentication failed for dc {dc} "
            f"(username_format={plan.username_format}): invalid credentials."
        ),
        module_id=module_id,
        field="username",
        target=dc,
        context=context,
    )
