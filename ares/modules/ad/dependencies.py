"""Shared Active Directory optional dependency checks."""
from __future__ import annotations

import importlib
from collections.abc import Iterable

from ares.core.errors import ModuleValidationError


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
