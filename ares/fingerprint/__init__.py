"""
ARES — fingerprint
OS, EDR, and environment fingerprinting

Public API for this package. Import from here in production code:

    from ares.fingerprint import ...
"""
from __future__ import annotations

try:
    from ares.fingerprint.engine import (  # noqa: F401
        EnvironmentFingerprinter,
        FingerprintResult,
        OSType,
        EDRVendor,
        DomainRole,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "EnvironmentFingerprinter",
    "FingerprintResult",
    "OSType",
    "EDRVendor",
    "DomainRole",
]
