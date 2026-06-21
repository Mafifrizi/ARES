"""
ARES — credential
Credential storage, management, and reuse testing.

Public API for this package. Import from here in production code:

    from ares.credential import CredentialVault, CredentialReuser
"""
from __future__ import annotations

try:
    from ares.credential.vault import (  # noqa: F401
        CredentialVault,
        Credential,
        CredentialType,
    )
except ImportError:
    pass

try:
    from ares.credential.reuse import (  # noqa: F401
        CredentialReuser,
        ReuseEngine,
        ReuseResult,
        ReuseAttempt,
        ReuseProtocol,
    )
except ImportError:
    pass

__all__ = [
    "CredentialVault",
    "Credential",
    "CredentialType",
    "CredentialReuser",
    "ReuseEngine",
    "ReuseResult",
    "ReuseAttempt",
    "ReuseProtocol",
]
