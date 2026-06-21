"""
ARES — normalize
Artifact normalization layer

Public API for this package. Import from here in production code:

    from ares.normalize import ...
"""
from __future__ import annotations

try:
    from ares.normalize.artifacts import (  # noqa: F401
        ArtifactNormalizer,
        ArtifactStore,
        HostArtifact,
        UserArtifact,
        HashArtifact,
        CredentialArtifact,
        PermissionArtifact,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ArtifactNormalizer",
    "ArtifactStore",
    "HostArtifact",
    "UserArtifact",
    "HashArtifact",
    "CredentialArtifact",
    "PermissionArtifact",
]
