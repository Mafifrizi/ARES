"""
ARES — artifact_intel
Artifact correlation and attack opportunity detection

Public API for this package. Import from here in production code:

    from ares.artifact_intel import ...
"""
from __future__ import annotations

try:
    from ares.artifact_intel.correlation import (  # noqa: F401
        ArtifactCorrelationEngine,
        CorrelationOpportunity,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ArtifactCorrelationEngine",
    "CorrelationOpportunity",
]
