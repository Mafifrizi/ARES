"""
ARES — technique
MITRE ATT&CK technique library

Public API for this package. Import from here in production code:

    from ares.technique import ...
"""
from __future__ import annotations

try:
    from ares.technique.library import (  # noqa: F401
        TechniqueLibrary,
        TechniqueRecord,
        MITRETactic,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "TechniqueLibrary",
    "TechniqueRecord",
    "MITRETactic",
]
