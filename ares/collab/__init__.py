"""
ARES — collab
Multi-operator collaboration manager

Public API for this package. Import from here in production code:

    from ares.collab import ...
"""
from __future__ import annotations

try:
    from ares.collab.manager import (  # noqa: F401
        CollaborationManager,
        OperatorRole,
        OperatorProfile,
        TargetLock,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "CollaborationManager",
    "OperatorRole",
    "OperatorProfile",
    "TargetLock",
]
