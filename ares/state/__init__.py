"""
ARES — state
Session/host state tracking

Public API for this package. Import from here in production code:

    from ares.state import ...
"""
from __future__ import annotations

try:
    from ares.state.target_state import (  # noqa: F401
        HostState,
        TargetHost,
        OperatorSession,
        CompromiseLevel,
        ServiceEntry,
        AttackHistoryEntry,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "HostState",
    "TargetHost",
    "OperatorSession",
    "CompromiseLevel",
    "ServiceEntry",
    "AttackHistoryEntry",
]
