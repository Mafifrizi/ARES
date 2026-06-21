"""
ARES — network
Network topology model

Public API for this package. Import from here in production code:

    from ares.network import ...
"""
from __future__ import annotations

try:
    from ares.network.model import (  # noqa: F401
        NetworkModel,
        PortEntry,
        Protocol,
    )
except ImportError:
    pass  # Optional deps not installed


try:
    from ares.network import model  # noqa: F401 — submodule re-export
except ImportError:
    pass

__all__ = [
    "NetworkModel",
    "PortEntry",
    "Protocol",
]
