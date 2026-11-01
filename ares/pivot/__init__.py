"""
ARES - pivot
Pivot tunnel management (SOCKS5, local-forward, teardown).

Public API for this package. Import from here in production code:

    from ares.pivot import PivotManager, PivotTunnel
"""
from __future__ import annotations

try:
    from ares.pivot.infrastructure import (  # noqa: F401
        PivotManager,
        PivotTunnel,
        PortForward,
        TunnelState,
        TunnelType,
    )
except ImportError:
    pass  # asyncssh not installed

__all__ = [
    "PivotManager",
    "PivotTunnel",
    "TunnelType",
    "TunnelState",
    "PortForward",
]
