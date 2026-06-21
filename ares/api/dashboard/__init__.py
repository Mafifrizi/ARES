"""
ARES — api.dashboard
Real-time campaign dashboard

Public API for this package. Import from here in production code:

    from ares.api.dashboard import ...
"""
from __future__ import annotations

try:
    from ares.api.dashboard.app import (  # noqa: F401
        dashboard_app,
        broadcast_finding,
        live_connections,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "dashboard_app",
    "broadcast_finding",
    "live_connections",
]
