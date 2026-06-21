"""
ARES — service_intel
Service intelligence and vulnerability mapping

Public API for this package. Import from here in production code:

    from ares.service_intel import ...
"""
from __future__ import annotations

try:
    from ares.service_intel.engine import (  # noqa: F401
        ServiceIntelEngine,
        ServiceProfile,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ServiceIntelEngine",
    "ServiceProfile",
]
