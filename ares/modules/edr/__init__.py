"""
ARES — modules.edr
EDR detection and adaptive evasion modules.
"""
from __future__ import annotations

try:
    from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule  # noqa: F401
except ImportError:
    pass

__all__ = ["EDRAdaptiveBypassModule"]
