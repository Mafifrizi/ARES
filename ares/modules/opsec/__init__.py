"""
ARES — modules.opsec
OPSEC and detection analysis modules.

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
"""
from __future__ import annotations

try:
    from ares.modules.opsec.coverage_predictor import CoveragePredictorModule  # noqa: F401
except ImportError:
    pass

__all__ = ["CoveragePredictorModule"]
