"""
ARES — modules.ai
AI-powered attack planning and orchestration modules.
"""
from __future__ import annotations

try:
    from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule  # noqa: F401
except ImportError:
    pass

__all__ = ["AIAutonomousPlannerModule"]
