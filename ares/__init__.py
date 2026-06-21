"""
ARES — Automated Red team Engagement System
Active Recon & Exploitation Suite for structured, AI-guided penetration testing.

Quickstart:
    from ares.core.campaign import Campaign, NoiseProfile
    from ares.goal.engine import GoalEngine, Goal
    from ares.state.target_state import OperatorSession
    from ares.cli.typer_main import cli
"""
from __future__ import annotations

from ares.__version__ import __version__

__author__  = "ARES Red Team"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
]
