"""
ARES - goal
Goal-based attack planning engine

Public API for this package. Import from here in production code:

    from ares.goal import ...
"""
from __future__ import annotations

try:
    from ares.goal.engine import (  # noqa: F401
        GOAL_DEFINITIONS,
        CapabilityGraph,
        Goal,
        GoalAttackPlan,
        GoalAttackStep,
        GoalDefinition,
        GoalEngine,
    )
except ImportError:
    pass  # Optional deps not installed

try:
    from ares.goal.planner import (  # noqa: F401
        AttackPlanner,
        PlannerContext,
        PlanSuggestion,
        Suggestion,
        auto_suggest,
    )
except ImportError:
    pass

try:
    from ares.goal.adaptive import (  # noqa: F401
        FALLBACK_GRAPH,
        AdaptiveStrategy,
    )
except ImportError:
    pass

__all__ = [
    "Goal",
    "GoalEngine",
    "GoalAttackPlan",
    "GoalAttackStep",
    "GoalDefinition",
    "GOAL_DEFINITIONS",
    "AttackPlanner",
    "PlannerContext",
    "PlanSuggestion", "Suggestion",
    "auto_suggest",
    "AdaptiveStrategy",
    "FALLBACK_GRAPH",
]
