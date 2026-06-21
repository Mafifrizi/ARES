"""
ARES — goal
Goal-based attack planning engine

Public API for this package. Import from here in production code:

    from ares.goal import ...
"""
from __future__ import annotations

try:
    from ares.goal.engine import (  # noqa: F401
        Goal,
        GoalEngine,
        GoalAttackPlan,
        GoalAttackStep,
        GoalDefinition,
        GOAL_DEFINITIONS,
        CapabilityGraph,
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
        AdaptiveStrategy,
        FALLBACK_GRAPH,
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
