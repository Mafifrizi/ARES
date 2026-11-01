"""
ares.strategy - Autonomous Engagement Strategy Engine

Re-exports all public symbols from submodules for backward compatibility.
Internal structure:
  strategy/models.py         - ModuleOutcome, RoundResult, EngagementResult, DetectionSpikeError
  strategy/knowledge_base.py - OutcomeKnowledgeBase
  strategy/notifier.py       - OperatorNotifier
  strategy/engine.py         - StrategyEngine
  strategy/enforcer.py       - ConstitutionEnforcer
  strategy/target_state.py   - TargetStateMap
"""

from ares.strategy.engine import (  # noqa: F401
    StrategyEngine,
)
from ares.strategy.knowledge_base import (  # noqa: F401
    OutcomeKnowledgeBase,
)
from ares.strategy.models import (  # noqa: F401
    DetectionSpikeError,
    EngagementResult,
    ModuleOutcome,
    RoundResult,
)
from ares.strategy.notifier import (  # noqa: F401
    OperatorNotifier,
)

__all__ = [
    "ModuleOutcome",
    "RoundResult",
    "EngagementResult",
    "DetectionSpikeError",
    "OutcomeKnowledgeBase",
    "OperatorNotifier",
    "StrategyEngine",
]
