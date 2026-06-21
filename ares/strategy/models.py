"""
ares.strategy.models — Data models for the autonomous engagement strategy engine.

Dataclasses used across StrategyEngine, KnowledgeBase, and Notifier.
Extracted from strategy/__init__.py for maintainability.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class ModuleOutcome:
    module_id:       str
    success:         bool
    quality:         float   = 0.0
    evidence:        str     = ""
    edr_vendor:      str     = "unknown"
    bypass_used:     str     = ""
    findings_count:  int     = 0
    timestamp:       float   = field(default_factory=time.monotonic)


@dataclass
class RoundResult:
    round_num:           int
    plan_confidence:     float
    detection_score:     float
    modules_executed:    list[str]
    outcomes:            list[ModuleOutcome]
    goal_achieved:       bool   = False
    stopped_reason:      str    = ""


@dataclass
class EngagementResult:
    goal:               str
    total_rounds:       int
    final_status:       str
    rounds:             list[RoundResult]
    final_detection_score: float
    modules_succeeded:  list[str]
    modules_failed:     list[str]
    knowledge_updates:  int
    elapsed_seconds:    float


class DetectionSpikeError(Exception):
    """Raised when detection score spikes >15% in a single round."""
    def __init__(self, msg: str, spike: float, round_num: int) -> None:
        super().__init__(msg)
        self.spike     = spike
        self.round_num = round_num
