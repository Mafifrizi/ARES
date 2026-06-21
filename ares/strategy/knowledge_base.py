"""
ares.strategy.knowledge_base — Per-session outcome tracking for autonomous engagements.

Tracks module success rates per EDR vendor across rounds.
Feeds context to AI planner for better decision-making in subsequent rounds.

Extracted from strategy/__init__.py for maintainability.
"""
from __future__ import annotations

from ares.core.logger import get_logger

logger = get_logger("ares.strategy.knowledge_base")


class OutcomeKnowledgeBase:
    """
    Per-session knowledge base tracking module success rates per EDR vendor.
    Persists in memory across rounds — feeds AI planner for better decisions.
    """

    def __init__(self) -> None:
        # (module_id, edr_vendor) → {"attempts": int, "successes": int, ...}
        self._rates: dict[tuple[str, str], dict] = {}

    def record_outcome(
        self, module_id: str, success: bool,
        quality: float = 1.0, evidence: str = "",
        edr_vendor: str = "unknown", bypass_used: str = ""
    ) -> None:
        key = (module_id, edr_vendor)
        if key not in self._rates:
            self._rates[key] = {"attempts": 0, "successes": 0, "total_quality": 0.0,
                                "bypass_techniques": set()}
        self._rates[key]["attempts"] += 1
        if success:
            self._rates[key]["successes"] += 1
        effective_quality = quality if success else 0.0
        self._rates[key]["total_quality"] = (
            self._rates[key].get("total_quality", 0.0) + effective_quality
        )
        if bypass_used:
            self._rates[key]["bypass_techniques"].add(bypass_used)

    def get_success_rates(self) -> dict[str, float]:
        """Return {module_id: quality_weighted_rate} across all EDR vendors."""
        agg: dict[str, dict] = {}
        for (mid, _vendor), stats in self._rates.items():
            if mid not in agg:
                agg[mid] = {"attempts": 0, "successes": 0, "total_quality": 0.0}
            agg[mid]["attempts"] += stats["attempts"]
            agg[mid]["successes"] += stats["successes"]
            agg[mid]["total_quality"] += stats.get("total_quality", 0.0)
        return {
            mid: round(s["total_quality"] / max(s["attempts"], 1), 3)
            for mid, s in agg.items()
        }

    def get_effective_techniques(self, edr_vendor: str) -> list[str]:
        """Return modules that succeeded against this specific EDR vendor."""
        return [
            mid for (mid, v), s in self._rates.items()
            if v == edr_vendor and s["successes"] > 0
        ]
