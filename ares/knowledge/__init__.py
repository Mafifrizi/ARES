"""
ARES — knowledge
Attack knowledge base and evidence storage

Public API for this package. Import from here in production code:

    from ares.knowledge import ...
"""
from __future__ import annotations

try:
    from ares.knowledge.base import (  # noqa: F401
        AttackKnowledgeBase,
        KBEntry,
        EvidenceStore,
        Evidence,
        CampaignGuardrail,
        OutcomeTracker,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "AttackKnowledgeBase",
    "KBEntry",
    "EvidenceStore",
    "Evidence",
    "CampaignGuardrail",
    "OutcomeTracker",
]

