"""
ARES — core.chain
Attack chain automation and dependency resolution

Public API for this package. Import from here in production code:

    from ares.core.chain import ...
"""
from __future__ import annotations

try:
    from ares.core.chain.chain import (  # noqa: F401
        AttackChain,
        DependencyResolver,
        CapabilityResolver,
        ChainAdvisor,
        ChainNode,
        CyclicDependencyError,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "AttackChain",
    "DependencyResolver",
    "CapabilityResolver",
    "ChainAdvisor",
    "ChainNode",
    "CyclicDependencyError",
]
