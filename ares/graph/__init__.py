"""
ARES — graph
Attack graph construction and path analysis

Public API for this package. Import from here in production code:

    from ares.graph import AttackGraph
    graph = AttackGraph()
    graph.build_from_store(store)
    path  = graph.find_path("jsmith", "Domain Admins")
    top   = graph.top_paths(5)
"""
from __future__ import annotations

try:
    from ares.graph.attack_graph import (  # noqa: F401
        AttackGraph,
        GraphNode,
        GraphEdge,
        EdgeType,
    )
except ImportError:
    pass  # networkx not installed

__all__ = [
    "AttackGraph",
    "GraphNode",
    "GraphEdge",
    "EdgeType",
]
