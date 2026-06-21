"""
ARES — worker
Distributed worker cluster

Public API for this package. Import from here in production code:

    from ares.worker import ...
"""
from __future__ import annotations

try:
    from ares.worker.cluster import (  # noqa: F401
        ClusterController,
        ClusterTask,
        InProcessTaskQueue,
        WorkerRegistration,
        TaskState,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ClusterController",
    "ClusterTask",
    "InProcessTaskQueue",
    "WorkerRegistration",
    "TaskState",
]
