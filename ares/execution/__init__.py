"""
ARES — execution
Remote command execution backends

Public API for this package. Import from here in production code:

    from ares.execution import ...
"""
from __future__ import annotations

try:
    from ares.execution.executor import (  # noqa: F401
        RemoteExecutor,
        ExecutionResult,
        ExecutionMethod,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "RemoteExecutor",
    "ExecutionResult",
    "ExecutionMethod",
]
