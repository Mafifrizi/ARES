"""
ARES — telemetry
Telemetry and metrics collection

Public API for this package. Import from here in production code:

    from ares.telemetry import TelemetryCollector, get_collector
"""
from __future__ import annotations

try:
    from ares.telemetry.collector import (  # noqa: F401
        TelemetryCollector,
        MetricsCollector,
        ExecutionMetric,
        WorkerHealthSnapshot,
        TelemetrySnapshot,
        get_collector,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "TelemetryCollector",
    "MetricsCollector",
    "ExecutionMetric",
    "WorkerHealthSnapshot",
    "TelemetrySnapshot",
    "get_collector",
]
