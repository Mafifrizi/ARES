"""
ARES — modules.reporting
Campaign report generation

Public API for this package. Import from here in production code:

    from ares.modules.reporting import ...
"""
from __future__ import annotations

try:
    from ares.modules.reporting.report_gen import (  # noqa: F401
        ReportGenerator,
        build_report_context,
        REMEDIATION_SLA,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ReportGenerator",
    "build_report_context",
    "REMEDIATION_SLA",
]
