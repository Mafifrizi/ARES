"""
ARES — security
Security hardening utilities, dependency auditing, and vulnerability scanning.

Public API for this package. Import from here in production code:

    from ares.security import run_dependency_audit, startup_audit
"""
from __future__ import annotations

try:
    from ares.security.audit import (  # noqa: F401
        run_dependency_audit,
        startup_audit,
        AuditResult,
        AuditPolicy,
        CVSSScore,
        Vulnerability,
    )
except ImportError:
    pass

__all__ = [
    "run_dependency_audit",
    "startup_audit",
    "AuditResult",
    "AuditPolicy",
    "CVSSScore",
    "Vulnerability",
]
