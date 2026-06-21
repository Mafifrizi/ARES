"""
ARES — core
Core ARES data models and engine

Public API for this package. Import from here in production code:

    from ares.core import ...
"""
from __future__ import annotations

try:
    from ares.core.campaign import (  # noqa: F401
        Campaign,
        Finding,
        Severity,
        NoiseProfile,
        ScopeEntry,
    )
except ImportError:
    pass  # Optional deps not installed

try:
    from ares.core.errors import (  # noqa: F401
        AresError,
        ScopeViolationError,
        RateLimitError,
        ModuleError,
        ValidationError,
    )
except ImportError:
    pass

try:
    from ares.core.logger import (  # noqa: F401
        get_logger,
    )
except ImportError:
    pass

try:
    from ares.core.config import (  # noqa: F401
        AresSettings,
        get_settings,
    )
except ImportError:
    pass

try:
    from ares.core.tracing import (  # noqa: F401
        setup_tracing,
        trace_module,
        get_tracer,
        get_current_trace_id,
        async_span,
        span,
    )
except ImportError:
    pass

__all__ = [
    "Campaign",
    "Finding",
    "Severity",
    "NoiseProfile",
    "ScopeEntry",
    "AresError",
    "ScopeViolationError",
    "RateLimitError",
    "ModuleError",
    "ValidationError",
    "get_logger",
    "AresSettings",
    "get_settings",
    "setup_tracing",
    "trace_module",
    "get_tracer",
    "get_current_trace_id",
    "async_span",
    "span",
]
