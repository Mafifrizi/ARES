"""
ARES — api
ARES REST API (FastAPI application)

Public API for this package. Import from here in production code:

    from ares.api import ...
"""
from __future__ import annotations

__all__ = [
    "app",
    "lifespan",
]


def __getattr__(name: str):
    """Load the FastAPI server lazily when package-level app symbols are used."""
    if name in __all__:
        from ares.api import server

        return getattr(server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
