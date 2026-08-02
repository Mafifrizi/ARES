"""Explicit operator tooling for canonical Alembic database ownership.

Application startup never invokes the adoption commands in this package.
Use ``python -m ares.db.migrations --help`` for the fixed noninteractive
operator surface.
"""

from ares.db.migrations.adoption import (
    SUPPORTED_GENERATIONS,
    AdoptionExit,
    AdoptionResult,
    RuntimeGeneration,
)

__all__ = [
    "AdoptionExit",
    "AdoptionResult",
    "RuntimeGeneration",
    "SUPPORTED_GENERATIONS",
]
