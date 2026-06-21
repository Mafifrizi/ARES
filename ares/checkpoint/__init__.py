"""
ARES — checkpoint
Campaign checkpoint save/restore

Public API for this package. Import from here in production code:

    from ares.checkpoint import ...
"""
from __future__ import annotations

try:
    from ares.checkpoint.manager import (  # noqa: F401
        CheckpointManager,
        CheckpointData,
        CheckpointManifest,
        build_checkpoint,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "CheckpointManager",
    "CheckpointData",
    "CheckpointManifest",
    "build_checkpoint",
]
