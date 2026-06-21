"""
ARES — marketplace
Module marketplace installer

Public API for this package. Import from here in production code:

    from ares.marketplace import ...
"""
from __future__ import annotations

try:
    from ares.marketplace.installer import (  # noqa: F401
        ModuleInstaller,
        ModuleManifest,
        LocalRegistry,
    )
except ImportError:
    pass  # Optional deps not installed

__all__ = [
    "ModuleInstaller",
    "ModuleManifest",
    "LocalRegistry",
]
