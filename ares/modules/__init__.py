"""
ARES — modules
Module base class and result types.

Public API:
    from ares.modules import BaseModule, ModuleResult
    from ares.modules.base import OpsecLevel   # for module authoring

Note: Module discovery uses PluginLoader (inspect.getmembers), not direct imports.
"""
from __future__ import annotations

try:
    from ares.modules.base import (  # noqa: F401
        BaseModule,
        ModuleResult,
    )
except ImportError:
    pass  # optional deps not installed

__all__ = [
    "BaseModule",
    "ModuleResult",
]
