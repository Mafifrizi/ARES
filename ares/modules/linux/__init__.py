"""
ARES — modules.linux
Linux privilege escalation and container escape modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.linux.container import ContainerEscapeModule  # noqa: F401
    from ares.modules.linux.kernel_suggester import KernelSuggesterModule  # noqa: F401
    from ares.modules.linux.ld_preload import LDPreloadModule  # noqa: F401
    from ares.modules.linux.nfs_escape import NFSEscapeModule  # noqa: F401
    from ares.modules.linux.privesc import LinuxPrivescModule  # noqa: F401
    from ares.modules.linux.service_hijack import ServiceHijackModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "ContainerEscapeModule",
    "KernelSuggesterModule",
    "LDPreloadModule",
    "NFSEscapeModule",
    "LinuxPrivescModule",
    "ServiceHijackModule",
]
