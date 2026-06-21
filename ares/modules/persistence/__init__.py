"""
ARES — modules.persistence
Persistence mechanism modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.persistence.scheduled_task import ScheduledTaskPersistence  # noqa: F401
    from ares.modules.persistence.scheduled_task import RegistryRunKeyPersistence  # noqa: F401
    from ares.modules.persistence.wmi_subscription import WMISubscriptionModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "ScheduledTaskPersistence",
    "RegistryRunKeyPersistence",
    "WMISubscriptionModule",
]
