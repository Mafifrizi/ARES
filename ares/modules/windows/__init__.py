"""
ARES — modules.windows
Windows post-exploitation modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.windows.applocker_bypass import AppLockerBypassModule  # noqa: F401
    from ares.modules.windows.dpapi import DPAPIModule  # noqa: F401
    from ares.modules.windows.lsa_secrets import LSASecretsModule  # noqa: F401
    from ares.modules.windows.lsass_dump import LsassDumpModule  # noqa: F401
    from ares.modules.windows.registry_enum import RegistryEnumModule  # noqa: F401
    from ares.modules.windows.scheduled_tasks_enum import ScheduledTasksEnumModule  # noqa: F401
    from ares.modules.windows.token_impersonation import TokenImpersonationModule  # noqa: F401
    from ares.modules.windows.uac_bypass import UACBypassModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "AppLockerBypassModule",
    "DPAPIModule",
    "LSASecretsModule",
    "LsassDumpModule",
    "RegistryEnumModule",
    "ScheduledTasksEnumModule",
    "TokenImpersonationModule",
    "UACBypassModule",
]
