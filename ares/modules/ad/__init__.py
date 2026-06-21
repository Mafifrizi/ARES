"""
ARES — modules.ad
Active Directory attack and enumeration modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.ad.adcs import ADCSModule  # noqa: F401
    from ares.modules.ad.asreproast import ASREPRoastModule  # noqa: F401
    from ares.modules.ad.coerce import CoerceModule  # noqa: F401
    from ares.modules.ad.dcsync import DCSyncModule  # noqa: F401
    from ares.modules.ad.delegation_abuse import DelegationAbuseModule  # noqa: F401
    from ares.modules.ad.enum_acl import ADEnumACLModule  # noqa: F401
    from ares.modules.ad.enum_computers import ADEnumComputersModule  # noqa: F401
    from ares.modules.ad.enum_spn import ADEnumSPNModule  # noqa: F401
    from ares.modules.ad.enum_users import ADEnumUsersModule  # noqa: F401
    from ares.modules.ad.kerberoast import KerberoastModule  # noqa: F401
    from ares.modules.ad.laps_enum import LAPSEnumModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "ADCSModule",
    "ASREPRoastModule",
    "CoerceModule",
    "DCSyncModule",
    "DelegationAbuseModule",
    "ADEnumACLModule",
    "ADEnumComputersModule",
    "ADEnumSPNModule",
    "ADEnumUsersModule",
    "KerberoastModule",
    "LAPSEnumModule",
]
