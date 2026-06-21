"""
ARES — modules.exfil
Exfiltration and data collection modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.exfil.secrets_scan import SecretsScan  # noqa: F401
    from ares.modules.exfil.smb_shares import SmbSharesExfil  # noqa: F401
    from ares.modules.exfil.staged_collection import StagedCollectionModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "SecretsScan",
    "SmbSharesExfil",
    "StagedCollectionModule",
]
