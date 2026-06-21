"""
ARES — modules.credential
Credential access and cracking modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.credential.crack import CrackModule  # noqa: F401
    from ares.modules.credential.golden_ticket import GoldenTicketModule  # noqa: F401
    from ares.modules.credential.pass_spray import PassSprayModule  # noqa: F401
    from ares.modules.credential.pass_the_hash import PassTheHashModule  # noqa: F401
    from ares.modules.credential.reuse import CredentialReuseModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "CrackModule",
    "GoldenTicketModule",
    "PassSprayModule",
    "PassTheHashModule",
    "CredentialReuseModule",
]
