"""
ARES — modules.recon
Reconnaissance and fingerprinting modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.recon.fingerprint import FingerprintModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "FingerprintModule",
]
