"""
ARES — modules.network
Network reconnaissance and pivot modules

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.network.dns_enum import DnsEnumModule  # noqa: F401
    from ares.modules.network.http_fingerprint import HttpFingerprintModule  # noqa: F401
    from ares.modules.network.pivot import PivotModule  # noqa: F401
    from ares.modules.network.port_scan import PortScanModule  # noqa: F401
    from ares.modules.network.service_detect import ServiceDetectModule  # noqa: F401
    from ares.modules.network.snmp_enum import SnmpEnumModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "DnsEnumModule",
    "HttpFingerprintModule",
    "PivotModule",
    "PortScanModule",
    "ServiceDetectModule",
    "SnmpEnumModule",
]
