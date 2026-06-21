"""
ARES — modules.cloud
Cloud attack modules (AWS, Azure, GCP)

Note: Primary module discovery uses PluginLoader (inspect.getmembers).
Direct imports from this package work but are not required.
"""
from __future__ import annotations

try:
    from ares.modules.cloud.aws import AWSEnumModule  # noqa: F401
    from ares.modules.cloud.aws_privesc import AWSPrivescModule  # noqa: F401
    from ares.modules.cloud.azure import AzureModule  # noqa: F401
    from ares.modules.cloud.azure_ad import AzureADModule  # noqa: F401
    from ares.modules.cloud.gcp import GCPModule  # noqa: F401
except ImportError:
    pass  # optional deps (impacket, ldap3, etc.) not installed

__all__ = [
    "AWSEnumModule",
    "AWSPrivescModule",
    "AzureModule",
    "AzureADModule",
    "GCPModule",
]
