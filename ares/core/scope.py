"""
ARES Campaign Scope & CloudScopeGuard
Provides declarative scope boundaries for network (CIDR/DNS) and cloud resources.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CloudScope:
    """
    Authorized cloud identifiers for a campaign (CloudScopeGuard).

    Configuration semantics:
    - If a provider list is empty: all identifiers for that provider are allowed
      (unrestricted / backward compatible).
    - If a provider list is populated: only identifiers explicitly listed are allowed.
      Any other identifier triggers a ScopeViolationError.
    """
    aws_account_ids: list[str] = field(default_factory=list)
    azure_subscription_ids: list[str] = field(default_factory=list)
    azure_tenant_ids: list[str] = field(default_factory=list)
    gcp_project_ids: list[str] = field(default_factory=list)

    def is_authorized(self, identifier: str, provider: str) -> bool:
        """
        Check if the given identifier is authorized for the cloud provider.
        Returns True if unconfigured (empty list) or if identifier is in the list.
        """
        if not identifier:
            return False
        clean_id = str(identifier).strip()
        mapping = {
            "aws": self.aws_account_ids,
            "azure": self.azure_subscription_ids,
            "azure_ad": self.azure_tenant_ids,
            "gcp": self.gcp_project_ids,
        }
        authorized = mapping.get(provider, [])
        if not authorized:
            return True  # Unconfigured = unrestricted (backward compatible)
        return clean_id in authorized


@dataclass
class CampaignScope:
    """Aggregated campaign scope holding network target entries and cloud boundaries."""
    entries: list[Any] = field(default_factory=list)
    cloud_scope: CloudScope = field(default_factory=CloudScope)
