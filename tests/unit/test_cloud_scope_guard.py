"""
Unit tests for CloudScopeGuard and CloudScope campaign validation.
Covers MOD-053 and MOD-063 architectural gap closure.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ares.core.campaign import Campaign, Severity
from ares.core.errors import ScopeViolationError
from ares.core.scope import CloudScope, CampaignScope
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.config import AresSettings
from ares.core.noise import NoiseController


class DummyCloudModule(BaseModule):
    MODULE_ID = "test.cloud"
    MODULE_NAME = "Test Cloud Module"
    MODULE_CATEGORY = "cloud"
    MODULE_DESCRIPTION = "Dummy cloud module for unit tests"


@pytest.fixture
def dummy_settings():
    return AresSettings()


@pytest.fixture
def dummy_noise():
    return MagicMock(spec=NoiseController)


class TestCloudScopeDataclass:
    def test_unconfigured_provider_is_permissive(self):
        """When an identifier list is empty, any identifier is authorized (backward compatible)."""
        scope = CloudScope()
        assert scope.is_authorized("123456789012", "aws") is True
        assert scope.is_authorized("sub-uuid-1", "azure") is True
        assert scope.is_authorized("tenant-uuid-1", "azure_ad") is True
        assert scope.is_authorized("my-gcp-project", "gcp") is True

    def test_empty_or_blank_identifier_is_rejected(self):
        scope = CloudScope(aws_account_ids=["123456789012"])
        assert scope.is_authorized("", "aws") is False
        assert scope.is_authorized("   ", "aws") is False

    def test_configured_provider_enforces_whitelist(self):
        scope = CloudScope(
            aws_account_ids=["111122223333", "444455556666"],
            azure_subscription_ids=["sub-alpha", "sub-beta"],
            azure_tenant_ids=["tenant-corp-1"],
            gcp_project_ids=["prod-security-01"],
        )
        # Authorized
        assert scope.is_authorized("111122223333", "aws") is True
        assert scope.is_authorized("444455556666", "aws") is True
        assert scope.is_authorized("sub-alpha", "azure") is True
        assert scope.is_authorized("tenant-corp-1", "azure_ad") is True
        assert scope.is_authorized("prod-security-01", "gcp") is True

        # Unauthorized
        assert scope.is_authorized("999999999999", "aws") is False
        assert scope.is_authorized("sub-rogue", "azure") is False
        assert scope.is_authorized("tenant-attacker", "azure_ad") is False
        assert scope.is_authorized("victim-project", "gcp") is False


class TestCampaignCloudScopeIntegration:
    def test_campaign_default_cloud_scope(self):
        campaign = Campaign(name="Test Campaign")
        assert isinstance(campaign.cloud_scope, CloudScope)
        assert campaign.cloud_scope.aws_account_ids == []
        # Test .scope.cloud_scope proxy compatibility
        assert hasattr(campaign.scope, "cloud_scope")
        assert campaign.scope.cloud_scope is campaign.cloud_scope

    def test_campaign_custom_cloud_scope(self):
        cloud_scope = CloudScope(aws_account_ids=["123456789012"])
        campaign = Campaign(name="SecOps AWS", cloud_scope=cloud_scope)
        assert campaign.cloud_scope.aws_account_ids == ["123456789012"]
        assert campaign.scope.cloud_scope.aws_account_ids == ["123456789012"]


class TestBaseModuleCloudScopeValidation:
    def test_validate_cloud_scope_unconfigured_passes(self, dummy_settings, dummy_noise):
        campaign = Campaign(name="Unrestricted Campaign")
        module = DummyCloudModule(dummy_settings, campaign, dummy_noise)

        # Should pass without raising
        module.validate_cloud_scope("123456789012", "aws")
        module.validate_cloud_scope("sub-id", "azure")
        module.validate_cloud_scope("tenant-id", "azure_ad")
        module.validate_cloud_scope("project-id", "gcp")

    def test_validate_cloud_scope_authorized_passes(self, dummy_settings, dummy_noise):
        cloud_scope = CloudScope(
            aws_account_ids=["123456789012"],
            azure_subscription_ids=["sub-allowed"],
        )
        campaign = Campaign(name="Restricted Campaign", cloud_scope=cloud_scope)
        module = DummyCloudModule(dummy_settings, campaign, dummy_noise)

        module.validate_cloud_scope("123456789012", "aws")
        module.validate_cloud_scope("sub-allowed", "azure")

    def test_validate_cloud_scope_unauthorized_raises_scope_violation(self, dummy_settings, dummy_noise):
        cloud_scope = CloudScope(
            aws_account_ids=["123456789012"],
            azure_subscription_ids=["sub-allowed"],
            azure_tenant_ids=["tenant-allowed"],
            gcp_project_ids=["proj-allowed"],
        )
        campaign = Campaign(name="Restricted Campaign", cloud_scope=cloud_scope)
        module = DummyCloudModule(dummy_settings, campaign, dummy_noise)

        with pytest.raises(ScopeViolationError) as exc_aws:
            module.validate_cloud_scope("999999999999", "aws")
        assert "Cloud aws identifier '999999999999' is not in authorized campaign scope" in str(exc_aws.value)

        with pytest.raises(ScopeViolationError) as exc_azure:
            module.validate_cloud_scope("sub-unauthorized", "azure")
        assert "Cloud azure identifier" in str(exc_azure.value)

        with pytest.raises(ScopeViolationError) as exc_tenant:
            module.validate_cloud_scope("tenant-unauthorized", "azure_ad")
        assert "Cloud azure_ad identifier" in str(exc_tenant.value)

        with pytest.raises(ScopeViolationError) as exc_gcp:
            module.validate_cloud_scope("proj-unauthorized", "gcp")
        assert "Cloud gcp identifier" in str(exc_gcp.value)


@pytest.mark.asyncio
class TestCloudModulesEnforcement:
    async def test_aws_recon_scope_enforcement(self, dummy_settings, dummy_noise):
        from ares.modules.cloud.aws import AWSEnumModule

        cloud_scope = CloudScope(aws_account_ids=["111111111111"])
        campaign = Campaign(name="AWS Restricted", cloud_scope=cloud_scope)
        mod = AWSEnumModule(dummy_settings, campaign, dummy_noise)

        # Mock session & STS to return an unauthorized account ID
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "999999999999", "Arn": "arn:aws:iam::999999999999:user/test"}
        mock_session = MagicMock()
        mock_session.client.return_value = mock_sts

        with patch.object(mod, "_make_session", return_value=mock_session):
            with pytest.raises(ScopeViolationError):
                await mod.run(access_key="fake", secret_key="fake")

    async def test_azure_recon_scope_enforcement(self, dummy_settings, dummy_noise):
        from ares.modules.cloud.azure import AzureModule

        cloud_scope = CloudScope(azure_subscription_ids=["sub-authorized"])
        campaign = Campaign(name="Azure Restricted", cloud_scope=cloud_scope)
        mod = AzureModule(dummy_settings, campaign, dummy_noise)

        # Unauthorized subscription ID must raise ScopeViolationError
        with pytest.raises(ScopeViolationError):
            await mod.run(subscription_id="sub-unauthorized")

    async def test_azure_ad_scope_enforcement(self, dummy_settings, dummy_noise):
        from ares.modules.cloud.azure_ad import AzureADModule

        cloud_scope = CloudScope(azure_tenant_ids=["tenant-corp-uuid"])
        campaign = Campaign(name="Entra Restricted", cloud_scope=cloud_scope)
        mod = AzureADModule(dummy_settings, campaign, dummy_noise)

        with pytest.raises(ScopeViolationError):
            await mod.run(tenant_id="tenant-attacker-uuid")

    async def test_gcp_recon_scope_enforcement(self, dummy_settings, dummy_noise):
        from ares.modules.cloud.gcp import GCPModule

        cloud_scope = CloudScope(gcp_project_ids=["gcp-corp-project"])
        campaign = Campaign(name="GCP Restricted", cloud_scope=cloud_scope)
        mod = GCPModule(dummy_settings, campaign, dummy_noise)

        with pytest.raises(ScopeViolationError):
            await mod.run(project_id="gcp-rogue-project")
