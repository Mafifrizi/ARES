"""
Tests for MOD-065: Missing SDK pre-flight validation in validate()
across cloud modules: cloud.aws, cloud.azure, cloud.azure_ad, and cloud.gcp.
"""

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.cloud.aws import AWSEnumModule
from ares.modules.cloud.azure import AzureModule
from ares.modules.cloud.azure_ad import AzureADModule
from ares.modules.cloud.gcp import GCPModule


def _make_context_deps():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Cloud-SDK-Preflight-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return settings, campaign, noise


@pytest.mark.asyncio
async def test_aws_sdk_preflight_missing():
    settings, campaign, noise = _make_context_deps()
    mod = AWSEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="aws", params={"access_key": "AKIA...", "secret_key": "secret"})

    with patch("importlib.util.find_spec", return_value=None):
        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate(ctx)

    assert "cloud.aws requires boto3" in str(exc_info.value)
    assert "pip install boto3" in str(exc_info.value)


@pytest.mark.asyncio
async def test_azure_sdk_preflight_missing():
    settings, campaign, noise = _make_context_deps()
    mod = AzureModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="azure", params={"subscription_id": "sub-123"})

    with patch("importlib.util.find_spec", return_value=None):
        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate(ctx)

    assert "cloud.azure requires azure.identity" in str(exc_info.value)
    assert "pip install ares-redteam[cloud]" in str(exc_info.value)


@pytest.mark.asyncio
async def test_azure_ad_sdk_preflight_missing():
    settings, campaign, noise = _make_context_deps()
    mod = AzureADModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="azure_ad", params={"tenant_id": "tenant-123"})

    with patch("importlib.util.find_spec", return_value=None):
        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate(ctx)

    assert "cloud.azure_ad requires msal" in str(exc_info.value)
    assert "pip install msal" in str(exc_info.value)


@pytest.mark.asyncio
async def test_gcp_sdk_preflight_missing():
    settings, campaign, noise = _make_context_deps()
    mod = GCPModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="gcp", params={"project_id": "test-project"})

    with patch("importlib.util.find_spec", return_value=None):
        with pytest.raises(ModuleValidationError) as exc_info:
            await mod.validate(ctx)

    assert "cloud.gcp requires google.cloud.resourcemanager" in str(exc_info.value)
    assert "pip install google-cloud-resource-manager" in str(exc_info.value)


@pytest.mark.asyncio
async def test_cloud_sdk_preflight_passes_when_installed():
    settings, campaign, noise = _make_context_deps()
    mod = AWSEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="aws", params={"access_key": "AKIA...", "secret_key": "secret"})

    dummy_spec = MagicMock()
    with patch("importlib.util.find_spec", return_value=dummy_spec):
        # Should not raise ModuleValidationError for SDK
        await mod.validate(ctx)
