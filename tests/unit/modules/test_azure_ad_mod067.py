"""
Tests for MOD-067: Azure AD indentation bug, UnboundLocalError,
and Graph API enumeration reachability in cloud.azure_ad.
"""

import pytest
from unittest.mock import MagicMock, patch
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.cloud.azure_ad import AzureADModule


def _make_module() -> AzureADModule:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Azure-AD-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return AzureADModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_azure_ad_enumerate_no_unbound_local_error():
    """Verify default technique='enumerate' does NOT raise UnboundLocalError when no token is present."""
    mod = _make_module()
    findings, raw = await mod.run(
        tenant_id="00000000-0000-0000-0000-000000000000",
        technique="enumerate",
    )
    assert isinstance(raw, dict)
    assert raw.get("tenant_id") == "00000000-0000-0000-0000-000000000000"
    assert "error" in raw
    assert "azure_ad_findings" in raw
    assert raw["azure_ad_findings"] == findings


@pytest.mark.asyncio
async def test_azure_ad_enumerate_reaches_graph_api():
    """Verify Graph API enumeration code path is reached and executed when token is supplied."""
    mod = _make_module()
    mock_tenant_results = {
        "guests": [{"userPrincipalName": "external_vendor@contractor.com"}],
        "service_principals": [
            {"displayName": "HighPrivDaemon", "privileged": True, "has_expired_secret": False}
        ],
        "privileged_users": [{"userPrincipalName": "admin@contoso.onmicrosoft.com"}],
        "user_count": 42,
    }

    with patch.object(mod, "_enumerate_tenant", return_value=mock_tenant_results) as mock_enum:
        findings, raw = await mod.run(
            tenant_id="11111111-2222-3333-4444-555555555555",
            access_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake",
            technique="enumerate",
        )

        mock_enum.assert_called_once_with(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake",
            "11111111-2222-3333-4444-555555555555",
        )

        assert raw.get("tenant_id") == "11111111-2222-3333-4444-555555555555"
        assert raw.get("technique") == "enumerate"
        assert raw.get("user_count") == 42
        assert raw.get("guest_count") == 1
        assert raw.get("sp_count") == 1
        assert "azure_ad_findings" in raw
        assert raw["azure_ad_findings"] == findings

        titles = [f.title for f in findings]
        assert any("Guest Accounts" in t for t in titles)
        assert any("Privileged Service Principals" in t for t in titles)


@pytest.mark.asyncio
async def test_azure_ad_device_code_technique_still_works():
    """Verify technique='device_code' flow works properly and populates expected keys."""
    mod = _make_module()
    mock_dc_info = {
        "user_code": "XYZ-9876",
        "verification_uri": "https://microsoft.com/devicelogin",
        "expires_in": 900,
        "interval": 5,
        "device_code": "mock_device_code",
    }

    with patch.object(mod, "_request_device_code", return_value=mock_dc_info) as mock_dc:
        findings, raw = await mod.run(
            tenant_id="99999999-8888-7777-6666-555555555555",
            technique="device_code",
        )

        mock_dc.assert_called_once()
        assert raw.get("technique") == "device_code"
        assert raw.get("user_code") == "XYZ-9876"
        assert "access_tokens" in raw
        assert "azure_ad_findings" in raw
        assert raw["azure_ad_findings"] == findings

        titles = [f.title for f in findings]
        assert any("Device Code Generated" in t for t in titles)
