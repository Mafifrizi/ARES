"""
Tests for MOD-064: Removal of operator-host IMDS/metadata probing
from cloud.aws and cloud.gcp discovery modules.
"""

import pytest
from unittest.mock import MagicMock, patch
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.cloud.aws import AWSEnumModule
from ares.modules.cloud.gcp import GCPModule


def _make_context_deps():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Cloud-IMDS-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return settings, campaign, noise


@pytest.mark.asyncio
async def test_aws_imds_probe_removed():
    """Verify cloud.aws run() no longer executes _check_imds or emits IMDS findings."""
    settings, campaign, noise = _make_context_deps()
    mod = AWSEnumModule(settings=settings, campaign=campaign, noise=noise)

    mock_session = MagicMock()
    mock_session.client.return_value.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test",
    }
    mock_session.client.return_value.get_account_password_policy.return_value = {
        "PasswordPolicy": {"MinimumPasswordLength": 14}
    }
    mock_session.client.return_value.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1}
    }
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = []
    mock_session.client.return_value.get_paginator.return_value = mock_paginator
    mock_session.client.return_value.list_buckets.return_value = {
        "Buckets": [{"Name": "test-safe-bucket"}]
    }
    mock_session.client.return_value.get_bucket_acl.return_value = {"Grants": []}

    with patch.object(mod, "_make_session", return_value=mock_session):
        findings, raw = await mod.run(
            access_key="AKIAEXAMPLETESTKEY01",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1",
        )

        # 1. IMDS check is completely gone from raw
        assert "imds" not in raw

        # 2. Other legitimate discovery operations remain active
        assert "identity" in raw
        assert "iam" in raw
        assert "s3" in raw
        assert "security_groups" in raw

        # 3. No IMDS / SSRF findings generated
        finding_titles = [f.title for f in findings]
        assert not any("IMDS" in t for t in finding_titles)
        assert not any("169.254.169.254" in str(f.description) for f in findings)


@pytest.mark.asyncio
async def test_gcp_metadata_probe_removed():
    """Verify cloud.gcp run() no longer executes _check_metadata_server or emits metadata findings."""
    settings, campaign, noise = _make_context_deps()
    mod = GCPModule(settings=settings, campaign=campaign, noise=noise)

    mock_iam_result = {"owner_count": 1, "service_account_users": []}
    mock_gcs_result = {"buckets_audited": 2, "public_buckets": []}
    mock_sa_result = {"old_keys": [], "many_keys": [], "total_accounts": 1}

    with patch("ares.modules.cloud.gcp._get_gcp_credentials", return_value=MagicMock()), \
         patch.object(mod, "_check_iam_bindings", return_value=mock_iam_result), \
         patch.object(mod, "_check_gcs_buckets", return_value=mock_gcs_result), \
         patch.object(mod, "_check_sa_keys", return_value=mock_sa_result):

        findings, raw = await mod.run(project_id="test-secure-project")

        # 1. metadata check is completely gone from raw
        assert "metadata" not in raw

        # 2. Legitimate GCP discovery operations remain active
        assert raw.get("iam") == mock_iam_result
        assert raw.get("gcs") == mock_gcs_result
        assert raw.get("service_accounts") == mock_sa_result

        # 3. No GCE metadata server findings generated
        finding_titles = [f.title for f in findings]
        assert not any("Metadata Server" in t for t in finding_titles)
        assert not any("metadata.google.internal" in str(f.description) for f in findings)
