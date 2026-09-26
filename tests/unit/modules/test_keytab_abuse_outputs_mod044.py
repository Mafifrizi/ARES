"""Unit test for MOD-044: keytab_abuse output key sync and normalizer pipeline."""
import os
import tempfile
from unittest.mock import MagicMock
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux.keytab_abuse import KeytabAbuseModule
from ares.normalize.artifacts import ArtifactNormalizer, ArtifactStore, CredentialArtifact
from ares.sdk import ExecutionContext
from tests.unit.modules.test_linux_ad_tradecraft import _synthesize_keytab


@pytest.mark.asyncio
async def test_keytab_abuse_output_keys_and_normalizer():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Linux-AD-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    module = KeytabAbuseModule(settings=settings, campaign=campaign, noise=noise)
    mock_vault = MagicMock()

    with tempfile.NamedTemporaryFile(suffix=".keytab", delete=False) as f:
        keytab_path = f.name
        f.write(_synthesize_keytab([
            {"principal": "SVC_SQL$@CORP.LOCAL", "keytype": 18, "vno": 2, "key_hex": "aa" * 32}
        ]))

    try:
        ctx = ExecutionContext(
            execution_id="test-exec-mod044",
            campaign_id=campaign.id,
            target="10.0.0.88",
            domain="corp.local",
            params={"keytab_path": keytab_path, "forge_silver_ticket": False},
            settings=settings,
            campaign=campaign,
            noise=noise,
            dry_run=False,
            vault=mock_vault,
        )
        res = await module.execute(ctx)

        assert res.status == "success"
        # MOD-044 contract verification: both machine_credentials and kerberos_keys are present
        assert "machine_credentials" in res.raw
        assert "kerberos_keys" in res.raw
        assert "entries" in res.raw
        assert len(res.raw["machine_credentials"]) == 1
        assert len(res.raw["kerberos_keys"]) == 1

        # Test end-to-end normalization through ArtifactNormalizer
        normalizer = ArtifactNormalizer()
        store = ArtifactStore()
        added = normalizer.normalize(
            module_id=KeytabAbuseModule.MODULE_ID,
            outputs=["machine_credentials", "kerberos_keys"],
            raw=res.raw,
            store=store,
        )

        assert added > 0
        creds = store.credentials()
        assert len(creds) >= 1
        cred = creds[0]
        assert isinstance(cred, CredentialArtifact)
        assert cred.cred_type == "keytab_key"
        assert cred.secret == "aa" * 32
        assert "SVC_SQL$" in cred.username
    finally:
        if os.path.exists(keytab_path):
            os.remove(keytab_path)
