"""
Unit tests for Grup B - Hash Masking in Finding.evidence and EvidenceRecord.data (MOD-027, MOD-042).
Verifies:
1. mask_secret_hash() correctly masks raw and colon-separated hashes.
2. samba_secrets masks ntlm_hash in evidence and EvidenceRecord, but preserves full hash in vault and raw.
3. lsa_secrets masks sam_hashes and cached_creds in evidence, but preserves full hashes in raw.
4. dcsync masks NTLM hash sample in evidence.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.core.security import mask_secret_hash
from ares.modules.ad.dcsync import DCSyncModule
from ares.modules.linux.samba_secrets import SambaSecretsModule
from tests.unit.modules.test_linux_ad_tradecraft import _synthesize_tdb
from ares.modules.params import DCSyncParams, LSASecretsParams, SambaSecretsParams
from ares.modules.windows.lsa_secrets import LSASecretsModule


def test_mask_secret_hash_behavior():
    # Empty or short
    assert mask_secret_hash("") == "***"
    assert mask_secret_hash(None) == "***"
    assert mask_secret_hash("short") == "***"

    # Standard raw hash (e.g. 32-char hex NTLM hash)
    raw_ntlm = "31d6cfe0d16ae931b73c59d7e0c089c0"
    masked = mask_secret_hash(raw_ntlm)
    assert masked == "31d6cf...89c0"
    assert raw_ntlm not in masked

    # Colon-separated pwdump format: user:rid:lmhash:nthash:::
    pwdump = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    masked_pwdump = mask_secret_hash(pwdump)
    assert masked_pwdump == "Administrator:500:aad3b4...04ee:31d6cf...89c0:::"
    assert "aad3b435b51404eeaad3b435b51404ee" not in masked_pwdump
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in masked_pwdump


@pytest.mark.asyncio
async def test_samba_secrets_hash_masking(monkeypatch):
    """MOD-042: samba_secrets must mask ntlm_hash in evidence and EvidenceRecord, but keep full in vault & raw."""
    settings = AresSettings(
        ares_secret_key="secret-key-32-chars-minimum-len!",
        ares_encryption_key="enc-key-32-chars-minimum-length!",
    )
    campaign = Campaign(
        name="test",
        client="test",
        scope=[ScopeEntry(cidr="192.168.1.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = SambaSecretsModule(settings=settings, campaign=campaign, noise=noise)
    mock_vault = MagicMock()

    with tempfile.NamedTemporaryFile(suffix=".tdb", delete=False) as f:
        tdb_path = f.name
        records = [
            (b"SECRETS/MACHINE_PASSWORD/CORP", b"P@ssw0rdMachine!\x00"),
        ]
        f.write(_synthesize_tdb(records))

    try:
        ctx = ExecutionContext(
            execution_id="exec-samba-mask",
            campaign_id=campaign.id,
            target="192.168.1.50",
            params=SambaSecretsParams(secrets_tdb_path=tdb_path),
            settings=settings,
            campaign=campaign,
            noise=noise,
            vault=mock_vault,
            dry_run=False,
        )
        res = await mod.execute(ctx)
        assert res.status == "success"
        assert len(res.findings) >= 1

        finding = res.findings[0]
        # Evidence in finding MUST be masked
        evidence_hash = finding.evidence.get("ntlm_hash")
        assert evidence_hash is not None
        assert "..." in evidence_hash
        assert len(evidence_hash) < 32

        # Vault MUST retain full 32-char hash
        assert mock_vault.store.called
        _, stored_val = mock_vault.store.call_args[0]
        assert len(stored_val) == 32
        assert stored_val.startswith(evidence_hash[:6])
        assert stored_val.endswith(evidence_hash[-4:])

        # Raw output MUST retain full 32-char hash
        assert len(res.raw["secrets"]) == 1
        raw_secret_hash = res.raw["secrets"][0]["ntlm_hash"]
        assert len(raw_secret_hash) == 32
        assert raw_secret_hash == stored_val
    finally:
        if os.path.exists(tdb_path):
            os.remove(tdb_path)


@pytest.mark.asyncio
async def test_lsa_secrets_hash_masking(monkeypatch):
    """MOD-027: lsa_secrets must mask sam_hashes and cached_creds in evidence, but keep full in raw."""
    settings = AresSettings(
        ares_secret_key="secret-key-32-chars-minimum-len!",
        ares_encryption_key="enc-key-32-chars-minimum-length!",
    )
    campaign = Campaign(
        name="test",
        client="test",
        scope=[ScopeEntry(cidr="192.168.1.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = LSASecretsModule(settings=settings, campaign=campaign, noise=noise)

    sample_sam = [
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    ]
    sample_cached = [
        "$DCC2$10240#testuser#31d6cfe0d16ae931b73c59d7e0c089c0",
    ]

    async def fake_dump(self_mod, *args, **kwargs):
        pass

    ctx = ExecutionContext(
        execution_id="exec-lsa-mask",
        campaign_id=campaign.id,
        target="192.168.1.50",
        params=LSASecretsParams(target="192.168.1.50", username="Admin", password="Password123!"),
        settings=settings,
        campaign=campaign,
        noise=noise,
        dry_run=False,
    )

    import sys
    impacket_mock = MagicMock()
    monkeypatch.setitem(sys.modules, "impacket", impacket_mock)
    monkeypatch.setitem(sys.modules, "impacket.examples", impacket_mock)
    monkeypatch.setitem(sys.modules, "impacket.examples.secretsdump", impacket_mock)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", impacket_mock)

    # Mock loop.run_in_executor to return sample sam & cached hashes
    loop = asyncio.get_running_loop()
    async def mock_run_in_executor(executor, func, *args):
        return {
            "sam": sample_sam,
            "lsa": ["_SC_Service:SecretVal"],
            "cached": sample_cached,
            "errors": [],
        }
    monkeypatch.setattr(loop, "run_in_executor", mock_run_in_executor)

    res = await mod.execute(ctx)
    assert res.status in ("partial", "success")

    # Find SAM finding and Cached finding
    sam_finding = next((f for f in res.findings if "SAM Database Dumped" in f.title), None)
    assert sam_finding is not None
    assert "..." in sam_finding.evidence["hashes"][0]
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in sam_finding.evidence["hashes"][0]

    cached_finding = next((f for f in res.findings if "Cached Domain Credentials" in f.title), None)
    assert cached_finding is not None
    assert "..." in cached_finding.evidence["hashes"][0]
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in cached_finding.evidence["hashes"][0]

    # Raw output MUST have full unmasked hashes
    assert res.raw["sam_hashes"] == sample_sam
    assert res.raw["cached_credentials"] == sample_cached
    assert res.raw["ntlm_hashes"] == sample_sam


@pytest.mark.asyncio
async def test_dcsync_hash_masking():
    """Verify DCSync masks sample NTLM hash in finding evidence."""
    settings = AresSettings(
        ares_secret_key="secret-key-32-chars-minimum-len!",
        ares_encryption_key="enc-key-32-chars-minimum-length!",
    )
    campaign = Campaign(
        name="test",
        client="test",
        scope=[ScopeEntry(cidr="192.168.1.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = DCSyncModule(settings=settings, campaign=campaign, noise=noise)

    raw_output = {
        "ntlm_hashes": [
            {"username": "krbtgt", "rid": "502", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
            {"username": "Administrator", "rid": "500", "nt_hash": "8846f7eaee8fb117ad06bdd830b7586c"},
        ]
    }
    mod._analyze(raw_output, "192.168.1.10")
    assert len(mod._findings) == 1
    finding = mod._findings[0]
    sample = finding.evidence["sample"]
    assert len(sample) == 2
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in sample[0]
    assert "..." in sample[0]
    assert "8846f7eaee8fb117ad06bdd830b7586c" not in sample[1]
    assert "..." in sample[1]
