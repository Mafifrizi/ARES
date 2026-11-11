"""AUDIT run-1 H14: module status must be gated on observed output, not on the
always-truthy ``raw`` dict.

Before the fix, modules computed ``status="success" if (findings or raw) else
"partial"``. Because ``raw`` is a dict that always carries loot scaffolding and
``*_audited`` flags, it is unconditionally truthy, so every module reported
"success" even when it observed zero hashes / accounts / credentials. The fix
gates on the module's declared ``OUTPUTS`` keys instead.

dcsync is used as the representative module (its declared output is
``ntlm_hashes``); the same one-line pattern was applied across all affected
modules, so a single anchored regression is sufficient to lock the behaviour.
"""

from unittest.mock import AsyncMock, patch

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.modules.ad.dcsync import DCSyncModule


def _make_module() -> tuple[DCSyncModule, Campaign]:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="DCSync-Status-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = DCSyncModule(settings=settings, campaign=campaign, noise=noise)
    return mod, campaign


def _ctx(campaign: Campaign) -> ExecutionContext:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    return ExecutionContext(
        execution_id="test-exec-dcsync-h14",
        campaign_id=campaign.id,
        target="10.0.0.5",
        params={"target_user": "krbtgt"},
        settings=settings,
        campaign=campaign,
        noise=NoiseController(campaign),
        dry_run=False,
    )


async def _run_with(mod, campaign, run_return):
    with patch.object(
        mod,
        "_extract_ad_params",
        return_value={"dc": "10.0.0.5", "domain": "corp.local",
                      "username": "svc_repl", "password": "x"},
    ):
        with patch.object(mod, "run", AsyncMock(return_value=run_return)):
            return await mod.execute(_ctx(campaign))


@pytest.mark.asyncio
async def test_status_is_partial_when_no_hashes_observed():
    """No findings and an empty ntlm_hashes list must yield 'partial'."""
    mod, campaign = _make_module()
    result = await _run_with(mod, campaign, ([], {"ntlm_hashes": [], "target": "krbtgt"}))
    assert result.status == "partial"


@pytest.mark.asyncio
async def test_status_is_success_when_hashes_observed():
    """A populated ntlm_hashes output must yield 'success' even without findings."""
    mod, campaign = _make_module()
    result = await _run_with(
        mod, campaign,
        ([], {"ntlm_hashes": [{"username": "krbtgt", "nt_hash": "a" * 32}], "target": "krbtgt"}),
    )
    assert result.status == "success"
