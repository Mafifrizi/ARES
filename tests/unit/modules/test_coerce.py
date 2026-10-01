from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.ad.coerce import CoerceModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Coerce-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return CoerceModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_coerce_fails_does_not_emit_false_finding():
    mod = _make_module()

    # Mock all coercion methods returning False (failed)
    with patch.object(mod, "_petitpotam_sync", return_value=False), \
         patch.object(mod, "_printerbug_sync", return_value=False), \
         patch.object(mod, "_dfscoerce_sync", return_value=False):

        findings, raw = await mod.run(
            dc="10.0.0.1",
            listener_ip="10.0.0.99",
            username="testuser",
            password="testpassword",
            domain="corp.local",
        )

        assert len(findings) == 0
        assert raw["sent"] is False
        assert raw["coercion_sent"] is False


@pytest.mark.asyncio
async def test_coerce_success_emits_finding():
    mod = _make_module()

    with patch.object(mod, "_petitpotam_sync", return_value=True):
        findings, raw = await mod.run(
            dc="10.0.0.1",
            listener_ip="10.0.0.99",
            username="testuser",
            password="testpassword",
            domain="corp.local",
        )

        assert len(findings) == 1
        assert "Authentication Coercion Sent" in findings[0].title
        assert raw["sent"] is True
        assert raw["coercion_sent"] is True
