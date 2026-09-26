"""
Tests for MOD-043: ccache_hunt real kernel keyring read and no empty vault injection.
Verifies:
1. Vault is never injected with empty secret when keydata or ticket_bytes is empty.
2. Remote runner is invoked to inspect /proc/keys and read keyctl payloads.
3. PermissionError on /proc/keys produces low-confidence finding (0.35) and is_tgt=False.
"""

from unittest.mock import MagicMock, mock_open, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux.ccache_hunt import CcacheHuntModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Ccache-MOD043-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return CcacheHuntModule(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_no_empty_vault_injection_when_keydata_empty():
    """Verify vault is NOT called when tickets have empty payload/keydata."""
    mod = _make_module()
    mock_vault = MagicMock()

    # Stub ticket with empty keydata
    stub_tickets = [
        {
            "client": "user@CORP.LOCAL",
            "server": "krbtgt/CORP.LOCAL",
            "keydata": "",
            "ticket_bytes": b"",
            "is_tgt": False,
        }
    ]

    with patch.object(mod, "_scan_and_parse_sync", return_value=stub_tickets), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            target="10.0.0.25",
            vault=mock_vault,
        )

        # Vault should not be injected with empty secret
        mock_vault.store.assert_not_called()
        assert raw["stored_in_vault"] == 0


@pytest.mark.asyncio
async def test_keyring_read_via_runner_extracts_payload():
    """Verify runner is called with 'cat /proc/keys' and 'keyctl print'."""
    mod = _make_module()

    mock_proc_keys = (
        "2e3a1f4b 2/2 1 1d 3f030000 1000 1000 user krb_ccache:administrator@CORP.LOCAL\n"
    )

    mock_runner = MagicMock()
    def fake_run(cmd: str):
        if "cat /proc/keys" in cmd:
            return mock_proc_keys
        if "keyctl print 2e3a1f4b" in cmd:
            return "REAL_TICKET_PAYLOAD_BYTES_HEX_123456"
        return ""

    mock_runner.side_effect = fake_run

    with patch("os.path.exists", return_value=False), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            target="10.0.0.25",
            scan_kcm_socket=False,
            search_dirs=[],
            runner=mock_runner,
        )

        # Verify runner was invoked
        calls = [c[0][0] for c in mock_runner.call_args_list]
        assert any("cat /proc/keys" in c for c in calls)
        assert any("keyctl print 2e3a1f4b" in c for c in calls)

        # Verify ticket payload was extracted
        assert len(raw["tickets"]) == 1
        ticket = raw["tickets"][0]
        assert ticket["keydata"] == "REAL_TICKET_PAYLOAD_BYTES_HEX_123456"
        assert ticket["confidence"] == 0.95


@pytest.mark.asyncio
async def test_proc_keys_permission_denied_low_confidence():
    """Verify PermissionError on /proc/keys yields low-confidence finding (0.35) and is_tgt=False."""
    mod = _make_module()

    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", side_effect=PermissionError("Access denied")), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            target="10.0.0.25",
            scan_kcm_socket=False,
            search_dirs=[],
        )

        assert len(findings) == 1
        finding = findings[0]
        assert "Inaccessible" in finding.title
        assert finding.confidence == 0.35
        assert raw["tickets"][0]["is_tgt"] is False
