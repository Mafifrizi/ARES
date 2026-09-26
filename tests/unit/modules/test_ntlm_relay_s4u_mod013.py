"""
Tests for MOD-013: Real S4U2Self + S4U2Proxy implementation in ntlm_relay.py.
Verifies:
1. _s4u_attack invokes both S4U2Self (to self) and S4U2Proxy (to target host).
2. Finding is only published on valid ticket generation with calibrated confidence.
3. If S4U fails, no false success finding is published.
"""

from unittest.mock import MagicMock, patch
import os
import sys
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.lateral.ntlm_relay import NTLMRelayModule, RBCDResult


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="NTLM-Relay-S4U-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return NTLMRelayModule(settings=settings, campaign=campaign, noise=noise)


def test_s4u_attack_invokes_both_s4u2self_and_s4u2proxy(tmp_path):
    """Verify _s4u_attack invokes getKerberosTGS twice: first for self, second for target."""
    mock_impacket = MagicMock()
    mock_krb5 = MagicMock()
    mock_kerberosv5 = MagicMock()
    mock_types = MagicMock()
    mock_constants = MagicMock()
    mock_ccache_mod = MagicMock()

    mock_tgt = b"MOCK_TGT"
    mock_cipher = MagicMock()
    mock_session_key = b"MOCK_SK"
    mock_kerberosv5.getKerberosTGT.return_value = (mock_tgt, mock_cipher, b"OLD_KEY", mock_session_key)

    mock_tgs_s4u = b"MOCK_TGS_S4U"
    mock_final_tgs = b"MOCK_FINAL_TGS"
    mock_kerberosv5.getKerberosTGS.side_effect = [
        (mock_tgs_s4u, mock_cipher, b"", b"TGS_SK"),
        (mock_final_tgs, mock_cipher, b"", b"FINAL_SK"),
    ]

    mock_ccache = MagicMock()
    mock_ccache_mod.CCache.return_value = mock_ccache

    mock_modules = {
        "impacket": mock_impacket,
        "impacket.krb5": mock_krb5,
        "impacket.krb5.kerberosv5": mock_kerberosv5,
        "impacket.krb5.types": mock_types,
        "impacket.krb5.constants": mock_constants,
        "impacket.krb5.ccache": mock_ccache_mod,
    }

    with patch.dict(sys.modules, mock_modules):
        ticket_path = NTLMRelayModule._s4u_attack(
            dc="10.0.0.1",
            domain="CORP.LOCAL",
            machine_name="ARES01$",
            machine_pass="Secret123!",
            target_host="target-srv.corp.local",
            target_user="Administrator",
        )

        assert ticket_path != ""
        assert os.path.exists(ticket_path)
        # Cleanup created ccache
        try:
            os.unlink(ticket_path)
        except OSError:
            pass

        # Verify getKerberosTGS was called twice (S4U2Self and S4U2Proxy)
        assert mock_kerberosv5.getKerberosTGS.call_count == 2
        calls = mock_kerberosv5.getKerberosTGS.call_args_list
        # Step 2 call: serverName is self
        assert calls[0].kwargs["tgt"] == mock_tgt
        # Step 3 call: tgt is tgs_s4u
        assert calls[1].kwargs["tgt"] == mock_tgs_s4u


from ares.modules.lateral.ntlm_relay import (
    CoercionResult,
    NTLMRelayModule,
    RBCDResult,
    RelayTarget,
)


@pytest.mark.asyncio
async def test_finding_published_only_when_ticket_exists(tmp_path):
    """Verify RBCD finding is published with calibrated confidence when ticket is verified."""
    mod = _make_module()

    fake_ticket = tmp_path / "admin@target.ccache"
    fake_ticket.write_bytes(b"FAKE_CCACHE_DATA")

    success_result = RBCDResult(
        target_host="10.0.0.50",
        machine_account="ARES01$",
        machine_password="Secret123!",
        delegation_set=True,
        ticket_path=str(fake_ticket),
        impersonated_user="Administrator",
        success=True,
    )

    relay_targets = [
        RelayTarget(
            host="10.0.0.50",
            smb_signing="disabled",
            ldap_signing="not_required",
            relay_to_ldap=True,
        )
    ]
    coercions = [
        CoercionResult(
            method="petitpotam",
            source="10.0.0.1",
            target="10.0.0.50",
            success=True,
        )
    ]

    with patch.object(mod, "_discover_hosts", return_value=["10.0.0.50"]), \
         patch.object(mod, "_check_relay_targets", return_value=relay_targets), \
         patch.object(mod, "_coerce_authentication", return_value=coercions), \
         patch.object(mod, "_rbcd_attack", return_value=success_result), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            dc="10.0.0.1",
            domain="CORP.LOCAL",
            username="admin",
            password="password",
            targets=["10.0.0.50"],
            mode="full",
        )

        rbcd_findings = [f for f in findings if "RBCD Attack Success" in f.title]
        assert len(rbcd_findings) == 1
        finding = rbcd_findings[0]
        assert "Administrator" in finding.title
        assert finding.confidence == 0.95
        assert raw["rbcd"]["success"] is True


@pytest.mark.asyncio
async def test_no_finding_when_s4u_fails():
    """Verify no false success finding is published if ticket is not generated."""
    mod = _make_module()

    failed_result = RBCDResult(
        target_host="10.0.0.50",
        machine_account="ARES01$",
        machine_password="Secret123!",
        delegation_set=True,
        ticket_path="",
        impersonated_user="",
        success=False,
        error="S4U2proxy ticket request failed",
    )

    relay_targets = [
        RelayTarget(
            host="10.0.0.50",
            smb_signing="disabled",
            ldap_signing="not_required",
            relay_to_ldap=True,
        )
    ]
    coercions = [
        CoercionResult(
            method="petitpotam",
            source="10.0.0.1",
            target="10.0.0.50",
            success=True,
        )
    ]

    with patch.object(mod, "_discover_hosts", return_value=["10.0.0.50"]), \
         patch.object(mod, "_check_relay_targets", return_value=relay_targets), \
         patch.object(mod, "_coerce_authentication", return_value=coercions), \
         patch.object(mod, "_rbcd_attack", return_value=failed_result), \
         patch.object(mod, "before_request"):

        findings, raw = await mod.run(
            dc="10.0.0.1",
            domain="CORP.LOCAL",
            username="admin",
            password="password",
            targets=["10.0.0.50"],
            mode="full",
        )

        rbcd_findings = [f for f in findings if "RBCD Attack Success" in f.title]
        assert len(rbcd_findings) == 0
        assert raw["rbcd"]["success"] is False
