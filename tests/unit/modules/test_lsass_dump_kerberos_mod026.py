"""
Tests for MOD-026: lsass_dump real Kerberos ticket extraction from pypykatz.
Verifies:
1. _parse_dump populates raw["kerberos_tickets"] when pypykatz returns kerberos_creds.
2. raw["kerberos_tickets"] is empty when pypykatz returns no kerberos_creds.
3. run() raw["kerberos_tickets"] reflects the extracted tickets.
"""

from unittest.mock import MagicMock, patch
import os
import sys
import tempfile
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.windows.lsass_dump import LsassDumpModule


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="LSASS-MOD026-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return LsassDumpModule(settings=settings, campaign=campaign, noise=noise)


def test_parse_dump_extracts_kerberos_tickets():
    """Verify _parse_dump extracts kerberos tickets from luid.kerberos_creds into raw."""
    mod = _make_module()

    mock_mimi = MagicMock()
    mock_luid = MagicMock()

    # MSV cred
    mock_msv = MagicMock()
    mock_msv.username = "Administrator"
    mock_msv.domainname = "CORP"
    mock_msv.NThash = "aad3b435b51404eeaad3b435b51404ee"
    mock_luid.msv_creds = [mock_msv]

    # Kerberos cred with tickets
    mock_krb = MagicMock()
    mock_krb.username = "Administrator"
    mock_krb.domainname = "CORP.LOCAL"
    mock_krb.ticket_path = "C:\\Windows\\Temp\\ticket.kirbi"
    mock_krb.kirbi_hash = "6a5b4c3d2e1f..."
    mock_krb.tickets = []
    mock_luid.kerberos_creds = [mock_krb]

    mock_mimi.logon_sessions = {1234: mock_luid}

    mock_pypykatz = MagicMock()
    mock_pypykatz.parse_minidump_file.return_value = mock_mimi

    mock_modules = {
        "pypykatz": MagicMock(),
        "pypykatz.pypykatz": MagicMock(pypykatz=mock_pypykatz),
    }

    raw = {}
    with patch.dict(sys.modules, mock_modules):
        hashes = mod._parse_dump("dummy.dmp", raw=raw)

        assert len(hashes) == 1
        assert hashes[0]["username"] == "Administrator"
        assert hashes[0]["nt_hash"] == "aad3b435b51404eeaad3b435b51404ee"

        assert len(raw["kerberos_tickets"]) == 1
        ticket = raw["kerberos_tickets"][0]
        assert ticket["username"] == "Administrator"
        assert ticket["domain"] == "CORP.LOCAL"
        assert ticket["ticket_path"] == "C:\\Windows\\Temp\\ticket.kirbi"
        assert ticket["ticket_data"] == "6a5b4c3d2e1f..."
        assert mod._last_kerberos_tickets == raw["kerberos_tickets"]


def test_parse_dump_empty_when_no_kerberos_creds():
    """Verify raw['kerberos_tickets'] is empty when pypykatz has no kerberos creds."""
    mod = _make_module()

    mock_mimi = MagicMock()
    mock_luid = MagicMock()

    # MSV cred only
    mock_msv = MagicMock()
    mock_msv.username = "Administrator"
    mock_msv.domainname = "CORP"
    mock_msv.NThash = "aad3b435b51404eeaad3b435b51404ee"
    mock_luid.msv_creds = [mock_msv]
    mock_luid.kerberos_creds = []

    mock_mimi.logon_sessions = {1234: mock_luid}

    mock_pypykatz = MagicMock()
    mock_pypykatz.parse_minidump_file.return_value = mock_mimi

    mock_modules = {
        "pypykatz": MagicMock(),
        "pypykatz.pypykatz": MagicMock(pypykatz=mock_pypykatz),
    }

    raw = {}
    with patch.dict(sys.modules, mock_modules):
        hashes = mod._parse_dump("dummy.dmp", raw=raw)

        assert len(hashes) == 1
        assert len(raw["kerberos_tickets"]) == 0
        assert mod._last_kerberos_tickets == []


@pytest.mark.asyncio
async def test_run_populates_extracted_kerberos_tickets():
    """Verify run() outputs raw['kerberos_tickets'] reflecting extracted tickets."""
    mod = _make_module()

    fake_extracted_tickets = [
        {
            "username": "svc_sql",
            "domain": "CORP.LOCAL",
            "ticket_path": "C:\\Temp\\sql.kirbi",
            "ticket_data": "abcdef123456",
        }
    ]
    fake_hashes = [{"username": "svc_sql", "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c1", "rid": ""}]

    with patch.object(mod, "_check_lsass_protections_sync", return_value={"runasppl": False, "credential_guard": False, "vbs": False}), \
         patch.object(mod, "_comsvcs_dump_sync", return_value=fake_hashes), \
         patch.object(mod, "before_request"):

        mod._last_kerberos_tickets = fake_extracted_tickets

        findings, raw = await mod.run(
            target="10.0.0.10",
            username="Administrator",
            password="Password123!",
        )

        assert raw["kerberos_tickets"] == fake_extracted_tickets
        assert len(raw["ntlm_hashes"]) == 1
