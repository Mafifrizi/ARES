"""
Unit test suite for Wave 3: Modern Windows Posture & Token Security.
Verifies:
  - windows.lsass_dump graceful posture assessment for Credential Guard and RunAsPPL.
  - windows.lsass_dump force parameter override.
  - windows.token_impersonation non-destructive Named Pipe audit (spoolss / PrintSpoofer, efsrpc).
  - windows.registry_enum Microsoft Recommended Driver Blocklist (BYOVD mitigation) and HVCI checks.
"""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.errors import ModuleError
from ares.core.noise import NoiseController
from ares.modules.windows.lsass_dump import LsassDumpModule
from ares.modules.windows.token_impersonation import TokenImpersonationModule
from ares.modules.windows.registry_enum import RegistryEnumModule


@pytest.fixture
def mock_impacket_modules():
    mock_impacket = MagicMock()
    mock_smb = MagicMock()
    mock_smb.SMBConnection = MagicMock()
    mock_transport = MagicMock()
    mock_rrp = MagicMock()
    mock_rrp.MSRPC_UUID_RRP = "dummy-uuid"
    mock_wmi = MagicMock()
    mock_dtypes = MagicMock()
    mock_dtypes.NULL = None

    mock_modules = {
        "impacket": mock_impacket,
        "impacket.smbconnection": mock_smb,
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.transport": mock_transport,
        "impacket.dcerpc.v5.rrp": mock_rrp,
        "impacket.dcerpc.v5.wmi": mock_wmi,
        "impacket.dcerpc.v5.dtypes": mock_dtypes,
    }
    with patch.dict(sys.modules, mock_modules):
        yield mock_modules


def _make_module(cls):
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test-Windows-Wave3",
        operator="lead_operator",
        scope=[
            ScopeEntry(cidr="192.168.0.0/16"),
            ScopeEntry(cidr="10.0.0.0/8"),
        ],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


class TestLsassDumpResilience:
    """Tests for Credential Guard & RunAsPPL pre-execution posture detection."""

    @pytest.mark.asyncio
    async def test_credential_guard_detected_graceful_posture(self, mock_impacket_modules):
        mod = _make_module(LsassDumpModule)

        # Mock remote registry check returning active Credential Guard
        with patch.object(
            mod,
            "_check_lsass_protections_sync",
            return_value={
                "runasppl": False,
                "credential_guard": True,
                "vbs": True,
                "details": {"LsaCfgFlags": 1, "EnableVirtualizationBasedSecurity": 1},
            },
        ), patch.object(mod, "_comsvcs_dump_sync") as mock_dump:
            findings, raw = await mod.run(
                target="192.168.1.10",
                username="Administrator",
                password="Password123!",
                technique="comsvcs",
            )

            # Dump should NOT have been executed
            mock_dump.assert_not_called()

            assert raw["mitigated"] is True
            assert raw["hash_count"] == 0
            assert raw["hashes"] == []
            assert raw["protections"]["credential_guard"] is True

            # Hardened posture finding must be generated
            assert len(findings) == 1
            f = findings[0]
            assert "Credential Guard / RunAsPPL Active" in f.title
            assert f.severity == Severity.LOW
            assert "192.168.1.10" in f.host
            assert f.mitre_technique == "T1003.001"
            assert "COMPLIANT_HARDENED" in str(f.evidence.get("posture_status"))

    @pytest.mark.asyncio
    async def test_runasppl_detected_graceful_posture(self, mock_impacket_modules):
        mod = _make_module(LsassDumpModule)

        with patch.object(
            mod,
            "_check_lsass_protections_sync",
            return_value={
                "runasppl": True,
                "credential_guard": False,
                "vbs": False,
                "details": {"RunAsPPL": 1},
            },
        ), patch.object(mod, "_comsvcs_dump_sync") as mock_dump:
            findings, raw = await mod.run(
                target="192.168.1.11",
                username="Administrator",
                password="Password123!",
            )

            mock_dump.assert_not_called()
            assert raw["mitigated"] is True
            assert any("RunAsPPL" in f.title for f in findings)
            assert any("RunAsPPL (LSA Protected Process Light)" in f.description for f in findings)

    @pytest.mark.asyncio
    async def test_force_override_bypasses_protection_check(self, mock_impacket_modules):
        mod = _make_module(LsassDumpModule)

        fake_hashes = [{"username": "Administrator", "rid": "500", "nt_hash": "aad3b435b51404eeaad3b435b51404ee"}]

        with patch.object(
            mod,
            "_check_lsass_protections_sync",
            return_value={
                "runasppl": True,
                "credential_guard": True,
                "vbs": True,
                "details": {},
            },
        ), patch.object(mod, "_comsvcs_dump_sync", return_value=fake_hashes) as mock_dump:
            findings, raw = await mod.run(
                target="192.168.1.12",
                username="Administrator",
                password="Password123!",
                force=True,
            )

            # When force=True, dump must be called despite protections
            mock_dump.assert_called_once()
            assert raw["mitigated"] is False
            assert raw["hash_count"] == 1
            assert any("LSASS Dump" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_unprotected_target_executes_normal_dump(self, mock_impacket_modules):
        mod = _make_module(LsassDumpModule)

        fake_hashes = [
            {"username": "Administrator", "rid": "500", "nt_hash": "329153f560eb329c0e1deea55e88a1e9"},
            {"username": "krbtgt", "rid": "502", "nt_hash": "a5e88a1e9329153f560eb329c0e1dee1"},
        ]

        with patch.object(
            mod,
            "_check_lsass_protections_sync",
            return_value={"runasppl": False, "credential_guard": False, "vbs": False, "details": {}},
        ), patch.object(mod, "_comsvcs_dump_sync", return_value=fake_hashes):
            findings, raw = await mod.run(
                target="192.168.1.13",
                username="Administrator",
                password="Password123!",
            )

            assert raw["mitigated"] is False
            assert raw["hash_count"] == 2
            assert any(f.severity == Severity.CRITICAL for f in findings)
            assert any("Golden Ticket possible" in f.description for f in findings)


class TestTokenImpersonationNamedPipes:
    """Tests for Named Pipe audit and PrintSpoofer / Potato attack vector detection (Disabled under MOD-030)."""

    @pytest.mark.asyncio
    async def test_printspoofer_confirmed_on_service_account(self, mock_impacket_modules):
        mod = _make_module(TokenImpersonationModule)

        with pytest.raises(ModuleError) as exc_info:
            await mod.run(
                target="192.168.1.20",
                username="iis apppool\\defaultapppool",
                password="Password123!",
            )
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)
        assert len(mod._findings) == 0

    @pytest.mark.asyncio
    async def test_spooler_pipe_accessible_normal_user_vector(self, mock_impacket_modules):
        mod = _make_module(TokenImpersonationModule)

        with pytest.raises(ModuleError) as exc_info:
            await mod.run(
                target="192.168.1.21",
                username="normal_user",
                password="Password123!",
            )
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)
        assert len(mod._findings) == 0

    @pytest.mark.asyncio
    async def test_service_account_without_spooler_reports_potato(self, mock_impacket_modules):
        mod = _make_module(TokenImpersonationModule)

        with pytest.raises(ModuleError) as exc_info:
            await mod.run(
                target="192.168.1.22",
                username="nt service\\mssql$sqlexpress",
                password="Password123!",
            )
        assert "module disabled: privilege check heuristic insufficient, named pipe != exploitation confirmed (MOD-030)" in str(exc_info.value)
        assert len(mod._findings) == 0


class TestRegistryEnumDriverBlocklist:
    """Tests for Microsoft Recommended Driver Blocklist and HVCI posture audits."""

    @pytest.mark.asyncio
    async def test_driver_blocklist_enabled(self, mock_impacket_modules):
        mod = _make_module(RegistryEnumModule)

        fake_hits = [
            {
                "hive": "HKLM",
                "path": "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                "values": {"VulnerableDriverBlocklistEnable": 1},
                "description": "Microsoft Recommended Driver Blocklist",
                "severity": "HIGH",
            },
            {
                "hive": "HKLM",
                "path": "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                "values": {"Enabled": 1},
                "description": "Hypervisor-Enforced Code Integrity (HVCI)",
                "severity": "MEDIUM",
            },
        ]

        with patch("asyncio.get_running_loop") as mock_loop:
            fake_loop = MagicMock()
            mock_loop.return_value = fake_loop
            fake_loop.run_in_executor = AsyncMock(return_value={"hits": fake_hits, "putty": [], "errors": []})

            findings, raw = await mod.run(
                target="192.168.1.30",
                username="Administrator",
                password="Password123!",
            )

            assert raw["driver_blocklist_enabled"] is True
            assert raw["hvci_enabled"] is True
            # When enabled, no BYOVD alert should be generated
            assert not any("Driver Blocklist Disabled" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_driver_blocklist_disabled_reports_high_finding(self, mock_impacket_modules):
        mod = _make_module(RegistryEnumModule)

        fake_hits = [
            {
                "hive": "HKLM",
                "path": "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                "values": {"VulnerableDriverBlocklistEnable": 0},
                "description": "Microsoft Recommended Driver Blocklist",
                "severity": "HIGH",
            }
        ]

        with patch("asyncio.get_running_loop") as mock_loop:
            fake_loop = MagicMock()
            mock_loop.return_value = fake_loop
            fake_loop.run_in_executor = AsyncMock(return_value={"hits": fake_hits, "putty": [], "errors": []})

            findings, raw = await mod.run(
                target="192.168.1.31",
                username="Administrator",
                password="Password123!",
            )

            assert raw["driver_blocklist_enabled"] is False
            byovd_finding = next((f for f in findings if "Driver Blocklist Disabled" in f.title), None)
            assert byovd_finding is not None
            assert byovd_finding.severity == Severity.HIGH
            assert "BYOVD" in byovd_finding.description
            assert byovd_finding.mitre_technique == "T1068"

    @pytest.mark.asyncio
    async def test_driver_blocklist_unconfigured_reports_high_finding(self, mock_impacket_modules):
        mod = _make_module(RegistryEnumModule)

        fake_hits = [
            {
                "hive": "HKLM",
                "path": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "values": {"AutoAdminLogon": "0"},
                "description": "AutoLogon credentials",
                "severity": "CRITICAL",
            }
        ]

        with patch("asyncio.get_running_loop") as mock_loop:
            fake_loop = MagicMock()
            mock_loop.return_value = fake_loop
            fake_loop.run_in_executor = AsyncMock(return_value={"hits": fake_hits, "putty": [], "errors": []})

            findings, raw = await mod.run(
                target="192.168.1.32",
                username="Administrator",
                password="Password123!",
            )

            assert raw["driver_blocklist_enabled"] is False
            unconf_finding = next((f for f in findings if "Driver Blocklist Unconfigured" in f.title), None)
            assert unconf_finding is not None
            assert unconf_finding.severity == Severity.HIGH
            assert "BYOVD" in unconf_finding.description
