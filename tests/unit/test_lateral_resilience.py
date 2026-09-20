"""
Unit test suite for Wave 2: Lateral Movement Resilience & Modern Windows Mitigations.
Verifies:
  - Kerberos ticket (.ccache / KRB5CCNAME) resolution and NTLM fallback across lateral modules.
  - Feasibility and validation support for Kerberos tickets without passwords.
  - WebClient service discovery and WebDAV UNC coercion for SMB signing bypass (Windows 11 24H2+).
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.lateral.modules import (
    BaseLateralModule,
    LateralResult,
    LateralTechnique,
    AuthStrategy,
    PsExecLateral,
    WmiExecLateral,
    WinRMLateral,
)
from ares.modules.lateral.dcom import DCOMLateral
from ares.modules.lateral.ntlm_relay import (
    NTLMRelayModule,
    RelayTarget,
    CoercionResult,
)
from ares.modules.ad.coerce import CoerceModule


def _make_module(cls):
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test-Lateral-Wave2",
        scope=[
            ScopeEntry(cidr="192.168.0.0/16"),
            ScopeEntry(cidr="10.0.0.0/8"),
        ],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


class TestLateralAuthStrategyResolution:
    """Tests for resolving Kerberos ticket reuse vs NTLM vs cleartext passwords."""

    def test_cleartext_password_resolved(self):
        auth = BaseLateralModule.resolve_auth_strategy(
            secret="P@ssw0rd123!",
            domain="CORP.LOCAL",
            username="jdoe",
        )
        assert auth.auth_type == "password"
        assert auth.do_kerberos is False
        assert auth.password == "P@ssw0rd123!"
        assert auth.nthash == ""
        assert auth.lmhash == ""
        assert auth.ccache_path is None

    def test_ntlm_hash_32_chars_resolved(self):
        nthash = "8846f7eaee8fb117ad06bdd830b7586c"
        auth = BaseLateralModule.resolve_auth_strategy(
            secret=nthash,
            domain="CORP.LOCAL",
            username="jdoe",
        )
        assert auth.auth_type == "ntlm"
        assert auth.do_kerberos is False
        assert auth.password == ""
        assert auth.nthash == nthash
        assert auth.lmhash == ""

    def test_ntlm_hash_lm_nt_pair_resolved(self):
        lm_nt = "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        auth = BaseLateralModule.resolve_auth_strategy(
            secret=lm_nt,
            domain="CORP.LOCAL",
            username="jdoe",
        )
        assert auth.auth_type == "ntlm"
        assert auth.do_kerberos is False
        assert auth.password == ""
        assert auth.lmhash == "aad3b435b51404eeaad3b435b51404ee"
        assert auth.nthash == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_ccache_file_path_resolved(self, tmp_path):
        ccache_file = tmp_path / "administrator.ccache"
        ccache_file.write_bytes(b"\x05\x04\x00\x00")
        auth = BaseLateralModule.resolve_auth_strategy(
            secret=str(ccache_file),
            domain="CORP.LOCAL",
            username="administrator",
        )
        assert auth.auth_type == "kerberos"
        assert auth.do_kerberos is True
        assert auth.ccache_path == str(ccache_file)
        assert auth.password == ""
        assert os.environ.get("KRB5CCNAME") == str(ccache_file)

    def test_ccache_prefix_resolved(self):
        auth = BaseLateralModule.resolve_auth_strategy(
            secret="ccache:/var/tmp/krb5cc_1000",
            domain="CORP.LOCAL",
            username="svc_backup",
        )
        assert auth.auth_type == "kerberos"
        assert auth.do_kerberos is True
        assert auth.ccache_path == "/var/tmp/krb5cc_1000"

    def test_krb5ccname_environment_variable_resolved(self, monkeypatch):
        monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_shared")
        auth = BaseLateralModule.resolve_auth_strategy(
            secret="",
            domain="CORP.LOCAL",
            username="admin_user",
            do_kerberos=True,
        )
        assert auth.auth_type == "kerberos"
        assert auth.do_kerberos is True
        assert auth.ccache_path == "/tmp/krb5cc_shared"


class TestLateralValidationAndFeasibility:
    """Tests for validating ExecutionContext with Kerberos tickets and checking defense feasibility."""

    @pytest.mark.asyncio
    async def test_validate_passes_with_kerberos_ticket(self, monkeypatch):
        monkeypatch.setenv("KRB5CCNAME", "/tmp/ticket.ccache")
        module = _make_module(WmiExecLateral)
        ctx = ExecutionContext(
            target="192.168.1.50",
            domain="CORP.LOCAL",
            params={
                "target": "192.168.1.50",
                "domain": "CORP.LOCAL",
                "username": "admin",
                "ticket": "/tmp/ticket.ccache",
            },
        )
        # Should not raise ModuleValidationError because ticket is recognized
        await module.validate(ctx)

    @pytest.mark.asyncio
    async def test_validate_fails_when_no_credentials_or_ticket(self, monkeypatch):
        monkeypatch.delenv("KRB5CCNAME", raising=False)
        module = _make_module(WmiExecLateral)
        ctx = ExecutionContext(
            target="192.168.1.50",
            domain="CORP.LOCAL",
            params={"target": "192.168.1.50", "domain": "CORP.LOCAL", "username": "admin"},
        )
        with pytest.raises(ModuleValidationError) as exc:
            await module.validate(ctx)
        assert "requires credentials" in str(exc.value)

    @pytest.mark.asyncio
    async def test_feasibility_considers_kerberos_ticket_positive(self, monkeypatch):
        monkeypatch.setenv("KRB5CCNAME", "/tmp/ticket.ccache")
        module = _make_module(PsExecLateral)
        ctx = ExecutionContext(
            target="192.168.1.50",
            domain="CORP.LOCAL",
            params={"target": "192.168.1.50", "domain": "CORP.LOCAL", "username": "admin"},
        )
        report = await module.assess_feasibility(ctx)
        # Credentials blocker should not appear
        assert not any("No credentials" in b for b in report.blockers)


class TestLateralExecutionKerberosAndFallback:
    """Tests for Kerberos execution and fallback across lateral modules."""

    @pytest.mark.asyncio
    async def test_wmiexec_kerberos_with_ntlm_fallback(self):
        module = _make_module(WmiExecLateral)

        mock_impacket = MagicMock()
        mock_dcomrt = MagicMock()
        mock_dcom_inst = MagicMock()
        mock_iInterface = MagicMock()
        mock_dcom_inst.CoCreateInstanceEx.return_value = mock_iInterface

        call_count = 0
        def _dcom_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs.get("doKerberos"):
                raise Exception("KDC_ERR_C_PRINCIPAL_UNKNOWN: Kerberos ticket expired")
            return mock_dcom_inst

        mock_dcomrt.DCOMConnection = MagicMock(side_effect=_dcom_side_effect)

        mock_smb = MagicMock()
        mock_smb_inst = MagicMock()
        mock_smb_inst.getFile.side_effect = lambda share, path, callback: callback(b"CORP\\admin\r\n")
        mock_smb.SMBConnection = MagicMock(return_value=mock_smb_inst)

        mock_wmi = MagicMock()
        mock_wmi_services = MagicMock()
        mock_proc = MagicMock()
        mock_wmi_services.GetObject.return_value = (mock_proc, MagicMock())
        mock_wmi.IWbemLevel1Login.return_value.NTLMLogin.return_value = mock_wmi_services

        mock_dcom = MagicMock()
        mock_dcom.wmi = mock_wmi

        mock_modules = {
            "impacket": mock_impacket,
            "impacket.dcerpc": MagicMock(),
            "impacket.dcerpc.v5": MagicMock(),
            "impacket.dcerpc.v5.dcomrt": mock_dcomrt,
            "impacket.dcerpc.v5.dcom": mock_dcom,
            "impacket.dcerpc.v5.dcom.wmi": mock_wmi,
            "impacket.dcerpc.v5.dtypes": MagicMock(),
            "impacket.smbconnection": mock_smb,
        }

        with patch.dict(sys.modules, mock_modules):
            result = await module.move(
                target="192.168.1.50",
                username="admin",
                domain="CORP.LOCAL",
                secret="P@ssw0rd123!",
                command="whoami",
                do_kerberos=True,
            )

            assert call_count == 2
            assert result.technique == LateralTechnique.WMIEXEC
            assert result.success is True

    @pytest.mark.asyncio
    async def test_dcom_kerberos_with_ntlm_fallback(self):
        module = _make_module(DCOMLateral)

        mock_impacket = MagicMock()
        mock_dcomrt = MagicMock()
        mock_dcom_inst = MagicMock()

        call_count = 0
        def _dcom_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs.get("doKerberos"):
                raise Exception("KRB_AP_ERR_SKEW: Clock skew too great")
            return mock_dcom_inst

        mock_dcomrt.DCOMConnection = MagicMock(side_effect=_dcom_side_effect)

        mock_mmc = MagicMock()
        mock_mmc_inst = MagicMock()
        mock_mmc.IMMCApplication2 = MagicMock(return_value=mock_mmc_inst)

        mock_modules = {
            "impacket": mock_impacket,
            "impacket.dcerpc": MagicMock(),
            "impacket.dcerpc.v5": MagicMock(),
            "impacket.dcerpc.v5.dcomrt": mock_dcomrt,
            "impacket.dcerpc.v5.dcom": MagicMock(),
            "impacket.dcerpc.v5.dcom.mmc": mock_mmc,
            "impacket.dcerpc.v5.dcom.wmi": MagicMock(),
            "impacket.dcerpc.v5.dcom.oaut": MagicMock(),
        }

        with patch.dict(sys.modules, mock_modules):
            result = await module.move(
                target="192.168.1.60",
                username="admin",
                domain="CORP.LOCAL",
                secret="P@ssw0rd123!",
                command="whoami",
                do_kerberos=True,
            )

            assert call_count == 2
            assert result.technique == LateralTechnique.DCOM
            assert result.success is True

    @pytest.mark.asyncio
    async def test_winrm_kerberos_with_ntlm_fallback(self):
        module = _make_module(WinRMLateral)

        mock_winrm = MagicMock()
        call_count = 0
        mock_resp = MagicMock(status_code=0, std_out=b"NT AUTHORITY\\SYSTEM", std_err=b"")

        def _session_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs.get("transport") == "kerberos":
                raise Exception("Cannot authenticate via Kerberos: Ticket not found")
            mock_inst = MagicMock()
            mock_inst.run_cmd.return_value = mock_resp
            return mock_inst

        mock_winrm.Session = MagicMock(side_effect=_session_side_effect)

        with patch.dict(sys.modules, {"winrm": mock_winrm}):
            result = await module.move(
                target="192.168.1.70",
                username="admin",
                domain="CORP.LOCAL",
                secret="P@ssw0rd123!",
                command="whoami",
                do_kerberos=True,
            )

            assert call_count == 2
            assert result.success is True
            assert result.privilege == "SYSTEM"


class TestWebClientSMBsigningBypass:
    """Tests for WebClient service discovery and WebDAV UNC coercion bypassing SMB signing."""

    @pytest.mark.asyncio
    async def test_webclient_relay_target_discovery(self):
        module = _make_module(NTLMRelayModule)

        # Simulate host where SMB signing is required (Windows 11 24H2 default)
        # but WebClient service is active and LDAP signing is not required
        relay_target = RelayTarget(
            host="192.168.1.80",
            smb_signing="required",
            ldap_signing="not_required",
            relay_to_ldap=True,
            relay_to_smb=False,
            webclient_running=True,
            webdav_relayable=True,
        )

        with patch.object(module, "_check_relay_targets", AsyncMock(return_value=[relay_target])), \
             patch.object(module, "_coerce_authentication", AsyncMock(return_value=[
                 CoercionResult(method="petitpotam_webdav", source="192.168.1.80", target="192.168.1.10", success=True, webdav_used=True)
             ])):

            findings, raw = await module.run(
                dc="192.168.1.10",
                domain="CORP.LOCAL",
                username="jdoe",
                password="Password123!",
                mode="discover",
                targets=["192.168.1.80"],
            )

            # Finding emitted for SMB Signing Bypass via WebClient
            bypass_findings = [f for f in findings if "SMB Signing Bypass" in f.title]
            assert len(bypass_findings) == 1
            assert "WebClient / WebDAV" in bypass_findings[0].title
            assert bypass_findings[0].evidence.get("webclient_running") is True
            assert bypass_findings[0].evidence.get("bypass_mechanism") == "WebDAV UNC coercion over HTTP port 80"

    @pytest.mark.asyncio
    async def test_coerce_authentication_webdav_mode(self):
        module = _make_module(NTLMRelayModule)

        results = await module._coerce_authentication(
            source="192.168.1.80",
            target="192.168.1.10",
            domain="CORP.LOCAL",
            username="jdoe",
            password="Password123!",
            use_webdav=True,
        )

        # Ensure methods attempted were WebDAV variants
        for res in results:
            assert res.webdav_used is True
            assert "webdav" in res.method

    @pytest.mark.asyncio
    async def test_ad_coerce_webdav_execution(self):
        module = _make_module(CoerceModule)

        with patch.object(module, "_petitpotam_sync", return_value=True):
            findings, raw = await module.run(
                dc="192.168.1.20",
                listener_ip="192.168.1.10",
                method="petitpotam",
                use_webdav=True,
                webdav_port=80,
            )

            assert raw["webdav_coercion_used"] is True
            assert raw["method"] == "petitpotam_webdav"
            assert len(findings) >= 1
            assert "WebDAV / SMB Signing Bypass" in findings[0].title
            assert findings[0].evidence.get("webdav_coercion") is True
            assert findings[0].evidence.get("smb_signing_bypass") is True
