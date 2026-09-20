"""
Unit test suite for Wave 4: Modern Identity & Adaptive Exfiltration (2026 - 2031).
Validates:
  - Active Directory Fine-Grained Password Policies (FGPP / PSO via msDS-PasswordSettings).
  - Entra ID Hybrid Identity synchronization and Smart Lockout detection.
  - Safe spray attempts calculation and throttling under strict PSOs.
  - OAuth 2.0 Device Code Flow posture audit (T1528 / T1550).
  - Cloud Living-off-the-Trusted-Services (LOTS) egress path audit and Tenant Restrictions enforcement (T1567.002).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.credential.pass_spray import (
    PassSprayModule,
    query_password_policy,
)
from ares.modules.credential.reuse import (
    CredentialReuseModule,
    _audit_oauth_posture_sync,
)
from ares.modules.exfil.staged_collection import (
    StagedCollectionModule,
    _audit_lots_egress_sync,
)


def _make_module(cls):
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test-Wave4-Identity-Exfil",
        scope=[ScopeEntry(cidr="10.0.0.0/8"), ScopeEntry(cidr="192.168.1.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


# ---------------------------------------------------------------------------
# 1. Fine-Grained Password Policies (FGPP / PSO) & Hybrid Sync
# ---------------------------------------------------------------------------

class TestFineGrainedPasswordPolicies:
    """Validates AD PSO querying, safe pacing calculation, and hybrid sync detection."""

    def test_query_password_policy_with_pso_calculates_stricter_safe_attempts(self):
        """When PSOs exist with lower thresholds, safe_attempts_per_user must tighten."""
        fake_conn = MagicMock()
        fake_conn.bind.return_value = True

        # Default domain policy entries
        domain_entry = MagicMock()
        domain_entry.lockoutThreshold = 10
        domain_entry.lockoutDuration = -18000000000  # 30 mins
        domain_entry.lockOutObservationWindow = -18000000000  # 30 mins
        domain_entry.minPwdLength = 8
        domain_entry.pwdHistoryLength = 24

        # PSO entry with strict lockout threshold (e.g. 5 attempts)
        pso_entry = MagicMock()
        pso_entry.cn = "Strict-Admins-PSO"
        setattr(pso_entry, "msDS-LockoutThreshold", 5)
        setattr(pso_entry, "msDS-LockoutDuration", -18000000000)
        setattr(pso_entry, "msDS-LockoutObservationWindow", -18000000000)
        setattr(pso_entry, "msDS-MinimumPasswordLength", 16)
        setattr(pso_entry, "msDS-PasswordSettingsPrecedence", 10)

        # Hybrid user entry
        hybrid_entry = MagicMock()
        hybrid_entry.sAMAccountName = "cloudsync_user"
        setattr(hybrid_entry, "msDS-ExternalDirectoryObjectId", "11111111-2222-3333-4444-555555555555")

        # Mock search responses for successive queries
        def fake_search(dn, filter_str, search_scope=None, attributes=None, size_limit=None):
            if "msDS-PasswordSettings" in filter_str:
                fake_conn.entries = [pso_entry]
            elif "msDS-ExternalDirectoryObjectId" in filter_str:
                fake_conn.entries = [hybrid_entry]
            else:
                fake_conn.entries = [domain_entry]
            return True

        fake_conn.search.side_effect = fake_search

        fake_server = MagicMock()
        fake_ldap3 = MagicMock()
        fake_ldap3.Server.return_value = fake_server
        fake_ldap3.Connection.return_value = fake_conn
        fake_ldap3.SUBTREE = 2

        with patch.dict("sys.modules", {"ldap3": fake_ldap3}):
            res = query_password_policy("10.0.0.1", "CORP.LOCAL", "admin", "Secret123!")

        assert res["lockout_threshold"] == 10
        assert res["pso_enforced"] is True
        assert len(res["pso_policies"]) == 1
        assert res["pso_policies"][0]["name"] == "Strict-Admins-PSO"
        assert res["pso_policies"][0]["lockout_threshold"] == 5
        # Effective threshold is min(10, 5) = 5 -> safe_attempts = max(1, 5 - 2) = 3
        assert res["safe_attempts_per_user"] == 3
        assert res["hybrid_sync_detected"] is True

    def test_query_password_policy_no_pso_uses_default_threshold(self):
        """When no PSOs exist, default domain lockout threshold is used."""
        fake_conn = MagicMock()
        fake_conn.bind.return_value = True

        domain_entry = MagicMock()
        domain_entry.lockoutThreshold = 10
        domain_entry.lockoutDuration = -18000000000
        domain_entry.lockOutObservationWindow = -18000000000
        domain_entry.minPwdLength = 8
        domain_entry.pwdHistoryLength = 24

        def fake_search(dn, filter_str, search_scope=None, attributes=None, size_limit=None):
            if "msDS-PasswordSettings" in filter_str or "msDS-ExternalDirectoryObjectId" in filter_str:
                fake_conn.entries = []
            else:
                fake_conn.entries = [domain_entry]
            return True

        fake_conn.search.side_effect = fake_search

        fake_ldap3 = MagicMock()
        fake_ldap3.Server.return_value = MagicMock()
        fake_ldap3.Connection.return_value = fake_conn
        fake_ldap3.SUBTREE = 2

        with patch.dict("sys.modules", {"ldap3": fake_ldap3}):
            res = query_password_policy("10.0.0.1", "CORP.LOCAL", "admin", "Secret123!")

        assert res["lockout_threshold"] == 10
        assert res["pso_enforced"] is False
        assert res["pso_policies"] == []
        assert res["hybrid_sync_detected"] is False
        # max(1, 10 - 2) = 8
        assert res["safe_attempts_per_user"] == 8

    def test_pass_spray_run_emits_pso_and_hybrid_findings(self):
        """PassSprayModule.run generates structured findings for PSO and Entra ID sync."""
        mod = _make_module(PassSprayModule)
        policy_info = {
            "lockout_threshold": 10,
            "pso_enforced": True,
            "pso_policies": [{
                "name": "Strict-Tier0-PSO",
                "lockout_threshold": 3,
                "lockout_duration_min": 60,
                "observation_window_min": 60,
                "min_password_length": 18,
            }],
            "hybrid_sync_detected": True,
            "safe_attempts_per_user": 1,
            "safe_spray_delay_s": 5400.0,
        }

        fake_ldap3 = MagicMock()
        fake_conn = MagicMock()
        fake_conn.bind.return_value = False
        fake_ldap3.Connection.return_value = fake_conn

        with patch.dict("sys.modules", {"ldap3": fake_ldap3}):
            findings, raw = asyncio.run(mod.run(
                target="10.0.0.5",
                domain="CORP.LOCAL",
                users=["alice"],
                passwords=["Summer2026!"],
                protocol="ldap",
                policy_info=policy_info,
            ))

        titles = [f.title for f in findings]
        assert any("Fine-Grained Password Policy (PSO) Enforced" in t for t in titles)
        assert any("Entra ID Hybrid Sync & Cloud Smart Lockout Active" in t for t in titles)

        pso_finding = next(f for f in findings if "Fine-Grained Password Policy" in f.title)
        assert pso_finding.severity == Severity.LOW
        assert pso_finding.mitre_technique == "T1110.003"
        assert pso_finding.confidence == 0.95

        hybrid_finding = next(f for f in findings if "Entra ID Hybrid Sync" in f.title)
        assert hybrid_finding.severity == Severity.LOW
        assert hybrid_finding.mitre_technique == "T1110.003"

        assert raw["pso_enforced"] is True
        assert raw["safe_attempts_per_user"] == 1
        assert raw["hybrid_sync_detected"] is True


# ---------------------------------------------------------------------------
# 2. OAuth 2.0 Device Code Flow / Modern Identity Posture Assessment
# ---------------------------------------------------------------------------

class TestOAuthPostureAssessment:
    """Validates non-destructive OAuth 2.0 device code endpoint assessment (T1528 / T1550)."""

    def test_audit_oauth_posture_sync_detects_permitted(self):
        """Device authorization endpoint returning code/tokens marks device_code_permitted."""
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"device_code": "xyz123", "user_code": "ABCD-EFGH"}'
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = _audit_oauth_posture_sync("contoso.onmicrosoft.com")

        assert res["device_code_endpoint_active"] is True
        assert res["device_code_permitted"] is True
        assert "contoso.onmicrosoft.com" in res["checked_endpoint"]

    def test_audit_oauth_posture_sync_handles_blocked(self):
        """When device code endpoint fails or refuses connections, permitted is False."""
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            res = _audit_oauth_posture_sync("contoso.local")

        assert res["device_code_endpoint_active"] is False
        assert res["device_code_permitted"] is False

    def test_credential_reuse_emits_oauth_finding_when_permitted(self):
        """CredentialReuseModule.run creates MEDIUM finding when device code flow is open."""
        mod = _make_module(CredentialReuseModule)
        fake_vault = MagicMock()

        mock_oauth_audit = MagicMock(return_value={
            "device_code_endpoint_active": True,
            "device_code_permitted": True,
            "checked_endpoint": "https://login.microsoftonline.com/contoso.com/oauth2/v2.0/devicecode",
        })

        with patch("ares.credential.reuse.ReuseEngine") as MockEngine:
            mock_engine_inst = MagicMock()
            mock_engine_inst.spray = AsyncMock(return_value=[])
            MockEngine.return_value = mock_engine_inst

            findings, raw = asyncio.run(mod.run(
                target="10.0.0.50",
                vault=fake_vault,
                oauth_audit_func=mock_oauth_audit,
            ))

        titles = [f.title for f in findings]
        assert any("OAuth 2.0 Device Code Flow Vector Permitted on 10.0.0.50" in t for t in titles)

        oauth_finding = next(f for f in findings if "OAuth 2.0 Device Code Flow" in f.title)
        assert oauth_finding.severity == Severity.MEDIUM
        assert oauth_finding.mitre_technique == "T1528"
        assert oauth_finding.mitre_tactic == "Credential Access"
        assert oauth_finding.confidence == 0.9

        assert raw["oauth_device_code_permitted"] is True
        assert "devicecode" in raw["oauth_device_code_endpoint"]

    def test_credential_reuse_no_oauth_finding_when_restricted(self):
        """When device code endpoint is restricted or offline, no finding is raised."""
        mod = _make_module(CredentialReuseModule)
        fake_vault = MagicMock()

        mock_oauth_audit = MagicMock(return_value={
            "device_code_endpoint_active": False,
            "device_code_permitted": False,
            "checked_endpoint": None,
        })

        with patch("ares.credential.reuse.ReuseEngine") as MockEngine:
            mock_engine_inst = MagicMock()
            mock_engine_inst.spray = AsyncMock(return_value=[])
            MockEngine.return_value = mock_engine_inst

            findings, raw = asyncio.run(mod.run(
                target="10.0.0.60",
                vault=fake_vault,
                oauth_audit_func=mock_oauth_audit,
            ))

        assert not any("OAuth 2.0 Device Code Flow" in f.title for f in findings)
        assert raw["oauth_device_code_permitted"] is False


# ---------------------------------------------------------------------------
# 3. Cloud LOTS Egress & Tenant Restrictions Assessment
# ---------------------------------------------------------------------------

class TestCloudLOTSEgressAssessment:
    """Validates Living-off-the-Trusted-Services cloud egress audit and Tenant Restrictions (T1567.002)."""

    def test_audit_lots_egress_sync_detects_open_routes_without_restrictions(self):
        """Outbound connection succeeds to trusted cloud services without restriction headers."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Microsoft-IIS/10.0", "Content-Length": "0"}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = _audit_lots_egress_sync("10.0.0.1")

        assert len(res["lots_routes_open"]) == 3
        assert "m365_graph" in res["lots_routes_open"]
        assert "aws_s3" in res["lots_routes_open"]
        assert "azure_blob" in res["lots_routes_open"]
        assert res["tenant_restrictions_enforced"] is False

    def test_audit_lots_egress_sync_detects_tenant_restrictions_enforced(self):
        """When enterprise proxy injects or enforces Tenant Restrictions, flag is set."""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Restrict-Access-To-Tenants": "contoso.com",
            "Restrict-Access-Context": "guid-here",
        }
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = _audit_lots_egress_sync("10.0.0.1")

        assert res["tenant_restrictions_enforced"] is True

    def test_staged_collection_emits_lots_finding_when_unrestricted(self):
        """StagedCollectionModule.run generates HIGH finding when LOTS routes are open without restrictions."""
        mod = _make_module(StagedCollectionModule)

        mock_lots_audit = MagicMock(return_value={
            "lots_routes_open": ["m365_graph", "azure_blob"],
            "tenant_restrictions_enforced": False,
            "checked_endpoints": ["m365_graph", "aws_s3", "azure_blob"],
        })

        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            findings, raw = asyncio.run(mod.run(
                target="10.0.0.10",
                username="admin",
                search_paths=["/var/log"],
                lots_audit_func=mock_lots_audit,
            ))

        titles = [f.title for f in findings]
        assert any("Cloud LOTS Exfiltration Route Open (Missing Tenant Restrictions)" in t for t in titles)

        lots_finding = next(f for f in findings if "Cloud LOTS Exfiltration Route" in f.title)
        assert lots_finding.severity == Severity.HIGH
        assert lots_finding.mitre_technique == "T1567.002"
        assert lots_finding.mitre_tactic == "Exfiltration"
        assert lots_finding.confidence == 0.85

        assert raw["lots_routes_open"] == ["m365_graph", "azure_blob"]
        assert raw["tenant_restrictions_enforced"] is False

    def test_staged_collection_no_lots_finding_when_restrictions_present(self):
        """When Tenant Restrictions are active, no LOTS exfiltration finding is emitted."""
        mod = _make_module(StagedCollectionModule)

        mock_lots_audit = MagicMock(return_value={
            "lots_routes_open": ["m365_graph"],
            "tenant_restrictions_enforced": True,
            "checked_endpoints": ["m365_graph", "aws_s3", "azure_blob"],
        })

        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            findings, raw = asyncio.run(mod.run(
                target="10.0.0.10",
                username="admin",
                search_paths=["/var/log"],
                lots_audit_func=mock_lots_audit,
            ))

        assert not any("Cloud LOTS Exfiltration Route" in f.title for f in findings)
        assert raw["tenant_restrictions_enforced"] is True

    def test_staged_collection_no_lots_finding_when_egress_blocked(self):
        """When host is completely airgapped / no cloud egress routes, no finding is emitted."""
        mod = _make_module(StagedCollectionModule)

        mock_lots_audit = MagicMock(return_value={
            "lots_routes_open": [],
            "tenant_restrictions_enforced": False,
            "checked_endpoints": ["m365_graph", "aws_s3", "azure_blob"],
        })

        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            findings, raw = asyncio.run(mod.run(
                target="10.0.0.10",
                username="admin",
                search_paths=["/var/log"],
                lots_audit_func=mock_lots_audit,
            ))

        assert not any("Cloud LOTS Exfiltration Route" in f.title for f in findings)
        assert raw["lots_routes_open"] == []
