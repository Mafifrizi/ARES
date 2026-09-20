"""
Unit tests for ADCS ESC1-ESC15 expansion and Shadow Credentials audit (Wave 1).
Validates detection of:
  - ESC1 (Enrollee SAN + Auth EKU)
  - ESC2 (Any Purpose EKU)
  - ESC3 (Enrollment Agent EKU)
  - ESC4 (Dangerous Template ACLs)
  - ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 on CA)
  - ESC9 (CT_FLAG_NO_SECURITY_EXTENSION / KB5014754 bypass)
  - ESC10 (Weak Subject Name Mapping)
  - ESC13 (Universal Group OID Binding / msDS-OIDToGroupLink)
  - ESC14 (Weak Directory Path Mapping)
  - ESC15 (Legacy Schema v1 Arbitrary Policy)
  - Shadow Credentials (msDS-KeyCredentialLink DACL posture)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.modules.ad.adcs import (
    ADCSModule,
    _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    _CT_FLAG_NO_SECURITY_EXTENSION,
    _CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME,
    _CT_FLAG_ADD_DIRECTORY_PATH,
    _EDITF_ATTRIBUTESUBJECTALTNAME2,
    _ENROLLMENT_AGENT_EKU,
    _ANY_PURPOSE_EKU,
    _SZ_OID_NTDS_CA_SECURITY_EXT,
    _MSDS_KEY_CREDENTIAL_LINK_GUID,
)


def _make_adcs_module() -> tuple[ADCSModule, Campaign]:
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test-ADCS-Wave1",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = ADCSModule(settings=settings, campaign=campaign, noise=noise)
    return mod, campaign


class TestADCSESCExpansion:

    def test_esc_constants_integrity(self):
        """Verify constant values conform to Microsoft ADCS & Certified Pre-Owned specs."""
        assert _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT == 0x00000001
        assert _CT_FLAG_NO_SECURITY_EXTENSION == 0x00080000
        assert _CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME == 0x40000000
        assert _CT_FLAG_ADD_DIRECTORY_PATH == 0x00000100
        assert _EDITF_ATTRIBUTESUBJECTALTNAME2 == 0x00040000
        assert _ENROLLMENT_AGENT_EKU == "1.3.6.1.4.1.311.20.2.1"
        assert _ANY_PURPOSE_EKU == "2.5.29.37.0"
        assert _SZ_OID_NTDS_CA_SECURITY_EXT == "1.3.6.1.4.1.311.25.2"
        assert _MSDS_KEY_CREDENTIAL_LINK_GUID == "5b47d60f-6090-40b2-9f37-2a4de45f3063"

    def test_analyze_esc1_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC1",
            "msPKI_Certificate_Name_Flag": _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],  # Client Auth
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC1"]) == 1
        assert any(f.severity == Severity.CRITICAL for f in mod._findings)
        assert any("ADCS ESC1" in f.title for f in mod._findings)

    def test_analyze_esc2_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC2",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": [_ANY_PURPOSE_EKU],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC2"]) == 1
        assert any(f.severity == Severity.HIGH for f in mod._findings)
        assert any("ADCS ESC2" in f.title for f in mod._findings)

    def test_analyze_esc3_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC3",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": [_ENROLLMENT_AGENT_EKU],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC3"]) == 1
        assert any(f.severity == Severity.HIGH for f in mod._findings)
        assert any("ADCS ESC3" in f.title for f in mod._findings)

    def test_analyze_esc4_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC4",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "dangerous_acls": [{"trustee_sid": "S-1-5-21-513", "right": "WriteDACL"}],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC4"]) == 1
        assert any(f.severity == Severity.HIGH for f in mod._findings)
        assert any("ADCS ESC4" in f.title for f in mod._findings)

    def test_analyze_esc6_detected(self):
        mod, _ = _make_adcs_module()
        ca_list = [{
            "name": "Enterprise-CA-1",
            "dns_host": "ca.corp.local",
            "flags": _EDITF_ATTRIBUTESUBJECTALTNAME2,
            "templates": ["User", "Computer"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations([], ca_list)
        assert len(esc_map["ESC6"]) == 1
        assert any(f.severity == Severity.CRITICAL for f in mod._findings)
        assert any("ADCS ESC6" in f.title for f in mod._findings)

    def test_analyze_esc9_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC9",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": _CT_FLAG_NO_SECURITY_EXTENSION,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC9"]) == 1
        assert any(f.severity == Severity.HIGH for f in mod._findings)
        assert any("ADCS ESC9" in f.title for f in mod._findings)

    def test_analyze_esc10_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC10",
            "msPKI_Certificate_Name_Flag": _CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC10"]) == 1
        assert any(f.severity == Severity.HIGH for f in mod._findings)
        assert any("ADCS ESC10" in f.title for f in mod._findings)

    def test_analyze_esc13_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC13",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "policy_oids": ["1.3.6.1.4.1.311.99.1"],
            "linked_groups": ["CN=Enterprise Admins,CN=Users,DC=corp,DC=local"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC13"]) == 1
        assert any(f.severity == Severity.CRITICAL for f in mod._findings)
        assert any("ADCS ESC13" in f.title for f in mod._findings)

    def test_analyze_esc14_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC14",
            "msPKI_Certificate_Name_Flag": _CT_FLAG_ADD_DIRECTORY_PATH,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 2,
            "ekus": ["1.3.6.1.5.5.7.3.2"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC14"]) == 1
        assert any(f.severity == Severity.MEDIUM for f in mod._findings)
        assert any("ADCS ESC14" in f.title for f in mod._findings)

    def test_analyze_esc15_detected(self):
        mod, _ = _make_adcs_module()
        templates = [{
            "name": "VulnESC15",
            "msPKI_Certificate_Name_Flag": 0,
            "msPKI_Enrollment_Flag": 0,
            "msPKI_RA_Signature": 0,
            "schema_version": 1,  # Schema v1 legacy
            "ekus": ["1.3.6.1.5.5.7.3.2"],
        }]
        vulns, esc_map = mod._analyze_template_misconfigurations(templates, [])
        assert len(esc_map["ESC15"]) == 1
        assert any(f.severity == Severity.MEDIUM for f in mod._findings)
        assert any("ADCS ESC15" in f.title for f in mod._findings)


class TestShadowCredentialsAudit:

    def test_shadow_credentials_audit_posture(self, monkeypatch):
        import sys
        import types

        mod, _ = _make_adcs_module()

        # Build mock user entry with msDS-KeyCredentialLink
        mock_entry = MagicMock()
        mock_entry.sAMAccountName = "victim_da"
        mock_entry.distinguishedName = "CN=victim_da,CN=Users,DC=corp,DC=local"
        mock_key_attr = MagicMock()
        mock_key_attr.values = [b"mock_raw_key_material"]
        mock_entry.attach_mock(mock_key_attr, "msDS-KeyCredentialLink")
        mock_entry.nTSecurityDescriptor = None

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                self.entries = [mock_entry]

            def bind(self):
                return True

            def search(self, *args, **kwargs):
                return True

            def unbind(self):
                return True

        class FakeServer:
            def __init__(self, *args, **kwargs):
                pass

        class FakeTls:
            def __init__(self, *args, **kwargs):
                pass

        ldap3_mod = types.ModuleType("ldap3")
        ldap3_mod.AUTO_BIND_NONE = "AUTO_BIND_NONE"
        ldap3_mod.ALL = "ALL"
        ldap3_mod.NTLM = "NTLM"
        ldap3_mod.SUBTREE = "SUBTREE"
        ldap3_mod.Connection = FakeConnection
        ldap3_mod.Server = FakeServer
        ldap3_mod.Tls = FakeTls

        monkeypatch.setitem(sys.modules, "ldap3", ldap3_mod)

        posture = mod._audit_shadow_credentials_sync(
            dc="10.0.0.1", username="operator", password="Password123!",
            domain="corp.local", target_user="victim_da",
        )
        assert posture["account_found"] is True
        assert posture["has_existing_credentials"] is True
        assert posture["key_credential_count"] == 1

    def test_shadow_credentials_missing_ldap3_graceful(self, monkeypatch):
        import sys
        mod, _ = _make_adcs_module()
        monkeypatch.setitem(sys.modules, "ldap3", None)
        posture = mod._audit_shadow_credentials_sync(
            dc="10.0.0.1", username="operator", password="Password123!",
            domain="corp.local", target_user="victim_da",
        )
        assert posture["account_found"] is False
        assert "ldap3" in posture.get("error", "")


class TestADCSLiveWorkflow:

    @pytest.mark.asyncio
    async def test_full_run_with_modern_esc_counts(self):
        mod, _ = _make_adcs_module()

        mock_templates = [
            {
                "name": "VulnESC1",
                "msPKI_Certificate_Name_Flag": _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
                "msPKI_Enrollment_Flag": 0,
                "msPKI_RA_Signature": 0,
                "schema_version": 2,
                "ekus": ["1.3.6.1.5.5.7.3.2"],
            },
            {
                "name": "VulnESC9",
                "msPKI_Certificate_Name_Flag": 0,
                "msPKI_Enrollment_Flag": _CT_FLAG_NO_SECURITY_EXTENSION,
                "msPKI_RA_Signature": 0,
                "schema_version": 2,
                "ekus": ["1.3.6.1.5.5.7.3.2"],
            },
        ]
        mock_cas = [{
            "name": "Corp-Root-CA",
            "dns_host": "ca.corp.local",
            "flags": 0,
            "templates": ["VulnESC1", "VulnESC9"],
        }]

        with patch.object(mod, "_enum_templates_sync", return_value=(mock_templates, mock_cas)), \
             patch.object(mod, "_audit_shadow_credentials_sync", return_value={"target_user": "Administrator", "is_vulnerable": False}):
            findings, raw = await mod.run(
                dc="10.0.0.10",
                domain="corp.local",
                username="alice",
                password="SecretPassword123!",
                exploit_esc1=False,
                target_user="Administrator",
            )
            assert raw["esc1_count"] == 1
            assert raw["esc9_count"] == 1
            assert raw["esc2_count"] == 0
            assert len(raw["vulnerabilities"]) == 2
            assert "adcs_findings" in raw
            assert "certificate" in raw
            assert len(findings) >= 2
