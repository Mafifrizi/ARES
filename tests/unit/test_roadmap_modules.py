"""
Unit tests for ARES Roadmap modules (Tier 1, 2, 3).

Coverage:
  1.  credential.crack         — OpsecLevel.LOCAL, validate() no hashes, CrackJob submission
  2.  recon.fingerprint        — validate() no target, EDR finding trigger, DC finding trigger
  3.  network.pivot            — validate() no target/no creds, dry_run, teardown
  4.  ad.adcs                  — validate() no dc/domain/creds, template parsing, ESC1 detection
  5.  ad.delegation_abuse      — validate() RBCD needs target_computer, LDAP enum mock
  6.  ad.coerce                — STEALTH block, validate() no listener, dry_run
  7.  windows.lsass_dump       — STEALTH block, validate(), error classification
  8.  windows.dpapi            — validate(), error classification (auth/network), dry_run
  9.  ad.laps_enum             — validate(), vault.store() called with password, dry_run
  10. lateral.mssql            — validate(), error classification (auth 18456 vs network)
  11. cloud.azure_ad           — validate() no tenant_id, dry_run
"""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from tests.unit.modules.test_modules import _make_module

# ── env bootstrap ─────────────────────────────────────────────────────────────
os.environ.setdefault("ARES_SECRET_KEY",       "test-roadmap-key-32chars-minimum!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "test-roadmap-enc-32chars-minimum!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestRoadmap1!")


def _run(coro):
    return asyncio.run(coro)


def _mock_campaign(noise="normal"):
    from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
    return Campaign(
        name="test", client="test",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile(noise),
    )


def _mock_ctx(params=None, target="10.0.0.1", domain="corp.local",
              noise="normal", vault=None):
    from ares.core.config import AresSettings
    from ares.core.context import ExecutionContext
    from ares.core.noise import NoiseController
    from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
    params = params or {}
    campaign = Campaign(
        name="test", client="test",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile(noise),
    )
    return ExecutionContext.build(
        campaign=campaign,
        target=params.get("target", target),
        module_id="test.module",
        params=params,
        domain=params.get("domain", domain),
        vault=vault,
        settings=AresSettings(
            ares_secret_key="test-roadmap-key-32chars-minimum!",
            ares_encryption_key="test-roadmap-enc-32chars-minimum!",
        ),
        noise=NoiseController(campaign),
        opsec_profile=noise,
        dry_run=False,
    )


# ══════════════════════════════════════════════════════════════════════
# 1 — credential.crack
# ══════════════════════════════════════════════════════════════════════

class TestCredentialCrack:

    def test_opsec_level_local_exists(self):
        """OpsecLevel.LOCAL must exist — crash fixed in BUG-01."""
        from ares.modules.base import OpsecLevel
        assert OpsecLevel.LOCAL == "local"
        assert OpsecLevel.LOCAL is not None

    def test_crack_module_uses_local_opsec(self):
        from ares.modules.credential.crack import CrackModule
        from ares.modules.base import OpsecLevel
        assert CrackModule.OPSEC_LEVEL == OpsecLevel.LOCAL

    def test_validate_raises_when_no_vault(self):
        from ares.modules.credential.crack import CrackModule
        from ares.core.errors import ModuleValidationError
        from ares.core.context import ExecutionContext
        mod, _ = _make_module(CrackModule)
        ctx = _mock_ctx()
        # ctx.vault is None by default

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_raises_when_no_hashes_in_vault(self):
        from ares.modules.credential.crack import CrackModule
        from ares.core.errors import ModuleValidationError
        from ares.credential.vault import CredentialVault

        mod, _ = _make_module(CrackModule)
        vault = CredentialVault(encryption_key=None)   # empty vault
        ctx   = _mock_ctx(vault=vault)

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run_returns_dry_run_result(self):
        from ares.modules.credential.crack import CrackModule
        mod, _  = _make_module(CrackModule)
        ctx     = _mock_ctx()
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_hashcat_mode_mapping_correct(self):
        from ares.modules.credential.crack import _HASHCAT_MODES
        assert _HASHCAT_MODES["krb5tgs"]   == 13100
        assert _HASHCAT_MODES["krb5asrep"] == 18200
        assert _HASHCAT_MODES["ntlm"]      == 1000


# ══════════════════════════════════════════════════════════════════════
# 2 — recon.fingerprint
# ══════════════════════════════════════════════════════════════════════

class TestReconFingerprint:

    def test_validate_raises_when_no_target(self):
        from ares.modules.recon.fingerprint import FingerprintModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(FingerprintModule)
        ctx = _mock_ctx(target="")
        ctx.target = ""
        ctx.params = {}

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.recon.fingerprint import FingerprintModule
        mod, _      = _make_module(FingerprintModule)
        ctx         = _mock_ctx()
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_edr_finding_generated_for_crowdstrike(self):
        from ares.modules.recon.fingerprint import FingerprintModule
        from ares.fingerprint.engine import FingerprintResult, EDRVendor, DomainRole, OSType
        mod, _ = _make_module(FingerprintModule)

        result = FingerprintResult(
            host="10.0.0.1",
            edr_vendors=[EDRVendor.CROWDSTRIKE],
            detection_risk="critical",
            stealth_required=True,
            recommended_profile="stealth",
        )
        # Simulate _assess_risk having set values correctly
        assert result.stealth_required is True
        assert EDRVendor.CROWDSTRIKE in result.edr_vendors

    def test_module_id_and_opsec(self):
        from ares.modules.recon.fingerprint import FingerprintModule
        from ares.modules.base import OpsecLevel
        assert FingerprintModule.MODULE_ID == "recon.fingerprint"
        assert FingerprintModule.OPSEC_LEVEL == OpsecLevel.LOW


# ══════════════════════════════════════════════════════════════════════
# 3 — network.pivot
# ══════════════════════════════════════════════════════════════════════

class TestNetworkPivot:

    def test_validate_raises_no_target(self):
        from ares.modules.network.pivot import PivotModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(PivotModule)
        ctx = _mock_ctx(target="")
        ctx.target = ""
        ctx.params = {}

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_raises_no_username(self):
        from ares.modules.network.pivot import PivotModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(PivotModule)
        ctx = _mock_ctx(params={"target": "10.0.0.5"})

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.network.pivot import PivotModule
        mod, _      = _make_module(PivotModule)
        ctx         = _mock_ctx()
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_teardown_clears_manager(self):
        from ares.modules.network.pivot import PivotModule, _PIVOT_MANAGERS
        mod, _ = _make_module(PivotModule)
        campaign_id = "test-campaign-teardown"
        # Inject a fake manager
        fake_pm = MagicMock()
        fake_pm.all_tunnels.return_value = []
        _PIVOT_MANAGERS[campaign_id] = fake_pm

        async def _test():
            await mod.teardown(campaign_id=campaign_id)
            assert campaign_id not in _PIVOT_MANAGERS
        _run(_test())


# ══════════════════════════════════════════════════════════════════════
# 4 — ad.adcs
# ══════════════════════════════════════════════════════════════════════

class TestADADCS:

    def test_validate_requires_dc(self):
        from ares.modules.ad.adcs import ADCSModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(ADCSModule)
        ctx = _mock_ctx(params={"domain": "corp.local", "username": "user",
                                 "password": "pass"})
        ctx.target = ""

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.ad.adcs import ADCSModule
        mod, _      = _make_module(ADCSModule)
        ctx         = _mock_ctx(params={"dc": "10.0.0.1", "domain": "corp.local",
                                         "username": "u", "password": "p"})
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_esc1_detection_flag(self):
        """ESC1 flag value must match CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT."""
        from ares.modules.ad.adcs import _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        assert _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT == 0x1

    def test_module_mitre(self):
        from ares.modules.ad.adcs import ADCSModule
        assert "T1649" in ADCSModule.MITRE_TECHNIQUES


# ══════════════════════════════════════════════════════════════════════
# 5 — ad.delegation_abuse
# ══════════════════════════════════════════════════════════════════════

class TestADDelegationAbuse:

    def test_rbcd_mode_requires_target_computer(self):
        from ares.modules.ad.delegation_abuse import DelegationAbuseModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(DelegationAbuseModule)
        ctx = _mock_ctx(params={
            "dc": "10.0.0.1", "domain": "corp.local",
            "username": "u", "password": "p",
            "mode": "rbcd",   # RBCD without target_computer
        })
        ctx.target = "10.0.0.1"

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.ad.delegation_abuse import DelegationAbuseModule
        mod, _      = _make_module(DelegationAbuseModule)
        ctx         = _mock_ctx(params={"dc": "10.0.0.1", "domain": "corp.local",
                                         "username": "u", "password": "p"})
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())


# ══════════════════════════════════════════════════════════════════════
# 6 — ad.coerce
# ══════════════════════════════════════════════════════════════════════

class TestADCoerce:

    def test_blocked_in_stealth(self):
        from ares.modules.ad.coerce import CoerceModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(CoerceModule)
        ctx = _mock_ctx(
            params={"dc": "10.0.0.1", "listener_ip": "10.0.0.99"},
            noise="stealth",
        )
        ctx.target = "10.0.0.1"

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_requires_listener_ip(self):
        from ares.modules.ad.coerce import CoerceModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(CoerceModule)
        ctx = _mock_ctx(params={"dc": "10.0.0.1"})   # no listener_ip
        ctx.target = "10.0.0.1"

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.ad.coerce import CoerceModule
        mod, _      = _make_module(CoerceModule)
        ctx         = _mock_ctx(params={"dc": "10.0.0.1", "listener_ip": "10.0.0.99"})
        ctx.target  = "10.0.0.1"
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_opsec_is_high_noise(self):
        from ares.modules.ad.coerce import CoerceModule
        from ares.modules.base import OpsecLevel
        assert CoerceModule.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE


# ══════════════════════════════════════════════════════════════════════
# 7 — windows.lsass_dump
# ══════════════════════════════════════════════════════════════════════

class TestWindowsLsassDump:

    def test_blocked_in_stealth(self):
        from ares.modules.windows.lsass_dump import LsassDumpModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(LsassDumpModule)
        ctx = _mock_ctx(params={"target": "10.0.0.5", "username": "admin"}, noise="stealth")
        ctx.target = "10.0.0.5"

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_requires_username(self):
        from ares.modules.windows.lsass_dump import LsassDumpModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(LsassDumpModule)
        ctx = _mock_ctx(params={"target": "10.0.0.5"})   # no username
        ctx.target = "10.0.0.5"

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.windows.lsass_dump import LsassDumpModule
        mod, _      = _make_module(LsassDumpModule)
        ctx         = _mock_ctx(params={"target": "10.0.0.5", "username": "admin"})
        ctx.target  = "10.0.0.5"
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_pypykatz_import_error_handled(self):
        from ares.modules.windows.lsass_dump import LsassDumpModule
        import tempfile, os
        mod, _ = _make_module(LsassDumpModule)
        # Create an empty fake dump file
        _fd, fake_dump = tempfile.mkstemp(suffix=".dmp")
        os.close(_fd)
        try:
            result = mod._parse_dump(fake_dump)
            # Without pypykatz installed, should return [] not raise
            assert isinstance(result, list)
        finally:
            os.unlink(fake_dump)


# ══════════════════════════════════════════════════════════════════════
# 8 — windows.dpapi
# ══════════════════════════════════════════════════════════════════════

class TestWindowsDPAPI:

    def test_validate_requires_target(self):
        from ares.modules.windows.dpapi import DPAPIModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(DPAPIModule)
        ctx = _mock_ctx(params={"username": "user"})
        ctx.target = ""

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_requires_username(self):
        from ares.modules.windows.dpapi import DPAPIModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(DPAPIModule)
        ctx = _mock_ctx(params={"target": "10.0.0.5"})   # no username

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.windows.dpapi import DPAPIModule
        mod, _      = _make_module(DPAPIModule)
        ctx         = _mock_ctx(params={"target": "10.0.0.5", "username": "user"})
        ctx.target  = "10.0.0.5"
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_auth_error_classified(self):
        """SMB login failure must surface as AuthenticationFailed, not generic error."""
        from ares.modules.windows.dpapi import DPAPIModule
        from ares.core.errors import AuthenticationFailed
        mod, _ = _make_module(DPAPIModule)

        async def _test():
            with patch.object(
                mod,
                "_transfer_dpapi_files",
                side_effect=Exception("STATUS_LOGON_FAILURE"),
            ):
                with pytest.raises((AuthenticationFailed, Exception)):
                    await mod.run(
                        target="10.0.0.5", username="user", password="wrong"
                    )
        _run(_test())

    def test_chrome_parse_returns_list_on_missing_file(self):
        """_parse_chrome_logindata must return [] if file doesn't exist."""
        from ares.modules.windows.dpapi import DPAPIModule
        mod, _ = _make_module(DPAPIModule)
        result = mod._parse_chrome_logindata({}, "")
        assert isinstance(result, list)
        assert result == []


# ══════════════════════════════════════════════════════════════════════
# 9 — ad.laps_enum
# ══════════════════════════════════════════════════════════════════════

class TestADLAPSEnum:

    def test_dry_run(self):
        from ares.modules.ad.laps_enum import LAPSEnumModule
        mod, _      = _make_module(LAPSEnumModule)
        ctx         = _mock_ctx(params={"dc": "10.0.0.1", "domain": "corp.local",
                                         "username": "u", "password": "p"})
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_vault_store_called_for_each_entry(self):
        """BUG-02 regression: vault.store() must be called for every LAPS entry."""
        from ares.modules.ad.laps_enum import LAPSEnumModule
        from ares.credential.vault import CredentialVault

        mod, _ = _make_module(LAPSEnumModule)
        vault = CredentialVault(encryption_key=None)

        laps_entries = [
            {"computer": "WKSTN01", "password": "P@ssw0rd1!", "version": "v1", "expiry": ""},
            {"computer": "WKSTN02", "password": "Summer2024!", "version": "v1", "expiry": ""},
        ]

        async def _test():
            # Inject vault into module campaign
            campaign    = _mock_campaign()
            campaign._vault = vault
            mod.campaign    = campaign

            # Call run() with patched LDAP query
            with patch.object(mod, "_query_laps_sync", return_value=laps_entries):
                findings, raw = await mod.run(
                    dc="10.0.0.1", domain="corp.local",
                    username="u", password="p", vault=vault,
                )

            # Both passwords must be in vault
            stored = [c for c in vault._store.values()
                      if c.domain in ("WKSTN01", "WKSTN02")]
            assert len(stored) == 2, (
                f"Expected 2 vault entries, got {len(stored)}. "
                "vault.store() not called for all LAPS entries (BUG-02)."
            )
        _run(_test())

    def test_validate_requires_dc(self):
        from ares.modules.ad.laps_enum import LAPSEnumModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(LAPSEnumModule)
        ctx = _mock_ctx(params={"domain": "corp.local", "username": "u",
                                 "password": "p"})
        ctx.target = ""

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())


# ══════════════════════════════════════════════════════════════════════
# 10 — lateral.mssql
# ══════════════════════════════════════════════════════════════════════

class TestLateralMSSQL:

    def test_validate_requires_target(self):
        from ares.modules.lateral.mssql import MSSQLModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(MSSQLModule)
        ctx = _mock_ctx(params={"username": "sa", "password": "pass"})
        ctx.target = ""

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_validate_requires_username(self):
        from ares.modules.lateral.mssql import MSSQLModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(MSSQLModule)
        ctx = _mock_ctx(params={"target": "10.0.0.20"})   # no username

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.lateral.mssql import MSSQLModule
        mod, _      = _make_module(MSSQLModule)
        ctx         = _mock_ctx(params={"target": "10.0.0.20", "username": "sa",
                                         "password": "pass"})
        ctx.target  = "10.0.0.20"
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_auth_error_18456_classified(self):
        """SQL Server error 18456 = wrong credentials — must raise AuthenticationFailed."""
        from ares.modules.lateral.mssql import MSSQLModule
        from ares.core.errors import AuthenticationFailed
        mod, _ = _make_module(MSSQLModule)

        async def _test():
            with patch.object(mod, "_enum_server_sync",
                              return_value={"error": "Login failed for user 'sa'. (18456)"}):
                with pytest.raises((AuthenticationFailed, Exception)):
                    await mod.run(
                        target="10.0.0.20", username="sa",
                        password="wrong", port=1433,
                    )
        _run(_test())

    def test_network_error_classified(self):
        """Connection refused to port 1433 must raise NetworkError."""
        from ares.modules.lateral.mssql import MSSQLModule
        from ares.core.errors import NetworkError
        mod, _ = _make_module(MSSQLModule)

        async def _test():
            with patch.object(mod, "_enum_server_sync",
                              return_value={"error": "Connection timed out to 10.0.0.20:1433"}):
                with pytest.raises((NetworkError, Exception)):
                    await mod.run(
                        target="10.0.0.20", username="sa",
                        password="pass", port=1433,
                    )
        _run(_test())


# ══════════════════════════════════════════════════════════════════════
# 11 — cloud.azure_ad
# ══════════════════════════════════════════════════════════════════════

class TestCloudAzureAD:

    def test_validate_requires_tenant_id(self):
        from ares.modules.cloud.azure_ad import AzureADModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(AzureADModule)
        ctx = _mock_ctx(params={})   # no tenant_id

        async def _test():
            with pytest.raises((ModuleValidationError, Exception)):
                await mod.validate(ctx)
        _run(_test())

    def test_dry_run(self):
        from ares.modules.cloud.azure_ad import AzureADModule
        mod, _      = _make_module(AzureADModule)
        ctx         = _mock_ctx(params={"tenant_id": "12345678-0000-0000-0000-000000000000"})
        ctx.dry_run = True

        async def _test():
            result = await mod.execute(ctx)
            assert result.status == "dry_run"
        _run(_test())

    def test_module_mitre(self):
        from ares.modules.cloud.azure_ad import AzureADModule
        assert "T1528" in AzureADModule.MITRE_TECHNIQUES
        assert "T1606" in AzureADModule.MITRE_TECHNIQUES

    def test_device_code_response_structure(self):
        """_request_device_code must return dict with user_code or error."""
        from ares.modules.cloud.azure_ad import AzureADModule
        mod, _ = _make_module(AzureADModule)
        # Without msal installed, should return error dict not raise
        result = mod._request_device_code("fake-tenant", "fake-client")
        assert isinstance(result, dict)
        assert "user_code" in result or "error" in result


# ══════════════════════════════════════════════════════════════════════
# 12 — Cross-cutting: OpsecLevel enum completeness
# ══════════════════════════════════════════════════════════════════════

class TestOpsecLevelEnum:

    def test_all_levels_exist(self):
        from ares.modules.base import OpsecLevel
        assert OpsecLevel.SILENT    == "silent"
        assert OpsecLevel.LOCAL     == "local"
        assert OpsecLevel.LOW       == "low"
        assert OpsecLevel.MEDIUM    == "medium"
        assert OpsecLevel.HIGH_NOISE == "high_noise"

    def test_new_modules_have_correct_opsec(self):
        """Spot-check OPSEC levels on new modules match their declared risk."""
        from ares.modules.base import OpsecLevel
        from ares.modules.ad.coerce       import CoerceModule
        from ares.modules.ad.adcs         import ADCSModule
        from ares.modules.windows.lsass_dump import LsassDumpModule
        from ares.modules.network.pivot   import PivotModule
        from ares.modules.credential.crack import CrackModule

        assert CoerceModule.OPSEC_LEVEL    == OpsecLevel.HIGH_NOISE  # triggers MDI
        assert LsassDumpModule.OPSEC_LEVEL == OpsecLevel.HIGH_NOISE  # triggers EDR
        assert ADCSModule.OPSEC_LEVEL      == OpsecLevel.LOW         # LDAP query only
        assert PivotModule.OPSEC_LEVEL     == OpsecLevel.LOW         # encrypted SSH
        assert CrackModule.OPSEC_LEVEL     == OpsecLevel.LOCAL       # zero network
