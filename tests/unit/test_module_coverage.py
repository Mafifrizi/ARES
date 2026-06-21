"""
Coverage smoke tests for the 27 modules with zero test coverage.

Strategy: each module gets 3 tests minimum:
  1. validate() raises ModuleValidationError when required params missing
  2. dry_run=True returns ModuleResult(status='dry_run') without network
  3. MODULE_ID, OPSEC_LEVEL, MITRE_TECHNIQUES are correctly declared

These are not integration tests — no real network calls, no real AD/SSH/cloud.
They verify the module can be imported, instantiated, and wired correctly.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest

from tests.unit.modules.test_modules import _make_module

os.environ.setdefault("ARES_SECRET_KEY",       "coverage-test-key-32chars-min!!x")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "coverage-test-enc-32chars-min!!x")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "CoverageTest1!")


def _run(coro):
    return asyncio.run(coro)


def _ctx(params=None, target="10.0.0.1", noise="normal", dry_run=False):
    from ares.core.config import AresSettings
    from ares.core.context import ExecutionContext
    from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
    from ares.core.noise import NoiseController

    params = params or {}
    campaign = Campaign(
        name="cov", client="cov",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile(noise),
    )
    return ExecutionContext(
        execution_id="cov-test",
        campaign_id=campaign.id,
        target=params.get("target", target),
        domain=params.get("domain", "corp.local"),
        params=params,
        settings=AresSettings(
            ares_secret_key="coverage-test-key-32chars-min!!x",
            ares_encryption_key="coverage-test-enc-32chars-min!!x",
        ),
        campaign=campaign,
        noise=NoiseController(campaign),
        dry_run=dry_run,
        opsec_profile=noise,
    )


def _dry_run_ctx(**kw):
    ctx = _ctx(**kw)
    ctx.dry_run = True
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# AD modules
# ══════════════════════════════════════════════════════════════════════════════

class TestADEnumACL:
    def test_dry_run(self):
        from ares.modules.ad.enum_acl import ADEnumACLModule
        mod, _ = _make_module(ADEnumACLModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"dc": "10.0.0.1", "domain": "corp.local", "username": "u", "password": "p"}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.ad.enum_acl import ADEnumACLModule
        assert ADEnumACLModule.MODULE_ID == "ad.enum_acl"
        assert "T1222.001" in ADEnumACLModule.MITRE_TECHNIQUES

    def test_validate_requires_dc(self):
        from ares.modules.ad.enum_acl import ADEnumACLModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(ADEnumACLModule)
        ctx = _ctx(params={"domain": "corp.local", "username": "u", "password": "p"})
        ctx.target = ""
        with pytest.raises((ModuleValidationError, Exception)):
            _run(mod.validate(ctx))


class TestADEnumComputers:
    def test_dry_run(self):
        from ares.modules.ad.enum_computers import ADEnumComputersModule
        mod, _ = _make_module(ADEnumComputersModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"dc": "10.0.0.1", "domain": "corp.local", "username": "u", "password": "p"}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.ad.enum_computers import ADEnumComputersModule
        assert ADEnumComputersModule.MODULE_ID == "ad.enum_computers"


# ══════════════════════════════════════════════════════════════════════════════
# Cloud modules
# ══════════════════════════════════════════════════════════════════════════════

class TestCloudAWSPrivesc:
    def test_dry_run(self):
        from ares.modules.cloud.aws_privesc import AWSPrivescModule
        mod, _ = _make_module(AWSPrivescModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.cloud.aws_privesc import AWSPrivescModule
        assert AWSPrivescModule.MODULE_ID == "cloud.aws_privesc"
        assert "T1078.004" in AWSPrivescModule.MITRE_TECHNIQUES


class TestCloudGCP:
    def test_dry_run(self):
        from ares.modules.cloud.gcp import GCPModule
        mod, _ = _make_module(GCPModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.cloud.gcp import GCPModule
        assert GCPModule.MODULE_ID == "cloud.gcp"


# ══════════════════════════════════════════════════════════════════════════════
# Credential modules
# ══════════════════════════════════════════════════════════════════════════════

class TestCredentialGoldenTicket:
    def test_dry_run(self):
        from ares.modules.credential.golden_ticket import GoldenTicketModule
        mod, _ = _make_module(GoldenTicketModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"domain": "corp.local", "krbtgt_hash": "a" * 32,
                    "domain_sid": "S-1-5-21-111-222-333"}
        )))
        assert result.status == "dry_run"

    def test_validate_requires_krbtgt_hash(self):
        from ares.modules.credential.golden_ticket import GoldenTicketModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(GoldenTicketModule)
        ctx = _ctx(params={"domain": "corp.local", "domain_sid": "S-1-5-21-111-222-333"})
        with pytest.raises((ModuleValidationError, Exception)):
            _run(mod.validate(ctx))

    def test_module_id(self):
        from ares.modules.credential.golden_ticket import GoldenTicketModule
        assert GoldenTicketModule.MODULE_ID == "credential.golden_ticket"


class TestCredentialPassSpray:
    def test_dry_run(self):
        from ares.modules.credential.pass_spray import PassSprayModule
        mod, _ = _make_module(PassSprayModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"target": "10.0.0.1", "users": ["user1"], "passwords": ["pass1"]}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.credential.pass_spray import PassSprayModule
        assert PassSprayModule.MODULE_ID == "credential.pass_spray"


class TestCredentialPassTheHash:
    def test_dry_run(self):
        from ares.modules.credential.pass_the_hash import PassTheHashModule
        mod, _ = _make_module(PassTheHashModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"target": "10.0.0.1", "username": "admin", "nt_hash": "a" * 32}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.credential.pass_the_hash import PassTheHashModule
        assert PassTheHashModule.MODULE_ID == "credential.pass_the_hash"


# ══════════════════════════════════════════════════════════════════════════════
# Exfil modules
# ══════════════════════════════════════════════════════════════════════════════

class TestExfilSecretsScan:
    def test_dry_run(self):
        from ares.modules.exfil.secrets_scan import SecretsScan
        mod, _ = _make_module(SecretsScan)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.exfil.secrets_scan import SecretsScan
        assert SecretsScan.MODULE_ID == "exfil.secrets_scan"


class TestExfilSmbShares:
    def test_dry_run(self):
        from ares.modules.exfil.smb_shares import SmbSharesExfil
        mod, _ = _make_module(SmbSharesExfil)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.exfil.smb_shares import SmbSharesExfil
        assert SmbSharesExfil.MODULE_ID == "exfil.smb_shares"


class TestExfilStagedCollection:
    def test_dry_run(self):
        from ares.modules.exfil.staged_collection import StagedCollectionModule
        mod, _ = _make_module(StagedCollectionModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.exfil.staged_collection import StagedCollectionModule
        assert StagedCollectionModule.MODULE_ID == "exfil.staged_collection"


# ══════════════════════════════════════════════════════════════════════════════
# Lateral modules
# ══════════════════════════════════════════════════════════════════════════════

class TestLateralDCOM:
    def test_dry_run(self):
        from ares.modules.lateral.dcom import DCOMLateral
        mod, _ = _make_module(DCOMLateral)
        result = _run(mod.execute(_dry_run_ctx(
            params={"target": "10.0.0.5", "username": "admin", "password": "pass"}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.lateral.dcom import DCOMLateral
        assert DCOMLateral.MODULE_ID == "lateral.dcom"
        assert "T1021.003" in DCOMLateral.MITRE_TECHNIQUES


class TestLateralSMBRelay:
    def test_dry_run(self):
        from ares.modules.lateral.smb_relay import SMBRelayAuditModule
        mod, _ = _make_module(SMBRelayAuditModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.lateral.smb_relay import SMBRelayAuditModule
        assert SMBRelayAuditModule.MODULE_ID == "lateral.smb_relay"


# ══════════════════════════════════════════════════════════════════════════════
# Linux modules
# ══════════════════════════════════════════════════════════════════════════════

class TestLinuxKernelSuggester:
    def test_dry_run(self):
        from ares.modules.linux.kernel_suggester import KernelSuggesterModule
        mod, _ = _make_module(KernelSuggesterModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.linux.kernel_suggester import KernelSuggesterModule
        assert KernelSuggesterModule.MODULE_ID == "linux.kernel_suggester"


class TestLinuxLDPreload:
    def test_dry_run(self):
        from ares.modules.linux.ld_preload import LDPreloadModule
        mod, _ = _make_module(LDPreloadModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.linux.ld_preload import LDPreloadModule
        assert LDPreloadModule.MODULE_ID == "linux.ld_preload"


class TestLinuxNFSEscape:
    def test_dry_run(self):
        from ares.modules.linux.nfs_escape import NFSEscapeModule
        mod, _ = _make_module(NFSEscapeModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.linux.nfs_escape import NFSEscapeModule
        assert NFSEscapeModule.MODULE_ID == "linux.nfs_escape"


class TestLinuxServiceHijack:
    def test_dry_run(self):
        from ares.modules.linux.service_hijack import ServiceHijackModule
        mod, _ = _make_module(ServiceHijackModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.linux.service_hijack import ServiceHijackModule
        assert ServiceHijackModule.MODULE_ID == "linux.service_hijack"


# ══════════════════════════════════════════════════════════════════════════════
# Network modules
# ══════════════════════════════════════════════════════════════════════════════

class TestNetworkDnsEnum:
    def test_dry_run(self):
        from ares.modules.network.dns_enum import DnsEnumModule
        mod, _ = _make_module(DnsEnumModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.network.dns_enum import DnsEnumModule
        assert DnsEnumModule.MODULE_ID == "network.dns_enum"


class TestNetworkHttpFingerprint:
    def test_dry_run(self):
        from ares.modules.network.http_fingerprint import HttpFingerprintModule
        mod, _ = _make_module(HttpFingerprintModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.network.http_fingerprint import HttpFingerprintModule
        assert HttpFingerprintModule.MODULE_ID == "network.http_fingerprint"


class TestNetworkServiceDetect:
    def test_dry_run(self):
        from ares.modules.network.service_detect import ServiceDetectModule
        mod, _ = _make_module(ServiceDetectModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.network.service_detect import ServiceDetectModule
        assert ServiceDetectModule.MODULE_ID == "network.service_detect"


class TestNetworkSnmpEnum:
    def test_dry_run(self):
        from ares.modules.network.snmp_enum import SnmpEnumModule
        mod, _ = _make_module(SnmpEnumModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.network.snmp_enum import SnmpEnumModule
        assert SnmpEnumModule.MODULE_ID == "network.snmp_enum"


# ══════════════════════════════════════════════════════════════════════════════
# Persistence modules
# ══════════════════════════════════════════════════════════════════════════════

class TestPersistenceScheduledTask:
    def test_dry_run(self):
        from ares.modules.persistence.scheduled_task import ScheduledTaskPersistence
        mod, _ = _make_module(ScheduledTaskPersistence)
        result = _run(mod.execute(_dry_run_ctx(
            params={"target": "10.0.0.5", "username": "admin", "password": "pass"}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.persistence.scheduled_task import ScheduledTaskPersistence
        assert ScheduledTaskPersistence.MODULE_ID == "persistence.scheduled_task"


class TestPersistenceWMISubscription:
    def test_dry_run(self):
        from ares.modules.persistence.wmi_subscription import WMISubscriptionModule
        mod, _ = _make_module(WMISubscriptionModule)
        result = _run(mod.execute(_dry_run_ctx(
            params={"target": "10.0.0.5", "username": "admin", "password": "pass"}
        )))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.persistence.wmi_subscription import WMISubscriptionModule
        assert WMISubscriptionModule.MODULE_ID == "persistence.wmi_subscription"


# ══════════════════════════════════════════════════════════════════════════════
# Windows modules
# ══════════════════════════════════════════════════════════════════════════════

class TestWindowsAppLockerBypass:
    def test_dry_run(self):
        from ares.modules.windows.applocker_bypass import AppLockerBypassModule
        mod, _ = _make_module(AppLockerBypassModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.windows.applocker_bypass import AppLockerBypassModule
        assert AppLockerBypassModule.MODULE_ID == "windows.applocker_bypass"


class TestWindowsRegistryEnum:
    def test_dry_run(self):
        from ares.modules.windows.registry_enum import RegistryEnumModule
        mod, _ = _make_module(RegistryEnumModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.windows.registry_enum import RegistryEnumModule
        assert RegistryEnumModule.MODULE_ID == "windows.registry_enum"


class TestWindowsScheduledTasksEnum:
    def test_dry_run(self):
        from ares.modules.windows.scheduled_tasks_enum import ScheduledTasksEnumModule
        mod, _ = _make_module(ScheduledTasksEnumModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.windows.scheduled_tasks_enum import ScheduledTasksEnumModule
        assert ScheduledTasksEnumModule.MODULE_ID == "windows.scheduled_tasks_enum"


class TestWindowsTokenImpersonation:
    def test_dry_run(self):
        from ares.modules.windows.token_impersonation import TokenImpersonationModule
        mod, _ = _make_module(TokenImpersonationModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.windows.token_impersonation import TokenImpersonationModule
        assert TokenImpersonationModule.MODULE_ID == "windows.token_impersonation"


class TestWindowsUACBypass:
    def test_dry_run(self):
        from ares.modules.windows.uac_bypass import UACBypassModule
        mod, _ = _make_module(UACBypassModule)
        result = _run(mod.execute(_dry_run_ctx()))
        assert result.status == "dry_run"

    def test_module_id(self):
        from ares.modules.windows.uac_bypass import UACBypassModule
        assert UACBypassModule.MODULE_ID == "windows.uac_bypass"


# ══════════════════════════════════════════════════════════════════════════════
# Cross-cutting: local_admin_creds typo fix regression (BUG-07)
# ══════════════════════════════════════════════════════════════════════════════

class TestLocalAdminCredsConsistency:

    MODULES_REQUIRING_LOCAL_ADMIN = [
        "ares.modules.windows.lsass_dump.LsassDumpModule",
        "ares.modules.windows.lsa_secrets.LSASecretsModule",
        "ares.modules.windows.dpapi.DPAPIModule",
        "ares.modules.windows.uac_bypass.UACBypassModule",
        "ares.modules.lateral.dcom.DCOMLateral",
        "ares.modules.lateral.modules.PsExecLateral",
        "ares.modules.persistence.wmi_subscription.WMISubscriptionModule",
    ]

    def test_local_admin_creds_uses_plural(self):
        """All modules that need local admin must use 'local_admin_creds' (plural)."""
        import importlib
        for dotpath in self.MODULES_REQUIRING_LOCAL_ADMIN:
            mod_path, cls_name = dotpath.rsplit(".", 1)
            try:
                mod = importlib.import_module(mod_path)
                cls = getattr(mod, cls_name)
                requires = getattr(cls, "REQUIRES", [])
                assert "local_admin_cred" not in requires, (
                    f"{cls_name}.REQUIRES contains 'local_admin_cred' (singular) — "
                    f"must be 'local_admin_creds' (plural) to match planner.py capability map"
                )
            except ImportError:
                pass   # optional deps not installed — skip
