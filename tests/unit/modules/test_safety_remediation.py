"""
Automated Safety Remediation Unit Tests (Klaster A)
Verifies:
1. Linux modules reject remote execution without SSH credentials (fail-closed)
2. MSSQL xp_cmdshell always tears down in finally
3. Golden Ticket does not mutate process-wide CWD
4. Pass Spray rate limits per-attempt inside loop using ldap/default bucket
5. AWS Privesc harmonizes access_key and aws_access_key parameters
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from ares.core.config import AresSettings
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController


def make_module(cls):
    """Instantiate module with valid test settings, campaign, and noise controller."""
    settings = AresSettings()
    campaign = Campaign(
        name="KlasterA-Safety-Test",
        client="SafetyClient",
        operator="safety_tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return cls(settings=settings, campaign=campaign, noise=noise)


# ── 1. Linux Modules Fail-Closed Verification ───────────────────────────────

@pytest.mark.parametrize("mod_path,cls_name", [
    ("ares.modules.linux.privesc", "LinuxPrivescModule"),
    ("ares.modules.linux.service_hijack", "ServiceHijackModule"),
    ("ares.modules.linux.ld_preload", "LDPreloadModule"),
    ("ares.modules.linux.nfs_escape", "NFSEscapeModule"),
])
def test_linux_modules_validate_rejects_remote_without_credentials(mod_path, cls_name):
    """Remote targets must fail-closed if ssh_user/username is omitted."""
    mod = __import__(mod_path, fromlist=[cls_name])
    module_cls = getattr(mod, cls_name)
    instance = make_module(module_cls)

    ctx = ExecutionContext(
        target="10.0.0.5",
        campaign_id="test_camp",
        params={},
    )
    with pytest.raises(ModuleValidationError) as exc_info:
        asyncio.run(instance.validate(ctx))
    assert "requires 'username' or 'ssh_user'" in str(exc_info.value)
    assert "prohibited" in str(exc_info.value)


@pytest.mark.parametrize("mod_path,cls_name", [
    ("ares.modules.linux.privesc", "LinuxPrivescModule"),
    ("ares.modules.linux.service_hijack", "ServiceHijackModule"),
    ("ares.modules.linux.ld_preload", "LDPreloadModule"),
    ("ares.modules.linux.nfs_escape", "NFSEscapeModule"),
])
def test_linux_modules_validate_accepts_remote_with_credentials(mod_path, cls_name):
    """Remote targets pass validation if ssh_user or username is provided."""
    mod = __import__(mod_path, fromlist=[cls_name])
    module_cls = getattr(mod, cls_name)
    instance = make_module(module_cls)

    ctx = ExecutionContext(
        target="10.0.0.5",
        campaign_id="test_camp",
        params={"ssh_user": "operator"},
    )
    # Should not raise
    asyncio.run(instance.validate(ctx))


@pytest.mark.parametrize("mod_path,cls_name", [
    ("ares.modules.linux.privesc", "LinuxPrivescModule"),
    ("ares.modules.linux.service_hijack", "ServiceHijackModule"),
    ("ares.modules.linux.ld_preload", "LDPreloadModule"),
    ("ares.modules.linux.nfs_escape", "NFSEscapeModule"),
])
def test_linux_modules_run_refuses_remote_local_fallback(mod_path, cls_name):
    """Direct run() with remote host and no ssh_user must return error without executing local shell."""
    mod = __import__(mod_path, fromlist=[cls_name])
    module_cls = getattr(mod, cls_name)
    instance = make_module(module_cls)

    findings, raw = asyncio.run(instance.run(host="10.0.0.5", ssh_user=None))
    assert findings == []
    assert "prohibited" in raw.get("error", "").lower()


# ── 2. MSSQL xp_cmdshell Teardown Verification ─────────────────────────────

def test_mssql_xp_cmdshell_teardown_executed_even_on_query_failure():
    """xp_cmdshell must always be disabled in finally even if the shell command throws."""
    from ares.modules.lateral.mssql import MSSQLModule
    module = make_module(MSSQLModule)

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # Simulate command execution error during xp_cmdshell
    def cursor_execute(query):
        if "EXEC xp_cmdshell" in query:
            raise RuntimeError("Simulated query execution error")

    mock_cursor.execute.side_effect = cursor_execute

    with patch.dict("sys.modules", {"pymssql": MagicMock(connect=MagicMock(return_value=mock_conn))}):
        out = module._xp_cmdshell_sync("10.0.0.1", "sa", "Password123!", 1433, "whoami")

    # Assert teardown query was executed
    executed_queries = [call.args[0] for call in mock_cursor.execute.call_args_list]
    assert any("sp_configure 'xp_cmdshell', 0" in q for q in executed_queries), \
        "xp_cmdshell teardown (disable) was not executed in finally!"
    assert any("sp_configure 'show advanced options', 0" in q for q in executed_queries), \
        "show advanced options teardown was not executed in finally!"
    assert mock_conn.close.called


# ── 3. Golden Ticket CWD Isolation Verification ─────────────────────────────

def test_golden_ticket_does_not_mutate_process_cwd():
    """golden_ticket._forge must not call os.chdir under any circumstance."""
    from ares.modules.credential.golden_ticket import GoldenTicketModule
    mod = make_module(GoldenTicketModule)
    mod.before_request = AsyncMock()
    mod.noise.jitter.sleep = AsyncMock()

    cwd_before = os.getcwd()
    with patch("os.chdir") as mock_chdir:
        # Run golden ticket forge
        asyncio.run(mod.run(
            domain="corp.local",
            domain_sid="S-1-5-21-1234567890-1234567890-1234567890",
            krbtgt_hash="a" * 32,
            username="Administrator",
        ))
        assert not mock_chdir.called, "os.chdir was called during golden ticket execution!"
    assert os.getcwd() == cwd_before


# ── 4. Pass Spray Rate Limiting Verification ────────────────────────────────

def test_pass_spray_rate_limits_per_attempt_with_ldap_bucket():
    """pass_spray must acquire 'ldap' rate limiter on every attempt, not cloud_api."""
    from ares.modules.credential.pass_spray import PassSprayModule
    mod = make_module(PassSprayModule)
    mod.before_request = AsyncMock()
    mod.noise.jitter.sleep = AsyncMock()

    acquire_mock = AsyncMock()
    mod.noise.rate_limiter.acquire = acquire_mock

    users = ["user1", "user2", "user3"]
    passwords = ["Pass1"]

    with patch.dict("sys.modules", {"ldap3": MagicMock()}):
        with patch("asyncio.sleep", new=AsyncMock()):
            asyncio.run(mod.run(
                target="10.0.0.1",
                users=users,
                passwords=passwords,
                use_ldap=True,
                delay_s=0,
            ))

    # Assert rate_limiter.acquire was called for each attempt (3 times)
    assert acquire_mock.call_count == 3
    # Assert every call used 'ldap', NONE used 'cloud_api'
    for call in acquire_mock.call_args_list:
        assert call.args[0] == "ldap", f"Expected 'ldap' bucket, got {call.args[0]}"


# ── 5. AWS Privesc Parameter Normalization Verification ──────────────────────

def test_aws_privesc_accepts_both_access_key_variants():
    """aws_privesc must accept either access_key or aws_access_key."""
    from ares.modules.cloud.aws_privesc import AWSPrivescModule
    mod = make_module(AWSPrivescModule)

    # Both must validate without error
    ctx1 = ExecutionContext(target="aws", campaign_id="c", params={"access_key": "AKIA123"})
    asyncio.run(mod.validate(ctx1))

    ctx2 = ExecutionContext(target="aws", campaign_id="c", params={"aws_access_key": "AKIA123"})
    asyncio.run(mod.validate(ctx2))


# ── 6. On-Prem Module Rate Limiter Bucket Verification ──────────────────────

@pytest.mark.parametrize("mod_path,cls_name,expected_bucket,run_kwargs", [
    ("ares.modules.windows.token_impersonation", "TokenImpersonationModule", "smb", {"target": "10.0.0.1", "username": "admin", "password": "pwd"}),
    ("ares.modules.windows.lsa_secrets", "LSASecretsModule", "smb", {"target": "10.0.0.1", "username": "admin", "password": "pwd"}),
    ("ares.modules.persistence.wmi_subscription", "WMISubscriptionModule", "wmi", {"target": "10.0.0.1", "username": "admin", "password": "pwd", "command": "whoami"}),
    ("ares.modules.exfil.staged_collection", "StagedCollectionModule", "ssh", {"target": "10.0.0.1", "username": "admin", "key_path": "/tmp/k"}),
    ("ares.modules.credential.pass_the_hash", "PassTheHashModule", "smb", {"target": "10.0.0.1", "username": "admin", "nt_hash": "a"*32}),
])
def test_onprem_modules_rate_limiter_never_calls_cloud_api(mod_path, cls_name, expected_bucket, run_kwargs):
    """On-prem modules must use their semantic bucket (smb/wmi/ssh) and never touch cloud_api."""
    mod = __import__(mod_path, fromlist=[cls_name])
    module_cls = getattr(mod, cls_name)
    instance = make_module(module_cls)
    instance.before_request = AsyncMock()
    instance.noise.jitter.sleep = AsyncMock()
    acquire_mock = AsyncMock()
    instance.noise.rate_limiter.acquire = acquire_mock

    with patch.dict("sys.modules", {
        "impacket": MagicMock(),
        "impacket.smbconnection": MagicMock(),
        "impacket.examples.secretsdump": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.transport": MagicMock(),
        "impacket.dcerpc.v5.dcom": MagicMock(),
        "impacket.dcerpc.v5.dcomrt": MagicMock(),
        "paramiko": MagicMock(),
    }):
        # Mock inner execution loop or functions
        try:
            asyncio.run(instance.run(**run_kwargs))
        except Exception:
            pass

    assert acquire_mock.called, f"{cls_name} did not call rate_limiter.acquire"
    called_bucket = acquire_mock.call_args[0][0]
    assert called_bucket == expected_bucket, f"{cls_name} expected bucket {expected_bucket}, got {called_bucket}"
    assert called_bucket != "cloud_api", f"{cls_name} improperly used cloud_api rate limiter bucket!"

