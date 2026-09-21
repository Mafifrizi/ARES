"""
Tests for ARES Dual-Layer Scope Firewall & Egress Network Filter.
Verifies OS-level packet filtering controller, socket-level interception, ContextVar
task isolation, DNS resolution safety, cloud allowlists, and engine integration.
"""
from __future__ import annotations

import asyncio
import socket
import pytest
from unittest.mock import MagicMock, patch

from ares.core.campaign import Campaign, ScopeEntry
from ares.core.errors import ScopeFirewallBlockError
from ares.core.scope_firewall import (
    ScopeFirewall,
    OSFirewallController,
    get_os_firewall_status,
    scope_firewall_guard,
    scope_firewall_sync_guard,
    install_hooks,
    uninstall_hooks,
    _current_firewall,
)
from ares.core.engine import AresEngine, ModuleStatus, _extract_all_targets
from ares.core.config import AresSettings
from ares.core.execution_admission import _mint_test_dispatch_context


@pytest.fixture
def sample_campaign() -> Campaign:
    return Campaign(
        name="Firewall Test Campaign",
        client="ACME Corp",
        scope=[
            ScopeEntry(cidr="10.0.0.0/24"),
            ScopeEntry(cidr="192.168.1.0/24"),
        ],
        targets=["dc01.acme.local"],
        dc="10.0.0.1",
        operator="firewall_tester",
    )


class TestScopeFirewallCore:
    """Core socket and transport-level firewall interception tests."""

    def test_in_scope_allowed(self, sample_campaign: Campaign):
        fw = ScopeFirewall(campaign=sample_campaign, module_id="test.module")
        assert fw.is_allowed_address(("10.0.0.5", 445)) is True
        assert fw.is_allowed_address(("192.168.1.100", 80)) is True
        assert fw.is_allowed_address("10.0.0.50") is True

    def test_out_of_scope_blocked(self, sample_campaign: Campaign):
        fw = ScopeFirewall(campaign=sample_campaign, module_id="test.module")
        assert fw.is_allowed_address(("8.8.8.8", 53)) is False
        assert fw.is_allowed_address(("10.0.1.5", 445)) is False
        assert fw.is_allowed_address(("1.1.1.1", 443)) is False

        with pytest.raises(ScopeFirewallBlockError) as exc_info:
            fw.assert_allowed_address(("8.8.8.8", 53))
        assert exc_info.value.target_host == "8.8.8.8"
        assert exc_info.value.target_port == 53
        assert exc_info.value.module_id == "test.module"

    def test_loopback_allowed(self, sample_campaign: Campaign):
        fw = ScopeFirewall(campaign=sample_campaign, module_id="test.module", allow_loopback_ipc=True)
        assert fw.is_allowed_address(("127.0.0.1", 5432)) is True
        assert fw.is_allowed_address(("localhost", 8000)) is True
        assert fw.is_allowed_address(("::1", 9000)) is True

    def test_cloud_module_allowlist(self, sample_campaign: Campaign):
        cloud_fw = ScopeFirewall(campaign=sample_campaign, module_id="cloud.azure", module_category="cloud")
        assert cloud_fw.is_allowed_address(("login.microsoftonline.com", 443)) is True
        assert cloud_fw.is_allowed_address(("graph.microsoft.com", 443)) is True
        assert cloud_fw.is_allowed_address(("s3.amazonaws.com", 443)) is True

        # Non-cloud module trying to access cloud domain outside CIDRs
        recon_fw = ScopeFirewall(campaign=sample_campaign, module_id="recon.scan", module_category="recon")
        # Assuming login.microsoftonline.com resolves to public IP outside 10.0.0.0/24
        assert recon_fw._is_cloud_allowed("login.microsoftonline.com") is False


class TestScopeFirewallInterception:
    """Live socket hook interception and task isolation tests."""

    @pytest.mark.asyncio
    async def test_socket_connect_intercepted(self, sample_campaign: Campaign):
        async with scope_firewall_guard(sample_campaign, module_id="exploit.test"):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(ScopeFirewallBlockError) as exc_info:
                    s.connect(("8.8.8.8", 443))
                assert exc_info.value.target_host == "8.8.8.8"
                assert exc_info.value.target_port == 443
            finally:
                s.close()

    @pytest.mark.asyncio
    async def test_socket_sendto_intercepted(self, sample_campaign: Campaign):
        async with scope_firewall_guard(sample_campaign, module_id="recon.udp"):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                with pytest.raises(ScopeFirewallBlockError) as exc_info:
                    s.sendto(b"ping", ("1.1.1.1", 53))
                assert exc_info.value.target_host == "1.1.1.1"
            finally:
                s.close()

    @pytest.mark.asyncio
    async def test_asyncio_create_connection_intercepted(self, sample_campaign: Campaign):
        loop = asyncio.get_running_loop()
        async with scope_firewall_guard(sample_campaign, module_id="async.test"):
            with pytest.raises(ScopeFirewallBlockError) as exc_info:
                await loop.create_connection(asyncio.Protocol, host="8.8.8.8", port=80)
            assert exc_info.value.target_host == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_task_isolation_zero_bleed(self, sample_campaign: Campaign):
        """
        Verify that background tasks (e.g. database pool, telemetry) running concurrently
        do NOT have firewall restrictions applied to them.
        """
        results = {"guarded_blocked": False, "unguarded_success": False}

        async def background_unrelated_task():
            # Simulated database or internal task
            # _current_firewall ContextVar should be None here
            fw = _current_firewall.get()
            if fw is None:
                results["unguarded_success"] = True

        async def attack_module_task():
            async with scope_firewall_guard(sample_campaign, module_id="lateral.psexec"):
                fw = _current_firewall.get()
                if fw is not None:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect(("8.8.4.4", 80))
                        s.close()
                    except ScopeFirewallBlockError:
                        results["guarded_blocked"] = True

        await asyncio.gather(attack_module_task(), background_unrelated_task())
        assert results["guarded_blocked"] is True
        assert results["unguarded_success"] is True

    def test_sync_guard(self, sample_campaign: Campaign):
        with scope_firewall_sync_guard(sample_campaign, module_id="sync.test"):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(ScopeFirewallBlockError):
                    s.connect(("172.217.16.206", 80))
            finally:
                s.close()

    def test_unhook_cleanup(self):
        install_hooks()
        uninstall_hooks()
        # Verify socket.socket.connect is restored and can be invoked without ScopeFirewall
        assert _current_firewall.get() is None


class TestEngineIntegration:
    """Engine pre-check and recursive parameter target extraction tests."""

    def test_target_extraction(self):
        params = {
            "target": "10.0.0.1",
            "dc": "10.0.0.2",
            "rhosts": "10.0.0.3, 10.0.0.4",
            "nested": {
                "server": "https://10.0.0.5:8443/login",
                "other_param": "some_value",
            },
            "targets": ["10.0.0.6", "10.0.0.7:445"],
        }
        targets = _extract_all_targets(params)
        expected = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"]
        for exp in expected:
            assert exp in targets

    @pytest.mark.asyncio
    async def test_recon_module_precheck_enforced(self, sample_campaign: Campaign):
        settings = AresSettings(
            ares_secret_key="test-secret-key-min32-chars-xxxxxx",
            ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
            ares_default_admin_password="TestPass123!",
        )
        engine = AresEngine(settings=settings)

        # Mock a recon module in registry
        mock_recon_cls = MagicMock()
        mock_recon_cls.MODULE_CATEGORY = "recon"
        engine.registry["test.recon"] = mock_recon_cls

        # Attempt to run recon against out-of-scope target
        result = await engine.run_module(
            module_id="test.recon",
            campaign=sample_campaign,
            params={"target": "8.8.8.8"},
            actor_role="team_lead",
            skip_validation=True,
            dispatch_context=_mint_test_dispatch_context(engine, sample_campaign.id, "test.recon"),
        )
        assert result.status == ModuleStatus.FAILED
        assert "not in campaign scope" in (result.error or "")

    @pytest.mark.asyncio
    async def test_module_firewall_block_audit(self, sample_campaign: Campaign):
        settings = AresSettings(
            ares_secret_key="test-secret-key-min32-chars-xxxxxx",
            ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
            ares_default_admin_password="TestPass123!",
        )
        engine = AresEngine(settings=settings)

        class OutOfScopeAttacker:
            MODULE_CATEGORY = "lateral"

            def __init__(self, **kwargs):
                pass

            async def validate(self, ctx):
                pass

            async def execute(self, ctx):
                # Try to connect to out-of-scope IP directly
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect(("8.8.8.8", 445))
                finally:
                    s.close()
                return MagicMock(findings=[], raw={})

        engine.registry["lateral.attacker"] = OutOfScopeAttacker

        # Pass target that passes pre-check (in scope), but module secretly attacks 8.8.8.8!
        result = await engine.run_module(
            module_id="lateral.attacker",
            campaign=sample_campaign,
            params={"target": "10.0.0.5"},
            skip_validation=True,
            dispatch_context=_mint_test_dispatch_context(engine, sample_campaign.id, "lateral.attacker"),
        )
        assert result.status == ModuleStatus.FAILED
        assert result.outcome == "scope_firewall_blocked"
        assert "[ScopeFirewall]" in (result.error or "")


class TestOSFirewallController:
    """Tests for native OS / Kernel packet filtering controller."""

    def test_status_reporting(self):
        status = get_os_firewall_status()
        assert "platform" in status
        assert "engine" in status
        assert "elevated" in status
        assert "fallback_mode" in status
        assert status["fallback_mode"] == "In-Process Transport Socket Interception"

    def test_unprivileged_fallback_produces_no_errors(self, sample_campaign: Campaign):
        with patch.object(OSFirewallController, "is_elevated", return_value=False):
            rules = OSFirewallController.apply_rules(sample_campaign, ["10.0.0.0/24"])
            assert rules == []
            status = OSFirewallController.get_status()
            assert status["elevated"] is False
            assert status["active_rules_count"] == 0

    def test_windows_elevated_rule_application_and_cleanup(self, sample_campaign: Campaign):
        with (
            patch.object(OSFirewallController, "is_elevated", return_value=True),
            patch("sys.platform", "win32"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="Ok.", stderr="")
            rules = OSFirewallController.apply_rules(sample_campaign, ["10.0.0.0/24", "192.168.1.0/24"])
            assert len(rules) == 1
            assert rules[0].startswith("ARES_SCOPE_WALL_")
            assert mock_run.call_count == 1
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "netsh"
            assert "advfirewall" in cmd
            assert "remoteip=10.0.0.0/24,192.168.1.0/24" in cmd

            # Verify cleanup
            removed = OSFirewallController.remove_rules(rules)
            assert removed == 1
            del_cmd = mock_run.call_args[0][0]
            assert del_cmd[0] == "netsh"
            assert f"name={rules[0]}" in del_cmd

    def test_linux_elevated_rule_application_and_cleanup(self, sample_campaign: Campaign):
        with (
            patch.object(OSFirewallController, "is_elevated", return_value=True),
            patch("sys.platform", "linux"),
            patch("os.getpid", return_value=12345),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            rules = OSFirewallController.apply_rules(sample_campaign, ["172.16.0.0/16"])
            assert len(rules) == 1
            assert rules[0].startswith("ARES_SCOPE_WALL_")
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "iptables"
            assert "-d" in cmd
            assert "172.16.0.0/16" in cmd

            removed = OSFirewallController.remove_rules(rules)
            assert removed == 1

    def test_scope_firewall_guard_wires_os_firewall(self, sample_campaign: Campaign):
        with (
            patch.object(OSFirewallController, "apply_rules", return_value=["ARES_SCOPE_WALL_test"]) as mock_apply,
            patch.object(OSFirewallController, "remove_rules") as mock_remove,
        ):
            with scope_firewall_sync_guard(sample_campaign, enable_os_firewall=True) as fw:
                assert fw is not None
                mock_apply.assert_called_once()
            mock_remove.assert_called_once_with(["ARES_SCOPE_WALL_test"])
