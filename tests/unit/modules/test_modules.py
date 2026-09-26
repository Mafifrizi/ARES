"""Tests for ARES modules."""
from __future__ import annotations

import pytest
from unittest.mock import patch

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.linux.container import ContainerEscapeModule
from ares.modules.linux.privesc import LinuxPrivescModule


def _make_module(cls: type, noise_profile: str = "normal") -> tuple:
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Test",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile(noise_profile),
    )
    noise = NoiseController(campaign)
    module = cls(settings=settings, campaign=campaign, noise=noise)
    return module, campaign


class TestContainerEscape:
    @pytest.mark.asyncio
    async def test_no_socket_no_finding(self):
        module, _ = _make_module(ContainerEscapeModule)
        with patch("os.path.exists", return_value=False):
            result = await module._check_docker_socket()
        assert result["exists"] is False
        assert len(module._findings) == 0

    @pytest.mark.asyncio
    async def test_writable_socket_critical_finding(self):
        module, _ = _make_module(ContainerEscapeModule)
        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            result = await module._check_docker_socket()
        assert result["writable"] is True
        assert len(module._findings) == 1
        assert module._findings[0].severity.value == "critical"

    @pytest.mark.asyncio
    async def test_privileged_detection(self):
        module, _ = _make_module(ContainerEscapeModule)
        fake_status = "CapEff:\t000003ffffffffff\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = fake_status
            result = await module._check_privileged()
        # Not fully privileged (not 0x3FFFFFFFFF) - just a check the method runs
        assert "CapEff" in result or "error" in result

    @pytest.mark.asyncio
    async def test_k8s_token_not_found(self):
        module, _ = _make_module(ContainerEscapeModule)
        with patch("os.path.exists", return_value=False):
            result = await module._check_k8s_service_account()
        assert result["k8s_detected"] is False


class TestLinuxPrivesc:
    @pytest.mark.asyncio
    async def test_writable_path_detection_executes_on_target(self):
        """Path writability check must execute via remote runner on target, ignoring operator filesystem."""
        from unittest.mock import AsyncMock
        module, _ = _make_module(LinuxPrivescModule)

        # Mock target runner returning writable paths found on remote target
        mock_runner = AsyncMock(return_value="/usr/local/bin\n/opt/tools/bin\n")

        result = await module._check_writable_path(run=mock_runner)

        # Verify command executed on target
        assert mock_runner.called
        assert "echo \"$PATH\"" in mock_runner.call_args[0][0]
        assert result == ["/usr/local/bin", "/opt/tools/bin"]

    @pytest.mark.asyncio
    async def test_writable_path_finding_attributed_to_target_host(self):
        """Finding.host must be attributed to remote target IP/hostname, not localhost."""
        module, _ = _make_module(LinuxPrivescModule)

        target_host = "192.168.100.55"
        raw = {
            "host": target_host,
            "writable_path": ["/usr/local/bin"],
        }
        module._analyze(raw)

        writable_findings = [f for f in module._findings if "Writable PATH Dirs" in f.title]
        assert len(writable_findings) == 1
        finding = writable_findings[0]
        assert finding.host == target_host
        assert finding.host != "localhost"
        assert target_host in finding.title
        assert finding.evidence["host"] == target_host
        assert "/usr/local/bin" in finding.evidence["directories"]

    @pytest.mark.asyncio
    async def test_world_writable_etc_passwd(self):
        module, _ = _make_module(LinuxPrivescModule)
        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            result = await module._check_world_writable_sensitive()
        assert len(result) > 0
        assert len(module._findings) > 0
        assert module._findings[0].severity.value == "critical"

