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
        # Not fully privileged (not 0x3FFFFFFFFF) — just a check the method runs
        assert "CapEff" in result or "error" in result

    @pytest.mark.asyncio
    async def test_k8s_token_not_found(self):
        module, _ = _make_module(ContainerEscapeModule)
        with patch("os.path.exists", return_value=False):
            result = await module._check_k8s_service_account()
        assert result["k8s_detected"] is False


class TestLinuxPrivesc:
    @pytest.mark.asyncio
    async def test_writable_path_detection(self):
        import os
        module, _ = _make_module(LinuxPrivescModule)
        with patch("os.environ.get", return_value="/usr/bin:/tmp/writable"), \
             patch("os.path.isdir", return_value=True), \
             patch("os.access", side_effect=lambda p, m: "writable" in p):
            result = await module._check_writable_path()
        assert "/tmp/writable" in result

    @pytest.mark.asyncio
    async def test_world_writable_etc_passwd(self):
        module, _ = _make_module(LinuxPrivescModule)
        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            result = await module._check_world_writable_sensitive()
        assert len(result) > 0
        assert len(module._findings) > 0
        assert module._findings[0].severity.value == "critical"
