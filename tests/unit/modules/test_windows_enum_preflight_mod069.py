"""
Tests for MOD-069: Pre-flight parameter validation in validate()
and non-silent logging in run() for windows.registry_enum and windows.scheduled_tasks_enum.
"""

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.core.noise import NoiseController
from ares.modules.windows.registry_enum import RegistryEnumModule
from ares.modules.windows.scheduled_tasks_enum import ScheduledTasksEnumModule


def _make_context_deps():
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Windows-Enum-Preflight-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return settings, campaign, noise


@pytest.mark.asyncio
async def test_registry_enum_validate_fails_without_username():
    """Verify registry_enum fails fast in validate() when username is missing."""
    settings, campaign, noise = _make_context_deps()
    mod = RegistryEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="192.168.1.50", params={"target": "192.168.1.50"})

    with pytest.raises(ModuleValidationError) as exc_info:
        await mod.validate(ctx)

    assert "username" in str(exc_info.value).lower()
    assert exc_info.value.field == "username"


@pytest.mark.asyncio
async def test_registry_enum_validate_succeeds_with_credentials():
    """Verify registry_enum validate() passes when username and target are provided."""
    settings, campaign, noise = _make_context_deps()
    mod = RegistryEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(
        target="192.168.1.50",
        params={"target": "192.168.1.50", "username": "Administrator"},
    )
    await mod.validate(ctx)


@pytest.mark.asyncio
async def test_scheduled_tasks_enum_validate_fails_without_username():
    """Verify scheduled_tasks_enum fails fast in validate() when username is missing."""
    settings, campaign, noise = _make_context_deps()
    mod = ScheduledTasksEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(target="192.168.1.50", params={"target": "192.168.1.50"})

    with pytest.raises(ModuleValidationError) as exc_info:
        await mod.validate(ctx)

    assert "username" in str(exc_info.value).lower()
    assert exc_info.value.field == "username"


@pytest.mark.asyncio
async def test_scheduled_tasks_enum_validate_succeeds_with_credentials():
    """Verify scheduled_tasks_enum validate() passes when username and target are provided."""
    settings, campaign, noise = _make_context_deps()
    mod = ScheduledTasksEnumModule(settings=settings, campaign=campaign, noise=noise)
    ctx = ExecutionContext(
        target="192.168.1.50",
        params={"target": "192.168.1.50", "username": "Administrator"},
    )
    await mod.validate(ctx)


@pytest.mark.asyncio
async def test_enum_run_logs_warning_on_missing_params():
    """Verify run() logs a structured warning when invoked without required params instead of silent abort."""
    settings, campaign, noise = _make_context_deps()
    mod_reg = RegistryEnumModule(settings=settings, campaign=campaign, noise=noise)
    mod_tasks = ScheduledTasksEnumModule(settings=settings, campaign=campaign, noise=noise)

    with patch("ares.modules.windows.registry_enum.logger.warning") as mock_reg_warn:
        findings, raw = await mod_reg.run(target="192.168.1.50", username="")
        assert findings == []
        assert "error" in raw
        mock_reg_warn.assert_called_once()

    with patch("ares.modules.windows.scheduled_tasks_enum.logger.warning") as mock_tasks_warn:
        findings, raw = await mod_tasks.run(target="192.168.1.50", username="")
        assert findings == []
        assert "error" in raw
        mock_tasks_warn.assert_called_once()
