from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from ares.modules.persistence.scheduled_task import (
    ScheduledTaskPersistence,
    _tsch_delete_sync,
)


def _make_module():
    settings = AresSettings(
        ares_secret_key="test-secret-key-min32-chars-here!!",
        ares_encryption_key="test-enc-key-min32-chars-here-xxx",
    )
    campaign = Campaign(
        name="Scheduled-Task-Teardown-Test",
        operator="test_operator",
        scope=[ScopeEntry(cidr="10.0.0.0/24")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    return ScheduledTaskPersistence(settings=settings, campaign=campaign, noise=noise)


@pytest.mark.asyncio
async def test_scheduled_task_teardown_after_successful_run():
    """MOD-046: task is deleted in finally and created_artifacts is populated after successful run."""
    mod = _make_module()

    mock_register = MagicMock()
    mock_delete = MagicMock()

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.tsch": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules), \
         patch("ares.modules.persistence.scheduled_task._tsch_register_sync", mock_register), \
         patch("ares.modules.persistence.scheduled_task._tsch_delete_sync", mock_delete):
        findings, raw = await mod.run(
            target="10.0.0.5",
            username="admin",
            password="pass",
            domain="corp.local",
            task_name="AresTestTask",
            command="calc.exe",
        )

    mock_register.assert_called_once()
    mock_delete.assert_called_once_with(
        "10.0.0.5", "admin", "pass", "corp.local", "", "", "AresTestTask"
    )
    assert raw["created_artifacts"] == [r"scheduled_task:\AresTestTask"]
    assert raw["persistence_established"] is True


@pytest.mark.asyncio
async def test_scheduled_task_teardown_after_failure_in_middle():
    """MOD-046: task delete is executed in finally even when task creation fails midway."""
    mod = _make_module()

    mock_register = MagicMock(side_effect=RuntimeError("RPC connection broke during task creation"))
    mock_delete = MagicMock()

    mock_modules = {
        "impacket": MagicMock(),
        "impacket.dcerpc": MagicMock(),
        "impacket.dcerpc.v5": MagicMock(),
        "impacket.dcerpc.v5.tsch": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules), \
         patch("ares.modules.persistence.scheduled_task._tsch_register_sync", mock_register), \
         patch("ares.modules.persistence.scheduled_task._tsch_delete_sync", mock_delete):
        with pytest.raises(Exception):
            await mod.run(
                target="10.0.0.5",
                username="admin",
                password="pass",
                domain="corp.local",
                task_name="AresTestTaskFail",
                command="calc.exe",
            )

    # Delete must be called even though register failed midway
    mock_delete.assert_called_once_with(
        "10.0.0.5", "admin", "pass", "corp.local", "", "", "AresTestTaskFail"
    )


@pytest.mark.asyncio
async def test_scheduled_task_explicit_teardown_method():
    """MOD-046: explicit teardown() method delegates to _tsch_delete_sync and returns True."""
    mod = _make_module()
    mock_delete = MagicMock()

    with patch("ares.modules.persistence.scheduled_task._tsch_delete_sync", mock_delete):
        res = await mod.teardown(
            target="10.0.0.5",
            username="admin",
            password="pass",
            domain="corp.local",
            task_name="ManualTask",
        )

    assert res is True
    mock_delete.assert_called_once_with(
        "10.0.0.5", "admin", "pass", "corp.local", "", "", "ManualTask"
    )
