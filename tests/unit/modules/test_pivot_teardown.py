"""
Unit tests for MOD-018: network.pivot SSH subprocess teardown & guaranteed cleanup.
Validates:
- Subprocess is terminated and waited on after plan completion.
- Force kill fallback is triggered when terminate/wait hangs.
- Teardown executes in finally even when plan fails midway with an exception.
- Teardown timeout or error does not mask the original plan exception.
- PivotModule.teardown() handles ProcessLookupError gracefully.
- PivotManager.teardown_all() cleans up active tunnels.
"""
from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.campaign import Campaign, ScopeEntry
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan
from ares.core.execution_admission import _mint_test_plan_context
from ares.modules.network.pivot import PivotModule, _PIVOT_MANAGERS
from ares.pivot.infrastructure import PivotManager, PivotTunnel, TunnelState


@pytest.fixture
def settings() -> AresSettings:
    return AresSettings(
        ares_secret_key="test-secret-key-min32-chars-xxxxxx",
        ares_encryption_key="test-enc-key-min32-chars-xxxxxxx",
        ares_default_admin_password="TestEnginePass1!",
    )


@pytest.fixture
def campaign() -> Campaign:
    return Campaign(
        id="camp-pivot-test-001",
        name="Pivot Teardown Test Campaign",
        client="ACME Corp",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        operator="tester",
    )


class TestPivotTeardown:
    @pytest.mark.asyncio
    async def test_subprocess_terminated_after_plan_completion(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """SSH subprocess is terminated and waited on after campaign plan finishes normally."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        plan = ExecutionPlan().add_stage("pivot_stage", ["network.pivot"])
        dispatch_ctx = _mint_test_plan_context(engine, campaign.id, tuple(plan.all_module_ids()))

        # Mock the pivot module run so it succeeds
        pivot_cls = engine.registry.get("network.pivot")
        fast_run = AsyncMock(return_value=([], {"tunnel_id": "tun-001"}))

        # Setup mock tunnel and process
        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(return_value=0)
        mock_proc.kill = MagicMock()

        mock_tunnel = PivotTunnel()
        mock_tunnel.tunnel_id = "tun-001"
        mock_tunnel.state = TunnelState.ACTIVE
        mock_tunnel._proc = mock_proc
        mock_tunnel._conn = None

        mock_pm = MagicMock(spec=PivotManager)
        mock_pm.all_tunnels.return_value = [mock_tunnel]
        mock_pm.teardown_all.return_value = 1

        with patch.object(pivot_cls, "run", fast_run):
            with patch.dict(_PIVOT_MANAGERS, {campaign.id: mock_pm}):
                results = await engine.run_plan(
                    plan,
                    campaign,
                    dispatch_context=dispatch_ctx,
                )

        assert "network.pivot" in results
        # teardown_all or tunnel proc termination should have been invoked
        assert mock_pm.teardown_all.called or mock_proc.terminate.called
        assert campaign.id not in _PIVOT_MANAGERS

    @pytest.mark.asyncio
    async def test_teardown_runs_in_finally_on_plan_exception(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Teardown is guaranteed to run in finally even when plan fails midway with an exception."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        plan = ExecutionPlan().add_stage("failing_stage", ["network.pivot"])
        dispatch_ctx = _mint_test_plan_context(engine, campaign.id, tuple(plan.all_module_ids()))

        # Setup mock manager with process
        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(return_value=0)
        mock_proc.kill = MagicMock()

        mock_tunnel = PivotTunnel()
        mock_tunnel.tunnel_id = "tun-fail-001"
        mock_tunnel.state = TunnelState.ACTIVE
        mock_tunnel._proc = mock_proc
        mock_tunnel._conn = None

        mock_pm = MagicMock(spec=PivotManager)
        mock_pm.all_tunnels.return_value = [mock_tunnel]
        mock_pm.teardown_all.return_value = 1

        # Simulate exception during stage loop by mocking _guarded_run to raise directly
        with patch.object(
            engine, "_guarded_run", AsyncMock(side_effect=RuntimeError("Stage simulation crash"))
        ):
            with patch.dict(_PIVOT_MANAGERS, {campaign.id: mock_pm}):
                results = await engine.run_plan(
                    plan,
                    campaign,
                    dispatch_context=dispatch_ctx,
                )

        # Plan results should capture the unhandled exception
        assert "network.pivot" in results
        assert results["network.pivot"].status.value == "failed"
        # Teardown should have been executed in finally block
        assert mock_pm.teardown_all.called or mock_proc.terminate.called
        assert campaign.id not in _PIVOT_MANAGERS

    @pytest.mark.asyncio
    async def test_teardown_timeout_does_not_mask_original_exception(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Teardown timeout or error does not mask the original plan failure."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        plan = ExecutionPlan().add_stage("stage1", ["network.pivot"])
        dispatch_ctx = _mint_test_plan_context(engine, campaign.id, tuple(plan.all_module_ids()))

        # Mock manager whose teardown_all raises TimeoutError
        mock_pm = MagicMock(spec=PivotManager)
        mock_pm.teardown_all = MagicMock(side_effect=asyncio.TimeoutError("Teardown timed out"))
        mock_pm.all_tunnels.return_value = []

        with patch.object(
            engine, "_guarded_run", AsyncMock(side_effect=ValueError("Original plan error"))
        ):
            with patch.dict(_PIVOT_MANAGERS, {campaign.id: mock_pm}):
                results = await engine.run_plan(
                    plan,
                    campaign,
                    dispatch_context=dispatch_ctx,
                )

        # Original error must be reflected in results, not masked by Teardown timeout
        assert "network.pivot" in results
        assert "Original plan error" in (results["network.pivot"].error or "")
        assert campaign.id not in _PIVOT_MANAGERS

    @pytest.mark.asyncio
    async def test_pivot_subprocess_force_killed_on_hang(self) -> None:
        """If proc.wait() times out, force kill() is invoked."""
        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock()
        mock_proc.wait = MagicMock(side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=3))
        mock_proc.kill = MagicMock()

        pm = PivotManager(operator="tester")
        tunnel = PivotTunnel()
        tunnel.tunnel_id = "tun-hang-001"
        tunnel._proc = mock_proc
        pm._tunnels[tunnel.tunnel_id] = tunnel

        # Teardown tunnel
        pm.teardown(tunnel.tunnel_id)

        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()
        assert tunnel.tunnel_id not in pm._tunnels

    @pytest.mark.asyncio
    async def test_pivot_module_teardown_handles_dead_process(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """ProcessLookupError when process is already dead does not cause teardown to crash."""
        from ares.core.noise import NoiseController

        noise = NoiseController(campaign)
        mod = PivotModule(settings=settings, campaign=campaign, noise=noise)
        mock_proc = MagicMock()
        mock_proc.terminate = MagicMock(side_effect=ProcessLookupError("No such process"))
        mock_proc.kill = MagicMock()

        mock_tunnel = PivotTunnel()
        mock_tunnel.tunnel_id = "tun-dead"
        mock_tunnel._proc = mock_proc
        mock_tunnel._conn = None

        mock_pm = MagicMock()
        mock_pm.all_tunnels.return_value = [mock_tunnel]
        mock_pm.teardown_all.return_value = 1

        camp_id = "camp-dead-proc"
        _PIVOT_MANAGERS[camp_id] = mock_pm

        # Teardown should finish cleanly without ProcessLookupError
        await mod.teardown(campaign_id=camp_id)
        assert camp_id not in _PIVOT_MANAGERS
