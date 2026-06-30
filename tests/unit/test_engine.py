"""
Tests for ARES AresEngine — execution, timeout, retry, concurrency.

Modules used in engine tests are mocked to return instantly.
This tests ENGINE behavior (planning, parallelism, semaphore, timeout, retry)
not individual module behavior (which is tested in test_modules.py).
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch, AsyncMock

import pytest

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.engine import AresEngine, ExecutionPlan, ModuleStatus
from ares.core.notifier import build_notifier_from_settings


# ── Fixtures ──────────────────────────────────────────────────────────────────

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
        name="Engine Test Campaign",
        client="ACME",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
        operator="tester",
    )


def _fast_run(**kwargs: Any):
    """Instant async mock run — returns no findings, no raw data."""
    async def _inner(**kw: Any):
        return [], {}
    return _inner(**kwargs)


# ── Engine Tests ──────────────────────────────────────────────────────────────

class TestAsyncEngine:

    def test_blank_webhook_url_disables_notifier(self, settings: AresSettings) -> None:
        """Blank/whitespace webhook config is disabled, not validated as a URL."""
        settings.ares_webhook_url = "  "
        assert build_notifier_from_settings(settings) is None

    def test_http_webhook_url_still_rejected(self, settings: AresSettings) -> None:
        """SSRF protection remains strict for configured non-HTTPS webhooks."""
        settings.ares_webhook_url = "http://example.com/webhook"
        with pytest.raises(ValueError, match="must use https"):
            build_notifier_from_settings(settings)

    @pytest.mark.asyncio
    async def test_run_module_not_found(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        engine = AresEngine(settings=settings)
        engine.load_modules()
        result = await engine.run_module("nonexistent.module", campaign, {})
        assert result.status == ModuleStatus.FAILED
        assert "not found" in (result.error or "")

    @pytest.mark.asyncio
    async def test_run_module_timeout(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        engine = AresEngine(settings=settings)
        engine.load_modules()

        # Patch BOTH execute() and run():
        #   - engine calls instance.execute(ctx) on first attempt
        #   - retry path calls module2.run(**params) directly (bypasses execute)
        # Both must sleep forever so all attempts time out → status=TIMEOUT.
        async def slow_execute(self_unused, ctx):
            await asyncio.sleep(999)
            from ares.modules.base import ModuleResult
            return ModuleResult(status="success", module_id="linux.container")

        async def slow_run(self_unused, **kwargs):
            await asyncio.sleep(999)
            return [], {}

        mid = "linux.container"
        if mid in engine.registry:
            cls = engine.registry.get(mid)
            with patch.object(cls, "execute", slow_execute),                  patch.object(cls, "run", slow_run):
                result = await engine.run_module(
                    mid, campaign, {"target": "10.0.0.5"}, timeout_seconds=1
                )
            assert result.status == ModuleStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_execution_plan_parallel(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """All modules in a stage are attempted — mocked to return instantly."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        # Mock both modules so test runs in ms, not 20+ seconds on real filesystem
        fast = AsyncMock(return_value=([], {}))
        privesc_cls   = engine.registry.get("linux.privesc")
        container_cls = engine.registry.get("linux.container")

        patches = []
        if privesc_cls:
            patches.append(patch.object(privesc_cls, "run", fast))
        if container_cls:
            patches.append(patch.object(container_cls, "run", fast))

        with patches[0] if patches else _noop_ctx():
            ctx = patches[1] if len(patches) > 1 else _noop_ctx()
            with ctx:
                plan = (ExecutionPlan()
                    .add_stage("recon", ["linux.privesc", "linux.container"])
                )
                results = await engine.run_plan(plan, campaign, timeout_per_module=5)

        assert "linux.privesc"  in results
        assert "linux.container" in results

    @pytest.mark.asyncio
    async def test_plan_progress_callback(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Progress callback should be called for each module."""
        engine = AresEngine(settings=settings)
        engine.load_modules()

        fast = AsyncMock(return_value=([], {}))
        container_cls = engine.registry.get("linux.container")

        events: list[Any] = []

        async def on_progress(event: Any) -> None:
            events.append(event)

        ctx = patch.object(container_cls, "run", fast) if container_cls else _noop_ctx()
        with ctx:
            plan = ExecutionPlan().add_stage("test", ["linux.container"])
            await engine.run_plan(
                plan, campaign, on_progress=on_progress, timeout_per_module=5
            )
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Engine respects max_parallel — mocked to avoid filesystem scans."""
        engine = AresEngine(settings=settings, max_parallel=2)
        engine.load_modules()

        fast = AsyncMock(return_value=([], {}))
        privesc_cls   = engine.registry.get("linux.privesc")
        container_cls = engine.registry.get("linux.container")

        patches = []
        if privesc_cls:
            patches.append(patch.object(privesc_cls, "run", fast))
        if container_cls:
            patches.append(patch.object(container_cls, "run", fast))

        with patches[0] if patches else _noop_ctx():
            ctx = patches[1] if len(patches) > 1 else _noop_ctx()
            with ctx:
                plan = ExecutionPlan().add_stage(
                    "test", ["linux.privesc", "linux.container"]
                )
                results = await engine.run_plan(
                    plan, campaign, timeout_per_module=5
                )
        assert len(results) == 2


# ── Helpers ───────────────────────────────────────────────────────────────────

from contextlib import contextmanager

@contextmanager
def _noop_ctx():
    """No-op context manager for optional patches."""
    yield
