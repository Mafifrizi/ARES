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
    async def test_kerberoast_flat_dashboard_params_reach_execution(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        """Flat dashboard fields must satisfy Kerberoast's credential contract."""
        from ares.modules.ad.kerberoast import KerberoastModule
        from ares.modules.base import ModuleResult

        engine = AresEngine(settings=settings)
        engine.load_modules()
        captured: dict[str, Any] = {}

        async def fake_execute(self_unused: Any, ctx: Any) -> ModuleResult:
            captured["params"] = dict(ctx.params)
            return ModuleResult(
                status="success",
                raw={"reached": True},
                module_id="ad.kerberoast",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "use_ldaps": False,
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", fake_execute):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
            )

        assert result.status == ModuleStatus.DONE
        assert captured["params"] == params

    @pytest.mark.asyncio
    async def test_kerberoast_still_blocks_stealth_profile(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.campaign import NoiseProfile
        from ares.modules.ad.kerberoast import KerberoastModule

        campaign.noise_profile = NoiseProfile.STEALTH
        engine = AresEngine(settings=settings)
        engine.load_modules()

        async def unexpected_execute(self_unused: Any, ctx: Any) -> Any:
            raise AssertionError("stealth profile must block before execution")

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "use_ldaps": False,
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", unexpected_execute):
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
            )

        assert result.status == ModuleStatus.FAILED
        assert "blocked in STEALTH profile" in (result.error or "")

    @pytest.mark.asyncio
    async def test_kerberoast_classified_tgs_timeout_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberoast_tgs_timeout,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def classified_timeout(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                format_kerberoast_tgs_timeout(2),
                module_id="ad.kerberoast",
                field="kerberos_tgs",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", classified_timeout), \
             patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
            )

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "network_error"
        assert "found 2 Kerberoastable candidate account(s)" in result.outcome_message
        assert "Kerberos TGS request timed out" in result.outcome_message
        assert "port 88" in result.operator_next_steps[0]
        assert "clock synchronization" in result.operator_next_steps[0]
        assert "Kerberos service health" in result.operator_next_steps[0]
        assert "account/SPN validity" in result.operator_next_steps[0]

    @pytest.mark.asyncio
    async def test_asreproast_operator_outcome_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.modules.ad.asreproast import ASREPRoastModule
        from ares.modules.base import ModuleResult

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def candidate_failure(self_unused: Any, ctx: Any) -> ModuleResult:
            nonlocal calls
            calls += 1
            return ModuleResult(
                status="success",
                raw={
                    "outcome_category": "operator_error",
                    "outcome_message": (
                        "LDAP found 1 ASREPRoast candidate account(s), but Kerberos "
                        "did not return AS-REP material. Last Kerberos error: "
                        "KRB_AP_ERR_SKEW: Kerberos clock skew too great."
                    ),
                },
                module_id="ad.asreproast",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
        }
        with patch.object(ASREPRoastModule, "execute", candidate_failure), \
             patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module("ad.asreproast", campaign, params)

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert "ASREPRoast candidate" in result.outcome_message

    @pytest.mark.asyncio
    async def test_enum_users_nonretryable_bind_failure_does_not_retry(
        self, settings: AresSettings, campaign: Campaign, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.core.noise import JitterEngine
        from ares.modules.ad.enum_users import ADEnumUsersModule

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        def classified_bind_failure(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                "ad.enum_users LDAP bind failed: invalid LDAP credentials.",
                module_id="ad.enum_users",
                field="username",
            )

        monkeypatch.setattr(ADEnumUsersModule, "_ldap_query_sync", classified_bind_failure)

        async def no_noise_sleep(*args: Any, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(JitterEngine, "sleep", no_noise_sleep)
        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
            "use_ldaps": False,
        }
        with patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module("ad.enum_users", campaign, params)

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert result.findings == []
        assert "invalid LDAP credentials" in result.outcome_message
        assert "Passw0rd!" not in result.outcome_message

    @pytest.mark.asyncio
    async def test_kerberoast_clock_skew_does_not_retry(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberos_clock_skew,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def classified_clock_skew(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            raise ModuleValidationError(
                format_kerberos_clock_skew(),
                module_id="ad.kerberoast",
                field="time",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "alice@corp.local",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", classified_clock_skew), \
             patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module("ad.kerberoast", campaign, params)

        assert calls == 1
        assert retry_sleep.await_count == 0
        assert result.outcome == "operator_error"
        assert "clock skew too great" in result.outcome_message
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_retry_stops_when_retry_attempt_classifies_tgs_timeout(
        self, settings: AresSettings, campaign: Campaign
    ) -> None:
        from ares.core.errors import ModuleValidationError, NetworkError
        from ares.modules.ad.kerberoast import (
            KerberoastModule,
            format_kerberoast_tgs_timeout,
        )

        engine = AresEngine(settings=settings)
        engine.load_modules()
        calls = 0

        async def transient_then_classified(self_unused: Any, ctx: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise NetworkError("temporary KDC reachability failure")
            raise ModuleValidationError(
                format_kerberoast_tgs_timeout(2),
                module_id="ad.kerberoast",
                field="kerberos_tgs",
            )

        params = {
            "dc": "10.0.0.5",
            "domain": "corp.local",
            "username": "svc-roast",
            "password": "Passw0rd!",
            "target_user": "sqlsvc",
        }
        with patch.object(KerberoastModule, "execute", transient_then_classified), \
             patch("ares.core.engine.asyncio.sleep", new=AsyncMock()) as retry_sleep:
            result = await engine.run_module(
                "ad.kerberoast",
                campaign,
                params,
                actor_role="team_lead",
            )

        assert calls == 2
        assert retry_sleep.await_count == 1
        assert result.outcome == "network_error"
        assert "found 2 Kerberoastable candidate account(s)" in result.outcome_message
        assert "Kerberos TGS request timed out" in result.outcome_message

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
