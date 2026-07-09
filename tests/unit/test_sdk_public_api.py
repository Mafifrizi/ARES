from __future__ import annotations

import asyncio

import pytest

import ares.sdk as sdk
from ares.core.context import ExecutionContext
from ares.core.engine import AresEngine
from ares.modules.base import BaseModule, ModuleResult, OpsecLevel, validate_module_class


def test_public_sdk_re_exports_core_contracts() -> None:
    assert sdk.BaseModule is BaseModule
    assert sdk.ExecutionContext is ExecutionContext
    assert sdk.ModuleResult is ModuleResult
    assert sdk.OpsecLevel is OpsecLevel
    assert sdk.validate_module_class is validate_module_class


def test_public_sdk_all_contains_author_symbols() -> None:
    for symbol in (
        "BaseModule",
        "ExecutionContext",
        "ModuleResult",
        "ModuleTestHelper",
        "Finding",
        "Severity",
        "module_metadata",
        "requires_privilege",
        "timeout",
        "ModuleValidationError",
    ):
        assert symbol in sdk.__all__
        assert hasattr(sdk, symbol)


def test_module_metadata_decorator_available_from_public_sdk() -> None:
    @sdk.module_metadata(
        module_id="demo.example",
        name="Demo Example",
        category="network",
        description="SDK import smoke test",
        author="ARES",
        opsec=sdk.OpsecLevel.LOW,
        requires=["target"],
        outputs=["finding"],
        mitre=["T1592.002"],
    )
    class DemoModule(sdk.BaseModule):
        async def run(self, **kwargs):
            return [], {"ok": True}

    assert DemoModule.MODULE_ID == "demo.example"
    assert DemoModule.metadata()["id"] == "demo.example"
    assert sdk.validate_module_class(DemoModule) == []


def test_timeout_decorator_sets_runtime_timeout_contract() -> None:
    @sdk.timeout(42)
    class DemoModule(sdk.BaseModule):
        async def run(self, **kwargs):
            return [], {"ok": True}

    assert DemoModule.MODULE_TIMEOUT_SECONDS == 42
    assert DemoModule.DEFAULT_TIMEOUT_S == 42


@pytest.mark.parametrize("invalid_seconds", [0, -1, True, False, float("nan"), float("inf"), "60"])
def test_timeout_decorator_rejects_invalid_values(invalid_seconds) -> None:
    with pytest.raises(ValueError, match="positive finite number"):
        sdk.timeout(invalid_seconds)


def test_requires_privilege_sets_sdk_metadata() -> None:
    @sdk.requires_privilege(" domain_admin ")
    class DemoModule(sdk.BaseModule):
        async def run(self, **kwargs):
            return [], {"ok": True}

    assert DemoModule.REQUIRED_PRIVILEGE == "domain_admin"
    assert DemoModule.metadata()["required_privilege"] == "domain_admin"


@pytest.mark.parametrize("invalid_level", ["", "   ", None, 123])
def test_requires_privilege_rejects_invalid_values(invalid_level) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        sdk.requires_privilege(invalid_level)


def test_module_metadata_rejects_invalid_sdk_metadata() -> None:
    with pytest.raises(ValueError, match="category"):
        sdk.module_metadata(
            module_id="demo.invalid",
            name="Demo Invalid",
            category=" ",
            description="Bad category",
        )

    with pytest.raises(ValueError, match="opsec"):
        sdk.module_metadata(
            module_id="demo.invalid",
            name="Demo Invalid",
            category="network",
            description="Bad opsec",
            opsec="not-a-level",
        )

    with pytest.raises(ValueError, match="requires"):
        sdk.module_metadata(
            module_id="demo.invalid",
            name="Demo Invalid",
            category="network",
            description="Bad requires",
            requires=("target",),
        )


@pytest.mark.asyncio
async def test_runtime_uses_module_timeout_contract(monkeypatch) -> None:
    @sdk.module_metadata(
        module_id="demo.timeout",
        name="Demo Timeout",
        category="network",
        description="Runtime timeout contract test",
    )
    @sdk.timeout(7)
    class DemoModule(sdk.BaseModule):
        async def execute(self, ctx: sdk.ExecutionContext) -> sdk.ModuleResult:
            return sdk.ModuleResult(status="success", module_id=self.MODULE_ID)

        async def run(self, **kwargs):
            return [], {"ok": True}

    observed_timeouts: list[int | float] = []
    original_wait_for = asyncio.wait_for

    async def capture_wait_for(awaitable, timeout=None):
        observed_timeouts.append(timeout)
        return await original_wait_for(awaitable, timeout)

    class Registry:
        def __contains__(self, module_id):
            return module_id == "demo.timeout"

        def get(self, module_id):
            assert module_id == "demo.timeout"
            return DemoModule

    monkeypatch.setattr(asyncio, "wait_for", capture_wait_for)
    engine = AresEngine()
    engine._registry = Registry()
    helper = sdk.ModuleTestHelper(DemoModule, scope_cidrs=["127.0.0.1/32"])

    result = await engine.run_module(
        "demo.timeout",
        campaign=helper.campaign,
        params={"target": "127.0.0.1"},
        timeout_seconds=120,
        actor_role="team_lead",
    )

    assert result.status.value == "done"
    assert result.error is None
    assert 7 in observed_timeouts


@pytest.mark.asyncio
async def test_module_test_helper_available_from_public_sdk() -> None:
    @sdk.module_metadata(
        module_id="demo.helper",
        name="Demo Helper",
        category="network",
        description="SDK helper smoke test",
    )
    class DemoModule(sdk.BaseModule):
        async def execute(self, ctx: sdk.ExecutionContext) -> sdk.ModuleResult:
            return sdk.ModuleResult(
                status="dry_run" if ctx.dry_run else "success",
                module_id=self.MODULE_ID,
                raw={"target": ctx.target},
            )

        async def run(self, **kwargs):
            return [], {"ok": True}

    helper = sdk.ModuleTestHelper(DemoModule, scope_cidrs=["127.0.0.1/32"])
    result = await helper.run_full(target="127.0.0.1", dry_run=True)

    assert result.status == "dry_run"
    assert result.module_id == "demo.helper"
    assert result.raw == {"target": "127.0.0.1"}
