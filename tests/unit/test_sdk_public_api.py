from __future__ import annotations

import pytest

import ares.sdk as sdk
from ares.core.context import ExecutionContext
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
