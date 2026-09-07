"""Next-Gen ARES Module Authoring Contracts (v2 Sovereign Tier).

Provides:
- BaseModule[P, R]: Type-safe generic base class for class-based modules.
- ares_module: Modern declarative decorator for functional and class modules.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Generic, TypeVar

from pydantic import BaseModel

from ares.core.campaign import Finding
from ares.core.context import ExecutionContext
from ares.core.errors import ModuleValidationError
from ares.modules.base import (
    BaseModule as _CoreBaseModule,
    ModuleResult,
    OpsecLevel,
    validate_module_class,
)
from ares.sdk.params import validate_params

P = TypeVar("P", bound=Any)
R = TypeVar("R", bound=Any)


BaseModule = _CoreBaseModule


def ares_module(
    id: str,
    name: str,
    category: str,
    description: str = "",
    author: str = "Community",
    opsec: OpsecLevel = OpsecLevel.LOW,
    requires: list[str] | None = None,
    outputs: list[str] | None = None,
    mitre: list[str] | str | None = None,
    params_model: type[BaseModel] | None = None,
    capabilities: list[str] | None = None,
    timeout_seconds: int | float | None = None,
) -> Callable[[Any], type[BaseModule]]:
    """Declarative decorator for modern ARES module definitions.

    Supports both functional modules and class-based modules:

    Functional usage:
        @ares_module(
            id="ad.fast_check",
            name="Fast AD Check",
            category="ad",
            opsec=OpsecLevel.LOW,
            mitre="T1087.002",
            params_model=CheckParams,
        )
        async def fast_check(ctx: ExecutionContext[CheckParams]) -> ModuleResult:
            await ctx.emit_finding("AD User Found", Severity.MEDIUM)
            return ModuleResult(status="success", module_id="ad.fast_check")

    Class usage:
        @ares_module(
            id="ad.custom_attack",
            name="Custom Attack",
            category="ad",
        )
        class CustomAttack(BaseModule):
            ...
    """
    if not isinstance(category, str) or not category.strip():
        raise ValueError("ares_module category must be a non-empty string")
    if not isinstance(opsec, OpsecLevel) and str(opsec) not in {level.value for level in OpsecLevel}:
        raise ValueError("ares_module opsec must be an OpsecLevel or valid opsec level string")

    mitre_list: list[str] = [mitre] if isinstance(mitre, str) else (mitre or [])

    def decorator(target: Any) -> type[BaseModule]:
        # Case 1: Applied to a function
        if inspect.iscoroutinefunction(target) or inspect.isfunction(target):
            func = target

            class _DecoratedFunctionalModule(BaseModule):
                MODULE_ID = id
                MODULE_NAME = name
                MODULE_CATEGORY = category
                MODULE_DESCRIPTION = description
                MODULE_AUTHOR = author
                OPSEC_LEVEL = opsec
                REQUIRES = requires or []
                OUTPUTS = outputs or []
                MITRE_TECHNIQUES = mitre_list
                CAPABILITIES = capabilities or []
                MODULE_TIMEOUT_SECONDS = timeout_seconds
                PARAMS_MODEL = params_model

                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    super().__init__(*args, **kwargs)
                    self._fn = func

                async def execute(self, ctx: ExecutionContext) -> ModuleResult:
                    result = await self._fn(ctx)
                    if isinstance(result, ModuleResult):
                        if not result.module_id:
                            result.module_id = self.MODULE_ID
                        return result
                    if isinstance(result, tuple) and len(result) == 2:
                        findings, raw = result
                        return ModuleResult(
                            status="success" if findings or raw else "partial",
                            findings=findings or [],
                            raw=raw or {},
                            module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""),
                        )
                    # If function returned None or something else, collect findings from ctx
                    findings = getattr(ctx, "findings", [])
                    return ModuleResult(
                        status="success" if findings else "partial",
                        findings=findings,
                        module_id=self.MODULE_ID,
                        execution_id=getattr(ctx, "execution_id", ""),
                    )

                async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
                    ctx = ExecutionContext.for_test(
                        target=kwargs.get("target", "10.0.0.1"),
                        module_id=self.MODULE_ID,
                        params=kwargs,
                    )
                    res = await self.execute(ctx)
                    return res.findings, res.raw

            _DecoratedFunctionalModule.__name__ = func.__name__
            _DecoratedFunctionalModule.__doc__ = description or func.__doc__
            errors = validate_module_class(_DecoratedFunctionalModule)
            if errors:
                raise ValueError(f"Module functional definition '{func.__name__}' invalid: {errors}")
            return _DecoratedFunctionalModule

        # Case 2: Applied to a class
        cls = target
        cls.MODULE_ID = id
        cls.MODULE_NAME = name
        cls.MODULE_CATEGORY = category
        cls.MODULE_DESCRIPTION = description
        cls.MODULE_AUTHOR = author
        cls.OPSEC_LEVEL = opsec
        cls.REQUIRES = requires or []
        cls.OUTPUTS = outputs or []
        cls.MITRE_TECHNIQUES = mitre_list
        if capabilities is not None:
            cls.CAPABILITIES = capabilities
        if timeout_seconds is not None:
            cls.MODULE_TIMEOUT_SECONDS = timeout_seconds
            cls.DEFAULT_TIMEOUT_S = timeout_seconds
        if params_model is not None:
            cls.PARAMS_MODEL = params_model

        errors = validate_module_class(cls)
        if errors:
            raise ValueError(f"Module class {cls.__name__!r} has validation errors: {errors}")
        return cls

    return decorator


__all__ = [
    "BaseModule",
    "ModuleResult",
    "OpsecLevel",
    "ares_module",
    "validate_module_class",
]
