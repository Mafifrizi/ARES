"""Composable Execution Interceptor Pipeline for ARES SDK.

Provides pre-execution, post-execution, and error handling hooks to guarantee
safety invariants (Scope, Rate Limiting, Jitter, Secret Sanitization, Provenance)
without requiring manual boilerplate in attack modules.
"""
from __future__ import annotations

import abc
from typing import Any, Protocol, runtime_checkable

from ares.core.context import ExecutionContext
from ares.modules.base import ModuleResult


@runtime_checkable
class ExecutionInterceptor(Protocol):
    """Protocol for modular execution interceptors."""

    async def pre_execute(self, module: Any, ctx: ExecutionContext) -> None:
        """Run before module.execute(). Raises exception to abort execution."""
        ...

    async def post_execute(
        self, module: Any, ctx: ExecutionContext, result: ModuleResult
    ) -> ModuleResult:
        """Run after module.execute(). Can inspect or enrich the ModuleResult."""
        ...

    async def on_error(
        self, module: Any, ctx: ExecutionContext, error: Exception
    ) -> None:
        """Run if module.execute() or any interceptor raises an unhandled error."""
        ...


class BaseExecutionInterceptor(abc.ABC):
    """Convenience base class providing default no-op lifecycle hooks."""

    async def pre_execute(self, module: Any, ctx: ExecutionContext) -> None:
        pass

    async def post_execute(
        self, module: Any, ctx: ExecutionContext, result: ModuleResult
    ) -> ModuleResult:
        return result

    async def on_error(
        self, module: Any, ctx: ExecutionContext, error: Exception
    ) -> None:
        pass


class ExecutionPipeline:
    """Orchestrates an ordered chain of ExecutionInterceptors around module execution."""

    def __init__(self, interceptors: list[ExecutionInterceptor] | None = None) -> None:
        self._interceptors: list[ExecutionInterceptor] = list(interceptors or [])

    @property
    def interceptors(self) -> list[ExecutionInterceptor]:
        return list(self._interceptors)

    def add_interceptor(self, interceptor: ExecutionInterceptor) -> None:
        """Append an interceptor to the end of the pipeline."""
        self._interceptors.append(interceptor)

    async def run(
        self,
        module: Any,
        ctx: ExecutionContext,
        execute_fn: Any,
    ) -> ModuleResult:
        """Execute the module wrapped with the full interceptor pipeline."""
        executed_interceptors: list[ExecutionInterceptor] = []

        try:
            # 1. Run pre-execution hooks in forward order
            for interceptor in self._interceptors:
                await interceptor.pre_execute(module, ctx)
                executed_interceptors.append(interceptor)

            # 2. Execute the primary module function
            result = await execute_fn(ctx)
            if not isinstance(result, ModuleResult):
                raise TypeError(f"Module execution must return ModuleResult, got {type(result).__name__}")

            # 3. Run post-execution hooks in reverse order (onion pattern)
            for interceptor in reversed(self._interceptors):
                result = await interceptor.post_execute(module, ctx, result)

            return result

        except Exception as exc:
            # 4. Notify all executed interceptors of the failure in reverse order
            for interceptor in reversed(executed_interceptors):
                try:
                    await interceptor.on_error(module, ctx, exc)
                except Exception:
                    pass  # Preserve the root cause exception
            raise
