"""Declarative Module Contract System for ARES SDK.

Allows authors to declare permissions, circuit breakers, idempotency, and security
invariants in a clean, unified Python decorator (@module_contract).
"""
from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from ares.core.context import ExecutionContext
from ares.modules.base import ModuleResult
from ares.sdk.pipeline.base import ExecutionPipeline
from ares.sdk.pipeline.interceptors import (
    AdaptiveNoiseInterceptor,
    AuditProvenanceInterceptor,
    ScopeEnforcementInterceptor,
    SecretSanitizationInterceptor,
)
from ares.sdk.resilience.circuit_breaker import CircuitBreaker, CircuitBreakerTripped
from ares.sdk.security.permissions import CapabilitySandbox, SecurityPermission

M = TypeVar("M")


def module_contract(
    *,
    permissions: list[SecurityPermission] | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    params_model: Any = None,
    idempotency: str = "idempotent",
    compensation: str = "not_applicable",
    interceptors: list[Any] | None = None,
) -> Callable[[type[M]], type[M]]:
    """Class decorator for declaring enterprise security and governance contracts."""

    def decorator(cls: type[M]) -> type[M]:
        declared_perms = list(permissions or [])
        cls.PERMISSIONS = declared_perms  # type: ignore[attr-defined]
        cls.CIRCUIT_BREAKER = circuit_breaker  # type: ignore[attr-defined]
        cls.IDEMPOTENCY = idempotency  # type: ignore[attr-defined]
        cls.COMPENSATION = compensation  # type: ignore[attr-defined]

        if params_model is not None:
            cls.PARAMS_MODEL = params_model  # type: ignore[attr-defined]

        # Assemble the default execution pipeline
        pipeline = ExecutionPipeline()
        pipeline.add_interceptor(ScopeEnforcementInterceptor())
        pipeline.add_interceptor(AdaptiveNoiseInterceptor())
        if interceptors:
            for ic in interceptors:
                pipeline.add_interceptor(ic)
        pipeline.add_interceptor(SecretSanitizationInterceptor())
        pipeline.add_interceptor(AuditProvenanceInterceptor())
        cls.EXECUTION_PIPELINE = pipeline  # type: ignore[attr-defined]

        # Wrap execute() to automatically enforce permissions, circuit breaker, and pipeline
        original_execute = getattr(cls, "execute", None)
        if original_execute is not None:
            @functools.wraps(original_execute)
            async def wrapped_execute(self: Any, ctx: ExecutionContext) -> ModuleResult:
                # 1. Enforce Circuit Breaker (if configured)
                cb: CircuitBreaker | None = getattr(self, "CIRCUIT_BREAKER", None)
                if cb is not None:
                    cb.allow_execution()

                # 2. Enforce Capability Sandbox against parameters
                perms: list[SecurityPermission] = getattr(self, "PERMISSIONS", [])
                if perms:
                    raw_params = ctx.params.model_dump() if hasattr(ctx.params, "model_dump") else (ctx.params or {})
                    CapabilitySandbox.verify(perms, raw_params, ctx)

                # 3. Execute through the Interceptor Pipeline
                pipe: ExecutionPipeline = getattr(self, "EXECUTION_PIPELINE", pipeline)

                async def _inner_exec(c: ExecutionContext) -> ModuleResult:
                    try:
                        res = await original_execute(self, c)
                        if cb is not None:
                            cb.record_success()
                        return res
                    except Exception as exc:
                        if cb is not None:
                            cb.record_failure(exc)
                        raise

                return await pipe.run(self, ctx, _inner_exec)

            cls.execute = wrapped_execute  # type: ignore[assignment]

        return cls

    return decorator
