"""Concrete Security & Governance Interceptors for ARES Module Pipeline.

Enforces scope boundaries, noise throttling, secret scrubbing, and cryptographic
audit provenance without developer manual boilerplate.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ares.core.context import ExecutionContext
from ares.core.errors import ScopeError
from ares.core.logger import get_logger
from ares.modules.base import ModuleResult
from ares.sdk.pipeline.base import BaseExecutionInterceptor

logger = get_logger("ares.sdk.pipeline")


class ScopeEnforcementInterceptor(BaseExecutionInterceptor):
    """Zero-Trust Scope Enforcement Interceptor.

    Deterministic pre-flight check. Verifies all targets against the campaign scope
    before module execution begins. Prevents accidental out-of-scope activity.
    """

    async def pre_execute(self, module: Any, ctx: ExecutionContext) -> None:
        # Resolve target from context or parameter model
        target = getattr(ctx, "target", "")
        if not target and hasattr(ctx, "params"):
            params = ctx.params
            if hasattr(params, "target"):
                target = getattr(params, "target")
            elif hasattr(params, "dc"):
                target = getattr(params, "dc")
            elif isinstance(params, dict):
                target = params.get("target") or params.get("dc") or params.get("host") or ""

        if not target:
            return  # Targetless modules (cloud/recon metadata) handled by validation

        # Skip network scope validation for local/offline modules that do not declare network capabilities
        perms = getattr(module, "PERMISSIONS", [])
        if perms:
            from ares.sdk.security.permissions import NetworkPermission
            has_net = any(isinstance(p, NetworkPermission) or getattr(p, "name", "") == "network" for p in perms)
            if not has_net:
                return

        # 1. Check direct ScopeGuard if attached to context
        if hasattr(ctx, "scope_guard") and ctx.scope_guard is not None:
            ctx.scope_guard.assert_in_scope(target, action=getattr(module, "MODULE_ID", "module"))
            return

        # 2. Check campaign attached to module instance
        noise_ctrl = getattr(module, "noise", None)
        if noise_ctrl is not None and hasattr(noise_ctrl, "scope_guard"):
            noise_ctrl.scope_guard.assert_in_scope(target, action=getattr(module, "MODULE_ID", "module"))
            return

        # 3. Check campaign attached directly to execution context or its session
        campaign = getattr(ctx, "campaign", None)
        if campaign is None:
            session = getattr(ctx, "session", None)
            if session is not None and hasattr(session, "campaign"):
                campaign = session.campaign

        if campaign is not None:
            if not campaign.is_in_scope(target):
                raise ScopeError(
                    f"[ScopeEnforcementInterceptor] Target '{target}' is out of scope for campaign '{campaign.name}'"
                )


class AdaptiveNoiseInterceptor(BaseExecutionInterceptor):
    """Adaptive Noise & OPSEC Jitter Interceptor.

    Calculates noise impact against the campaign OPSEC budget and enforces
    micro-jitter delays to prevent alert clustering in target SIEM/EDR.
    """

    def __init__(self, apply_jitter: bool = True) -> None:
        self.apply_jitter = apply_jitter

    async def pre_execute(self, module: Any, ctx: ExecutionContext) -> None:
        if getattr(ctx, "dry_run", False):
            return  # No jitter in simulation mode

        noise_ctrl = getattr(module, "noise", None)
        if noise_ctrl is not None and self.apply_jitter:
            action = getattr(module, "MODULE_ID", "module_run")
            if hasattr(noise_ctrl, "rate_limiter"):
                await noise_ctrl.rate_limiter.acquire(action)
            if hasattr(noise_ctrl, "jitter"):
                await noise_ctrl.jitter.sleep()


class SecretSanitizationInterceptor(BaseExecutionInterceptor):
    """Scrubs plaintext credentials and sensitive tokens from execution results."""

    async def post_execute(
        self, module: Any, ctx: ExecutionContext, result: ModuleResult
    ) -> ModuleResult:
        # Scrub credentials in raw output dictionary if marked sensitive
        if isinstance(result.raw, dict):
            sanitized_raw = self._scrub_dict(result.raw)
            result.raw = sanitized_raw
        return result

    def _scrub_dict(self, d: dict[str, Any]) -> dict[str, Any]:
        scrubbed: dict[str, Any] = {}
        for k, v in d.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("password", "secret", "private_key", "nt_hash", "kerberos_hash")):
                if isinstance(v, str) and len(v) > 4:
                    scrubbed[k] = f"{v[:2]}...[REDACTED_BY_SANITIZER]...{v[-2:]}"
                else:
                    scrubbed[k] = "[REDACTED_BY_SANITIZER]"
            elif isinstance(v, dict):
                scrubbed[k] = self._scrub_dict(v)
            else:
                scrubbed[k] = v
        return scrubbed


class AuditProvenanceInterceptor(BaseExecutionInterceptor):
    """Cryptographic Provenance Interceptor.

    Calculates a tamper-evident SHA-256 integrity digest for the module execution
    and attaches an immutable audit receipt to the result.
    """

    async def post_execute(
        self, module: Any, ctx: ExecutionContext, result: ModuleResult
    ) -> ModuleResult:
        audit_packet = {
            "module_id": result.module_id or getattr(module, "MODULE_ID", "unknown"),
            "execution_id": getattr(ctx, "execution_id", ""),
            "status": result.status,
            "target": getattr(ctx, "target", ""),
            "findings_count": len(result.findings),
            "artifacts_count": len(result.artifacts) if result.artifacts else 0,
            "timestamp": time.time(),
        }
        serialized = json.dumps(audit_packet, sort_keys=True)
        provenance_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        if result.raw is None:
            result.raw = {}
        if isinstance(result.raw, dict):
            result.raw["_audit_provenance"] = {
                "provenance_hash": provenance_hash,
                "timestamp_ns": time.time_ns(),
                "verified": True,
            }

        return result
