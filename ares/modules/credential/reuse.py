"""
ARES Credential Module — Credential Reuse (T1078 / T1550.002)

Wraps ReuseEngine as a proper BaseModule so it can be registered in
the plugin loader and called as ``credential.reuse`` in chains/plans.

MITRE ATT&CK:
  T1078   — Valid Accounts
  T1550.002 — Pass the Hash
"""
from __future__ import annotations

from typing import Any

from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.logger import get_logger, audit
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.reuse")


class CredentialReuseModule(BaseModule):
    """
    Try each captured credential against one or more targets.

    Delegates to ReuseEngine for actual protocol-level spray logic.
    Returns one Finding per successful authentication.
    """

    MODULE_ID          = "credential.reuse"
    MODULE_NAME        = "Credential Reuse"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = "Systematically test captured credentials against live services via SMB, WinRM, SSH, LDAP and RDP"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    REQUIRES           = ["target"]
    OUTPUTS            = ["valid_credentials", "owned_hosts"]
    MITRE_TECHNIQUES   = ["T1078", "T1550.002"]

    OPSEC_LEVEL        = OpsecLevel.MEDIUM

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "credential.reuse requires 'target' — IP or hostname to test credentials against.",
                module_id=self.MODULE_ID, field="target",
            )
        vault = getattr(ctx, "vault", None)
        if not vault or not getattr(vault, "_store", None):
            raise ModuleValidationError(
                "credential.reuse requires credentials in vault — "
                "run ad.kerberoast/dcsync/pass_the_hash first.",
                module_id=self.MODULE_ID, field="vault",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        # Pass vault from ctx — it lives on ctx, NOT in ctx.params
        params = dict(ctx.params)
        params.pop("target", None)
        params.pop("vault", None)
        findings, raw = await self.run(
            **params,
            vault=getattr(ctx, "vault", None),
            target=getattr(ctx, "target", ctx.params.get("target", "")),
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.reuse")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        ctx     = kwargs.get("ctx") or kwargs
        target  = ctx.get("target", "")
        dry_run = ctx.get("dry_run", False)
        vault   = ctx.get("vault")

        if not target:
            return [], {"error": "no_target"}

        logger.info("credential_reuse", target=target, dry_run=dry_run)
        audit("credential_reuse", actor="operator", source="operator",
              target=target, technique="T1078")

        if dry_run:
            return [], {
                "dry_run": True,
                "valid_credentials": [],
                "owned_hosts": [],
                "note": "dry-run — no credentials sprayed",
            }

        if vault is None:
            return [], {"error": "no_vault_provided"}

        try:
            from ares.credential.reuse import ReuseEngine, ReuseProtocol
            engine = ReuseEngine(vault=vault)
            await self.before_request(target, "default")
            results = await engine.spray(target_hosts=[target])
            valid: list[str] = []

            for attempt in results:
                if attempt.success:
                    valid.append(attempt.cred_id)
                    self.finding(
                        title       = f"Valid credential reused on {target}",
                        description = (
                            f"Credential {attempt.cred_id[:8]}… authenticated via "
                            f"{attempt.protocol} on {target}"
                        ),
                        severity    = Severity.CRITICAL,
                        confidence  = 0.95,
                        host        = target,
                        mitre_technique = "T1078",
                        mitre_tactic    = "Lateral Movement",
                        remediation = "Rotate all compromised credentials immediately.",
                    )

            return self._findings[:], {
                "valid_credentials": valid,
                "owned_hosts": [target] if valid else [],
                "total_attempts": len(results),
            }

        except Exception as exc:
            raise self._classify_error(exc) from exc
