"""
Target Environment Fingerprinting — recon.fingerprint
MITRE: T1082 — System Information Discovery
       T1518.001 — Security Software Discovery

Thin wrapper around ares/fingerprint/engine.py (650 lines, fully implemented).
Runs passive-first OS/domain/EDR fingerprinting BEFORE attack modules.

Key outputs:
  - OSType, DomainRole, EDRVendor (CrowdStrike, SentinelOne, Defender ATP, ...)
  - detection_risk: low | medium | high | critical
  - recommended_profile: stealth | normal | aggressive
  - Stored to campaign._artifact_store for GoalEngine + AdaptiveOpsecEngine

OPSEC: LOW — passive techniques first (banner grab, DNS PTR, NTLM challenge).
       No authentication required. No exploit sent to target.
"""
from __future__ import annotations

from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.recon.fingerprint")

# EDR vendors that trigger automatic stealth recommendation
_HIGH_RISK_EDR = {"crowdstrike", "sentinelone", "defender_atp"}


class FingerprintModule(BaseModule):
    """
    recon.fingerprint — Passive-first OS, domain role, and EDR/AV detection before any attack module. Detects CrowdStrik

    OPSEC: LOW
    MITRE: "T1082", "T1518.001"
    OUTPUTS:  "fingerprint_result"
    """
    MODULE_ID          = "recon.fingerprint"
    MODULE_NAME        = "Target Environment Fingerprinting"
    MODULE_CATEGORY    = "recon"
    MODULE_DESCRIPTION = (
        "Passive-first OS, domain role, and EDR/AV detection before any attack module. "
        "Detects CrowdStrike, SentinelOne, Defender ATP, Carbon Black, and 5 more. "
        "Feeds AdaptiveOpsecEngine to auto-disable noisy modules when advanced EDR found."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["fingerprint_result"]
    MITRE_TECHNIQUES   = ["T1082", "T1518.001"]

    async def validate(self, ctx: "Any") -> None:
        """Enforce target is set."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "recon.fingerprint requires 'target' — IP or hostname to fingerprint.",
                module_id=self.MODULE_ID, field="target",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        target   = getattr(ctx, "target", "") or ctx.params.get("target", "")
        username = ctx.params.get("username", "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        secret   = ctx.params.get("password", "") or ctx.params.get("secret", "")
        timeout  = float(ctx.params.get("timeout", 5.0))

        findings, raw = await self.run(
            target=target, username=username, domain=domain,
            secret=secret, timeout=timeout,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("recon.fingerprint")
    async def run(self, target: str, username: str = "", domain: str = "",
                  secret: str = "", timeout: float = 5.0, **kwargs: Any):
        from ares.fingerprint.engine import EnvironmentFingerprinter, EDRVendor

        target = sanitize_hostname(target)
        logger.info("fingerprint_start", target=target)
        audit("recon_fingerprint", actor="operator", technique="T1082",
              source="operator", target=target)

        await self.before_request(target, "default")

        try:
            import asyncio
            fingerprinter = EnvironmentFingerprinter(timeout_s=timeout)
            result = await asyncio.wait_for(
                fingerprinter.fingerprint(
                    host=target,
                    username=username,
                    domain=domain,
                    secret=secret,
                ),
                timeout=timeout * 4 + 10,   # overall cap
            )
        except Exception as exc:
            raise self._classify_error(exc) from exc

        # Store result in campaign artifact store for other modules
        artifact_store = getattr(getattr(self, "campaign", None), "_artifact_store", None)
        if artifact_store and hasattr(artifact_store, "store_fingerprint"):
            try:
                artifact_store.store_fingerprint(result)
            except Exception:
                pass

        raw = result.to_dict()
        raw["target"] = target

        logger.info("fingerprint_done",
                    target=target,
                    os=result.os_type.value,
                    role=result.domain_role.value,
                    edr=[e.value for e in result.edr_vendors],
                    risk=result.detection_risk)

        # Finding: EDR detected — warn operator before attack modules run
        if result.edr_vendors:
            edr_names  = [e.value for e in result.edr_vendors]
            is_high    = any(e.value in _HIGH_RISK_EDR for e in result.edr_vendors)
            sev        = Severity.HIGH if is_high else Severity.MEDIUM
            self.finding(
                title       = f"EDR/AV Detected on {target}: {', '.join(edr_names)}",
                description = (
                    f"Security software detected on {target}: {', '.join(edr_names)}. "
                    + (
                        "Advanced EDR (CrowdStrike/SentinelOne/Defender ATP) detected — "
                        "STEALTH noise profile strongly recommended. "
                        "HIGH_NOISE modules (dcsync, kerberoast burst, psexec) "
                        "will generate immediate alerts."
                        if is_high else
                        f"EDR active — use NORMAL or STEALTH profile."
                    )
                ),
                severity    = sev,
                mitre_technique = "T1518.001",
                mitre_tactic    = "Discovery",
                evidence = {
                    "edr_vendors":           edr_names,
                    "detection_risk":        result.detection_risk,
                    "recommended_profile":   result.recommended_profile,
                    "stealth_required":      result.stealth_required,
                    "os":                    result.os_type.value,
                    "domain_role":           result.domain_role.value,
                    "methods_used":          result.methods_used,
                },
                remediation = (
                    "Operator action: switch campaign to --noise stealth before "
                    "running credential or lateral modules."
                ),
                host = target, confidence = 0.85,
            )

        # Finding: domain controller identified
        if result.is_dc:
            self.finding(
                title       = f"Domain Controller Identified: {target}",
                description = (
                    f"{target} identified as a Domain Controller "
                    f"(functional level: {result.dc_functional_level or 'unknown'}). "
                    "Priority target for DCSync, Kerberoasting, and ADCS exploitation."
                ),
                severity    = Severity.INFO,
                mitre_technique = "T1082",
                mitre_tactic    = "Discovery",
                evidence = {
                    "hostname":              result.hostname,
                    "domain":                result.domain,
                    "dc_functional_level":   result.dc_functional_level,
                    "os":                    result.os_type.value,
                },
                host = target, confidence = 0.95,
            )

        raw["fingerprint_result"] = {k: v for k, v in raw.items()}  # OUTPUTS key — shallow copy to avoid circular ref
        return self._findings[:], raw
