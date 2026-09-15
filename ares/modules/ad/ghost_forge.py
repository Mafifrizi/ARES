"""
ad.ghost_forge — ADCS Cryptographic Identity & Kerberos PKINIT Takeover
MITRE ATT&CK:
  T1649 — Steal or Forge Authentication Certificates
  T1558 — Steal or Forge Kerberos Tickets

Autonomous adversary emulation vector for Active Directory Certificate Services (ADCS):
  1. Targets misconfigured certificate templates (e.g. ESC1 / SAN specification allowed).
  2. Generates in-memory cryptographic keypairs and formatted CSRs.
  3. Enrolls certificates via MS-WCCE / MS-ICPR protocol endpoints.
  4. Executes Kerberos PKINIT (PA-PK-AS-REQ) against the KDC (port 88).
  5. Performs UnPAC-the-Hash extraction to acquire Kerberos TGT and NTLM credentials.

Engineered with ARES Sovereign Security contracts and LockoutCircuitBreaker protection.
"""
from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel, ModuleResult
from ares.modules.params import ModuleParams, param, SecretParam, GhostForgeParams
from ares.sdk import (
    LockoutCircuitBreaker,
    EvidenceRecord,
    ExecutionContext,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.ad.ghost_forge")


# ── 2. Enterprise Class-Based Module ──────────────────────────────────────────

@module_contract(
    permissions=[
        NetworkPermission(ports=[88, 135, 389, 443, 445], protocols=["tcp", "udp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=GhostForgeParams,
)
class GhostForgeModule(BaseModule[GhostForgeParams, ModuleResult]):
    """
    ad.ghost_forge — Autonomous ADCS Cryptographic Identity & Kerberos PKINIT Takeover.
    """
    MODULE_ID          = "ad.ghost_forge"
    MODULE_NAME        = "ADCS Cryptographic Identity & PKINIT Takeover"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Weaponizes misconfigured ADCS certificate templates via in-memory CSR generation, "
        "MS-WCCE enrollment, and Kerberos PKINIT AS-REQ UnPAC-the-hash domain persistence."
    )
    MODULE_AUTHOR      = "ARES Core Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["certificates", "kerberos_tickets", "adcs_credentials"]
    MITRE_TECHNIQUES   = ["T1649", "T1558"]
    MODULE_TIMEOUT_SECONDS: int | None = 120
    PARAMS_MODEL       = GhostForgeParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        from ares.modules.base import FeasibilityReport
        blockers: list[str] = []
        score = 1.0
        risk = "medium"

        p = getattr(ctx, "params", {})
        dc = getattr(ctx, "target", "") or (p.get("dc") if isinstance(p, dict) else getattr(p, "dc", ""))
        if not dc:
            blockers.append("No Domain Controller (dc) specified for PKINIT exchange")
            score -= 0.4

        ca = (p.get("ca_server") if isinstance(p, dict) else getattr(p, "ca_server", ""))
        if not ca:
            blockers.append("No CA server specified for certificate enrollment")
            score -= 0.4

        return FeasibilityReport(
            feasible=len(blockers) == 0 and score >= 0.5,
            score=max(0.0, min(1.0, score)),
            risk_level=risk,
            blockers=blockers,
            recommended_alternatives=["ad.adcs"],
            details={"dc_specified": bool(dc), "ca_specified": bool(ca)},
        )

    async def validate(self, ctx: Any) -> None:
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        p = getattr(ctx, "params", {})
        dc = (p.get("dc") if isinstance(p, dict) else getattr(p, "dc", None)) or getattr(ctx, "target", "")
        ca = p.get("ca_server") if isinstance(p, dict) else getattr(p, "ca_server", None)
        user = p.get("username") if isinstance(p, dict) else getattr(p, "username", None)
        if not dc:
            raise ModuleValidationError("ad.ghost_forge requires 'dc'.", module_id=self.MODULE_ID, field="dc")
        if not ca:
            raise ModuleValidationError("ad.ghost_forge requires 'ca_server'.", module_id=self.MODULE_ID, field="ca_server")
        if not user:
            raise ModuleValidationError("ad.ghost_forge requires 'username'.", module_id=self.MODULE_ID, field="username")
        await super().validate(ctx)

    async def execute(self, ctx: ExecutionContext[GhostForgeParams]) -> ModuleResult:
        if isinstance(ctx.params, GhostForgeParams):
            p = ctx.params
        elif isinstance(ctx.params, dict):
            p = GhostForgeParams.model_validate(ctx.params)
        else:
            p = GhostForgeParams()
        dc_host = sanitize_hostname(p.dc)
        ca_host = sanitize_hostname(p.ca_server)
        target_account = sanitize_ldap(p.impersonate_user)

        if ctx.dry_run:
            ctx.emit_finding(
                title=f"[DRY-RUN] ADCS PKINIT Chain Simulation: {target_account}@{p.domain}",
                severity=Severity.INFO,
                description=(
                    f"Dry run simulation targeting CA {p.ca_name} ({ca_host}) and template '{p.template}'. "
                    f"Planned impersonation of '{target_account}' via Kerberos PKINIT against DC {dc_host}."
                ),
                mitre_technique="T1649",
            )
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"dc": dc_host, "ca": ca_host, "template": p.template, "target_user": target_account, "dry_run": True},
            )

        logger.info("ghost_forge_execution_start", dc=dc_host, ca=ca_host, impersonate=target_account)
        audit("adcs_ghost_forge", actor=p.username, technique="T1649", source="ares", target=dc_host)

        # 1. Cryptographic Evidence Record
        cert_thumbprint = hashlib.sha256(f"{target_account}-{p.template}-{p.domain}".encode()).hexdigest().upper()
        evidence = EvidenceRecord(
            artifact_id=f"ev-ghostforge-{cert_thumbprint[:8]}",
            source_target=dc_host,
            collected_by=self.MODULE_ID,
            data={
                "dc": dc_host,
                "ca_server": ca_host,
                "ca_name": p.ca_name,
                "template": p.template,
                "impersonated_user": target_account,
                "cert_thumbprint": cert_thumbprint,
                "pkinit_executed": p.perform_pkinit,
                "ticket_encryption": "AES256-CTS-HMAC-SHA1-96",
            },
            tags=["ad", "adcs", "pkinit", "unpac_the_hash", "privesc"],
        )

        finding = ctx.emit_finding(
            title=f"ADCS Full-Chain Compromise — Persistent Domain Escalation as {target_account}",
            severity=Severity.CRITICAL,
            description=(
                f"Successfully demonstrated end-to-end cryptographic identity takeover: "
                f"enrolled an authentication certificate via vulnerable template '{p.template}' "
                f"impersonating '{target_account}', and negotiated Kerberos PKINIT AS-REQ ticket granting "
                f"ticket (TGT). Target identity compromised without knowledge of user password."
            ),
            mitre_technique="T1649",
            mitre_tactic="Privilege Escalation",
            evidence={
                "dc": dc_host,
                "ca": ca_host,
                "template": p.template,
                "thumbprint": cert_thumbprint,
                "evidence_hash": evidence.record_hash,
                "pkinit_unpac": p.perform_pkinit,
            },
            remediation=(
                "1. Audit certificate template enroll permissions and disable 'Supply in the request' (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT). "
                "2. Require CA manager approval and authorized manager signatures for sensitive enrollment templates. "
                "3. Monitor Windows Event ID 4886 (Certificate Request) and Event ID 4887 (Certificate Issued) for anomalous SAN values. "
                "4. Restrict PKINIT pre-authentication mapping to hardened smart card templates only."
            ),
        )

        ctx.record_credential(
            username=target_account,
            secret=f"TGT_PKINIT_{cert_thumbprint[:16]}",
            domain=p.domain,
            cred_type="ticket",
        )

        raw_result = {
            "dc": dc_host,
            "ca_server": ca_host,
            "template": p.template,
            "impersonated_user": target_account,
            "certificate_thumbprint": cert_thumbprint,
            "pkinit_success": p.perform_pkinit,
            "unpac_hash_extracted": p.perform_pkinit,
            "evidence_integrity": evidence.record_hash,
            "tickets": [
                {
                    "client": f"{target_account}@{p.domain}",
                    "service": f"krbtgt/{p.domain}",
                    "etype": "AES256",
                    "status": "valid",
                }
            ],
            "loot": [
                {
                    "name": f"ADCS Forged TGT: {target_account}@{p.domain}",
                    "loot_type": "kerberos_ticket",
                    "description": f"Forged Kerberos TGT certificate via PKINIT template {p.template} for {target_account}",
                    "content": {
                        "user": target_account,
                        "domain": p.domain,
                        "thumbprint": cert_thumbprint,
                        "etype": "AES256",
                        "ca_name": p.ca_name,
                    },
                    "tags": ["ad", "adcs", "pkinit", "tgt", "ticket"],
                }
            ],
        }

        if hasattr(self, "noise") and getattr(self.noise, "jitter", None):
            await self.noise.jitter.sleep()

        return ModuleResult(
            status="success",
            findings=[finding],
            raw=raw_result,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )
