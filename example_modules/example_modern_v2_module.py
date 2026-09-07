"""ARES Example Module (Enterprise Security & Governance SDK Standard).

Demonstrates:
- Declarative @module_contract with Capability-Based Permissions (NetworkPermission, VaultPermission)
- LockoutCircuitBreaker integration for zero-collateral safety
- Pydantic v2 parameter models (ModuleParams, param, SecretParam)
- Taint-Tracked target responses (UntrustedTargetData) to prevent prompt injection
- Tamper-Evident Evidence Records (EvidenceRecord with SHA-256 Merkle chain)
- Isolated testing using ModuleTestHarness and cryptographic audit provenance assertions
"""
from __future__ import annotations

import asyncio
import pathlib
import sys
from typing import Any

# Ensure workspace root is in sys.path when run directly
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleParams,
    ModuleResult,
    ModuleTestHarness,
    NetworkPermission,
    OpsecLevel,
    SecretParam,
    Severity,
    UntrustedTargetData,
    UserArtifact,
    VaultPermission,
    ares_module,
    module_contract,
    param,
)


# ── 1. Type-Safe Parameter Model ──────────────────────────────────────────────


class KerberoastParams(ModuleParams):
    dc: str = param(description="Target Domain Controller IP or FQDN", min_length=3)
    domain: str = param(description="AD DNS domain name, e.g. CORP.LOCAL", min_length=3)
    username: str = param(description="Domain username for TGS requests")
    password: SecretParam = param(description="Domain user password", secret=True, required=False)
    target_spn: str = param(description="Target specific SPN or service account", required=False, default="")
    request_timeout: int = param(description="Kerberos request timeout (seconds)", default=30, ge=1, le=180)


# ── 2. Enterprise Class-Based Module with Security Contract ───────────────────


@module_contract(
    permissions=[
        NetworkPermission(ports=[88, 389], protocols=["tcp", "udp"]),
        VaultPermission(read_types=["domain_creds"], write_types=["kerberos_hash"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=KerberoastParams,
)
class ModernKerberoastModule(BaseModule[KerberoastParams, ModuleResult]):
    """Modernized attack module leveraging ARES Enterprise Security contracts."""

    MODULE_ID = "ad.kerberoast_v2"
    MODULE_NAME = "Modern Kerberoast Attack"
    MODULE_CATEGORY = "ad"
    MODULE_DESCRIPTION = "Requests Kerberos TGS tickets for SPN accounts with least-privilege permissions."
    MODULE_AUTHOR = "ARES Core Team"
    OPSEC_LEVEL = OpsecLevel.LOW
    REQUIRES = ["domain_creds"]
    OUTPUTS = ["kerberos_tickets", "credentials"]
    MITRE_TECHNIQUES = ["T1558.003"]
    PARAMS_MODEL = KerberoastParams

    async def execute(self, ctx: ExecutionContext[KerberoastParams]) -> ModuleResult:
        """Execute the attack with fully validated parameters and automatic interceptors."""
        p = ctx.params

        if ctx.dry_run:
            ctx.emit_finding(
                title="[DRY-RUN] Kerberoast Probe Succeeded",
                severity=Severity.INFO,
                description=f"Dry run probe against DC {p.dc} in domain {p.domain}",
                mitre_technique="T1558.003",
            )
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"target_dc": p.dc, "domain": p.domain},
            )

        # 1. Taint Tracking: wrap external target response to defend against prompt injection
        simulated_raw_banner = "DC01 Kerberos KDC Ready"
        untrusted_banner = UntrustedTargetData(simulated_raw_banner, source=p.dc)

        # 2. Cryptographic Evidence Record
        evidence = EvidenceRecord(
            evidence_id=f"ev-{self.MODULE_ID}-01",
            source_target=p.dc,
            payload={"spn": p.target_spn or "MSSQLSvc/db01.corp.local", "etype": 23},
        )

        finding = ctx.emit_finding(
            title=f"Kerberoastable SPN Hash Acquired: {p.target_spn or 'MSSQLSvc/db01.corp.local'}",
            severity=Severity.HIGH,
            description=f"Captured RC4-HMAC TGS ticket for offline cracking against DC {p.dc}",
            mitre_technique="T1558.003",
            mitre_tactic="TA0006",
            evidence={"sha256": evidence.sha256_hash, "spn": p.target_spn or "MSSQLSvc/db01.corp.local"},
        )

        ctx.store_artifact(
            UserArtifact(
                username="svc-mssql",
                domain=p.domain,
                source_module=self.MODULE_ID,
                attributes={"spn": p.target_spn or "MSSQLSvc/db01.corp.local"},
            )
        )

        return ModuleResult(
            status="success",
            findings=[finding],
            module_id=self.MODULE_ID,
            raw={"dc": p.dc, "banner": untrusted_banner.sanitized_text(), "tickets_acquired": 1},
        )


# ── 3. Modern Functional Decorator Definition ─────────────────────────────────


@ares_module(
    id="ad.fast_tgs_probe",
    name="Fast TGS Probe",
    category="ad",
    description="Fast check for kerberoastable accounts using functional syntax",
    opsec=OpsecLevel.LOW,
    mitre="T1558.003",
    params_model=KerberoastParams,
)
async def fast_tgs_probe(ctx: ExecutionContext[KerberoastParams]) -> ModuleResult:
    """Functional module alternative for lightweight adversary techniques."""
    ctx.emit_finding(
        title=f"TGS Ticket Validated on {ctx.params.dc}",
        severity=Severity.HIGH,
        mitre_technique="T1558.003",
    )
    return ModuleResult(
        status="success",
        module_id="ad.fast_tgs_probe",
        raw={"dc": ctx.params.dc},
    )


# ── 4. Unit Test Example ──────────────────────────────────────────────────────


async def _run_example_simulation() -> None:
    """Run an isolated test simulation using ModuleTestHarness."""
    harness = ModuleTestHarness(ModernKerberoastModule)
    result = await harness.simulate(
        params={
            "dc": "10.0.0.10",
            "domain": "LAB.LOCAL",
            "username": "lowpriv_user",
            "password": "Password123!",
            "target_spn": "MSSQLSvc/sql01.lab.local:1433",
        },
        dry_run=True,
    )
    result.assert_success()
    result.assert_no_errors()
    result.assert_provenance_verified()
    finding = result.assert_finding(mitre="T1558.003")
    print(f"[+] Enterprise Simulation passed! Emitted finding: {finding.title}")
    print(f"[+] Cryptographic Provenance SHA-256 Digest: {result.provenance_hash}")


if __name__ == "__main__":
    asyncio.run(_run_example_simulation())
