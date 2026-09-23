"""
Bi-Directional Kerberos Ticket Converter - credential.ticket_converter
MITRE: T1558 (Steal or Forge Kerberos Tickets)

Provides pure in-memory cryptographic and structural transcoding between:
  - Linux Kerberos Credential Cache (ccache v4)
  - Windows Mimikatz / Rubeus Kerberos Credential (.kirbi / KRB-CRED ASN.1)

Zero temporary file creation and zero external binary dependencies (pyasn1/impacket-free).
"""
from __future__ import annotations

import base64
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.linux._parsers import CcacheParser, KirbiASN1Codec, build_ccache_v4
from ares.modules.params import TicketConverterParams
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

logger = get_logger("ares.modules.credential.ticket_converter")


@module_contract(
    permissions=[
        FilesystemPermission(read_only=True),
        ProcessPermission(allow_subprocesses=False),
        VaultPermission(read_types=["ticket"], write_types=["ticket", "kerberos_key"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=TicketConverterParams,
)
class TicketConverterModule(BaseModule[TicketConverterParams, ModuleResult]):
    """
    credential.ticket_converter - In-memory transcoding between ccache v4 and Windows .kirbi format.

    OPSEC: SILENT (Pure mathematical and data structure transcoding in memory)
    MITRE: "T1558"
    OUTPUTS: ["converted_ticket"]
    """

    MODULE_ID = "credential.ticket_converter"
    MODULE_NAME = "Bi-Directional Kerberos Ticket Converter"
    MODULE_CATEGORY = "credential"
    MODULE_DESCRIPTION = (
        "Transcodes Kerberos tickets in-memory between Linux ccache v4 and Windows .kirbi "
        "format without saving files to disk or requiring external utilities."
    )
    MODULE_AUTHOR = "ARES Sovereign Team <team@ares-framework.io>"
    OPSEC_LEVEL = OpsecLevel.SILENT
    REQUIRES = []
    OUTPUTS = ["converted_ticket"]
    MITRE_TECHNIQUES = ["T1558"]
    PARAMS_MODEL = TicketConverterParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        """Evaluates feasibility based on input parameters."""
        from ares.modules.base import FeasibilityReport

        params = getattr(ctx, "params", {}) if hasattr(ctx, "params") else {}
        ticket_b64 = params.get("ticket_b64", "")
        src_fmt = params.get("source_format", "ccache").lower()
        dst_fmt = params.get("target_format", "kirbi").lower()

        blockers = []
        if not ticket_b64:
            blockers.append("No ticket_b64 payload provided for conversion.")
        if src_fmt not in ("ccache", "kirbi"):
            blockers.append(f"Unsupported source_format: {src_fmt}")
        if dst_fmt not in ("ccache", "kirbi"):
            blockers.append(f"Unsupported target_format: {dst_fmt}")

        return FeasibilityReport(
            feasible=len(blockers) == 0,
            score=1.0 if not blockers else 0.0,
            risk_level="low",
            blockers=blockers,
            recommended_alternatives=[],
            opsec_tuning={"in_memory_only": True, "disk_writes": 0},
            details={"source_format": src_fmt, "target_format": dst_fmt},
        )

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation."""
        await super().validate(ctx)
        if not isinstance(ctx, ExecutionContext):
            return

        params = ctx.params if isinstance(ctx.params, dict) else {}
        ticket_b64 = params.get("ticket_b64", "")
        if not ticket_b64 or not isinstance(ticket_b64, str) or len(ticket_b64) < 4:
            raise ModuleValidationError(
                "credential.ticket_converter requires valid non-empty 'ticket_b64'.",
                module_id=self.MODULE_ID,
                field="ticket_b64",
            )

        src_fmt = params.get("source_format", "ccache").lower()
        dst_fmt = params.get("target_format", "kirbi").lower()
        if src_fmt == dst_fmt:
            raise ModuleValidationError(
                f"Source and target formats cannot be identical ({src_fmt} == {dst_fmt}).",
                module_id=self.MODULE_ID,
                field="target_format",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: ticket conversion simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        ticket_b64 = ctx.params.get("ticket_b64", "")
        source_format = ctx.params.get("source_format", "ccache").lower()
        target_format = ctx.params.get("target_format", "kirbi").lower()

        findings, raw = await self.run(
            target=target,
            ticket_b64=ticket_b64,
            source_format=source_format,
            target_format=target_format,
            vault=getattr(ctx, "vault", None),
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("credential.ticket_converter")
    async def run(
        self,
        target: str,
        ticket_b64: str,
        source_format: str = "ccache",
        target_format: str = "kirbi",
        vault: Any = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        await self.before_request(target, "default")
        logger.info(
            "ticket_converter_start",
            src=source_format,
            dst=target_format,
        )
        audit("credential_ticket_converter", actor="operator", technique="T1558", target=target)

        try:
            raw_bytes = base64.b64decode(ticket_b64)
        except Exception as exc:
            raise ModuleValidationError(
                f"Failed to decode Base64 ticket payload: {exc}",
                module_id=self.MODULE_ID,
                field="ticket_b64",
            ) from exc

        converted_bytes = b""
        ticket_meta: dict[str, Any] = {}

        if source_format == "ccache" and target_format == "kirbi":
            principal, tickets = CcacheParser.parse(raw_bytes, include_expired=True)
            if not tickets:
                raise ModuleValidationError(
                    "Input ccache payload contains no valid Kerberos credentials.",
                    module_id=self.MODULE_ID,
                    field="ticket_b64",
                )
            target_ticket = tickets[0]
            converted_bytes = KirbiASN1Codec.encode_kirbi(target_ticket)
            ticket_meta = {
                "client": target_ticket["client"],
                "server": target_ticket["server"],
                "endtime_str": target_ticket.get("endtime_str", ""),
                "is_tgt": target_ticket.get("is_tgt", False),
            }

        elif source_format == "kirbi" and target_format == "ccache":
            ticket_data = KirbiASN1Codec.decode_kirbi(raw_bytes)
            converted_bytes = build_ccache_v4(ticket_data["client"], [ticket_data])
            ticket_meta = {
                "client": ticket_data["client"],
                "server": ticket_data["server"],
                "endtime_str": "valid",
                "is_tgt": "krbtgt" in ticket_data["server"],
            }
        else:
            raise ModuleValidationError(
                f"Unsupported conversion path: {source_format} -> {target_format}",
                module_id=self.MODULE_ID,
            )

        converted_b64 = base64.b64encode(converted_bytes).decode("ascii")

        # Store to AresVault if available
        _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
        if _vault:
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel

            campaign_id = getattr(getattr(self, "campaign", None), "id", "")
            try:
                cred = Credential(
                    campaign_id=campaign_id,
                    username=ticket_meta.get("client", "converted-user"),
                    domain=target,
                    cred_type=CredentialType.KRB5_TGT if ticket_meta.get("is_tgt") else CredentialType.KRB5_TGS,
                    privilege=PrivilegeLevel.DOMAIN_ADMIN if ticket_meta.get("is_tgt") else PrivilegeLevel.DOMAIN_USER,
                    source_module=self.MODULE_ID,
                    target_host=target,
                )
                _vault.store(cred, converted_b64)
            except Exception as ex:
                logger.debug("vault_store_converted_failed", error=str(ex)[:60])

        ev = EvidenceRecord(
            artifact_id=f"converted-ticket-{ticket_meta.get('client', 'user')}",
            source_target=target,
            collected_by=self.MODULE_ID,
            data={
                "source_format": source_format,
                "target_format": target_format,
                "client": ticket_meta.get("client"),
                "server": ticket_meta.get("server"),
                "converted_size_bytes": len(converted_bytes),
            },
            tags=["ticket_converter", "kerberos", target_format],
        )

        self.finding(
            title=f"Kerberos Ticket Converted: {source_format.upper()} -> {target_format.upper()}",
            description=(
                f"Successfully transcoded Kerberos credential from {source_format} to {target_format} in-memory. "
                f"Principal: {ticket_meta.get('client')}, Service: {ticket_meta.get('server')}."
            ),
            severity=Severity.INFO,
            mitre_technique="T1558",
            mitre_tactic="Credential Access",
            evidence={
                "source_format": source_format,
                "target_format": target_format,
                "client": ticket_meta.get("client"),
                "server": ticket_meta.get("server"),
                "original_bytes": len(raw_bytes),
                "converted_bytes": len(converted_bytes),
            },
            remediation="Ensure credential materials are isolated and not transferred across network boundaries.",
            host=target,
            confidence=1.0,
        )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "source_format": source_format,
            "target_format": target_format,
            "converted_ticket_b64": converted_b64,
            "metadata": ticket_meta,
            "evidence_integrity": [ev.record_hash],
        }
