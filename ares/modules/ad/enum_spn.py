"""AD SPN Enumeration — Production ldap3 Implementation. MITRE: T1558.003, T1087.002"""
from __future__ import annotations
import datetime
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.enum_spn")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.core.errors import AresError, ModuleValidationError
from ares.modules.ad.dependencies import (
    ad_bind_dry_run_metadata,
    build_ad_bind_plan,
    classify_ad_ldap_bind_failure,
    sanitize_ad_username,
)

def _dn_to_base(domain):
    return ",".join(f"DC={p}" for p in domain.upper().split("."))

def _days_since_ts(ts):
    if not ts or str(ts) in ("0","9223372036854775807"): return None
    try:
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=int(str(ts))//10)
        return max(0,(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)-dt).days)
    except Exception: return None

class ADEnumSPNModule(BaseModule):
    """
    ad.enum_spn — Find SPN accounts (Kerberoasting candidates)

    OPSEC: LOW
    MITRE: "T1558.003","T1087.002"
    OUTPUTS:  "spn_list"
    """
    MODULE_ID="ad.enum_spn"; MODULE_NAME="AD SPN Enumeration"; MODULE_CATEGORY="ad"
    MODULE_DESCRIPTION="Find SPN accounts (Kerberoasting candidates)"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL=OpsecLevel.LOW; REQUIRES=[]; OUTPUTS=["spn_list"]
    MITRE_TECHNIQUES=["T1558.003","T1087.002"]

    async def validate(self, ctx: "Any") -> None:
        """Enforce dc, domain, and credentials before any LDAP connection is made."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.enum_spn requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.enum_spn requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.enum_spn requires domain credentials — "
                "pass 'username'/'password' in params or provide a vault credential.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+). Credentials sourced from vault."""
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        dc, domain, username, password = ad["dc"], ad["domain"], ad["username"], ad["password"]
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={
                    "dry_run": True,
                    "dc": dc,
                    "domain": domain,
                    **ad_bind_dry_run_metadata(username, domain),
                },
            )
        findings, raw = await self.run(
            dc=dc, username=username, password=password, domain=domain,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.enum_spn")
    async def run(self, dc, username, password, domain, **kwargs):
        dc, username, domain = (
            sanitize_hostname(dc),
            sanitize_ad_username(username),
            sanitize_ldap(domain),
        )
        await self.before_request(dc,"ldap")
        logger.info("ad.enum_spn_start", dc=dc)
        try:
            import asyncio as _asyncio
            loop = _asyncio.get_running_loop()
            spns = await loop.run_in_executor(
                None,
                lambda: self._fetch_spns_sync(dc, username, password, domain),
            )
        except AresError:
            raise
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"LDAP SPN failed: {exc}") from exc
        raw = {"spn_list": spns}
        # ISU-07: produce UserArtifact objects (is_kerberoastable=True)
        try:
            from ares.normalize.artifacts import UserArtifact, ArtifactStore
            store = getattr(getattr(self, "campaign", None), "_artifact_store", None)
            if store is None:
                store = ArtifactStore()
            for spn_entry in spns:
                artifact = UserArtifact(
                    username=spn_entry.get("samAccountName", ""),
                    domain=domain,
                    enabled=True,
                    spns=spn_entry.get("spns", []),
                    is_service=True,
                )
                store.add(artifact)
        except Exception:
            pass
        await self.noise.jitter.sleep()
        self._analyze(raw)
        logger.info("ad.enum_spn_done", total=len(spns))
        return self._findings, raw

    def _fetch_spns_sync(self, dc, username, password, domain):
        """
        Sync (non-async) — runs in executor so it never blocks the event loop.
        Issue #1 fix: moved from async def to sync def + run_in_executor call above.
        Issue #2 fix: conn.unbind() in try/finally — always closes even on exception.
        """
        import ssl
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        # Try LDAPS first, fallback to plain LDAP
        bind_plan = build_ad_bind_plan(username, domain)
        conn = None
        last_error = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl,
                                 tls=tls_arg, get_info=ALL,
                                 connect_timeout=10)
                conn_kwargs = dict(
                    user=bind_plan.user,
                    password=password,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=30,
                )
                if bind_plan.mode == "ntlm":
                    conn_kwargs["authentication"] = ldap3.NTLM
                conn = Connection(server, **conn_kwargs)
                result = conn.bind()
                if not result:
                    ldap_result = getattr(conn, "result", {}) or {}
                    raise classify_ad_ldap_bind_failure(
                        LDAPBindError("LDAP bind returned false"),
                        module_id=self.MODULE_ID,
                        dc=dc,
                        bind_plan=bind_plan,
                        result=ldap_result,
                    )
                break
            except AresError:
                raise
            except Exception as exc:
                last_error = classify_ad_ldap_bind_failure(
                    exc,
                    module_id=self.MODULE_ID,
                    dc=dc,
                    bind_plan=bind_plan,
                )
                if isinstance(last_error, ModuleValidationError):
                    raise last_error
                conn = None
                continue

        if conn is None:
            if last_error is not None:
                raise last_error
            raise ConnectionError(f"Could not bind to {dc} on ports 636 or 389")

        base       = _dn_to_base(domain)
        spn_filter = (
            "(&(objectClass=user)(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        spns: list[dict] = []

        try:
            cookie: bytes | bool = True
            while cookie:
                conn.search(
                    base, spn_filter,
                    search_scope=SUBTREE,
                    paged_size=200,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName", "servicePrincipalName", "memberOf",
                                "msDS-SupportedEncryptionTypes", "pwdLastSet",
                                "userAccountControl"],
                )
                for e in conn.entries:
                    try:
                        uac    = int(e.userAccountControl.value or 0)
                        enc_raw = 0
                        try:
                            enc_attr = getattr(e, "msDS-SupportedEncryptionTypes", None)
                            if enc_attr and enc_attr.value is not None:
                                enc_raw = int(enc_attr.value)
                        except Exception:
                            enc_raw = 0
                        groups   = [str(g) for g in (e.memberOf.values or [])]
                        is_admin = any(
                            "Domain Admins" in g or "Enterprise Admins" in g for g in groups
                        )
                        spns.append({
                            "name":          str(e.sAMAccountName),
                            "spn_list":          [str(s) for s in (e.servicePrincipalName.values or [])],
                            "is_admin":      is_admin,
                            "uses_rc4":      (enc_raw == 0) or bool(enc_raw & 0x4),
                            "days_since_pwd": _days_since_ts(e.pwdLastSet.value),
                            "enabled":       not bool(uac & 0x0002),
                        })
                    except Exception:
                        pass   # skip malformed entry
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )
            return spns
        finally:
            try:
                conn.unbind()     # Issue #2: always runs, no resource leak
            except Exception:
                pass

    def _analyze(self, raw):
        spns = raw.get("spn_list",[])
        if not spns: return
        rc4      = [s for s in spns if s.get("uses_rc4")]
        privd    = [s for s in spns if s.get("is_admin")]
        old_pass = [s for s in spns if (s.get("days_since_pwd") or 0) > 365]
        self.finding(title=f"Kerberoastable Service Accounts ({len(spns)})",
            description=(f"{len(spns)} SPN accounts — {len(rc4)} use RC4 (fastest to crack), "
                         f"{len(privd)} in privileged groups."),
            severity=Severity.CRITICAL if privd else Severity.HIGH,
            mitre_technique="T1558.003", mitre_tactic="Credential Access",
            evidence={"total_spns":len(spns),"rc4_accounts":[s["name"] for s in rc4[:10]],
                      "privileged_spns":[s["name"] for s in privd[:10]],"hashcat_mode_rc4":13100},
            remediation=("1. Migrate to gMSA. 2. Set-ADUser -KerberosEncryptionType AES256. "
                         "3. Monitor Event ID 4769."))
        if old_pass:
            self.finding(title=f"Service Accounts with Stale Passwords ({len(old_pass)})",
                description=f"{len(old_pass)} SPN accounts have passwords older than 1 year.",
                severity=Severity.MEDIUM, mitre_technique="T1558.003", mitre_tactic="Credential Access",
                evidence={"accounts":[s["name"] for s in old_pass]},
                remediation="Rotate service account passwords annually, or migrate to gMSA.")
