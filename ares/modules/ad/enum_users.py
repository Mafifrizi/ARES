"""
AD User Enumeration — Production Implementation
MITRE: T1087.002, T1201

ldap3 with NTLM auth, paged search, UAC flag parsing.
Detects: dormant accounts, ASREPRoastable, no-expiry, missing lockout.
"""
from __future__ import annotations
import asyncio
import datetime
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.enum_users")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.core.errors import AresError, ModuleValidationError, NetworkError
from ares.modules.ad.dependencies import (
    build_ad_bind_plan,
    classify_ad_ldap_bind_failure,
)

UAC_ACCOUNT_DISABLE      = 0x0002
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_PREAUTH_NOT_REQUIRED = 0x400000

def _dn_to_base(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.upper().split("."))

def _parse_windows_ts(ts: Any) -> datetime.datetime | None:
    if not ts or str(ts) in ("0", "9223372036854775807"):
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(str(ts)) // 10)
    except (ValueError, OverflowError, TypeError):
        return None

def _days_since(dt: datetime.datetime | None) -> int | None:
    if dt is None:
        return None
    return max(0, (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - dt).days)

class ADEnumUsersModule(BaseModule):
    """
    ad.enum_users — Enumerate domain users, attributes, dormant accounts, password policy

    OPSEC: LOW
    MITRE: "T1087.002", "T1201"
    OUTPUTS:  "user_list"
    """
    MODULE_ID          = "ad.enum_users"
    MODULE_NAME        = "AD User Enumeration"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Enumerate domain users, attributes, dormant accounts, password policy"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["user_list"]
    MITRE_TECHNIQUES   = ["T1087.002", "T1201"]
    MODULE_TIMEOUT_SECONDS: int | None = 90  # seconds

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
                "ad.enum_users requires 'dc' (Domain Controller IP or hostname). "
                "Pass via params['dc'] or set as target.",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.enum_users requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.enum_users requires domain credentials — "
                "pass 'username'/'password' in params or provide a vault credential.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+). Credentials sourced from vault."""
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        dc, domain, username, password = ad["dc"], ad["domain"], ad["username"], ad["password"]
        use_ldaps = ctx.params.get("use_ldaps", True)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "dc": dc, "domain": domain},
            )
        findings, raw = await self.run(
            dc=dc, username=username, password=password, domain=domain, use_ldaps=use_ldaps,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.enum_users")
    async def run(self, dc, username, password, domain, use_ldaps=True, **kwargs):
        dc, username, domain = sanitize_hostname(dc), sanitize_ldap(username), sanitize_ldap(domain)
        await self.before_request(dc, "ldap")
        page_size = self.noise.get_ldap_page_size()
        logger.info("ad.enum_users_start", dc=dc, domain=domain, ldaps=use_ldaps)
        try:
            loop = asyncio.get_running_loop()
            users, policy = await loop.run_in_executor(
                None,
                lambda: self._ldap_query_sync(dc, username, password, domain, use_ldaps, page_size),
            )
        except AresError:
            raise
        except Exception as exc:
            raise NetworkError(f"LDAP failed on {dc}: {exc}") from exc
        raw = {"user_list": users, "password_policy": policy}
        # ISU-07: produce UserArtifact objects for ArtifactIntelEngine
        try:
            from ares.normalize.artifacts import UserArtifact, ArtifactStore
            store = getattr(getattr(self, "campaign", None), "_artifact_store", None)
            if store is None:
                store = ArtifactStore()
            for u in users:
                artifact = UserArtifact(
                    username=u.get("samAccountName", u.get("username", "")),
                    domain=domain,
                    enabled=u.get("enabled", True),
                    no_preauth=bool(u.get("noPreauth")),
                    spns=u.get("spns", []),
                    is_admin="Admins" in " ".join(u.get("memberOf", [])),
                )
                store.add(artifact)
        except Exception:
            pass  # artifact creation is best-effort
        await self.noise.jitter.sleep()
        self._analyze(raw)
        logger.info("ad.enum_users_done", total=len(users), findings=len(self._findings))
        return self._findings, raw

    def _ldap_query_sync(self, dc, username, password, domain, use_ldaps, page_size):
        """
        Sync (non-async) — runs in executor so it never blocks the event loop.
        Fix Issue #1: moved from async def to sync def + run_in_executor call above.
        Fix Issue #2: conn.unbind() in try/finally — always closes even on exception.
        """
        import ssl
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        bind_plan = build_ad_bind_plan(username, domain)
        last_failure: AresError | None = None
        conn = None
        for port, use_ssl in ([(636, True), (389, False)] if use_ldaps else [(389, False)]):
            attempt_conn = None
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl,
                                 tls=tls_arg, get_info=ALL,
                                 connect_timeout=10)
                conn_kwargs = {
                    "user": bind_plan.user,
                    "password": password,
                    "auto_bind": ldap3.AUTO_BIND_NONE,
                    "receive_timeout": 30,
                }
                if bind_plan.mode == "ntlm":
                    conn_kwargs["authentication"] = NTLM
                attempt_conn = Connection(server, **conn_kwargs)
                result = attempt_conn.bind()
                if not result:
                    bind_error = LDAPBindError(f"Bind failed: {attempt_conn.result}")
                    classified = classify_ad_ldap_bind_failure(
                        bind_error,
                        module_id=self.MODULE_ID,
                        dc=dc,
                        bind_plan=bind_plan,
                        result=attempt_conn.result,
                    )
                    if isinstance(classified, ModuleValidationError):
                        raise classified from bind_error
                    last_failure = classified
                    continue
                conn = attempt_conn
                break
            except ModuleValidationError:
                raise
            except Exception as exc:
                classified = classify_ad_ldap_bind_failure(
                    exc,
                    module_id=self.MODULE_ID,
                    dc=dc,
                    bind_plan=bind_plan,
                    result=getattr(attempt_conn, "result", None),
                )
                if isinstance(classified, ModuleValidationError):
                    raise classified from exc
                last_failure = classified
            finally:
                if attempt_conn is not None and attempt_conn is not conn:
                    try:
                        attempt_conn.unbind()
                    except Exception:
                        pass

        if conn is None:
            if isinstance(last_failure, NetworkError):
                raise NetworkError(
                    f"{last_failure.message} Verify use_ldaps={str(use_ldaps).lower()}, "
                    "LDAP port 389 versus LDAPS port 636, firewall rules, and "
                    "DC certificate/LDAPS configuration.",
                    module_id=self.MODULE_ID,
                    target=dc,
                    context=last_failure.context,
                ) from last_failure
            raise NetworkError(
                f"{self.MODULE_ID} could not bind to {dc} using "
                f"use_ldaps={str(use_ldaps).lower()} on ports 389/636.",
                module_id=self.MODULE_ID,
                target=dc,
            )

        base  = _dn_to_base(domain)
        users: list[dict] = []

        # Issue #2: unbind always fires, even if an entry parse crashes mid-loop
        try:
            cookie: bytes | bool = True
            while cookie:
                conn.search(
                    base,
                    "(&(objectClass=user)(objectCategory=person))",
                    search_scope=SUBTREE,
                    paged_size=page_size,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName", "memberOf", "userAccountControl",
                                "pwdLastSet", "lastLogon", "badPwdCount"],
                )
                for e in conn.entries:
                    try:
                        uac      = int(e.userAccountControl.value or 0)
                        groups   = [str(g) for g in (e.memberOf.values or [])]
                        is_admin = any(
                            "Domain Admins" in g or "Enterprise Admins" in g or
                            "CN=Administrators" in g
                            for g in groups
                        )
                        users.append({
                            "samAccountName":   str(e.sAMAccountName),
                            "enabled":          not bool(uac & UAC_ACCOUNT_DISABLE),
                            "noExpiry":         bool(uac & UAC_DONT_EXPIRE_PASSWORD),
                            "noPreauth":        bool(uac & UAC_PREAUTH_NOT_REQUIRED),
                            "isAdmin":          is_admin,
                            "badPwdCount":      int(e.badPwdCount.value or 0),
                            "days_since_login": _days_since(_parse_windows_ts(e.lastLogon.value)),
                            "days_since_pwd":   _days_since(_parse_windows_ts(e.pwdLastSet.value)),
                        })
                    except Exception:
                        pass   # skip malformed entry, continue
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )

            conn.search(base, "(objectClass=domainDNS)",
                        attributes=["minPwdLength", "pwdHistoryLength", "lockoutThreshold"])
            policy: dict = {}
            if conn.entries:
                ep     = conn.entries[0]
                policy = {
                    "minPwdLength":     int(ep.minPwdLength.value     or 0),
                    "pwdHistoryLength": int(ep.pwdHistoryLength.value  or 0),
                    "lockoutThreshold": int(ep.lockoutThreshold.value  or 0),
                }
            return users, policy
        finally:
            try:
                conn.unbind()     # Issue #2: always runs, no leak
            except Exception:
                pass

    def _analyze(self, raw):
        users, policy = raw.get("user_list",[]), raw.get("password_policy",{})
        dormant = [u for u in users if u.get("enabled") and (u.get("days_since_login") or 0) > 90]
        if dormant:
            self.finding(title=f"Dormant Active Accounts ({len(dormant)})",
                description=f"{len(dormant)} enabled accounts unused 90+ days — low-detection targets.",
                severity=Severity.MEDIUM, mitre_technique="T1078.002", mitre_tactic="Initial Access",
                evidence={"accounts":[u["samAccountName"] for u in dormant[:15]]},
                remediation="Auto-disable after 90 days inactivity.")
        no_preauth = [u for u in users if u.get("noPreauth") and u.get("enabled")]
        if no_preauth:
            self.finding(title=f"ASREPRoastable Accounts ({len(no_preauth)})",
                description=f"{len(no_preauth)} accounts have Kerberos pre-auth disabled.",
                severity=Severity.HIGH, mitre_technique="T1558.004", mitre_tactic="Credential Access",
                evidence={"accounts":[u["samAccountName"] for u in no_preauth]},
                remediation="Enable Kerberos pre-authentication on all accounts.")
        no_expiry = [u for u in users if u.get("noExpiry") and u.get("enabled")]
        if no_expiry:
            self.finding(title=f"Passwords Never Expire ({len(no_expiry)})",
                description=f"{len(no_expiry)} accounts retain old passwords indefinitely.",
                severity=Severity.LOW, mitre_technique="T1201", mitre_tactic="Discovery",
                evidence={"accounts":[u["samAccountName"] for u in no_expiry[:15]]},
                remediation="Enforce password rotation. Remove DONT_EXPIRE_PASSWORD flag.")
        min_len = policy.get("minPwdLength", 0)
        if isinstance(min_len, int) and 0 < min_len < 12:
            self.finding(title=f"Weak Password Policy (min length: {min_len})",
                description=f"Domain minimum password length is {min_len}. Standard is 14+.",
                severity=Severity.MEDIUM, mitre_technique="T1201", mitre_tactic="Discovery",
                evidence={"policy":policy},
                remediation="Set minimum password length to 14+.")
        if policy.get("lockoutThreshold", 0) == 0:
            self.finding(title="No Account Lockout — Password Spray Possible",
                description="No lockout threshold allows unlimited spray attempts.",
                severity=Severity.HIGH, mitre_technique="T1110.003", mitre_tactic="Credential Access",
                evidence={"lockoutThreshold":0},
                remediation="Set lockout threshold to 5-10 attempts.")
