"""
AD ACL Enumeration — Production ldap3 Implementation
Find dangerous ACL delegations: WriteDACL, GenericAll, GenericWrite, DCSync rights.
MITRE: T1222.001, T1003.006
"""
from __future__ import annotations
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.enum_acl")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

# Active Directory extended rights GUIDs
DCSYNC_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}

class ADEnumACLModule(BaseModule):
    """
    ad.enum_acl — Find WriteDACL, GenericAll, GenericWrite, DCSync delegation misconfigs

    OPSEC: LOW
    MITRE: "T1222.001","T1003.006"
    OUTPUTS:  "acl_findings"
    """
    MODULE_ID="ad.enum_acl"; MODULE_NAME="AD ACL Enumeration"; MODULE_CATEGORY="ad"
    MODULE_DESCRIPTION="Find WriteDACL, GenericAll, GenericWrite, DCSync delegation misconfigs"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL=OpsecLevel.LOW; REQUIRES=[]; OUTPUTS=["acl_findings"]
    MITRE_TECHNIQUES=["T1222.001","T1003.006"]

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
                "ad.enum_acl requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.enum_acl requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.enum_acl requires domain credentials — "
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
                raw={"dry_run": True, "dc": dc, "domain": domain},
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

    @trace_module("ad.enum_acl")
    async def run(self, dc, username, password, domain, **kwargs):
        dc,username,domain = sanitize_hostname(dc),sanitize_ldap(username),sanitize_ldap(domain)
        await self.before_request(dc,"ldap")
        logger.info("ad.enum_acl_start", dc=dc)
        try:
            import asyncio as _asyncio
            loop = _asyncio.get_running_loop()
            misconfigs = await loop.run_in_executor(
                None,
                lambda: self._enum_acls_sync(dc, username, password, domain),
            )
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"ACL enum failed: {exc}") from exc
        raw = {"misconfigs": misconfigs, "acl_findings": misconfigs}  # acl_findings = OUTPUTS key
        # ISU-07: produce PermissionArtifact objects for ArtifactIntelEngine
        try:
            from ares.normalize.artifacts import PermissionArtifact, ArtifactStore
            store = getattr(getattr(self, "campaign", None), "_artifact_store", None)
            if store is None:
                store = ArtifactStore()
            for m in misconfigs:
                artifact = PermissionArtifact(
                    principal=m.get("trustee", m.get("principal", "")),
                    target=m.get("target_dn", m.get("target", "")),
                    right=m.get("right", m.get("ace_type", "")),
                    domain=domain,
                )
                store.add(artifact)
        except Exception:
            pass  # artifact creation is best-effort
        await self.noise.jitter.sleep()
        self._analyze(raw)
        logger.info("ad.enum_acl_done", total=len(misconfigs))
        return self._findings, raw

    def _enum_acls_sync(self, dc, username, password, domain):
        """
        Sync — runs in executor (fix: was async def blocking event loop).
        Fixes: AUTO_BIND_NONE, cookie loop, LDAPS fallback, try/finally unbind.
        """
        import ssl
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl,
                                 tls=tls_arg, get_info=ALL, connect_timeout=10)
                conn = Connection(
                    server,
                    user=f"{domain.upper()}\\{username}",
                    password=password,
                    authentication=NTLM,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=30,
                )
                if not conn.bind():
                    raise LDAPBindError(f"Bind failed: {conn.result}")
                break
            except Exception:
                conn = None
                continue

        if conn is None:
            raise ConnectionError(f"Could not bind to {dc} on ports 636 or 389")

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        dangerous_rights = {
            0x000F01FF: "GenericAll",
            0x00020028: "WriteDACL",
            0x00020000: "GenericWrite",
            0x00080000: "WriteOwner",
        }
        sd_control = [("1.2.840.113556.1.4.801", True, bytes([0x30, 0x03, 0x02, 0x01, 0x07]))]
        dangerous: list[dict] = []

        try:
            cookie: bytes | bool = True
            while cookie:
                conn.search(
                    base,
                    "(&(objectClass=user)(objectCategory=person))",
                    search_scope=SUBTREE,
                    paged_size=100,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName", "ntSecurityDescriptor"],
                    controls=sd_control,
                )
                for entry in conn.entries:
                    sd = getattr(entry, "ntSecurityDescriptor", None)
                    if not sd or not sd.value:
                        continue
                    try:
                        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                        raw_sd = sd.raw_values[0] if hasattr(sd, "raw_values") else None
                        if not raw_sd:
                            continue
                        sd_obj = SR_SECURITY_DESCRIPTOR(data=raw_sd)
                        if not sd_obj.get("Dacl"):
                            continue
                        for ace in sd_obj["Dacl"]["Data"]:
                            if ace["AceType"] not in (0x00, 0x05):
                                continue
                            try:
                                mask = ace["Ace"]["Mask"]["MaskFields"]
                            except (KeyError, AttributeError):
                                continue
                            for right_mask, right_name in dangerous_rights.items():
                                if mask & right_mask == right_mask:
                                    from ldap3.protocol.formatters.formatters import format_sid
                                    sid = format_sid(ace["Ace"]["Sid"].getData())
                                    dangerous.append({
                                        "target":      str(entry.sAMAccountName),
                                        "right":       right_name,
                                        "trustee_sid": sid,
                                    })
                                    break
                    except Exception:
                        pass
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )

            # Check domain object for DCSync rights
            conn.search(
                base, "(objectClass=domainDNS)",
                attributes=["distinguishedName", "ntSecurityDescriptor"],
                controls=sd_control,
            )
            for entry in conn.entries:
                sd = getattr(entry, "ntSecurityDescriptor", None)
                if not sd or not sd.value:
                    continue
                try:
                    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                    raw_sd = sd.raw_values[0] if hasattr(sd, "raw_values") else None
                    if not raw_sd:
                        continue
                    sd_obj = SR_SECURITY_DESCRIPTOR(data=raw_sd)
                    if not sd_obj.get("Dacl"):
                        continue
                    repl_rights: dict[str, set] = {}
                    for ace in sd_obj["Dacl"]["Data"]:
                        if ace["AceType"] != 0x05:
                            continue
                        try:
                            obj_type = bytes(ace["Ace"]["ObjectType"]).hex()
                            from ldap3.protocol.formatters.formatters import format_sid
                            sid = format_sid(ace["Ace"]["Sid"].getData())
                            if obj_type in DCSYNC_RIGHTS:
                                repl_rights.setdefault(sid, set()).add(DCSYNC_RIGHTS[obj_type])
                        except Exception:
                            pass
                    for sid, rights in repl_rights.items():
                        if len(rights) >= 2:
                            dangerous.append({
                                "target":      "domain",
                                "right":       "DCSync",
                                "trustee_sid": sid,
                            })
                except Exception:
                    pass
            return dangerous
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
    def _analyze(self, raw):
        misconfigs = raw.get("misconfigs",[])
        if not misconfigs: return
        write_dacl  = [m for m in misconfigs if m["right"] == "WriteDACL"]
        generic_all = [m for m in misconfigs if m["right"] == "GenericAll"]
        if generic_all:
            self.finding(title=f"GenericAll ACE on {len(generic_all)} Objects",
                description=f"{len(generic_all)} objects have GenericAll ACE — full control over target.",
                severity=Severity.CRITICAL, mitre_technique="T1222.001", mitre_tactic="Defense Evasion",
                evidence={"objects": generic_all[:10]},
                remediation="Remove GenericAll ACE. Use specific delegations instead.")
        if write_dacl:
            self.finding(title=f"WriteDACL on {len(write_dacl)} Objects",
                description=f"{len(write_dacl)} objects have WriteDACL — attacker can grant arbitrary rights.",
                severity=Severity.HIGH, mitre_technique="T1222.001", mitre_tactic="Defense Evasion",
                evidence={"objects": write_dacl[:10]},
                remediation="Audit and remove WriteDACL delegations. Enable AD Protected Users.")
