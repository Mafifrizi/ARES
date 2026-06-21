"""
AD Computer Enumeration — Production ldap3 Implementation
Enumerate domain computers, DCs, OS versions, stale accounts.
MITRE: T1018, T1087.002
"""
from __future__ import annotations
import datetime
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.enum_computers")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

def _days_since_ts(ts):
    if not ts or str(ts) in ("0","9223372036854775807"): return None
    try:
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=int(str(ts))//10)
        return max(0,(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)-dt).days)
    except Exception: return None

class ADEnumComputersModule(BaseModule):
    """
    ad.enum_computers — Enumerate domain computers, OS versions, stale accounts, DCs

    OPSEC: LOW
    MITRE: "T1018","T1087.002"
    OUTPUTS:  "computer_list"
    """
    MODULE_ID="ad.enum_computers"; MODULE_NAME="AD Computer Enumeration"; MODULE_CATEGORY="ad"
    MODULE_DESCRIPTION="Enumerate domain computers, OS versions, stale accounts, DCs"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL=OpsecLevel.LOW; REQUIRES=[]; OUTPUTS=["computer_list"]
    MITRE_TECHNIQUES=["T1018","T1087.002"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.enum_computers requires 'dc'.",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.enum_computers requires 'domain'.",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.enum_computers requires domain credentials.",
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

    @trace_module("ad.enum_computers")
    async def run(self, dc, username, password, domain, **kwargs):
        dc,username,domain = sanitize_hostname(dc),sanitize_ldap(username),sanitize_ldap(domain)
        await self.before_request(dc,"ldap")
        logger.info("ad.enum_computers_start", dc=dc)
        try:
            computers = await self._fetch_computers(dc, username, password, domain)
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"Computer enum failed: {exc}") from exc
        raw = {"computer_list": computers}
        # ISU-07: produce HostArtifact objects for ArtifactIntelEngine
        try:
            from ares.normalize.artifacts import HostArtifact, ArtifactStore
            store = getattr(getattr(self, "campaign", None), "_artifact_store", None)
            if store is None:
                store = ArtifactStore()
            for comp in computers:
                artifact = HostArtifact(
                    hostname=comp.get("name", ""),
                    domain=domain,
                    os_version=comp.get("os", ""),
                    is_dc=comp.get("is_dc", False),
                )
                store.add(artifact)
        except Exception:
            pass
        await self.noise.jitter.sleep()
        self._analyze(raw)
        logger.info("ad.enum_computers_done", total=len(computers))
        return self._findings, raw

    async def _fetch_computers(self, dc, username, password, domain):
        import ssl
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, AUTO_BIND_NO_TLS, Tls
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(dc, port=636, use_ssl=True, tls=tls, get_info=ALL)
        conn = Connection(server, user=f"{domain.upper()}\\{username}", password=password,
                          authentication=NTLM, auto_bind=AUTO_BIND_NO_TLS)
        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        conn.search(base, "(objectClass=computer)", search_scope=SUBTREE,
                    attributes=["name","dNSHostName","operatingSystem","operatingSystemVersion",
                                "lastLogon","userAccountControl","primaryGroupID","whenCreated"])
        computers = []
        for e in conn.entries:
            uac = int(e.userAccountControl.value or 0)
            pgid = int(e.primaryGroupID.value or 0)
            computers.append({
                "name":         str(e.name),
                "dns":          str(e.dNSHostName or ""),
                "os":           str(e.operatingSystem or "Unknown"),
                "os_version":   str(e.operatingSystemVersion or ""),
                "is_dc":        pgid in (516, 521),  # Domain Controllers group
                "enabled":      not bool(uac & 0x0002),
                "days_since_logon": _days_since_ts(e.lastLogon.value),
            })
        conn.unbind()
        return computers

    def _analyze(self, raw):
        computers = raw.get("computer_list",[])
        if not computers: return
        dcs   = [c for c in computers if c.get("is_dc")]
        stale = [c for c in computers if c.get("enabled") and (c.get("days_since_logon") or 0) > 90]
        legacy_keywords = ("2003","2008","2012","xp","vista","7 enterprise","7 professional")
        legacy = [c for c in computers if any(kw in c.get("os","").lower() for kw in legacy_keywords)]

        if dcs:
            self.finding(title=f"Domain Controllers Found ({len(dcs)})",
                description=f"Found {len(dcs)} Domain Controllers. Targeting DCs for privilege escalation.",
                severity=Severity.INFO if len(dcs)>0 else Severity.CRITICAL,
                mitre_technique="T1018", mitre_tactic="Discovery",
                evidence={"dcs":[{"name":c["name"],"dns":c["dns"],"os":c["os"]} for c in dcs]},
                remediation="Ensure DCs are fully patched. Monitor DC access logs.")
        if legacy:
            self.finding(title=f"Legacy OS Computers ({len(legacy)})",
                description=f"{len(legacy)} computers running unsupported/legacy OS versions.",
                severity=Severity.HIGH, mitre_technique="T1018", mitre_tactic="Discovery",
                evidence={"computer_list":[{"name":c["name"],"os":c["os"]} for c in legacy[:15]]},
                remediation="Upgrade or isolate legacy systems. Apply available patches.")
        if stale:
            self.finding(title=f"Stale Computer Accounts ({len(stale)})",
                description=f"{len(stale)} enabled computer accounts inactive 90+ days.",
                severity=Severity.LOW, mitre_technique="T1087.002", mitre_tactic="Discovery",
                evidence={"computer_list":[c["name"] for c in stale[:15]]},
                remediation="Auto-disable computer accounts after 90 days inactivity.")
