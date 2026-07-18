"""
AD Computer Enumeration — Production ldap3 Implementation
Enumerate domain computers, DCs, OS versions, stale accounts.
MITRE: T1018, T1087.002
"""
from __future__ import annotations
import datetime
import re
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.enum_computers")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.core.errors import AresError, ModuleValidationError, NetworkError
from ares.modules.ad.dependencies import build_ad_bind_plan

def _days_since_ts(ts):
    if not ts or str(ts) in ("0","9223372036854775807"): return None
    try:
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=int(str(ts))//10)
        return max(0,(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)-dt).days)
    except Exception: return None


def _safe_ldap_exception_text(exc: BaseException) -> str:
    text = " ".join(str(exc).split())[:160]
    return re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*([:=])\s*[^\s,;]+",
        r"\1\2[redacted]",
        text,
    ) or type(exc).__name__


def _is_ldap_configuration_failure(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(
        marker in text
        for marker in (
            "ssl wrapping",
            "sslerror",
            "tls",
            "certificate",
            "wrong version number",
            "winerror 10054",
            "forcibly closed",
            "connection reset",
        )
    )


def _format_ldap_connection_failure(
    *, dc: str, port: int, use_ldaps: bool, exc: BaseException
) -> str:
    mode = "LDAPS" if use_ldaps else "plain LDAP"
    return (
        f"ad.enum_computers {mode} connection failed for dc {dc} "
        f"(use_ldaps={str(use_ldaps).lower()}, port {port}). "
        f"Verify DC LDAP/LDAPS support ({'LDAPS on port 636' if use_ldaps else 'plain LDAP on port 389'}), "
        "or switch use_ldaps to the supported mode; check the 389 vs 636 port, "
        "firewall rules, and certificate/LDAPS configuration. "
        f"Reason: {_safe_ldap_exception_text(exc)}"
    )

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
        use_ldaps = ctx.params.get("use_ldaps", True)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "dc": dc, "domain": domain},
            )
        findings, raw = await self.run(
            dc=dc, username=username, password=password, domain=domain,
            use_ldaps=use_ldaps,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.enum_computers")
    async def run(self, dc, username, password, domain, use_ldaps=True, **kwargs):
        dc,username,domain = sanitize_hostname(dc),sanitize_ldap(username),sanitize_ldap(domain)
        await self.before_request(dc,"ldap")
        logger.info("ad.enum_computers_start", dc=dc, ldaps=use_ldaps)
        try:
            computers = await self._fetch_computers(
                dc, username, password, domain, use_ldaps=use_ldaps
            )
        except AresError:
            raise
        except Exception as exc:
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

    async def _fetch_computers(self, dc, username, password, domain, use_ldaps=True):
        import ssl
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, AUTO_BIND_NO_TLS, Tls
        port = 636 if use_ldaps else 389
        tls = Tls(validate=ssl.CERT_NONE) if use_ldaps else None
        bind_plan = build_ad_bind_plan(username, domain)
        try:
            server = Server(
                dc,
                port=port,
                use_ssl=use_ldaps,
                tls=tls,
                get_info=ALL,
                connect_timeout=10,
            )
            conn_kwargs = {
                "user": bind_plan.user,
                "password": password,
                "auto_bind": AUTO_BIND_NO_TLS,
                "receive_timeout": 30,
            }
            if bind_plan.mode == "ntlm":
                conn_kwargs["authentication"] = NTLM
            conn = Connection(server, **conn_kwargs)
            if not conn.bind():
                raise ConnectionError(f"LDAP bind returned false: {conn.result}")
        except Exception as exc:
            message = _format_ldap_connection_failure(
                dc=dc, port=port, use_ldaps=use_ldaps, exc=exc
            )
            if _is_ldap_configuration_failure(exc):
                raise ModuleValidationError(
                    f"LDAP configuration validation failed: {message}",
                    module_id=self.MODULE_ID,
                    field="use_ldaps",
                    target=dc,
                ) from exc
            raise NetworkError(message, module_id=self.MODULE_ID, target=dc) from exc
        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        try:
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
            return computers
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

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
