"""
Hash Cracking Interface — credential.crack
MITRE: T1110.002 — Brute Force: Password Cracking

Thin wrapper around ares/credential/cracker.py (720 lines, fully implemented).
Runs hashcat (GPU) or john (CPU fallback) against uncracked hashes in the vault.
Cracked plaintext is encrypted and stored back to vault via vault.mark_cracked().

OPSEC: LOCAL — cracking happens entirely on the operator machine.
       Zero network traffic to target. Not included in campaign noise budget.

Hash types supported (hashcat modes):
  krb5tgs   → 13100 / 19700 / 19600  (from ad.kerberoast)
  krb5asrep → 18200                   (from ad.asreproast)
  ntlm      → 1000                    (from ad.dcsync, windows.lsa_secrets)
  netntlmv2 → 5600                    (from lateral.smb_relay)
  sha512    → 1800                    (from linux /etc/shadow)
"""
from __future__ import annotations

from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.crack")

# Hashcat mode mapping per credential type
_HASHCAT_MODES: dict[str, int] = {
    "krb5tgs":   13100,   # Kerberoast RC4
    "krb5tgs17": 19700,   # Kerberoast AES128
    "krb5tgs18": 19600,   # Kerberoast AES256
    "krb5asrep": 18200,   # ASREPRoast
    "ntlm":      1000,    # NTLM
    "lm":        3000,    # LM
    "netntlmv2": 5600,    # NetNTLMv2
    "sha512":    1800,    # sha512crypt (Linux)
    "md5":       500,     # md5crypt
}

# Priority per hash type (lower = cracked first; NTLM is fastest)
_CRACK_PRIORITY: dict[str, int] = {
    "ntlm":      1,
    "lm":        2,
    "netntlmv2": 3,
    "krb5asrep": 4,
    "krb5tgs":   5,
    "sha512":    6,
    "md5":       7,
}


class CrackModule(BaseModule):
    """
    credential.crack — "Crack hashes in CredentialVault using hashcat (GPU

    OPSEC: LOCAL
    MITRE: "T1110.002"
    REQUIRES: "vault"
    OUTPUTS:  "cracked_credentials"
    """
    MODULE_ID          = "credential.crack"
    MODULE_NAME        = "Hash Cracking"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = (
        "Crack hashes in CredentialVault using hashcat (GPU) or john (CPU fallback). "
        "Cracked plaintext is stored back to vault, immediately available for reuse."
    )
    OPSEC_LEVEL        = OpsecLevel.LOCAL   # local only — zero network traffic
    REQUIRES           = ["vault"]
    OUTPUTS            = ["cracked_credentials"]
    MITRE_TECHNIQUES   = ["T1110.002"]
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    MODULE_TIMEOUT_SECONDS: int | None = 3600  # seconds

    async def validate(self, ctx: "Any") -> None:
        """Enforce vault has hash credentials to crack."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        vault = getattr(ctx, "vault", None)
        if not vault:
            raise ModuleValidationError(
                "credential.crack requires a CredentialVault — "
                "run ad.kerberoast, ad.asreproast, or ad.dcsync first.",
                module_id=self.MODULE_ID, field="vault",
            )
        # Check there are actually hashes to crack
        from ares.credential.vault import CredentialType
        hashes = [
            c for c in vault._store.values()
            if c.is_hash and not c.cracked and c.active
        ]
        if not hashes:
            raise ModuleValidationError(
                "No uncracked hashes found in vault. "
                "Run ad.kerberoast / ad.asreproast / ad.dcsync first, "
                "or all hashes have already been cracked.",
                module_id=self.MODULE_ID, field="vault",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        vault        = getattr(ctx, "vault", None)
        timeout_s    = int(ctx.params.get("timeout_seconds", 3600))
        use_gpu      = bool(ctx.params.get("use_gpu", True))
        wordlist     = ctx.params.get("wordlist", "")

        findings, raw = await self.run(
            vault=vault, timeout_s=timeout_s, use_gpu=use_gpu, wordlist=wordlist,
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.crack")
    async def run(self, vault: "Any" = None, timeout_s: int = 3600,
                  use_gpu: bool = True, wordlist: str = "", **kwargs: Any):
        # Note: before_request() intentionally not called — credential.crack is
        # OpsecLevel.LOCAL (offline hash cracking, no network calls).
        # Scope, jitter, and rate-limit checks apply only to network-facing operations.
        from ares.credential.cracker import CrackingWorker, CrackingQueue, CrackJob, CrackStatus
        from ares.credential.vault import CredentialType

        if vault is None:
            return [], {"error": "no_vault_provided"}

        # Collect all uncracked hash credentials from vault
        hash_creds = [
            c for c in vault._store.values()
            if c.is_hash and not c.cracked and c.active
        ]

        if not hash_creds:
            return [], {"cracked": 0, "total": 0, "skipped": "no_hashes_in_vault"}

        logger.info("crack_start", total_hashes=len(hash_creds))
        audit("credential_crack", actor="operator", technique="T1110.002",
              detail=f"hashes={len(hash_creds)}")

        # Build CrackingWorker
        worker = CrackingWorker(
            vault=vault,
            timeout_s=timeout_s,
            use_gpu=use_gpu,
        )

        # Override wordlist if provided
        if wordlist:
            from pathlib import Path
            if Path(wordlist).exists():
                worker._wordlist = Path(wordlist)

        # Report tool availability before starting
        tools = worker.tool_status()
        if not tools["hashcat"]["available"] and not tools["john"]["available"]:
            logger.warning("crack_no_tool",
                           msg="Install hashcat or john-the-ripper for cracking")
            return [], {
                "error": "no_cracking_tool_available",
                "hint": "Install hashcat (GPU) or john (CPU): apt install hashcat john",
                "tools": tools,
            }

        queue = CrackingQueue(worker)

        # Map CredentialType → hash type string + hashcat mode
        def _hash_type(cred_type: CredentialType) -> tuple[str, int]:
            mapping = {
                CredentialType.KRB5_TGS:   ("krb5tgs",   13100),
                CredentialType.KRB5_ASREP: ("krb5asrep", 18200),
                CredentialType.NTLM:       ("ntlm",      1000),
            }
            return mapping.get(cred_type, ("ntlm", 1000))

        # Submit jobs ordered by crack priority (fastest first)
        for cred in hash_creds:
            hash_str  = vault.reveal(cred.id)
            if not hash_str:
                continue
            ht, mode = _hash_type(cred.cred_type)
            priority  = _CRACK_PRIORITY.get(ht, 9)
            job = CrackJob(
                cred_id      = cred.id,
                hash_value   = hash_str,
                hash_type    = ht,
                hashcat_mode = mode,
                username     = cred.username,
                domain       = cred.domain or "",
            )
            queue.submit(job, priority=priority)

        # Run until all jobs complete
        results = await queue.run_until_empty()

        cracked   = [r for r in results if r.status == CrackStatus.CRACKED]
        failed    = [r for r in results if r.status == CrackStatus.FAILED]
        skipped   = [r for r in results if r.status == CrackStatus.SKIPPED]

        logger.info("crack_complete",
                    cracked=len(cracked), failed=len(failed), skipped=len(skipped))

        # Generate findings — one per cracked credential (no plaintext in finding)
        if cracked:
            usernames = [r.username for r in cracked if r.username]
            self.finding(
                title       = f"Hash Cracking: {len(cracked)}/{len(results)} Hashes Cracked",
                description = (
                    f"Successfully cracked {len(cracked)} of {len(results)} hashes "
                    f"using {cracked[0].tool_used if cracked else 'hashcat/john'}. "
                    "Plaintext credentials stored in vault — "
                    "immediately available for credential.reuse and lateral movement."
                ),
                severity    = Severity.CRITICAL,
                mitre_technique = "T1110.002",
                mitre_tactic    = "Credential Access",
                evidence = {
                    "cracked_count": len(cracked),
                    "total_hashes":  len(results),
                    "usernames":     usernames[:20],
                    "tools_used":    list({r.tool_used for r in cracked}),
                    "avg_time_s":    round(
                        sum(r.elapsed_s for r in cracked) / len(cracked), 1
                    ) if cracked else 0,
                },
                remediation = (
                    "Enforce strong password policy (min 15 chars, complexity). "
                    "Migrate Kerberos service accounts to gMSA (auto-rotating, "
                    "240-char random passwords — uncrackable). "
                    "Enable AES-256 Kerberos encryption, disable RC4."
                ),
            )

        raw = {
            "cracked":             len(cracked),
            "cracked_credentials": [{"username": r.username, "domain": r.domain,
                                     "hash_type": r.hash_type}
                                    for r in cracked],   # OUTPUTS key
            "failed":        len(failed),
            "skipped":       len(skipped),
            "total":         len(results),
            "cracked_users": [{"username": r.username, "domain": r.domain,
                               "hash_type": r.hash_type, "tool": r.tool_used,
                               "elapsed_s": r.elapsed_s}
                              for r in cracked],   # no plaintext here
            "tools":         tools,
            "wordlist":      str(worker._wordlist) if worker._wordlist else None,
        }
        return self._findings[:], raw
