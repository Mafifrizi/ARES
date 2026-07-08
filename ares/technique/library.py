"""
ARES MITRE ATT&CK Technique Library
Complete mapping of all ARES modules to MITRE ATT&CK techniques.

Provides:
  - TechniqueLibrary: queryable technique database (ATT&CK Enterprise)
  - TechniqueMapper: maps module IDs ↔ technique IDs
  - CoverageReport: generates attack coverage heatmap per tactic
  - SimulationPlan: produces purple team simulation plan from techniques

Usage:
    lib = TechniqueLibrary()
    t = lib.get("T1558.003")          # Kerberoasting
    t.tactic                           # "Credential Access"
    t.detection                        # detection guidance
    t.mitigations                      # list of mitigations

    mapper = TechniqueMapper()
    techniques = mapper.for_module("ad.kerberoast")
    modules    = mapper.modules_for_technique("T1558.003")

    report = CoverageReport(mapper)
    report.coverage_by_tactic()        # {"Credential Access": 0.72, ...}
    report.to_html()                   # full heatmap HTML
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Technique:
    """A single MITRE ATT&CK technique or sub-technique."""
    technique_id:   str          # e.g. T1558.003
    name:           str
    tactic:         str          # primary tactic
    tactics:        list[str]    # all applicable tactics
    description:    str
    platforms:      list[str]    # Windows | Linux | macOS | Cloud | etc.
    permissions:    list[str]    # permissions required
    data_sources:   list[str]    # data sources for detection
    detection:      str          # detection guidance
    mitigations:    list[str]    # mitigation IDs / descriptions
    is_subtechnique: bool = False
    parent_id:      str = ""     # parent technique if subtechnique
    url:            str = ""
    severity:       str = "high" # ares-internal severity for reporting

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":           self.technique_id,
            "name":         self.name,
            "tactic":       self.tactic,
            "tactics":      self.tactics,
            "description":  self.description,
            "platforms":    self.platforms,
            "detection":    self.detection,
            "mitigations":  self.mitigations,
            "severity":     self.severity,
            "url":          self.url,
        }


# ── Technique database ─────────────────────────────────────────────────────────
# Selected ATT&CK Enterprise v14 techniques relevant to ARES modules

_TECHNIQUES: list[dict[str, Any]] = [
    # ── Credential Access ──────────────────────────────────────────────────
    {
        "id": "T1649",
        "name": "Steal or Forge Authentication Certificates",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may steal or forge certificates used for authentication to access systems. ADCS ESC1-ESC8 misconfigurations allow low-privileged users to obtain certificates as Domain Admin.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["Active Directory: Active Directory Object Modification", "Windows Registry"],
        "detection": "Monitor for certificate enrollment events (Event ID 4886/4887). Alert on certificate requests with UPN SANs differing from requestor. Review certificate template permissions.",
        "mitigations": ["Audit certificate template permissions", "Disable enrollee-supplied SAN", "Enable CA Manager Approval", "Monitor for certipy/Certify tool usage"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1649/",
    },
    {
        "id": "T1187",
        "name": "Forced Authentication",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information. PetitPotam, PrinterBug, and DFSCoerce force Windows hosts to authenticate to attacker-controlled systems.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["Network Traffic", "File: File Access"],
        "detection": "Monitor for MS-EFSRPC EfsRpcOpenFileRaw calls. Alert on Spooler RPC connections from unexpected sources. Monitor for Event ID 4624 with unexpected source IPs.",
        "mitigations": ["Disable Print Spooler on DCs", "Apply MS-EFSRPC patches (KB5005413)", "Enable Protected Users group for all privileged accounts"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1187/",
    },
    {
        "id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). COMSVCS.DLL MiniDump is the most common technique.",
        "platforms": ["Windows"],
        "permissions": ["SYSTEM"],
        "data_sources": ["Process: Process Access", "Windows Registry"],
        "detection": "Monitor Sysmon Event ID 10 (Process Access) for LSASS. Alert on rundll32.exe comsvcs.dll MiniDump pattern. Enable Credential Guard.",
        "mitigations": ["Enable Windows Credential Guard", "Disable WDigest authentication", "Enable Protected Process Light (PPL) for LSASS", "Deploy EDR with LSASS protection"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    {
        "id": "T1555.004",
        "name": "Credentials from Password Stores: Windows Credential Manager",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may acquire credentials from the Windows Credential Manager. DPAPI-protected credentials include Windows Vault entries, browser saved passwords, WiFi PSK, and RDP saved credentials.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["File: File Access", "Process: OS API Execution"],
        "detection": "Monitor access to %APPDATA%\\Microsoft\\Credentials and Chrome Login Data. Alert on CryptUnprotectData API calls from unexpected processes.",
        "mitigations": ["Enable Credential Guard", "Use hardware-backed credential storage", "Disable browser password saving via enterprise policy"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1555/004/",
    },
    {
        "id": "T1558.001",
        "name": "Steal or Forge Kerberos Tickets: Golden Ticket",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may forge Kerberos TGTs using the krbtgt account NTLM hash. Also covers Kerberos delegation abuse (RBCD, S4U2Self/S4U2Proxy) to obtain service tickets impersonating privileged users.",
        "platforms": ["Windows"],
        "permissions": ["User", "Administrator"],
        "data_sources": ["Active Directory: Active Directory Credential Request"],
        "detection": "Monitor for Kerberos tickets with unusual PAC contents or extended lifetimes. Alert on msDS-AllowedToActOnBehalfOfOtherIdentity modifications. Track S4U2Self requests.",
        "mitigations": ["Rotate krbtgt TWICE with 12h interval", "Enable Kerberos armoring (FAST)", "Audit RBCD configurations", "Use Protected Users security group"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1558/001/",
    },
    {
        "id": "T1558",
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may steal or forge Kerberos tickets to maintain persistence and move laterally in an environment.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["Active Directory: Active Directory Credential Request", "Windows Registry"],
        "detection": "Monitor for Kerberos traffic anomalies (RC4 TGS requests when AES is expected). Alert on AS-REP responses for accounts with no pre-auth disabled. Track TGS request volume spikes.",
        "mitigations": ["M1041 - Encrypt sensitive information", "M1026 - Privileged Account Management", "Enable AES-only Kerberos encryption"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1558/",
    },
    {
        "id": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries request Kerberos TGS tickets for services and crack them offline to recover service account passwords.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["Active Directory: Active Directory Credential Request"],
        "detection": "Monitor for 4769 events with RC4 encryption. Detect unusual TGS volume from non-service accounts. Alert on hashcat/john execution on endpoints.",
        "mitigations": ["Use strong random passwords (25+ chars) for service accounts", "Use Group Managed Service Accounts (gMSA)", "Enable AES-256 Kerberos encryption"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1558/003/",
    },
    {
        "id": "T1558.004",
        "name": "AS-REP Roasting",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries request AS-REP hashes for accounts with pre-authentication disabled, without any credentials.",
        "platforms": ["Windows"],
        "permissions": ["None"],
        "data_sources": ["Active Directory: Active Directory Credential Request"],
        "detection": "Monitor for EventID 4768 (Kerberos Auth Ticket Request) without pre-auth for accounts that should require it. Alert on 4625 and 4768 from unexpected sources.",
        "mitigations": ["Enforce Kerberos pre-authentication on all accounts", "Audit accounts with DONT_REQUIRE_PREAUTH flag", "Use Microsoft ATA / Defender for Identity"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1558/004/",
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries attempt to dump credentials to obtain account login information.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["Administrator", "SYSTEM"],
        "data_sources": ["Process: OS API Execution", "File: File Access"],
        "detection": "Monitor LSASS access (EventID 10 Sysmon). Alert on mimikatz signatures. Detect unusual NTDS.dit or SAM access.",
        "mitigations": ["M1043 - Credential Access Protection (RunAsPPL)", "M1027 - Password Policies", "M1026 - Privileged Account Management"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    {
        "id": "T1003.006",
        "name": "DCSync",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries abuse AD replication protocol to request password hashes from DCs, simulating a domain controller.",
        "platforms": ["Windows"],
        "permissions": ["Administrator", "Domain Controller"],
        "data_sources": ["Active Directory: Active Directory Object Access", "Network Traffic"],
        "detection": "Monitor for 4662 events on domain objects with 'Replicating Directory Changes' rights. Alert on unusual sources requesting replication. Defender for Identity has built-in DCSync detection.",
        "mitigations": ["Restrict Replicating Directory Changes rights", "Enable Protected Users group", "Deploy Defender for Identity"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1003/006/",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries may use brute force techniques to gain access to accounts without proper authorization.",
        "platforms": ["Windows", "Linux", "macOS", "IaaS", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        "permissions": ["User"],
        "data_sources": ["Authentication: Authentication Log", "Application Log"],
        "detection": "Monitor failed authentication logs. Alert on 4625 spikes. Detect spray patterns (same password across many accounts). Enable account lockout policies.",
        "mitigations": ["M1036 - Account Use Policies (lockout)", "M1032 - Multi-factor Authentication", "M1027 - Password Policies"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    # ── Discovery ─────────────────────────────────────────────────────────
    {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries enumerate accounts in an Active Directory environment.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        "permissions": ["User"],
        "data_sources": ["Process: Process Creation", "Network Traffic", "Active Directory: Active Directory Object Access"],
        "detection": "Monitor LDAP queries for user enumeration. Alert on net user /domain commands. Detect unusual DirectorySearcher usage.",
        "mitigations": ["M1028 - Operating System Configuration", "M1018 - User Account Management"],
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    {
        "id": "T1087.002",
        "name": "Domain Account",
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries enumerate domain user accounts via LDAP, net commands, or PowerShell.",
        "platforms": ["Windows"],
        "permissions": ["User"],
        "data_sources": ["Active Directory: Active Directory Object Access", "Network Traffic: Network Traffic Content"],
        "detection": "Monitor EventID 4661, LDAP traffic for broad user enumeration queries. Alert on objectClass=user queries returning large result sets.",
        "mitigations": ["Restrict LDAP queries", "Monitor LDAP audit logs", "Use LDAP signing"],
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1087/002/",
    },
    {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries enumerate remote systems in a network.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "Process: Process Creation"],
        "detection": "Monitor ARP cache, LDAP computer enumeration, ping sweeps. Alert on unusual LDAP objectClass=computer queries.",
        "mitigations": ["Network segmentation", "Firewall rules limiting ping and discovery protocols"],
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    {
        "id": "T1201",
        "name": "Password Policy Discovery",
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries discover password policies to determine the optimal attack strategy.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User"],
        "data_sources": ["Active Directory: Active Directory Object Access"],
        "detection": "Monitor for net accounts /domain and LDAP queries against Default Domain Policy.",
        "mitigations": ["M1028 - Operating System Configuration"],
        "severity": "info",
        "url": "https://attack.mitre.org/techniques/T1201/",
    },
    {
        "id": "T1222",
        "name": "File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries modify file/directory permissions to evade detection or maintain persistence.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User", "Administrator"],
        "data_sources": ["File: File Metadata"],
        "detection": "Monitor ACL changes on sensitive objects. Alert on icacls/chmod for critical paths.",
        "mitigations": ["M1022 - Restrict File and Directory Permissions"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1222/",
    },
    {
        "id": "T1222.001",
        "name": "Windows File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "tactics": ["Defense Evasion"],
        "description": "Adversaries modify NTFS ACLs using icacls, takeown, or Set-Acl to prevent access or evade detection.",
        "platforms": ["Windows"],
        "permissions": ["User", "Administrator"],
        "data_sources": ["Active Directory: Active Directory Object Modification"],
        "detection": "Alert on EventID 4670 for sensitive objects. Monitor WriteDACL usage on AD objects.",
        "mitigations": ["Restrict WriteDACL permission on AD objects"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1222/001/",
    },
    # ── Lateral Movement ──────────────────────────────────────────────────
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries use valid accounts to log into a service specifically designed to accept remote connections.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["Administrator", "User"],
        "data_sources": ["Logon Session: Logon Session Creation", "Network Traffic"],
        "detection": "Monitor for unusual remote service logons. Alert on 4624 Type 3/10 from unexpected sources.",
        "mitigations": ["M1035 - Limit Access to Resource Over Network", "M1032 - MFA"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries use RDP to move laterally across systems.",
        "platforms": ["Windows"],
        "permissions": ["Administrator", "User"],
        "data_sources": ["Logon Session: Logon Session Creation", "Network Traffic"],
        "detection": "Monitor EventID 4624 Type 10. Alert on RDP from non-standard sources. Enable RDP logging.",
        "mitigations": ["Network segmentation", "M1035 - Limit access", "M1032 - MFA"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    {
        "id": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries use SMB to copy files or tools to remote systems and execute them.",
        "platforms": ["Windows"],
        "permissions": ["Administrator"],
        "data_sources": ["Network File Share: Network Share Access", "Process: Process Creation"],
        "detection": "Monitor SMB access to admin shares (ADMIN$, C$). Alert on EventID 5140, 5145.",
        "mitigations": ["M1035 - Limit Access to Resource Over Network", "Disable unnecessary admin shares"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    {
        "id": "T1021.004",
        "name": "SSH",
        "tactic": "Lateral Movement",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries use SSH to move laterally across systems.",
        "platforms": ["Linux", "macOS"],
        "permissions": ["User"],
        "data_sources": ["Logon Session: Logon Session Creation", "Network Traffic"],
        "detection": "Monitor SSH authentication logs (/var/log/auth.log). Alert on key-based auth from unexpected sources.",
        "mitigations": ["M1042 - Disable or Remove Feature or Program", "Restrict SSH to known hosts"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    {
        "id": "T1021.006",
        "name": "Windows Remote Management",
        "tactic": "Lateral Movement",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries use WinRM to execute commands on remote Windows systems.",
        "platforms": ["Windows"],
        "permissions": ["Administrator"],
        "data_sources": ["Network Traffic", "Process: Process Creation"],
        "detection": "Monitor for unusual WinRM connections (port 5985/5986). Alert on PowerShell remoting from unexpected sources.",
        "mitigations": ["Disable WinRM where not required", "Network segmentation on ports 5985/5986"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1021/006/",
    },
    {
        "id": "T1047",
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "tactics": ["Execution", "Lateral Movement"],
        "description": "Adversaries use WMI to execute commands on remote systems or locally.",
        "platforms": ["Windows"],
        "permissions": ["Administrator"],
        "data_sources": ["Process: Process Creation", "WMI: WMI Creation"],
        "detection": "Monitor Sysmon EventID 19/20/21 (WmiActivity). Alert on Win32_Process.Create from suspicious callers.",
        "mitigations": ["M1026 - Privileged Account Management", "Network segmentation on DCOM ports"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1047/",
    },
    {
        "id": "T1569.002",
        "name": "Service Execution",
        "tactic": "Execution",
        "tactics": ["Execution"],
        "description": "Adversaries create or modify a service to execute malicious payloads (e.g., PsExec-style).",
        "platforms": ["Windows"],
        "permissions": ["Administrator", "SYSTEM"],
        "data_sources": ["Process: Process Creation", "Windows Registry"],
        "detection": "Alert on EventID 7045 (new service install), 7036 (service start). Monitor SCM access from unusual sources.",
        "mitigations": ["M1022 - Restrict File and Directory Permissions", "M1026 - Privileged Account Management"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1569/002/",
    },
    # ── Privilege Escalation ──────────────────────────────────────────────
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries bypass elevation controls to run with higher privileges.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User", "Administrator"],
        "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        "detection": "Monitor for UAC bypass patterns, sudo abuse, SUID exploitation.",
        "mitigations": ["M1047 - Audit", "Enable UAC prompt for all elevation"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "tactics": ["Privilege Escalation"],
        "description": "Adversaries break out of a containerized environment to access the underlying host.",
        "platforms": ["Containers"],
        "permissions": ["Administrator", "User", "root"],
        "data_sources": ["Container: Container Creation", "Process: Process Creation"],
        "detection": "Alert on privileged container creation. Monitor for docker.sock access from containers. Detect --privileged flag.",
        "mitigations": ["M1048 - Application Isolation and Sandboxing", "Avoid privileged containers"],
        "severity": "critical",
        "url": "https://attack.mitre.org/techniques/T1611/",
    },
    # ── Cloud ─────────────────────────────────────────────────────────────
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries use valid credentials to maintain access and evade detection.",
        "platforms": ["Windows", "Linux", "macOS", "IaaS", "Azure AD", "Office 365", "SaaS", "Google Workspace"],
        "permissions": ["User"],
        "data_sources": ["Authentication: Authentication Log", "Logon Session"],
        "detection": "Correlate login anomalies (unusual time, location, device). Detect credential stuffing.",
        "mitigations": ["M1032 - Multi-factor Authentication", "M1036 - Account Use Policies"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "tactics": ["Collection"],
        "description": "Adversaries access data from cloud storage objects (S3, Azure Blob, GCS).",
        "platforms": ["IaaS", "Google Workspace"],
        "permissions": ["User"],
        "data_sources": ["Cloud Storage: Cloud Storage Access"],
        "detection": "Monitor S3/GCS/Azure storage access logs for unusual patterns. Alert on public bucket access.",
        "mitigations": ["M1022 - Restrict File and Directory Permissions", "M1041 - Encrypt Sensitive Information"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "description": "Adversaries search for credentials in files, environment variables, or cloud metadata.",
        "platforms": ["Windows", "Linux", "macOS", "IaaS", "Azure AD"],
        "permissions": ["User"],
        "data_sources": ["File: File Access", "Process: Process Creation"],
        "detection": "Monitor for credential file access patterns. Alert on cloud metadata endpoint access.",
        "mitigations": ["Avoid storing credentials in code/config", "Use secrets manager", "IMDSv2"],
        "severity": "high",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "tactics": ["Command and Control"],
        "description": "Adversaries use proxies to disguise C2 traffic or route through intermediary systems.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "permissions": ["User"],
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "detection": "Monitor for SOCKS proxy indicators. Alert on unexpected SSH tunneling. Detect encrypted traffic on non-standard ports.",
        "mitigations": ["Network segmentation", "Monitor and restrict proxy usage"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1090/",
    },
    {
        "id": "T1090.001",
        "name": "Internal Proxy",
        "tactic": "Command and Control",
        "tactics": ["Command and Control"],
        "description": "Adversaries use internal proxies to relay C2 traffic through compromised hosts.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User"],
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "detection": "Monitor for SOCKS proxy connections. Alert on unusual port forwarding configurations.",
        "mitigations": ["Network segmentation", "Endpoint detection for proxy tools"],
        "severity": "medium",
        "url": "https://attack.mitre.org/techniques/T1090/001/",
    },
    {
        "id": "T1135",
        "name": "Network Share Discovery",
        "tactic": "Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries enumerate network shares on remote systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "permissions": ["User"],
        "data_sources": ["Network Traffic", "Process: Process Creation"],
        "detection": "Monitor net view commands, NetShareEnum API calls. Alert on broad share enumeration.",
        "mitigations": ["Restrict file/printer sharing", "Remove unnecessary shares"],
        "severity": "low",
        "url": "https://attack.mitre.org/techniques/T1135/",
    },
]


class TechniqueLibrary:
    """
    Queryable MITRE ATT&CK technique database.
    Covers all techniques used by ARES modules.
    """

    def __init__(self) -> None:
        self._by_id:     dict[str, Technique] = {}
        self._by_tactic: dict[str, list[Technique]] = {}
        self._load()

    def _load(self) -> None:
        for entry in _TECHNIQUES:
            tech = Technique(
                technique_id  = entry["id"],
                name          = entry["name"],
                tactic        = entry["tactic"],
                tactics       = entry["tactics"],
                description   = entry["description"],
                platforms     = entry["platforms"],
                permissions   = entry.get("permissions", []),
                data_sources  = entry.get("data_sources", []),
                detection     = entry["detection"],
                mitigations   = entry["mitigations"],
                severity      = entry.get("severity", "medium"),
                is_subtechnique = "." in entry["id"],
                parent_id     = entry["id"].split(".")[0] if "." in entry["id"] else "",
                url           = entry.get("url", ""),
            )
            self._by_id[tech.technique_id] = tech
            for tactic in tech.tactics:
                self._by_tactic.setdefault(tactic, []).append(tech)

    def get(self, technique_id: str) -> Technique | None:
        return self._by_id.get(technique_id)

    def by_tactic(self, tactic: str) -> list[Technique]:
        return self._by_tactic.get(tactic, [])

    def search(self, query: str) -> list[Technique]:
        q = query.lower()
        return [
            t for t in self._by_id.values()
            if q in t.technique_id.lower()
            or q in t.name.lower()
            or q in t.tactic.lower()
            or q in t.description.lower()
        ]

    def all_tactics(self) -> list[str]:
        return sorted(set(
            tac for t in self._by_id.values() for tac in t.tactics
        ))

    def all(self) -> list[Technique]:
        return list(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)


# ── Module → Technique mapping ────────────────────────────────────────────────

_MODULE_TECHNIQUE_MAP: dict[str, list[str]] = {
    # ── Active Directory ──────────────────────────────────────────────────────
    "ad.enum_users":          ["T1087.002", "T1201"],
    "ad.enum_computers":      ["T1018", "T1087.002"],
    "ad.enum_spn":            ["T1558.003", "T1087.002"],
    "ad.enum_acl":            ["T1222.001", "T1003.006"],
    "ad.kerberoast":          ["T1558.003"],
    "ad.asreproast":          ["T1558.004"],
    "ad.dcsync":              ["T1003.006"],
    "ad.adcs":                ["T1649"],
    "ad.delegation_abuse":    ["T1558.001", "T1134.001"],
    "ad.coerce":              ["T1187"],
    "ad.laps_enum":           ["T1552.004"],
    # ── Credential Access ─────────────────────────────────────────────────────
    "credential.pass_the_hash":   ["T1550.002"],
    "credential.pass_spray":      ["T1110.003"],
    "credential.golden_ticket":   ["T1558.001"],
    "credential.reuse":           ["T1078", "T1550.002"],
    "credential.crack":           ["T1110.002"],
    # ── Lateral Movement ──────────────────────────────────────────────────────
    "lateral.psexec":         ["T1569.002", "T1021.002"],
    "lateral.wmiexec":        ["T1047"],
    "lateral.dcom":           ["T1021.003"],
    "lateral.winrm":          ["T1021.006"],
    "lateral.ssh_pivot":      ["T1021.004", "T1090.001"],
    "lateral.rdp":            ["T1021.001"],
    "lateral.smb_relay":      ["T1557.001"],
    "lateral.mssql":          ["T1505.001"],
    # ── Persistence ───────────────────────────────────────────────────────────
    "persistence.scheduled_task":   ["T1053.005"],
    "persistence.wmi_subscription": ["T1546.003"],
    "persistence.registry_run":     ["T1547.001"],
    # ── Exfiltration ──────────────────────────────────────────────────────────
    "exfil.smb_shares":        ["T1039", "T1021.002"],
    "exfil.secrets_scan":      ["T1552"],
    "exfil.staged_collection": ["T1074.002"],
    # ── Windows Post-Exploitation ─────────────────────────────────────────────
    "windows.lsa_secrets":         ["T1003.002", "T1003.004"],
    "windows.lsass_dump":          ["T1003.001"],
    "windows.dpapi":               ["T1555.004", "T1555.003"],
    "windows.token_impersonation": ["T1134.001"],
    "windows.uac_bypass":          ["T1548.002"],
    "windows.applocker_bypass":    ["T1218"],
    "windows.registry_enum":       ["T1012"],
    "windows.scheduled_tasks_enum": ["T1053.005"],
    # ── Linux ────────────────────────────────────────────────────────────────
    "linux.privesc":          ["T1548.001", "T1053.003"],
    "linux.kernel_suggester": ["T1068"],
    "linux.ld_preload":       ["T1574.006"],
    "linux.service_hijack":   ["T1574.010"],
    "linux.nfs_escape":       ["T1611"],
    "linux.container":        ["T1611"],
    # ── Cloud ────────────────────────────────────────────────────────────────
    "cloud.aws":          ["T1526", "T1530", "T1552.005", "T1580"],
    "cloud.aws_privesc":  ["T1078.004", "T1548", "T1098"],
    "cloud.azure":        ["T1526", "T1530", "T1580", "T1078.004"],
    "cloud.gcp":          ["T1526", "T1530", "T1552.005", "T1580"],
    "cloud.azure_ad":     ["T1528", "T1606"],
    # ── Network ──────────────────────────────────────────────────────────────
    "network.port_scan":       ["T1046"],
    "network.service_detect":  ["T1046"],
    "network.dns_enum":        ["T1590.002"],
    "network.http_fingerprint": ["T1595.002"],
    "network.snmp_enum":       ["T1046"],
    "network.pivot":           ["T1090.001", "T1021.004"],
    # ── Recon & Reporting ────────────────────────────────────────────────────
    "recon.fingerprint":    ["T1082", "T1518.001"],
    "reporting.report_gen":              [],   # no offensive technique — output only
    # ── New strategic modules ─────────────────────────────────────────────────
    "opsec.coverage_predictor":          ["T1592"],
    "edr.bypass_adaptive":               ["T1562.001", "T1055", "T1027", "T1562.006"],
    "cloud.identity_federation_abuse":   ["T1606.002", "T1528", "T1550.001", "T1484.002"],
    "ai.autonomous_planner":             ["T1591"],

}


class TechniqueMapper:
    """Maps module IDs to MITRE techniques and vice versa."""

    def __init__(self, library: TechniqueLibrary | None = None) -> None:
        self.library = library or TechniqueLibrary()

    def for_module(self, module_id: str) -> list[Technique]:
        """Return all techniques associated with a module."""
        ids = _MODULE_TECHNIQUE_MAP.get(module_id, [])
        return [t for t in (self.library.get(tid) for tid in ids) if t]

    def modules_for_technique(self, technique_id: str) -> list[str]:
        """Return all module IDs that implement a technique."""
        return [
            mid for mid, tids in _MODULE_TECHNIQUE_MAP.items()
            if technique_id in tids
        ]

    def coverage_for_modules(self, module_ids: list[str]) -> dict[str, Any]:
        """Compute MITRE ATT&CK coverage for a set of modules."""
        covered_techniques: set[str] = set()
        covered_tactics:    set[str] = set()

        for mid in module_ids:
            for tech in self.for_module(mid):
                covered_techniques.add(tech.technique_id)
                covered_tactics.update(tech.tactics)

        all_tactics    = set(self.library.all_tactics())
        all_techniques = len(self.library)

        return {
            "techniques_covered": sorted(covered_techniques),
            "tactics_covered":    sorted(covered_tactics),
            "technique_count":    len(covered_techniques),
            "tactic_count":       len(covered_tactics),
            "technique_coverage": round(len(covered_techniques) / max(all_techniques, 1), 3),
            "tactic_coverage":    round(len(covered_tactics) / max(len(all_tactics), 1), 3),
            "tactic_breakdown": {
                tactic: [
                    t.technique_id for t in self.library.by_tactic(tactic)
                    if t.technique_id in covered_techniques
                ]
                for tactic in covered_tactics
            },
        }


class CoverageReport:
    """Generates MITRE ATT&CK coverage heatmap from executed modules."""

    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    def __init__(self, mapper: TechniqueMapper) -> None:
        self.mapper  = mapper
        self.library = mapper.library

    def from_findings(self, findings: list[Any]) -> dict[str, Any]:
        """Build coverage from campaign findings (each has mitre_technique field)."""
        technique_ids: set[str] = set()
        for f in findings:
            tid = getattr(f, "mitre_technique", "") or ""
            if tid:
                technique_ids.add(tid)

        covered: list[Technique] = [
            t for t in (self.library.get(tid) for tid in technique_ids) if t
        ]
        tactics_covered = set(tac for t in covered for tac in t.tactics)

        return {
            "total_techniques": len(technique_ids),
            "by_tactic": {
                tactic: [t.to_dict() for t in covered if tactic in t.tactics]
                for tactic in self.TACTIC_ORDER
                if tactic in tactics_covered
            },
        }

    def to_html_heatmap(self, coverage: dict[str, Any]) -> str:
        """Generate MITRE heatmap HTML fragment."""
        rows: list[str] = []
        by_tactic = coverage.get("by_tactic", {})
        for tactic in self.TACTIC_ORDER:
            techs = by_tactic.get(tactic, [])
            color = "#ef4444" if techs else "#1e293b"
            border = "border: 2px solid #ef4444;" if techs else ""
            tech_tags = "".join(
                f'<span style="background:#450a0a;color:#f87171;padding:2px 6px;'
                f'border-radius:3px;font-size:.75rem;margin:2px;display:inline-block">'
                f'{t["id"]}</span>'
                for t in techs[:5]
            )
            empty_tags = "<span style='color:#475569;font-size:.75rem'>&mdash;</span>"
            rendered_tags = tech_tags if techs else empty_tags
            rows.append(
                f'<div style="background:{color};{border}border-radius:6px;'
                f'padding:8px 10px;min-width:140px">'
                f'<div style="font-size:.72rem;color:#94a3b8;text-transform:uppercase;'
                f'letter-spacing:.04em">{tactic}</div>'
                f'{rendered_tags}'
                f'</div>'
            )
        return (
            '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));'
            'gap:.5rem">' + "".join(rows) + "</div>"
        )
