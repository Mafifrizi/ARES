"""
ARES Artifact Correlation Engine
Combines multiple artifact types to automatically discover lateral movement
and privilege escalation opportunities.

Correlation rules:

  RULE-01 (Credential + Host):
    credential(domain_admin) + host(domain_member)
    → OPPORTUNITY: domain_admin can pwn this host

  RULE-02 (Credential + Service):
    credential(svc_sql) + host(port 1433 open)
    → OPPORTUNITY: SQL service account may have DB admin

  RULE-03 (SPN + Credential + Host):
    user(spn=MSSQLSvc/db01) + credential(domain_user)
    → OPPORTUNITY: kerberoastable path to DB server

  RULE-04 (Permission + Credential):
    permission(WriteDACL on Domain Admins) + credential(user_with_dacl)
    → OPPORTUNITY: privilege escalation to DA via ACL abuse

  RULE-05 (Host + Credential + Reachability):
    host(dc01, port 445) + credential(any domain cred)
    → OPPORTUNITY: dcsync possible if priv escalated first

  RULE-06 (Hash + Host + Service):
    hash(ntlm, admin) + host(port 445 open)
    → OPPORTUNITY: pass-the-hash lateral movement

  RULE-07 (Cloud + Credential):
    cloud_resource(S3 public) + credential(aws_key)
    → OPPORTUNITY: expand S3 access / pivot to EC2

Output: CorrelationOpportunity list, sorted by severity and confidence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ares.core.logger import get_logger
from ares.normalize.artifacts import (
    ArtifactStore, CredentialArtifact, HashArtifact,
    HostArtifact, PermissionArtifact, UserArtifact,
    CloudResourceArtifact, ArtifactType,
)

logger = get_logger("ares.artifact_intel.correlation")


@dataclass
class CorrelationOpportunity:
    """A discovered attack opportunity from artifact correlation."""
    opportunity_id: str = ""
    rule_id:         str = ""
    title:           str = ""
    description:     str = ""
    severity:        str = "medium"   # critical | high | medium | low
    confidence:      float = 0.8
    attack_modules:  list[str] = field(default_factory=list)
    involved_artifacts: list[str] = field(default_factory=list)   # artifact UIDs
    params:          dict[str, Any] = field(default_factory=dict)
    discovered_at:   float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                 self.opportunity_id,
            "rule":               self.rule_id,
            "title":              self.title,
            "description":        self.description,
            "severity":           self.severity,
            "confidence":         self.confidence,
            "attack_modules":     self.attack_modules,
            "involved_artifacts": self.involved_artifacts,
            "params":             self.params,
        }


class ArtifactCorrelationEngine:
    """
    Correlates multiple artifact types to find compound attack opportunities.
    Each rule is independent and auditable.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()   # dedup by rule+artifact combo

    def correlate(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        Run all correlation rules against the artifact store.
        Returns deduplicated list of opportunities, sorted by severity.
        """
        opportunities: list[CorrelationOpportunity] = []

        opportunities.extend(self._rule_01_da_cred_host(store))
        opportunities.extend(self._rule_02_service_account_cred(store))
        opportunities.extend(self._rule_03_spn_lateral(store))
        opportunities.extend(self._rule_04_dacl_escalation(store))
        opportunities.extend(self._rule_05_dc_dcsync_path(store))
        opportunities.extend(self._rule_06_pth_lateral(store))
        opportunities.extend(self._rule_07_cloud_expansion(store))

        # Deduplicate
        unique: list[CorrelationOpportunity] = []
        for opp in opportunities:
            key = f"{opp.rule_id}:{':'.join(sorted(opp.involved_artifacts))}"
            if key not in self._seen:
                self._seen.add(key)
                unique.append(opp)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda o: (severity_order.get(o.severity, 4), -o.confidence))

        if unique:
            logger.info("correlation_opportunities_found",
                        count=len(unique),
                        titles=[o.title for o in unique[:5]])
        return unique

    # ── Correlation rules ──────────────────────────────────────────────────

    def _rule_01_da_cred_host(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-01: Domain admin credential + any domain host
        → Can directly pwn every host in domain.
        """
        opps: list[CorrelationOpportunity] = []
        da_creds = [
            c for c in store.credentials()
            if c.privilege in ("domain_admin", "enterprise_admin")
        ]
        if not da_creds:
            return opps

        hosts = store.hosts()
        for host in hosts[:20]:   # cap to avoid explosion
            for cred in da_creds[:3]:
                target = host.fqdn or host.hostname or host.ip_address
                opps.append(CorrelationOpportunity(
                    opportunity_id = f"rule01-{cred.uid[:6]}-{host.uid[:6]}",
                    rule_id        = "RULE-01",
                    title          = f"Domain Admin credential can access {target}",
                    description    = (
                        f"Credential {cred.username}@{cred.domain} has {cred.privilege} "
                        f"privilege. Can authenticate to {target} via SMB/WinRM/RDP."
                    ),
                    severity       = "critical",
                    confidence     = 0.95,
                    attack_modules = ["lateral.psexec", "lateral.winrm", "lateral.wmiexec"],
                    involved_artifacts = [cred.uid, host.uid],
                    params         = {
                        "target":   target,
                        "username": cred.username,
                        "domain":   cred.domain,
                    },
                ))
        return opps

    def _rule_02_service_account_cred(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-02: Service account credential + host with matching service
        → Service account may have elevated DB/app access.
        """
        opps: list[CorrelationOpportunity] = []
        svc_creds = [c for c in store.credentials() if c.privilege == "service_account"]
        if not svc_creds:
            return opps

        for cred in svc_creds:
            uname_lower = cred.username.lower()
            # Pattern matching: svc_sql → MSSQL, svc_iis → IIS, etc.
            service_hints: list[tuple[str, int, str]] = [
                ("sql", 1433, "MSSQL"),
                ("iis", 80,   "IIS"),
                ("oracle", 1521, "Oracle"),
                ("mysql", 3306, "MySQL"),
            ]
            for hint, port, svc_name in service_hints:
                if hint in uname_lower:
                    # Find hosts with matching port
                    hosts_with_svc = [
                        h for h in store.hosts()
                        if port in (h.open_ports or [])
                    ]
                    for host in hosts_with_svc:
                        target = host.fqdn or host.hostname or host.ip_address
                        opps.append(CorrelationOpportunity(
                            opportunity_id = f"rule02-{cred.uid[:6]}-{host.uid[:6]}",
                            rule_id        = "RULE-02",
                            title          = f"{svc_name} service account {cred.username} matches service on {target}",
                            description    = (
                                f"Service account {cred.username} likely has elevated access "
                                f"to {svc_name} on {target}:{port}."
                            ),
                            severity       = "high",
                            confidence     = 0.75,
                            attack_modules = ["credential.reuse"],
                            involved_artifacts = [cred.uid, host.uid],
                            params         = {
                                "target":      target,
                                "port":        port,
                                "cred_id":     cred.uid,
                                "service":     svc_name,
                            },
                        ))
        return opps

    def _rule_03_spn_lateral(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-03: Kerberoastable SPN user + any valid credential
        → Kerberoast → crack → lateral to service host.
        """
        opps: list[CorrelationOpportunity] = []
        spn_users = [u for u in store.users() if u.is_kerberoastable and u.enabled]
        any_creds  = store.credentials()
        if not spn_users or not any_creds:
            return opps

        for user in spn_users[:5]:
            for spn in user.spns[:2]:
                # Parse SPN: service/host:port
                parts = spn.split("/")
                service = parts[0] if parts else ""
                host_part = parts[1].split(":")[0] if len(parts) > 1 else ""
                opps.append(CorrelationOpportunity(
                    opportunity_id = f"rule03-{user.uid[:6]}",
                    rule_id        = "RULE-03",
                    title          = f"Kerberoast path via {user.username} → {host_part}",
                    description    = (
                        f"User {user.username}@{user.domain} has SPN {spn!r}. "
                        f"Kerberoast → crack hash → lateral to {host_part} as service={service}."
                    ),
                    severity       = "high",
                    confidence     = 0.85,
                    attack_modules = ["ad.kerberoast", "credential.crack", "lateral.psexec"],
                    involved_artifacts = [user.uid, any_creds[0].uid],
                    params         = {"target_user": user.username, "spn": spn},
                ))
        return opps

    def _rule_04_dacl_escalation(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-04: WriteDACL/GenericAll permission + matching credential
        → ACL abuse path to domain admin.
        """
        opps: list[CorrelationOpportunity] = []
        dangerous_perms = [
            p for p in store.permissions()
            if p.right in ("WriteDACL", "GenericAll", "AllExtendedRights",
                           "DS-Replication-Get-Changes-All")
        ]
        creds = store.credentials()
        if not dangerous_perms or not creds:
            return opps

        for perm in dangerous_perms:
            # Find credential matching the principal
            matching = [
                c for c in creds
                if perm.principal.lower() in c.username.lower()
            ]
            if matching:
                c = matching[0]
                opps.append(CorrelationOpportunity(
                    opportunity_id = f"rule04-{perm.uid[:6]}-{c.uid[:6]}",
                    rule_id        = "RULE-04",
                    title          = f"ACL abuse: {perm.principal} has {perm.right} on {perm.target}",
                    description    = (
                        f"Principal {perm.principal} has {perm.right} on {perm.target}. "
                        f"We have credential for this account → escalate to domain admin."
                    ),
                    severity       = "critical",
                    confidence     = 0.90,
                    attack_modules = ["ad.dcsync"],
                    involved_artifacts = [perm.uid, c.uid],
                    params         = {
                        "username": perm.principal,
                        "right":    perm.right,
                        "target":   perm.target,
                    },
                ))
        return opps

    def _rule_05_dc_dcsync_path(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-05: DC discovered + any credential
        → DCSync is a viable end goal.
        """
        dcs = [h for h in store.hosts() if h.is_dc]
        creds = store.credentials()
        opps: list[CorrelationOpportunity] = []
        if dcs and creds:
            dc = dcs[0]
            target = dc.fqdn or dc.hostname or dc.ip_address
            opps.append(CorrelationOpportunity(
                opportunity_id = f"rule05-{dc.uid[:6]}",
                rule_id        = "RULE-05",
                title          = f"DCSync opportunity: DC {target} accessible",
                description    = (
                    f"Domain Controller {target} discovered with {len(creds)} credential(s). "
                    f"Escalate to DA → DCSync all domain hashes."
                ),
                severity       = "critical",
                confidence     = 0.70,
                attack_modules = ["ad.dcsync", "ad.kerberoast", "ad.asreproast"],
                involved_artifacts = [dc.uid] + [c.uid for c in creds[:2]],
                params         = {"dc": target},
            ))
        return opps

    def _rule_06_pth_lateral(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-06: NTLM hash + host with SMB open
        → Pass-the-hash lateral movement.
        """
        opps: list[CorrelationOpportunity] = []
        ntlm_hashes = store.hashes()
        smb_hosts   = [h for h in store.hosts() if 445 in (h.open_ports or [])]
        if not ntlm_hashes or not smb_hosts:
            return opps

        for h in ntlm_hashes[:3]:
            for host in smb_hosts[:5]:
                target = host.fqdn or host.hostname or host.ip_address
                opps.append(CorrelationOpportunity(
                    opportunity_id = f"rule06-{h.uid[:6]}-{host.uid[:6]}",
                    rule_id        = "RULE-06",
                    title          = f"Pass-the-Hash: {h.username} → {target}",
                    description    = (
                        f"NTLM hash for {h.username}@{h.domain} available. "
                        f"Host {target} has SMB (port 445) open → pass-the-hash viable."
                    ),
                    severity       = "high",
                    confidence     = 0.80,
                    attack_modules = ["lateral.psexec"],
                    involved_artifacts = [h.uid, host.uid],
                    params         = {"target": target, "hash_id": h.uid},
                ))
        return opps

    def _rule_07_cloud_expansion(self, store: ArtifactStore) -> list[CorrelationOpportunity]:
        """
        RULE-07: Public cloud resource + cloud credential
        → Expand cloud enumeration / pivot to cloud infra.
        """
        opps: list[CorrelationOpportunity] = []
        public_resources = [
            a for a in store.get(ArtifactType.CLOUD_RESOURCE)
            if isinstance(a, CloudResourceArtifact) and a.is_public
        ]
        cloud_creds = [
            c for c in store.credentials() if c.cred_type in ("api_key", "jwt", "cleartext")
        ]
        for res in public_resources[:3]:
            opps.append(CorrelationOpportunity(
                opportunity_id = f"rule07-{res.uid[:6]}",
                rule_id        = "RULE-07",
                title          = f"Public cloud resource: {res.provider}/{res.resource_type} {res.resource_id!r}",
                description    = (
                    f"Public {res.provider} {res.resource_type} discovered. "
                    f"{'Credentials available for deeper access.' if cloud_creds else 'No credentials yet — enumerate.'}"
                ),
                severity       = "medium",
                confidence     = 0.85,
                attack_modules = [f"cloud.{res.provider}"],
                involved_artifacts = [res.uid] + ([cloud_creds[0].uid] if cloud_creds else []),
                params         = {
                    "resource_id":   res.resource_id,
                    "resource_type": res.resource_type,
                    "provider":      res.provider,
                },
            ))
        return opps
