"""
ARES Data Normalization Layer
Standardized artifact types that all modules produce and consume.

Every module output is normalized into typed artifacts.
This enables:
  - Cross-module data flow (kerberoast consumes spn_list from enum_spn)
  - Attack graph construction (artifacts become nodes)
  - Universal querying ("give me all credentials from this campaign")
  - Data deduplication (same host reported by two modules = one node)

Artifact taxonomy:
  Host         - IP address, hostname, OS, open ports
  Domain       - AD domain with trust relationships
  User         - domain/local user account
  Credential   - NTLM hash, cleartext, ticket, key
  Service      - SPN-registered service
  Permission   - ACE (who can do what to whom)
  Finding      - vulnerability/misconfiguration
  Hash         - crackable hash (KRB5TGS, KRB5ASREP, NTLM)
  Secret       - plaintext secret (API key, password, token)
  CloudResource - S3 bucket, IAM role, storage account

Usage in a module:
    from ares.normalize.artifacts import NormalizedArtifact, User, Host, Credential
    
    # In module.run():
    artifacts = [
        Host(ip="10.0.0.1", hostname="dc01", os="Windows Server 2022", is_dc=True),
        User(username="svc_sql", domain="CORP", spns=["MSSQLSvc/db01:1433"]),
    ]
    return findings, {"artifacts": [a.to_dict() for a in artifacts]}
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.normalize.artifacts")


# ── Artifact type registry ─────────────────────────────────────────────────────

class ArtifactType(str, Enum):
    HOST          = "host"
    DOMAIN        = "domain"
    USER          = "user"
    GROUP         = "group"
    CREDENTIAL    = "credential"
    SERVICE       = "service"
    PERMISSION    = "permission"
    HASH          = "hash"
    SECRET        = "secret"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK_PATH  = "network_path"


# ── Base artifact ─────────────────────────────────────────────────────────────

@dataclass
class NormalizedArtifact:
    """
    Base class for all normalized artifacts.
    Every artifact has:
      - type:        what it is
      - uid:         deterministic ID based on content (dedup-friendly)
      - source:      module that produced it
      - campaign_id: which campaign this belongs to
      - tags:        free-form labels
      - raw:         original data from module (preserved for graph edges)
    """
    artifact_type: ArtifactType = field(default=ArtifactType.HOST, init=True)
    source_module: str = ""
    campaign_id:   str = ""
    tags:          list[str] = field(default_factory=list)
    raw:           dict[str, Any] = field(default_factory=dict)
    metadata:      dict[str, Any] = field(default_factory=dict)
    _uid:          str | None = field(default=None, repr=False)

    @property
    def uid(self) -> str:
        """Deterministic UID - same content = same ID (enables deduplication)."""
        if self._uid:
            return self._uid
        key = f"{self.artifact_type.value}:{self._dedup_key()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _dedup_key(self) -> str:
        """Override in subclasses with the fields that make this artifact unique."""
        return str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "uid":          self.uid,
            "type":         self.artifact_type.value,
            "source_module": self.source_module,
            "campaign_id":  self.campaign_id,
            "tags":         self.tags,
            "metadata":     self.metadata,
        }
        d.update(self._to_dict_fields())
        return d

    def _to_dict_fields(self) -> dict[str, Any]:
        return {}

    def __hash__(self) -> int:
        return hash(self.uid)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NormalizedArtifact) and self.uid == other.uid


# ── Concrete artifact types ───────────────────────────────────────────────────

@dataclass
class HostArtifact(NormalizedArtifact):
    """A discovered host on the network."""
    ip_address:  str = ""
    ip:          str = ""   # convenience alias accepted in constructor
    hostname:    str = ""
    fqdn:        str = ""
    os:          str = ""
    os_version:  str = ""
    domain:      str = ""
    is_dc:       bool = False
    domain_controller: bool = False   # alias for is_dc
    open_ports:  list[int] = field(default_factory=list)
    services:    list[str] = field(default_factory=list)
    vulns:       list[dict[str, Any]] = field(default_factory=list)
    hostnames:   list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.HOST
        # Allow ip= shorthand
        if self.ip and not self.ip_address:
            self.ip_address = self.ip
        elif self.ip_address and not self.ip:
            self.ip = self.ip_address
        # Allow domain_controller= shorthand
        if self.domain_controller and not self.is_dc:
            self.is_dc = self.domain_controller
        elif self.is_dc and not self.domain_controller:
            self.domain_controller = self.is_dc

    def _dedup_key(self) -> str:
        return f"{self.ip_address}:{self.domain}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address, "hostname": self.hostname,
            "fqdn": self.fqdn, "os": self.os, "os_version": self.os_version,
            "domain": self.domain, "is_dc": self.is_dc, "open_ports": self.open_ports,
            "services": self.services, "vulns": self.vulns, "hostnames": self.hostnames,
        }


@dataclass
class DomainArtifact(NormalizedArtifact):
    """An Active Directory domain."""
    domain_name:   str = ""
    netbios_name:  str = ""
    forest:        str = ""
    domain_level:  int = 0   # 2003=2, 2008=3, 2012=4, 2016=6, 2019=7
    trusts:        list[str] = field(default_factory=list)
    dc_count:      int = 0

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.DOMAIN

    def _dedup_key(self) -> str:
        return self.domain_name.lower()

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "domain_name": self.domain_name, "netbios_name": self.netbios_name,
            "forest": self.forest, "domain_level": self.domain_level,
            "trusts": self.trusts, "dc_count": self.dc_count,
        }


@dataclass
class UserArtifact(NormalizedArtifact):
    """A domain or local user account."""
    username:     str = ""
    domain:       str = ""
    display_name: str = ""
    enabled:      bool = True
    spns:         list[str] = field(default_factory=list)   # Kerberoastable if non-empty
    spn:          list[str] = field(default_factory=list)   # alias for spns
    groups:       list[str] = field(default_factory=list)   # Group memberships
    member_of:    list[str] = field(default_factory=list)   # alias for groups
    is_admin:     bool = False
    is_service:   bool = False
    no_preauth:   bool = False   # ASREPRoastable if True
    password_age_days: int = 0
    last_logon_days:   int = 0

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.USER
        # Sync spn ↔ spns
        if self.spn and not self.spns:
            self.spns = self.spn
        elif self.spns and not self.spn:
            self.spn = self.spns
        # Sync groups ↔ member_of
        if self.member_of and not self.groups:
            self.groups = self.member_of
        elif self.groups and not self.member_of:
            self.member_of = self.groups

    def _dedup_key(self) -> str:
        return f"{self.domain.lower()}\\{self.username.lower()}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "username": self.username, "domain": self.domain,
            "enabled": self.enabled, "spns": self.spns, "member_of": self.member_of,
            "is_admin": self.is_admin, "is_service": self.is_service,
            "no_preauth": self.no_preauth, "password_age_days": self.password_age_days,
        }

    @property
    def is_kerberoastable(self) -> bool:
        return bool(self.spns) and self.enabled

    @property
    def is_asreproastable(self) -> bool:
        return self.no_preauth and self.enabled


@dataclass
class CredentialArtifact(NormalizedArtifact):
    """A captured credential of any type."""
    username:    str = ""
    domain:      str = ""
    cred_type:   str = ""   # ntlm | cleartext | kerberos_ticket | api_key | jwt | ssh_key
    secret:      str = ""   # plaintext secret (optional, for test fixtures)
    secret_hash: str = ""   # SHA-256 of the secret value (for dedup without storing plaintext)
    cracked:     bool = False
    source_host: str = ""
    host:        str = ""   # alias for source_host
    target:      str = ""   # alias for source_host
    protocol:    str = ""   # ssh | smb | winrm | rdp etc
    privilege:   str = ""   # domain_admin | service_account | local_admin | user | unknown
    has_password: bool = False
    note:        str = ""

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.CREDENTIAL
        if self.target and not self.source_host:
            self.source_host = self.target
        elif self.source_host and not self.target:
            self.target = self.source_host
        if self.host and not self.source_host:
            self.source_host = self.host
        elif self.source_host and not self.host:
            self.host = self.source_host
        if self.target and not self.host:
            self.host = self.target
        elif self.host and not self.target:
            self.target = self.host
        if self.secret and not self.secret_hash:
            self.secret_hash = hashlib.sha256(self.secret.encode("utf-8", errors="ignore")).hexdigest()

    def _dedup_key(self) -> str:
        return f"{self.domain}\\{self.username}:{self.cred_type}:{self.source_host}:{self.secret_hash[:8]}"

    def _to_dict_fields(self) -> dict[str, Any]:
        d = {
            "username": self.username, "domain": self.domain,
            "cred_type": self.cred_type, "cracked": self.cracked,
            "source_host": self.source_host, "privilege": self.privilege,
            "protocol": self.protocol, "has_password": self.has_password,
            "note": self.note,
        }
        return d


@dataclass
class HashArtifact(NormalizedArtifact):
    """A crackable hash (Kerberos TGS, AS-REP, NTLM)."""
    hash_type:  str = ""    # krb5tgs_rc4 | krb5tgs_aes | krb5asrep | ntlm
    username:   str = ""
    domain:     str = ""
    module_id:  str = ""    # which module produced this hash
    hashcat_mode: int = 0
    hash_value:   str = ""  # full hash string (passed to cracker, not logged)
    hash_preview: str = ""  # first 12 chars for identification only (auto-derived)
    nt_hash:      str = ""  # NT hash specifically (NTLM only)

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.HASH
        # Auto-derive hash_preview from hash_value if not set
        if self.hash_value and not self.hash_preview:
            self.hash_preview = self.hash_value[:12]

    def _dedup_key(self) -> str:
        return f"{self.hash_type}:{self.domain}\\{self.username}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "hash_type": self.hash_type, "username": self.username,
            "domain": self.domain, "hashcat_mode": self.hashcat_mode,
            "hash_preview": self.hash_preview,
        }

    @property
    def crack_command(self) -> str:
        return f"hashcat -m {self.hashcat_mode} hashes.txt wordlist.txt -r rules/best64.rule"


@dataclass
class PermissionArtifact(NormalizedArtifact):
    """An ACE (Access Control Entry) - who can do what to whom."""
    principal:   str = ""   # who holds the right
    target:      str = ""   # object the right is on
    right:       str = ""   # GenericAll, WriteDACL, etc.
    domain:      str = ""
    is_dangerous: bool = False

    DANGEROUS_RIGHTS = {
        "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
        "AllExtendedRights", "DS-Replication-Get-Changes-All",
    }

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.PERMISSION
        self.is_dangerous = self.is_dangerous or (self.right in self.DANGEROUS_RIGHTS)

    def _dedup_key(self) -> str:
        return f"{self.principal}→{self.right}→{self.target}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "principal": self.principal, "target": self.target,
            "right": self.right, "domain": self.domain, "is_dangerous": self.is_dangerous,
        }


@dataclass
class CloudResourceArtifact(NormalizedArtifact):
    """A cloud resource (S3, IAM role, storage account, GCS bucket)."""
    provider:     str = ""   # aws | azure | gcp
    resource_type: str = ""  # s3_bucket | iam_role | storage_container | gcs_bucket
    resource_id:   str = ""
    region:        str = ""
    is_public:     bool = False
    permissions:   list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.CLOUD_RESOURCE

    def _dedup_key(self) -> str:
        return f"{self.provider}:{self.resource_type}:{self.resource_id}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "resource_type": self.resource_type,
            "resource_id": self.resource_id, "region": self.region,
            "is_public": self.is_public, "permissions": self.permissions,
        }


# ── Artifact store (in-memory, per-campaign) ──────────────────────────────────

class ArtifactStore:
    """
    In-memory artifact store for a single campaign run.
    Deduplicates by artifact UID.
    Can be serialized to DB or passed between modules.
    """

    def __init__(self) -> None:
        self._store: dict[str, NormalizedArtifact] = {}

    def add(self, artifact: NormalizedArtifact) -> NormalizedArtifact:
        """Add or merge artifact. Returns the canonical (possibly existing) artifact."""
        if artifact.uid in self._store:
            return self._store[artifact.uid]  # dedup
        self._store[artifact.uid] = artifact
        return artifact

    def add_credential(self, artifact: CredentialArtifact) -> CredentialArtifact:
        """Add or merge a CredentialArtifact. Returns canonical artifact."""
        return self.add(artifact)  # type: ignore[return-value]

    def add_many(self, artifacts: list[NormalizedArtifact]) -> None:
        for a in artifacts:
            self.add(a)

    def get(self, artifact_type: ArtifactType) -> list[NormalizedArtifact]:
        return [a for a in self._store.values() if a.artifact_type == artifact_type]

    def hosts(self)       -> list[HostArtifact]:
        return [a for a in self._store.values() if isinstance(a, HostArtifact)]          # type: ignore[return-value]

    def users(self)       -> list[UserArtifact]:
        return [a for a in self._store.values() if isinstance(a, UserArtifact)]          # type: ignore[return-value]

    def credentials(self) -> list[CredentialArtifact]:
        return [a for a in self._store.values() if isinstance(a, CredentialArtifact)]    # type: ignore[return-value]

    def hashes(self)      -> list[HashArtifact]:
        return [a for a in self._store.values() if isinstance(a, HashArtifact)]          # type: ignore[return-value]

    def permissions(self) -> list[PermissionArtifact]:
        return [a for a in self._store.values() if isinstance(a, PermissionArtifact)]    # type: ignore[return-value]

    def kerberoastable(self) -> list[UserArtifact]:
        return [u for u in self.users() if u.is_kerberoastable]

    def asreproastable(self) -> list[UserArtifact]:
        return [u for u in self.users() if u.is_asreproastable]

    def to_list(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._store.values()]

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self._store.values():
            k = a.artifact_type.value
            counts[k] = counts.get(k, 0) + 1
        return counts

    def __len__(self) -> int:
        return len(self._store)

    def clear(self) -> None:
        """Remove all artifacts from the store."""
        self._store.clear()

    def total(self) -> int:
        """Return total number of artifacts."""
        return len(self._store)


# ── Public aliases ────────────────────────────────────────────────────────────
#: ArtifactNormalizer is the canonical external-facing name for ArtifactStore.
ArtifactNormalizer = ArtifactStore


# ── Artifact Normalizer ───────────────────────────────────────────────────────

class ArtifactNormalizer:
    """
    Auto-normalizes module raw output into typed ArtifactStore entries.
    Called by AresEngine after each successful module execution.

    Maps module OUTPUTS capability tags to raw output keys → artifact types.
    """

    def normalize(
        self,
        module_id: str,
        outputs:   list[str],
        raw:       dict,
        store:     ArtifactStore,
    ) -> int:
        """
        Normalize raw module output into artifacts.
        Returns number of artifacts added.

        Args:
            module_id: module that produced the output
            outputs:   module OUTPUTS capability list
            raw:       raw output dict from the module
            store:     ArtifactStore to populate
        """
        count = 0
        for capability in outputs:
            try:
                added = self._normalize_capability(capability, raw, store)
                count += added
            except Exception as exc:
                logger.warning(
                    "artifact_normalization_failed",
                    module_id=module_id,
                    capability=capability,
                    error=str(exc),
                )
        return count

    def _normalize_capability(
        self, capability: str, raw: dict, store: ArtifactStore
    ) -> int:
        """Route a capability to its specific normalizer."""
        handlers: dict[str, Any] = {
            "user_list":              self._normalize_users,
            "users":                  self._normalize_users,
            "domain_users":           self._normalize_users,
            "computer_list":          self._normalize_computers,
            "computers":              self._normalize_computers,
            "kerberos_hashes":        self._normalize_kerberos_hashes,
            "asrep_hashes":           self._normalize_asrep_hashes,
            "ntlm_hashes":            self._normalize_ntlm_hashes,
            "hashes":                 self._normalize_ntlm_hashes,
            "cached_hashes":          self._normalize_ntlm_hashes,
            "spn_list":               self._normalize_spns,
            "spns":                   self._normalize_spns,
            "acl_findings":           self._normalize_permissions,
            "misconfigs":             self._normalize_permissions,
            "aws_findings":           self._normalize_cloud,
            "privesc_vectors":        self._normalize_host_vuln,
            # P0 Capabilities
            "cleartext_credentials":  self._normalize_cleartext_credentials,
            "credentials":            self._normalize_cleartext_credentials,
            "browser_passwords":      self._normalize_cleartext_credentials,
            "cracked_credentials":    self._normalize_cracked_credentials,
            "laps_passwords":         self._normalize_laps_passwords,
            "kerberos_tickets":       self._normalize_kerberos_tickets,
            "kerberos_ticket":        self._normalize_kerberos_tickets,
            "tickets":                self._normalize_kerberos_tickets,
            "golden_ticket":          self._normalize_kerberos_tickets,
            "open_ports":             self._normalize_open_ports,
            "service_map":            self._normalize_open_ports,
            # LSA Secrets & Cached Domain Credentials (MOD-028)
            "lsa_secrets":            self._normalize_lsa_secrets,
            "windows.lsa_secrets":    self._normalize_lsa_secrets,
            "cached_credentials":     self._normalize_cached_domain_credentials,
            "cached_domain_credentials": self._normalize_cached_domain_credentials,
            # Valid Credentials (MOD-033)
            "valid_credentials":      self._normalize_valid_credentials,
            # Kerberos Ticket Conversion (MOD-036)
            "converted_ticket":       self._normalize_converted_ticket,
            "converted_ticket_b64":   self._normalize_converted_ticket,
            # Samba Secrets & Machine Hashes (MOD-041)
            "samba_secrets":          self._normalize_samba_secrets,
            "machine_account_hash":   self._normalize_samba_secrets,
            # Linux Keytab Credentials (MOD-044)
            "kerberos_keys":          self._normalize_keytab_keys,
            "machine_credentials":    self._normalize_keytab_keys,
            # AWS IAM Privesc Paths (MOD-052)
            "iam_privesc_paths":      self._normalize_iam_privesc,
            "aws_privesc_paths":      self._normalize_iam_privesc,
            # Reconnaissance & Service Fingerprinting (MOD-062)
            "dns_records":            self._normalize_dns_records,
            "subdomains":             self._normalize_dns_records,
            "service_versions":       self._normalize_service_versions,
            "vulnerable_services":    self._normalize_service_versions,
            "web_fingerprint":        self._normalize_web_fingerprint,
            "admin_interfaces":       self._normalize_web_fingerprint,
            # Azure & Azure AD (MOD-066)
            "azure_findings":         self._normalize_azure,
            "azure_ad_findings":      self._normalize_azure_ad,
            "access_tokens":          self._normalize_tokens,
            "access_token":           self._normalize_tokens,
            "oauth_tokens":           self._normalize_tokens,
            # GCP (MOD-068)
            "gcp_findings":           self._normalize_gcp,
            # Linux Containers & K8s (MOD-040)
            "container_escape_vectors": self._normalize_container_vectors,
            "k8s_rbac_findings":      self._normalize_k8s_rbac,
            # Identity Federation (MOD-051)
            "federation_trusts":      self._normalize_federation_trusts,
            "golden_saml_paths":      self._normalize_golden_saml,
            "pivot_paths":            self._normalize_pivot_paths,
            # SNMP & Network Discovery (MOD-061 / Recon)
            "snmp_findings":          self._normalize_snmp_findings,
            "system_info":            self._normalize_system_info,
            "password_policy":        self._normalize_password_policy,
            # Windows Scheduled Tasks & Registry (MOD-070)
            "scheduled_tasks":        self._normalize_scheduled_tasks,
            "credential_hints":       self._normalize_registry_credentials,
            # Secrets Scanner & SMB Shares (MOD-074)
            "credential_list":        self._normalize_secrets_scan,
            "discovered_secrets":     self._normalize_secrets_scan,
            "sensitive_data_found":   self._normalize_secrets_scan,
            "file_share_list":        self._normalize_smb_shares,
            "sensitive_file_paths":   self._normalize_smb_shares,
        }
        handler = handlers.get(capability)
        if handler:
            try:
                return handler(raw, store, capability)
            except TypeError:
                return handler(raw, store)
        return 0

    def _normalize_users(self, raw: dict, store: ArtifactStore) -> int:
        users = raw.get("users") or raw.get("user_list", [])
        count = 0
        for u in users:
            if not isinstance(u, dict):
                continue
            artifact = UserArtifact(
                username    = u.get("samAccountName", u.get("username", "")),
                domain      = u.get("domain", ""),
                enabled     = u.get("enabled", True),
                is_admin    = bool(u.get("isAdmin", u.get("is_admin", u.get("adminCount", 0) > 0))),
                no_preauth  = bool(u.get("noPreauth", u.get("no_preauth", u.get("dont_req_preauth", False)))),
                spns        = u.get("spns", u.get("spn", [])),
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_computers(self, raw: dict, store: ArtifactStore) -> int:
        computers = raw.get("computers") or raw.get("computer_list", [])
        count = 0
        for c in computers:
            if not isinstance(c, dict):
                continue
            artifact = HostArtifact(
                ip_address = c.get("ip", c.get("ip_address", "")),
                hostname   = c.get("dns", c.get("dns_name", c.get("name", ""))),
                is_dc      = c.get("is_dc", False),
                os         = c.get("os", ""),
                os_version = c.get("os_version", ""),
                domain     = c.get("domain", ""),
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_kerberos_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = raw.get("hashes") or raw.get("kerberos_hashes", [])
        count  = 0
        for h in hashes:
            if isinstance(h, str):
                # Parse username from hash: $krb5tgs$23$*username$DOMAIN$...
                parts    = h.split("$")
                raw_user = parts[3].split("@")[0] if len(parts) > 3 else ""
                username = raw_user.lstrip("*")
                domain   = parts[4].split("@")[0] if len(parts) > 4 else ""
                artifact = HashArtifact(
                    username     = username,
                    domain       = domain,
                    hash_value   = h[:120],
                    hash_type    = "krb5tgs",
                    hashcat_mode = 13100,
                )
                store.add(artifact)
                count += 1
            elif isinstance(h, dict):
                artifact = HashArtifact(
                    username     = h.get("username", ""),
                    domain       = h.get("domain", ""),
                    hash_value   = (h.get("hash") or h.get("hash_value") or "")[:120],
                    hash_type    = "krb5tgs",
                    hashcat_mode = 13100,
                )
                store.add(artifact)
                count += 1
        return count

    def _normalize_asrep_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = raw.get("hashes") or raw.get("asrep_hashes", [])
        count  = 0
        for h in hashes:
            if isinstance(h, str):
                parts    = h.split("$")
                user_part = parts[3] if len(parts) > 3 else ""
                if "@" in user_part:
                    username, domain = user_part.split("@", 1)
                else:
                    username = user_part
                    domain = parts[4].split("@")[0] if len(parts) > 4 else ""
                artifact = HashArtifact(
                    username     = username,
                    domain       = domain,
                    hash_value   = h[:120],
                    hash_type    = "krb5asrep",
                    hashcat_mode = 18200,
                )
                store.add(artifact)
                count += 1
            elif isinstance(h, dict):
                artifact = HashArtifact(
                    username     = h.get("username", ""),
                    domain       = h.get("domain", ""),
                    hash_value   = (h.get("hash") or h.get("hash_value") or "")[:120],
                    hash_type    = "krb5asrep",
                    hashcat_mode = 18200,
                )
                store.add(artifact)
                count += 1
        return count

    def _normalize_ntlm_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = (
            raw.get("hashes")
            or raw.get("ntlm_hashes")
            or raw.get("sam_hashes")
            or []
        )
        count  = 0
        for h in hashes:
            if isinstance(h, dict):
                artifact = HashArtifact(
                    username     = h.get("username", ""),
                    domain       = h.get("domain", ""),
                    hash_value   = h.get("nt_hash") or h.get("hash") or h.get("ntlm", ""),
                    hash_type    = "ntlm",
                    hashcat_mode = 1000,
                )
                store.add(artifact)
                count += 1
            elif isinstance(h, str):
                parts = h.split(":")
                username = parts[0] if parts else ""
                nt_hash = ""
                if len(parts) >= 4:
                    nt_hash = parts[3]
                elif len(parts) == 2:
                    nt_hash = parts[1]
                else:
                    nt_hash = h
                artifact = HashArtifact(
                    username     = username,
                    domain       = "",
                    hash_value   = nt_hash,
                    hash_type    = "ntlm",
                    hashcat_mode = 1000,
                )
                store.add(artifact)
                count += 1
        return count

    def _normalize_spns(self, raw: dict, store: ArtifactStore) -> int:
        spns = raw.get("spns") or raw.get("spn_list", [])
        count = 0
        for s in spns:
            if not isinstance(s, dict):
                continue
            spn_entries = s.get("spns") or s.get("spn_list") or s.get("spn", [])
            if isinstance(spn_entries, str):
                spn_entries = [spn_entries]
            artifact = UserArtifact(
                username        = s.get("samAccountName", s.get("name", s.get("username", ""))),
                domain          = s.get("domain", ""),
                enabled         = s.get("enabled", True),
                is_admin        = s.get("is_admin", s.get("isAdmin", False)),
                spns            = spn_entries,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_permissions(self, raw: dict, store: ArtifactStore) -> int:
        misconfigs = raw.get("misconfigs", [])
        count = 0
        for m in misconfigs:
            if not isinstance(m, dict):
                continue
            artifact = PermissionArtifact(
                principal  = m.get("trustee_sid", ""),
                target     = m.get("target", ""),
                right      = m.get("right", ""),
                domain     = "",
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_cloud(self, raw: dict, store: ArtifactStore) -> int:
        count = 0
        region = raw.get("region", "")
        s3 = raw.get("s3", {})
        for bucket in s3.get("public_buckets", []):
            artifact = CloudResourceArtifact(
                resource_id   = bucket.get("name", ""),
                resource_type = "s3_bucket",
                region        = region,
                is_public     = True,
            )
            store.add(artifact)
            count += 1
        for path in raw.get("privesc_paths", []):
            if isinstance(path, dict):
                res_id = (
                    path.get("role_arn")
                    or path.get("policy_name")
                    or path.get("action")
                    or path.get("technique")
                    or "iam_privesc_path"
                )
            elif isinstance(path, str):
                res_id = path
            else:
                continue
            artifact = CloudResourceArtifact(
                resource_id   = str(res_id),
                resource_type = "iam_role",
                region        = region,
                is_public     = False,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_host_vuln(self, raw: dict, store: ArtifactStore) -> int:
        host = raw.get("target") or raw.get("host", "")
        if not host or host == "localhost":
            return 0
        existing = None
        for h in store.hosts():
            if h.ip_address == host or h.hostname == host:
                existing = h
                break
        vulns = raw.get("privesc_vectors", [])
        parsed_vulns = []
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    parsed_vulns.append(v)
                elif hasattr(v, "evidence") and isinstance(v.evidence, dict):
                    parsed_vulns.append(v.evidence)
                elif isinstance(v, str) and v:
                    parsed_vulns.append({"vector": v})
        if existing:
            if parsed_vulns:
                existing.vulns.extend(parsed_vulns)
            return 1
        artifact = HostArtifact(
            ip_address = host,
            hostname   = host,
            vulns      = parsed_vulns,
        )
        store.add(artifact)
        return 1

    # ── P0 Handlers ────────────────────────────────────────────────────────────

    def _normalize_cleartext_credentials(self, raw: dict, store: ArtifactStore) -> int:
        creds = raw.get("cleartext_credentials") or raw.get("credentials", [])
        if isinstance(creds, (dict, str)):
            creds = [creds]
        elif not isinstance(creds, list):
            return 0
        count = 0
        default_target = raw.get("target") or raw.get("host", "")
        for c in creds:
            if hasattr(c, "evidence") and isinstance(c.evidence, dict):
                ev = c.evidence
                username = ev.get("user") or ev.get("username", "")
                secret = ev.get("password") or ev.get("secret", "")
                domain = ev.get("domain", "")
                source_host = ev.get("host") or default_target
                privilege = "unknown"
            elif isinstance(c, dict):
                username = c.get("username") or c.get("user") or c.get("account", "")
                domain = c.get("domain", "")
                secret = c.get("password") or c.get("secret") or c.get("plaintext", "")
                source_host = c.get("host") or c.get("target") or c.get("computer") or default_target
                privilege = c.get("privilege", "unknown")
            elif isinstance(c, str):
                username = "unknown"
                domain = ""
                secret = c
                source_host = default_target
                privilege = "unknown"
            else:
                logger.warning("cleartext_credentials_invalid_entry", type=type(c).__name__)
                continue
            if not username and not secret:
                continue
            artifact = CredentialArtifact(
                username    = username,
                domain      = domain,
                cred_type   = "cleartext",
                secret      = secret,
                source_host = source_host,
                privilege   = privilege,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_cracked_credentials(self, raw: dict, store: ArtifactStore) -> int:
        cracked = raw.get("cracked_credentials") or raw.get("cracked_users", [])
        count = 0
        for c in cracked:
            if not isinstance(c, dict):
                continue
            secret = c.get("plaintext") or c.get("password") or c.get("secret", "")
            artifact = CredentialArtifact(
                username    = c.get("username", ""),
                domain      = c.get("domain", ""),
                cred_type   = "cleartext" if secret else (c.get("hash_type") or "ntlm"),
                secret      = secret,
                cracked     = True,
                source_host = c.get("host") or c.get("target", ""),
                privilege   = c.get("privilege", "unknown"),
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_laps_passwords(self, raw: dict, store: ArtifactStore) -> int:
        laps = raw.get("laps_passwords") or raw.get("entries", [])
        count = 0
        for e in laps:
            if not isinstance(e, dict):
                continue
            comp = e.get("computer") or e.get("computer_name") or e.get("host", "")
            pwd  = e.get("password", "")
            has_pwd = bool(e.get("has_password", False) or pwd)
            note = ""
            if not pwd and e.get("has_password"):
                note = "password stored in vault"
            artifact = CredentialArtifact(
                username    = e.get("username", "Administrator"),
                domain      = e.get("domain", "") or comp,
                cred_type   = "laps",
                secret      = pwd,
                source_host = comp,
                privilege   = "local_admin",
                has_password= has_pwd,
                note        = note,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_kerberos_tickets(self, raw: dict, store: ArtifactStore) -> int:
        tickets = (
            raw.get("kerberos_tickets")
            or raw.get("kerberos_ticket")
            or raw.get("tickets")
            or []
        )
        if isinstance(tickets, (str, dict)):
            tickets = [tickets]
        count = 0
        for t in tickets:
            if isinstance(t, str):
                artifact = CredentialArtifact(
                    username  = "unknown",
                    domain    = "",
                    cred_type = "kerberos_ticket",
                    secret    = t,
                )
                store.add(artifact)
                count += 1
            elif isinstance(t, dict):
                client = (
                    t.get("client")
                    or t.get("username")
                    or t.get("default_principal")
                    or t.get("principal", "")
                )
                realm = t.get("realm") or t.get("domain", "")
                if "@" in client and not realm:
                    parts = client.split("@", 1)
                    client = parts[0]
                    realm = parts[1]
                ticket_path = (
                    t.get("file_path")
                    or t.get("ticket_path")
                    or t.get("ccache_path")
                    or t.get("path", "")
                )
                artifact = CredentialArtifact(
                    username    = client,
                    domain      = realm,
                    cred_type   = "kerberos_ticket",
                    secret      = ticket_path,
                    source_host = t.get("target") or t.get("host", ""),
                )
                store.add(artifact)
                count += 1
        return count

    def _normalize_open_ports(self, raw: dict, store: ArtifactStore) -> int:
        ports_raw = raw.get("open_ports") or raw.get("port_results") or []
        ports: list[int] = []
        if isinstance(ports_raw, list):
            for p in ports_raw:
                if isinstance(p, int):
                    ports.append(p)
                elif isinstance(p, dict) and "port" in p and isinstance(p["port"], int):
                    ports.append(p["port"])
                elif str(p).isdigit():
                    ports.append(int(p))
        if "service_map" in raw and isinstance(raw["service_map"], dict):
            for k in raw["service_map"]:
                if str(k).isdigit():
                    ports.append(int(k))
        ports = sorted(list(set(ports)))
        if not ports:
            return 0
        target = raw.get("target") or raw.get("host", "")
        # Look for existing HostArtifact with same target/ip
        existing_host = None
        if target:
            for h in store.hosts():
                if h.ip_address == target or h.hostname == target:
                    existing_host = h
                    break
        if existing_host:
            existing_host.open_ports = sorted(list(set(existing_host.open_ports + ports)))
            return 1
        artifact = HostArtifact(
            ip_address = target,
            hostname   = target,
            open_ports = ports,
        )
        store.add(artifact)
        return 1

    def _normalize_lsa_secrets(self, raw: dict, store: ArtifactStore) -> int:
        """
        Normalize LSA secrets (service accounts, machine account passwords, DPAPI keys)
        into CredentialArtifact(cred_type="lsa_secret").
        """
        secrets = raw.get("lsa_secrets") or []
        if isinstance(secrets, (str, dict)):
            secrets = [secrets]
        count = 0
        target = raw.get("target") or raw.get("host", "")
        domain_default = raw.get("domain", "")
        for s in secrets:
            if isinstance(s, dict):
                username = s.get("username") or s.get("name") or s.get("secret_name", "")
                domain = s.get("domain") or domain_default
                secret_val = s.get("secret") or s.get("value") or s.get("password", "")
                source_host = s.get("host") or s.get("target") or target
                privilege = s.get("privilege") or ("service_account" if ("$MACHINE.ACC" in username or "_SC_" in username) else "unknown")
            elif isinstance(s, str):
                s_str = s.strip()
                if ":" in s_str:
                    name_part, val_part = s_str.split(":", 1)
                    username = name_part.strip()
                    secret_val = val_part.strip()
                else:
                    username = ""
                    secret_val = s_str
                domain = domain_default
                source_host = target
                privilege = "service_account" if ("$MACHINE.ACC" in username or "_SC_" in username or "DPAPI" in username) else "unknown"
            else:
                continue

            artifact = CredentialArtifact(
                username=username,
                domain=domain,
                cred_type="lsa_secret",
                secret=secret_val,
                cracked=False,
                source_host=source_host,
                privilege=privilege,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_cached_domain_credentials(self, raw: dict, store: ArtifactStore) -> int:
        """
        Normalize DCC2 / MSCACHE2 cached domain hashes into CredentialArtifact(cred_type="cached_domain", cracked=False).
        """
        cached = raw.get("cached_credentials") or raw.get("cached_creds", [])
        if isinstance(cached, (str, dict)):
            cached = [cached]
        count = 0
        target = raw.get("target") or raw.get("host", "")
        domain_default = raw.get("domain", "")
        for c in cached:
            if isinstance(c, dict):
                username = c.get("username", "")
                domain = c.get("domain") or domain_default
                hash_val = c.get("hash") or c.get("secret", "")
                source_host = c.get("host") or c.get("target") or target
                privilege = c.get("privilege", "user")
            elif isinstance(c, str):
                c_str = c.strip()
                if ":" in c_str:
                    user_part, hash_part = c_str.split(":", 1)
                    if "\\" in user_part:
                        domain, username = user_part.split("\\", 1)
                    else:
                        domain = domain_default
                        username = user_part
                    hash_val = hash_part.strip()
                elif "#" in c_str and ("$DCC2$" in c_str or "$MSCACHE2$" in c_str):
                    parts = c_str.split("#")
                    username = parts[1] if len(parts) > 1 else ""
                    domain = domain_default
                    hash_val = c_str
                else:
                    username = ""
                    domain = domain_default
                    hash_val = c_str
                source_host = target
                privilege = "user"
            else:
                continue

            artifact = CredentialArtifact(
                username=username,
                domain=domain,
                cred_type="cached_domain",
                secret=hash_val,
                cracked=False,
                source_host=source_host,
                privilege=privilege,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_valid_credentials(
        self, raw: dict, store: ArtifactStore, capability: str = "valid_credentials"
    ) -> int:
        """
        Normalize standardized valid_credentials output (MOD-033).
        Contract: list[dict] with username, password, target, port, method, protocol, privilege, domain.
        """
        entries = raw.get("valid_credentials", [])
        if not isinstance(entries, list):
            return 0
        count = 0
        for entry in entries:
            if not isinstance(entry, dict):
                logger.warning(
                    "valid_credentials_invalid_entry",
                    type=type(entry).__name__,
                )
                continue
            artifact = CredentialArtifact(
                username=entry.get("username", ""),
                secret=entry.get("password", ""),
                target=entry.get("target", ""),
                source_host=entry.get("target", ""),
                host=entry.get("target", ""),
                protocol=entry.get("protocol", ""),
                cred_type=entry.get("method", "password"),
                privilege=entry.get("privilege", "unknown"),
                domain=entry.get("domain") or "",
                cracked=False,
                source_module=capability,
            )
            store.add_credential(artifact)
            count += 1
        return count

    # ── Group A Handlers (MOD-036, MOD-041, MOD-044, MOD-052, MOD-062) ─────────

    def _normalize_converted_ticket(
        self, raw: dict, store: ArtifactStore, capability: str = "converted_ticket"
    ) -> int:
        """MOD-036: Normalize converted Kerberos ticket (kirbi <-> ccache)."""
        ticket_b64 = raw.get("converted_ticket_b64") or raw.get("converted_ticket")
        if not ticket_b64 or not isinstance(ticket_b64, str):
            return 0
        meta = raw.get("metadata", {})
        is_tgt = meta.get("is_tgt", False)
        target = raw.get("target", "")
        artifact = CredentialArtifact(
            username=meta.get("client") or "converted-user",
            domain=target or meta.get("server") or "",
            cred_type="tgt" if is_tgt else "tgs",
            secret=ticket_b64,
            source_host=target,
            privilege="domain_admin" if is_tgt else "domain_user",
            source_module=capability,
        )
        store.add_credential(artifact)
        return 1

    def _normalize_samba_secrets(
        self, raw: dict, store: ArtifactStore, capability: str = "samba_secrets"
    ) -> int:
        """MOD-041: Normalize Samba secrets.tdb machine account hashes and secrets."""
        secrets = raw.get("samba_secrets") or raw.get("secrets") or raw.get("machine_account_hash")
        if not secrets:
            return 0
        if isinstance(secrets, dict):
            secrets = [secrets]
        elif not isinstance(secrets, list):
            return 0
        count = 0
        target = raw.get("target", "")
        for sec in secrets:
            if not isinstance(sec, dict):
                continue
            username = sec.get("account_name", f"{target}$")
            domain = sec.get("domain", target)
            ntlm = sec.get("ntlm_hash")
            if ntlm:
                h_artifact = HashArtifact(
                    username=username,
                    domain=domain,
                    hash_type="ntlm",
                    hash_value=ntlm,
                    source_module=capability,
                )
                store.add(h_artifact)
                count += 1
            plain = sec.get("plaintext") or sec.get("password")
            if plain:
                c_artifact = CredentialArtifact(
                    username=username,
                    domain=domain,
                    cred_type="cleartext",
                    secret=plain,
                    source_host=target,
                    privilege="service_account",
                    source_module=capability,
                )
                store.add_credential(c_artifact)
                count += 1
        return count

    def _normalize_keytab_keys(
        self, raw: dict, store: ArtifactStore, capability: str = "kerberos_keys"
    ) -> int:
        """MOD-044: Normalize Kerberos keytab extracted entries."""
        entries = raw.get("kerberos_keys") or raw.get("machine_credentials") or raw.get("entries")
        if not entries:
            return 0
        if isinstance(entries, dict):
            entries = [entries]
        elif not isinstance(entries, list):
            return 0
        count = 0
        target = raw.get("target", "")
        for e in entries:
            if not isinstance(e, dict):
                continue
            key_hex = e.get("key_hex", "")
            principal = e.get("principal", f"{target}$")
            realm = e.get("realm", target)
            artifact = CredentialArtifact(
                username=principal,
                domain=realm,
                cred_type="keytab_key",
                secret=key_hex,
                source_host=target,
                privilege="service_account",
                note=f"enctype={e.get('enctype', '')}, kvno={e.get('kvno', '')}",
                source_module=capability,
            )
            store.add_credential(artifact)
            count += 1
        return count

    def _normalize_iam_privesc(
        self, raw: dict, store: ArtifactStore, capability: str = "iam_privesc_paths"
    ) -> int:
        """MOD-052: Normalize AWS IAM privilege escalation paths into PermissionArtifact."""
        paths = raw.get("iam_privesc_paths") or raw.get("aws_privesc_paths", [])
        if not isinstance(paths, list):
            return 0
        count = 0
        target = raw.get("target", "") or raw.get("account_id", "")
        for p in paths:
            if not isinstance(p, dict):
                continue
            artifact = PermissionArtifact(
                principal=p.get("principal") or p.get("user") or p.get("role") or "current_user",
                target=p.get("target") or p.get("resource") or target or "aws_account",
                right=p.get("action") or p.get("privilege") or p.get("technique") or "iam_privesc",
                domain=raw.get("account_id") or raw.get("region") or "aws",
                is_dangerous=True,
                source_module=capability,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_dns_records(
        self, raw: dict, store: ArtifactStore, capability: str = "dns_records"
    ) -> int:
        """MOD-062: Normalize DNS reconnaissance records and discovered subdomains."""
        count = 0
        domain = raw.get("domain", "")
        subdomains = raw.get("subdomains", [])
        if isinstance(subdomains, list):
            for sub in subdomains:
                if isinstance(sub, dict):
                    fqdn = sub.get("fqdn") or sub.get("subdomain", "")
                    ips = sub.get("ips", [])
                    ip = ips[0] if ips and isinstance(ips, list) else ""
                elif isinstance(sub, str):
                    fqdn = sub
                    ip = ""
                else:
                    continue
                if fqdn:
                    artifact = HostArtifact(
                        ip_address=ip or fqdn,
                        hostname=fqdn,
                        fqdn=fqdn,
                        domain=domain,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        dns_records = raw.get("dns_records", {})
        if isinstance(dns_records, dict):
            for rtype in ("A", "AAAA"):
                ips = dns_records.get(rtype, [])
                if isinstance(ips, list):
                    for ip in ips:
                        if isinstance(ip, str) and ip:
                            artifact = HostArtifact(
                                ip_address=ip,
                                hostname=domain,
                                fqdn=domain,
                                domain=domain,
                                source_module=capability,
                            )
                            store.add(artifact)
                            count += 1
        return count

    def _normalize_service_versions(
        self, raw: dict, store: ArtifactStore, capability: str = "service_versions"
    ) -> int:
        """MOD-062: Normalize service detect version banners into HostArtifact."""
        target = raw.get("target") or raw.get("host", "")
        if not target:
            return 0
        service_versions = raw.get("service_versions", {})
        ports: list[int] = []
        services: list[str] = []
        if isinstance(service_versions, dict):
            for p_str, info in service_versions.items():
                if str(p_str).isdigit():
                    ports.append(int(p_str))
                if isinstance(info, dict) and info.get("service"):
                    services.append(f"{p_str}:{info['service']}")
                elif isinstance(info, str) and info:
                    services.append(f"{p_str}:{info}")
        ports = sorted(list(set(ports)))
        vuln_svcs = raw.get("vulnerable_services", [])
        parsed_vulns = []
        if isinstance(vuln_svcs, list):
            for vs in vuln_svcs:
                if isinstance(vs, dict):
                    parsed_vulns.append(vs)
                elif hasattr(vs, "evidence") and isinstance(vs.evidence, dict):
                    parsed_vulns.append(vs.evidence)

        existing = None
        for h in store.hosts():
            if h.ip_address == target or h.hostname == target:
                existing = h
                break
        if existing:
            if ports:
                existing.open_ports = sorted(list(set(existing.open_ports + ports)))
            if services:
                existing.services = sorted(list(set(existing.services + services)))
            if parsed_vulns:
                existing.vulns.extend(parsed_vulns)
            if raw.get("os") and not existing.os:
                existing.os = raw.get("os", "")
            return 1
        artifact = HostArtifact(
            ip_address=target,
            hostname=target,
            os=raw.get("os", "") or raw.get("detected_os", ""),
            open_ports=ports,
            services=services,
            vulns=parsed_vulns,
            source_module=capability,
        )
        store.add(artifact)
        return 1

    def _normalize_web_fingerprint(
        self, raw: dict, store: ArtifactStore, capability: str = "web_fingerprint"
    ) -> int:
        """MOD-062: Normalize web server fingerprint and technologies into HostArtifact."""
        target = raw.get("target") or raw.get("host", "")
        if not target:
            return 0
        web_fp = raw.get("web_fingerprint", {})
        server = web_fp.get("server", "") if isinstance(web_fp, dict) else ""
        admin_interfaces = raw.get("admin_interfaces", [])
        existing = None
        for h in store.hosts():
            if h.ip_address == target or h.hostname == target:
                existing = h
                break
        if existing:
            if server and not existing.os:
                existing.os = server
            if admin_interfaces:
                existing.metadata["admin_interfaces"] = admin_interfaces
            return 1
        artifact = HostArtifact(
            ip_address=target,
            hostname=target,
            os=server,
            metadata={"admin_interfaces": admin_interfaces} if admin_interfaces else {},
            source_module=capability,
        )
        store.add(artifact)
        return 1

    def _normalize_azure(
        self, raw: dict, store: ArtifactStore, capability: str = "azure_findings"
    ) -> int:
        """Normalize Azure recon and attack output into CloudResourceArtifact, PermissionArtifact, UserArtifact."""
        count = 0
        subscription_id = raw.get("subscription_id", "")
        # 1. Storage
        storage = raw.get("storage", {})
        if isinstance(storage, dict):
            for c in storage.get("public_containers", []):
                if isinstance(c, dict):
                    sa = c.get("storage_account", "")
                    c_name = c.get("container", "")
                    rg = c.get("resource_group", "")
                    artifact = CloudResourceArtifact(
                        provider="azure",
                        resource_type="storage_container",
                        resource_id=f"{sa}/{c_name}",
                        region=rg,
                        is_public=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        # 2. RBAC
        rbac = raw.get("rbac", {})
        if isinstance(rbac, dict):
            for o in rbac.get("owner_assignments", []):
                if isinstance(o, dict):
                    p_id = o.get("principal_id", "")
                    scope = o.get("scope", "") or f"/subscriptions/{subscription_id}"
                    if p_id:
                        artifact = PermissionArtifact(
                            principal=p_id,
                            target=scope,
                            right="Owner",
                            domain=subscription_id,
                            is_dangerous=True,
                            source_module=capability,
                        )
                        store.add(artifact)
                        count += 1
            for c in rbac.get("contributor_assignments", []):
                if isinstance(c, dict):
                    p_id = c.get("principal_id", "")
                    scope = c.get("scope", "") or f"/subscriptions/{subscription_id}"
                    if p_id:
                        artifact = PermissionArtifact(
                            principal=p_id,
                            target=scope,
                            right="Contributor",
                            domain=subscription_id,
                            is_dangerous=True,
                            source_module=capability,
                        )
                        store.add(artifact)
                        count += 1
            for admin in rbac.get("classic_admins", []):
                if isinstance(admin, str) and admin:
                    artifact = PermissionArtifact(
                        principal=admin,
                        target=f"/subscriptions/{subscription_id}",
                        right="ClassicCoAdministrator",
                        domain=subscription_id,
                        is_dangerous=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        # 3. NSG
        nsg = raw.get("nsg", {})
        if isinstance(nsg, dict):
            for rule in nsg.get("open_rules", []):
                if isinstance(rule, dict):
                    nsg_name = rule.get("nsg", "")
                    r_name = rule.get("rule_name", "")
                    rg = rule.get("resource_group", "")
                    artifact = CloudResourceArtifact(
                        provider="azure",
                        resource_type="network_security_group",
                        resource_id=f"{nsg_name}/{r_name}" if r_name else nsg_name,
                        region=rg,
                        is_public=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        # 4. AAD users
        aad = raw.get("aad_users", {})
        if isinstance(aad, dict):
            for u in aad.get("admin_users", []):
                if isinstance(u, str) and u:
                    artifact = UserArtifact(
                        username=u,
                        domain="azure_ad",
                        is_admin=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        return count

    def _normalize_azure_ad(
        self, raw: dict, store: ArtifactStore, capability: str = "azure_ad_findings"
    ) -> int:
        """Normalize Azure AD findings into UserArtifact and PermissionArtifact."""
        count = 0
        tenant_id = raw.get("tenant_id", "azure_ad")
        # 1. Privileged users
        for u in raw.get("privileged_users", []):
            if isinstance(u, str) and u:
                artifact = UserArtifact(
                    username=u,
                    domain=tenant_id,
                    is_admin=True,
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
        # 2. Guests
        for g in raw.get("guests", []):
            g_name = g.get("userPrincipalName", "") if isinstance(g, dict) else (g if isinstance(g, str) else "")
            if g_name:
                artifact = UserArtifact(
                    username=g_name,
                    domain=tenant_id,
                    is_admin=False,
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
        # 3. High privilege service principals
        for sp in raw.get("high_priv_sps", []):
            if isinstance(sp, str) and sp:
                artifact = PermissionArtifact(
                    principal=sp,
                    target=tenant_id,
                    right="PrivilegedAppRole",
                    domain=tenant_id,
                    is_dangerous=True,
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
        # 4. Service principals list
        for sp in raw.get("service_principals", []):
            if isinstance(sp, dict) and sp.get("privileged"):
                sp_name = sp.get("displayName") or sp.get("appId", "")
                if sp_name:
                    artifact = PermissionArtifact(
                        principal=sp_name,
                        target=tenant_id,
                        right="PrivilegedServicePrincipal",
                        domain=tenant_id,
                        is_dangerous=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        return count

    def _normalize_tokens(
        self, raw: dict, store: ArtifactStore, capability: str = "access_tokens"
    ) -> int:
        """Normalize access tokens and OAuth tokens into CredentialArtifact(cred_type='oauth_token')."""
        count = 0
        tokens = raw.get("access_tokens") or raw.get("oauth_tokens") or raw.get("access_token") or raw.get("tokens")
        if not tokens:
            return 0
        if isinstance(tokens, (str, dict)):
            tokens = [tokens]
        elif not isinstance(tokens, list):
            return 0
        tenant = raw.get("tenant_id") or raw.get("domain") or "cloud"
        for t in tokens:
            if isinstance(t, str):
                t_str = t.strip()
                if not t_str:
                    continue
                artifact = CredentialArtifact(
                    username="oauth_bearer",
                    domain=tenant,
                    cred_type="oauth_token",
                    secret=t_str,
                    source_host=tenant,
                    privilege="token",
                    source_module=capability,
                )
                store.add_credential(artifact)
                count += 1
            elif isinstance(t, dict):
                tok_val = t.get("access_token") or t.get("token") or t.get("secret", "")
                if not tok_val:
                    continue
                username = t.get("user") or t.get("username") or t.get("client_id") or "oauth_bearer"
                scope = t.get("scope") or t.get("resource", "")
                artifact = CredentialArtifact(
                    username=username,
                    domain=tenant,
                    cred_type="oauth_token",
                    secret=tok_val,
                    source_host=tenant,
                    privilege="token",
                    note=f"scope={scope}" if scope else "",
                    source_module=capability,
                )
                store.add_credential(artifact)
                count += 1
            else:
                logger.warning("access_token_invalid_entry", type=type(t).__name__)
        return count

    def _normalize_gcp(
        self, raw: dict, store: ArtifactStore, capability: str = "gcp_findings"
    ) -> int:
        """Normalize GCP reconnaissance findings into CloudResourceArtifact and PermissionArtifact."""
        count = 0
        project_id = raw.get("project_id", "gcp")
        # 1. GCS public buckets
        gcs = raw.get("gcs", {})
        if isinstance(gcs, dict):
            for b in gcs.get("public_buckets", []):
                if isinstance(b, dict):
                    b_name = b.get("bucket", "")
                    if b_name:
                        artifact = CloudResourceArtifact(
                            provider="gcp",
                            resource_type="gcs_bucket",
                            resource_id=b_name,
                            region=project_id,
                            is_public=True,
                            source_module=capability,
                        )
                        store.add(artifact)
                        count += 1
        # 2. IAM bindings
        iam = raw.get("iam", {})
        if isinstance(iam, dict):
            for pb in iam.get("public_bindings", []):
                if isinstance(pb, str) and " → " in pb:
                    member, role = pb.split(" → ", 1)
                    artifact = PermissionArtifact(
                        principal=member.strip(),
                        target=project_id,
                        right=role.strip(),
                        domain="gcp",
                        is_dangerous=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
            for ob in iam.get("owner_bindings", []):
                if isinstance(ob, str) and ob:
                    artifact = PermissionArtifact(
                        principal=ob,
                        target=project_id,
                        right="roles/owner",
                        domain="gcp",
                        is_dangerous=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
        # 3. Service account keys
        sa = raw.get("service_accounts", {})
        if isinstance(sa, dict):
            for mk in sa.get("many_keys", []):
                if isinstance(mk, dict):
                    email = mk.get("service_account", "")
                    key_count = mk.get("active_key_count", 0)
                    if email:
                        artifact = CredentialArtifact(
                            username=email,
                            domain="gcp",
                            cred_type="service_account_key",
                            source_host=project_id,
                            privilege="service_account",
                            note=f"active_keys={key_count}",
                            source_module=capability,
                        )
                        store.add_credential(artifact)
                        count += 1
        return count

    def _normalize_container_vectors(
        self, raw: dict, store: ArtifactStore, capability: str = "container_escape_vectors"
    ) -> int:
        """Normalize container escape vectors into HostArtifact vulns and metadata."""
        target = raw.get("target") or raw.get("host") or "container-host"
        existing = None
        for h in store.hosts():
            if h.ip_address == target or h.hostname == target:
                existing = h
                break
        host = existing or HostArtifact(
            ip_address=target,
            hostname=target,
            source_module=capability,
        )
        count = 0
        # Check docker socket
        ds = raw.get("docker_socket", {})
        if isinstance(ds, dict) and ds.get("writable"):
            vuln_entry = {"type": "container_escape", "vector": "docker_socket_writable", "severity": "CRITICAL"}
            host.vulns.append(vuln_entry)
            host.metadata.setdefault("container_escape_vectors", []).append(vuln_entry)
            count += 1
        # Check privileged
        priv = raw.get("privileged", {})
        if isinstance(priv, dict) and priv.get("privileged"):
            vuln_entry = {"type": "container_escape", "vector": "privileged_container", "severity": "CRITICAL"}
            host.vulns.append(vuln_entry)
            host.metadata.setdefault("container_escape_vectors", []).append(vuln_entry)
            count += 1
        # Check host mounts
        hm = raw.get("host_mounts", {})
        if isinstance(hm, dict) and hm.get("high"):
            vuln_entry = {"type": "container_escape", "vector": "host_mounts_high_risk", "mounts": hm["high"], "severity": "CRITICAL"}
            host.vulns.append(vuln_entry)
            host.metadata.setdefault("container_escape_vectors", []).append(vuln_entry)
            count += 1
        # If raw["container_escape_vectors"] has items
        vectors = raw.get("container_escape_vectors", [])
        if isinstance(vectors, list):
            for v in vectors:
                if isinstance(v, dict):
                    host.vulns.append(v)
                    count += 1
                elif hasattr(v, "evidence") and isinstance(v.evidence, dict):
                    host.vulns.append(v.evidence)
                    count += 1
        if count and not existing:
            store.add(host)
        return max(count, 1 if count else 0)

    def _normalize_k8s_rbac(
        self, raw: dict, store: ArtifactStore, capability: str = "k8s_rbac_findings"
    ) -> int:
        """Normalize Kubernetes RBAC findings into PermissionArtifact."""
        findings = raw.get("k8s_rbac_findings") or raw.get("k8s_findings", [])
        if not isinstance(findings, list):
            return 0
        count = 0
        for f in findings:
            if not isinstance(f, dict):
                if hasattr(f, "evidence") and isinstance(f.evidence, dict):
                    f = f.evidence
                else:
                    continue
            principal = f.get("service_account") or f.get("principal") or "system:serviceaccount"
            target = f.get("resource") or f.get("target") or "k8s_cluster"
            verb = f.get("verb") or f.get("right") or "cluster-admin"
            artifact = PermissionArtifact(
                principal=principal,
                target=target,
                right=verb,
                domain="k8s",
                is_dangerous=True,
                source_module=capability,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_federation_trusts(
        self, raw: dict, store: ArtifactStore, capability: str = "federation_trusts"
    ) -> int:
        """Normalize identity federation trusts into CloudResourceArtifact."""
        trusts = raw.get("federation_trusts", [])
        if isinstance(trusts, (str, dict)):
            trusts = [trusts]
        elif not isinstance(trusts, list):
            return 0
        count = 0
        for t in trusts:
            if isinstance(t, str):
                t_str = t.strip()
                if not t_str:
                    continue
                if "Azure" in t_str:
                    provider = "azure"
                    res_type = "federation_trust"
                    res_id = t_str.split(":", 1)[1].strip() if ":" in t_str else t_str
                elif "AWS" in t_str:
                    provider = "aws"
                    res_type = "saml_provider"
                    res_id = t_str.split(":", 1)[1].strip() if ":" in t_str else t_str
                elif "ADFS" in t_str:
                    provider = "adfs"
                    res_type = "relying_party"
                    res_id = t_str.split(":", 1)[1].strip() if ":" in t_str else t_str
                else:
                    provider = "cloud"
                    res_type = "federation_trust"
                    res_id = t_str
                artifact = CloudResourceArtifact(
                    provider=provider,
                    resource_type=res_type,
                    resource_id=res_id,
                    is_public=False,
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
            elif isinstance(t, dict):
                artifact = CloudResourceArtifact(
                    provider=t.get("provider", "cloud"),
                    resource_type=t.get("resource_type", "federation_trust"),
                    resource_id=t.get("resource_id") or t.get("name", "trust"),
                    is_public=t.get("is_public", False),
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
            else:
                logger.warning("federation_trust_invalid_entry", type=type(t).__name__)
        return count

    def _normalize_golden_saml(
        self, raw: dict, store: ArtifactStore, capability: str = "golden_saml_paths"
    ) -> int:
        """Normalize Golden SAML paths into PermissionArtifact."""
        paths = raw.get("golden_saml_paths", [])
        if isinstance(paths, dict):
            paths = [paths]
        elif not isinstance(paths, list):
            return 0
        count = 0
        for p in paths:
            if not isinstance(p, dict):
                continue
            rps = p.get("relying_parties", [])
            for rp in (rps if isinstance(rps, list) else [str(rps)]):
                if rp:
                    artifact = PermissionArtifact(
                        principal="adfs_token_signing_key",
                        target=rp,
                        right="GoldenSAML_AssertionForgery",
                        domain="federation",
                        is_dangerous=True,
                        source_module=capability,
                    )
                    store.add(artifact)
                    count += 1
            if not rps:
                artifact = PermissionArtifact(
                    principal="adfs_token_signing_key",
                    target=p.get("attack", "Golden SAML"),
                    right="GoldenSAML",
                    domain="federation",
                    is_dangerous=True,
                    source_module=capability,
                )
                store.add(artifact)
                count += 1
        return count

    def _normalize_pivot_paths(
        self, raw: dict, store: ArtifactStore, capability: str = "pivot_paths"
    ) -> int:
        """Normalize cross-cloud pivot paths into PermissionArtifact."""
        paths = raw.get("pivot_paths", [])
        if not isinstance(paths, list):
            return 0
        count = 0
        for p in paths:
            if not isinstance(p, dict):
                continue
            path_name = p.get("path") or p.get("name", "cross_cloud_pivot")
            tech = p.get("technique", "T1606.002")
            artifact = PermissionArtifact(
                principal="federated_identity",
                target=path_name,
                right=tech,
                domain="multi_cloud",
                is_dangerous=True,
                source_module=capability,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_snmp_findings(
        self, raw: dict, store: ArtifactStore, capability: str = "snmp_findings"
    ) -> int:
        """Normalize SNMP enumeration findings into CredentialArtifact and HostArtifact."""
        count = 0
        target = raw.get("target") or raw.get("host", "")
        # Community strings
        valid_comms = raw.get("valid_communities", [])
        if isinstance(valid_comms, list):
            for vc in valid_comms:
                comm = vc.get("community", "") if isinstance(vc, dict) else (vc if isinstance(vc, str) else "")
                if comm:
                    artifact = CredentialArtifact(
                        username="snmp",
                        secret=comm,
                        cred_type="snmp_community",
                        source_host=target,
                        privilege="local_admin" if comm.lower() in ("private", "write") else "user",
                        source_module=capability,
                    )
                    store.add_credential(artifact)
                    count += 1
        # System info
        sys_info = raw.get("system_info", {})
        if isinstance(sys_info, dict) and target:
            sys_descr = sys_info.get("sysDescr", "")
            sys_name = sys_info.get("sysName", "")
            existing = None
            for h in store.hosts():
                if h.ip_address == target or h.hostname == target:
                    existing = h
                    break
            if existing:
                if sys_descr and not existing.os:
                    existing.os = sys_descr
                if sys_name and not existing.hostname:
                    existing.hostname = sys_name
                existing.metadata["snmp_system_info"] = sys_info
            else:
                h = HostArtifact(
                    ip_address=target,
                    hostname=sys_name or target,
                    os=sys_descr,
                    metadata={"snmp_system_info": sys_info},
                    source_module=capability,
                )
                store.add(h)
            count += 1
        return count

    def _normalize_system_info(
        self, raw: dict, store: ArtifactStore, capability: str = "system_info"
    ) -> int:
        """Normalize generic system_info dict into HostArtifact."""
        target = raw.get("target") or raw.get("host", "")
        sys_info = raw.get("system_info", {})
        if not target and isinstance(sys_info, dict):
            target = sys_info.get("sysName") or sys_info.get("hostname", "")
        if not target:
            return 0
        existing = None
        for h in store.hosts():
            if h.ip_address == target or h.hostname == target:
                existing = h
                break
        if existing:
            if isinstance(sys_info, dict):
                existing.metadata["system_info"] = sys_info
                if sys_info.get("sysDescr") and not existing.os:
                    existing.os = sys_info["sysDescr"]
            return 1
        h = HostArtifact(
            ip_address=target,
            hostname=target,
            os=sys_info.get("sysDescr", "") if isinstance(sys_info, dict) else "",
            metadata={"system_info": sys_info} if isinstance(sys_info, dict) else {},
            source_module=capability,
        )
        store.add(h)
        return 1

    def _normalize_password_policy(
        self, raw: dict, store: ArtifactStore, capability: str = "password_policy"
    ) -> int:
        """Normalize AD/cloud password policy into DomainArtifact metadata."""
        policy = raw.get("password_policy", {})
        if not isinstance(policy, dict) or not policy:
            return 0
        domain = raw.get("domain", "") or raw.get("dc", "") or "default"
        existing_domain = None
        for d in store.get(ArtifactType.DOMAIN):
            if isinstance(d, DomainArtifact) and d.domain_name.lower() == domain.lower():
                existing_domain = d
                break
        if existing_domain:
            existing_domain.metadata["password_policy"] = policy
            return 1
        d_artifact = DomainArtifact(
            domain_name=domain,
            metadata={"password_policy": policy},
            source_module=capability,
        )
        store.add(d_artifact)
        return 1

    def _normalize_scheduled_tasks(
        self, raw: dict, store: ArtifactStore, capability: str = "scheduled_tasks"
    ) -> int:
        """Normalize scheduled tasks into PermissionArtifact and HostArtifact metadata."""
        count = 0
        target = raw.get("target") or raw.get("host", "")
        seen_tasks: set[str] = set()
        for key in ("writable_path_tasks", "high_priv_tasks", "all_tasks"):
            tasks = raw.get(key, [])
            if isinstance(tasks, list):
                for t in tasks:
                    if isinstance(t, dict):
                        task_name = t.get("task") or t.get("name", "")
                        if task_name and task_name not in seen_tasks:
                            seen_tasks.add(task_name)
                            run_as = t.get("run_as", "SYSTEM")
                            artifact = PermissionArtifact(
                                principal=run_as,
                                target=task_name,
                                right="ExecuteScheduledTask",
                                domain=target,
                                is_dangerous=bool(t.get("writable_indicator") or key == "writable_path_tasks"),
                                source_module=capability,
                            )
                            store.add(artifact)
                            count += 1
        if target:
            for h in store.hosts():
                if h.ip_address == target or h.hostname == target:
                    h.metadata["scheduled_tasks_count"] = raw.get("total_tasks", count)
                    break
        return count

    def _normalize_registry_credentials(
        self, raw: dict, store: ArtifactStore, capability: str = "credential_hints"
    ) -> int:
        """Normalize registry credential hits (AutoLogon, VNC, PuTTY) into CredentialArtifact."""
        count = 0
        target = raw.get("target") or raw.get("host", "")
        # 1. Credential hits (AutoLogon, VNC, etc.)
        hits = raw.get("credential_hits", [])
        if isinstance(hits, list):
            for h in hits:
                if not isinstance(h, dict):
                    continue
                vals = h.get("values", {})
                if not isinstance(vals, dict):
                    continue
                path = h.get("path", "")
                if "Winlogon" in path:
                    user = vals.get("DefaultUserName", "")
                    pwd = vals.get("DefaultPassword", "")
                    dom = vals.get("DefaultDomainName", "") or target
                    if pwd and isinstance(pwd, str):
                        artifact = CredentialArtifact(
                            username=user.strip("\x00"),
                            domain=dom.strip("\x00"),
                            cred_type="cleartext",
                            secret=pwd.strip("\x00"),
                            source_host=target,
                            privilege="local_admin",
                            note="registry_autologon",
                            source_module=capability,
                        )
                        store.add_credential(artifact)
                        count += 1
                elif "VNC" in path:
                    pwd = vals.get("Password", "")
                    if pwd:
                        artifact = CredentialArtifact(
                            username="vnc",
                            domain=target,
                            cred_type="vnc_password",
                            secret=str(pwd),
                            source_host=target,
                            privilege="user",
                            note=f"registry_{path}",
                            source_module=capability,
                        )
                        store.add_credential(artifact)
                        count += 1
        # 2. PuTTY sessions
        putty = raw.get("putty_sessions", [])
        if isinstance(putty, list):
            for s in putty:
                if isinstance(s, dict):
                    u = s.get("user_name", "")
                    h_name = s.get("host_name", "")
                    s_name = s.get("session_name", "")
                    if u or h_name:
                        artifact = CredentialArtifact(
                            username=u or "unknown",
                            domain=h_name,
                            cred_type="putty_session",
                            source_host=target,
                            note=f"session={s_name} remote={h_name}",
                            source_module=capability,
                        )
                        store.add_credential(artifact)
                        count += 1
        return count

    def _normalize_secrets_scan(
        self, raw: dict, store: ArtifactStore, capability: str = "discovered_secrets"
    ) -> int:
        """Normalize secrets scanner findings into CredentialArtifact."""
        count = 0
        target = raw.get("target") or raw.get("host", "")
        secrets = raw.get("discovered_secrets") or []
        if isinstance(secrets, list):
            for s in secrets:
                if not isinstance(s, dict):
                    continue
                sec_val = s.get("secret_value") or s.get("extracted_secret") or ""
                pattern = s.get("pattern", "secret")
                fpath = s.get("file", "")
                line = s.get("line", 0)
                if sec_val:
                    artifact = CredentialArtifact(
                        username=pattern,
                        secret=sec_val,
                        cred_type=pattern,
                        source_host=target,
                        privilege="unknown",
                        note=f"{fpath}:{line}",
                        source_module=capability,
                    )
                    store.add_credential(artifact)
                    count += 1
        cred_list = raw.get("credential_list", [])
        if target and (cred_list or raw.get("sensitive_data_found")):
            for h in store.hosts():
                if h.ip_address == target or h.hostname == target:
                    if cred_list:
                        h.metadata["secret_files"] = cred_list
                    if raw.get("sensitive_data_found"):
                        h.metadata["sensitive_data_found"] = True
                    break
        return count

    def _normalize_smb_shares(
        self, raw: dict, store: ArtifactStore, capability: str = "file_share_list"
    ) -> int:
        """Normalize SMB shares and sensitive file paths into HostArtifact metadata."""
        target = raw.get("target") or raw.get("host", "")
        if not target:
            return 0
        share_list = raw.get("file_share_list", [])
        file_paths = raw.get("sensitive_file_paths", [])
        existing = None
        for h in store.hosts():
            if h.ip_address == target or h.hostname == target:
                existing = h
                break
        if existing:
            if share_list:
                existing.metadata["file_shares"] = share_list
            if file_paths:
                existing.metadata["sensitive_files"] = file_paths
            return 1
        h = HostArtifact(
            ip_address=target,
            hostname=target,
            metadata={
                "file_shares": share_list,
                "sensitive_files": file_paths,
            },
            source_module=capability,
        )
        store.add(h)
        return 1



