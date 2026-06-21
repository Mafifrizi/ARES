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
  Host         — IP address, hostname, OS, open ports
  Domain       — AD domain with trust relationships
  User         — domain/local user account
  Credential   — NTLM hash, cleartext, ticket, key
  Service      — SPN-registered service
  Permission   — ACE (who can do what to whom)
  Finding      — vulnerability/misconfiguration
  Hash         — crackable hash (KRB5TGS, KRB5ASREP, NTLM)
  Secret       — plaintext secret (API key, password, token)
  CloudResource — S3 bucket, IAM role, storage account

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
    _uid:          str | None = field(default=None, repr=False)

    @property
    def uid(self) -> str:
        """Deterministic UID — same content = same ID (enables deduplication)."""
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
    privilege:   str = ""   # domain_admin | service_account | local_admin | user | unknown

    def __post_init__(self) -> None:
        self.artifact_type = ArtifactType.CREDENTIAL
        if self.host and not self.source_host:
            self.source_host = self.host
        elif self.source_host and not self.host:
            self.host = self.source_host

    def _dedup_key(self) -> str:
        return f"{self.domain}\\{self.username}:{self.cred_type}:{self.secret_hash[:8]}"

    def _to_dict_fields(self) -> dict[str, Any]:
        return {
            "username": self.username, "domain": self.domain,
            "cred_type": self.cred_type, "cracked": self.cracked,
            "source_host": self.source_host, "privilege": self.privilege,
        }


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
    """An ACE (Access Control Entry) — who can do what to whom."""
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
        self.is_dangerous = self.right in self.DANGEROUS_RIGHTS

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
            except Exception:
                pass  # Never let normalization failures block the engine
        return count

    def _normalize_capability(
        self, capability: str, raw: dict, store: ArtifactStore
    ) -> int:
        """Route a capability to its specific normalizer."""
        handlers: dict[str, Any] = {
            "user_list":        self._normalize_users,
            "computer_list":    self._normalize_computers,
            "kerberos_hashes":  self._normalize_kerberos_hashes,
            "asrep_hashes":     self._normalize_asrep_hashes,
            "ntlm_hashes":      self._normalize_ntlm_hashes,
            "spn_list":         self._normalize_spns,
            "acl_findings":     self._normalize_permissions,
            "aws_findings":     self._normalize_cloud,
            "privesc_vectors":  self._normalize_host_vuln,
        }
        handler = handlers.get(capability)
        if handler:
            return handler(raw, store)
        return 0

    def _normalize_users(self, raw: dict, store: ArtifactStore) -> int:
        users = raw.get("users", [])
        count = 0
        for u in users:
            if not isinstance(u, dict):
                continue
            artifact = UserArtifact(
                username    = u.get("samAccountName", u.get("username", "")),
                domain      = u.get("domain", ""),
                enabled     = u.get("enabled", True),
                is_admin    = u.get("isAdmin", False),
                no_preauth  = u.get("noPreauth", False),
                spns        = u.get("spns", []),
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_computers(self, raw: dict, store: ArtifactStore) -> int:
        computers = raw.get("computers", [])
        count = 0
        for c in computers:
            if not isinstance(c, dict):
                continue
            artifact = HostArtifact(
                ip_address = "",
                hostname   = c.get("dns", c.get("name", "")),
                is_dc      = c.get("is_dc", False),
                os         = c.get("os", ""),
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_kerberos_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = raw.get("hashes", [])
        count  = 0
        accounts = raw.get("accounts", [])
        for h in hashes:
            if not isinstance(h, str):
                continue
            # Parse username from hash: $krb5tgs$23$*username$DOMAIN$...
            parts    = h.split("$")
            username = parts[3].split("@")[0] if len(parts) > 3 else ""
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
        return count

    def _normalize_asrep_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = raw.get("hashes", [])
        count  = 0
        for h in hashes:
            if not isinstance(h, str):
                continue
            parts    = h.split("$")
            username = parts[3].split("@")[0] if len(parts) > 3 else ""
            domain   = parts[4].split("@")[0] if len(parts) > 4 else ""
            artifact = HashArtifact(
                username     = username,
                domain       = domain,
                hash_value   = h[:120],
                hash_type    = "krb5asrep",
                hashcat_mode = 18200,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_ntlm_hashes(self, raw: dict, store: ArtifactStore) -> int:
        hashes = raw.get("hashes", [])
        count  = 0
        for h in hashes:
            if not isinstance(h, dict):
                continue
            artifact = HashArtifact(
                username     = h.get("username", ""),
                domain       = "",
                hash_value   = h.get("nt_hash", ""),
                hash_type    = "ntlm",
                hashcat_mode = 1000,
            )
            store.add(artifact)
            count += 1
        return count

    def _normalize_spns(self, raw: dict, store: ArtifactStore) -> int:
        spns = raw.get("spns", [])
        count = 0
        for s in spns:
            if not isinstance(s, dict):
                continue
            artifact = UserArtifact(
                username        = s.get("name", ""),
                domain          = "",
                enabled         = s.get("enabled", True),
                is_admin        = s.get("is_admin", False),
                spns            = s.get("spns", []),
                is_kerberoastable = bool(s.get("spns")),
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
        return count

    def _normalize_host_vuln(self, raw: dict, store: ArtifactStore) -> int:
        host = raw.get("host", "")
        if host and host != "localhost":
            artifact = HostArtifact(
                ip_address = host,
                hostname   = host,
            )
            store.add(artifact)
            return 1
        return 0
