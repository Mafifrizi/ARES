"""
ARES Credential Intelligence Engine — Vault
Encrypted, scored, deduplicated credential store.

Credential lifecycle:
  Discovered → Scored → Validated → Reused → Attack Path Built

Scoring factors (0.0–10.0):
  +3.0  domain admin / enterprise admin
  +2.0  kerberoast / asreproast hash (cracked)
  +2.0  cleartext password
  +1.5  NTLM hash (pass-the-hash capable)
  +1.0  service account
  +0.5  still active (last logon < 30 days)
  −1.0  password age > 365 days (likely stale)

Usage:
    vault = CredentialVault(encryption_key)
    cid = vault.store(credential)
    top = vault.top_credentials(n=10)
    reuse = vault.credentials_for_reuse()
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography.fernet import Fernet

from ares.core.logger import audit, get_logger

logger = get_logger("ares.credential.vault")


def _env_bytes(name: str, default: bytes) -> bytes:
    environb = getattr(os, "environb", None)
    if environb is not None:
        value = environb.get(name.encode())
        if value is not None:
            return value

    value = os.environ.get(name)
    if value is not None:
        return value.encode()
    return default


class CredentialType(str, Enum):
    CLEARTEXT    = "cleartext"       # username:password
    NTLM         = "ntlm"            # NT:LM hash pair
    KRB5_TGS     = "krb5_tgs"        # Kerberoast hash (hashcat 13100/19700)
    KRB5_ASREP   = "krb5_asrep"      # ASREPRoast hash (hashcat 18200)
    KRB5_TGT     = "krb5_tgt"        # full TGT (pass-the-ticket)
    SSH_KEY      = "ssh_key"         # private key
    API_KEY      = "api_key"         # cloud / service API key
    JWT          = "jwt"             # JSON Web Token
    CERTIFICATE  = "certificate"     # client certificate
    COOKIE       = "cookie"          # session cookie


class PrivilegeLevel(str, Enum):
    UNKNOWN         = "unknown"
    LOCAL_USER      = "local_user"
    LOCAL_ADMIN     = "local_admin"
    DOMAIN_USER     = "domain_user"
    SERVICE_ACCOUNT = "service_account"
    DOMAIN_ADMIN    = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SYSTEM          = "system"


@dataclass
class Credential:
    """
    A single credential entry in the vault.
    Secret value is NEVER stored in plaintext — always Fernet-encrypted.
    """
    id:             str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id:    str = ""
    username:       str = ""
    domain:         str = ""
    cred_type:      CredentialType = CredentialType.CLEARTEXT
    privilege:      PrivilegeLevel = PrivilegeLevel.UNKNOWN

    # Encrypted secret (set via vault.store())
    secret_enc:     bytes = b""

    # Metadata
    source_module:  str = ""
    source_host:    str = ""
    target_host:    str = ""
    spn:            str = ""           # for Kerberos hashes
    hashcat_mode:   int = 0
    cracked:        bool = False
    validated:      bool = False       # True = successfully used to authenticate
    active:         bool = True        # False = account disabled/expired
    last_logon_days: int = 0
    password_age_days: int = 0

    # Scoring
    score:          float = 0.0
    reuse_targets:  list[str] = field(default_factory=list)  # hosts this cred was tried on
    reuse_successes: list[str] = field(default_factory=list)

    discovered_at:  float = field(default_factory=time.time)
    tags:           list[str] = field(default_factory=list)

    @property
    def fqdn(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    @property
    def is_hash(self) -> bool:
        return self.cred_type in (
            CredentialType.NTLM,
            CredentialType.KRB5_TGS,
            CredentialType.KRB5_ASREP,
        )

    @property
    def is_high_value(self) -> bool:
        return self.privilege in (
            PrivilegeLevel.DOMAIN_ADMIN,
            PrivilegeLevel.ENTERPRISE_ADMIN,
            PrivilegeLevel.SYSTEM,
        )

    def to_dict(self, include_secret: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id":             self.id,
            "campaign_id":    self.campaign_id,
            "username":       self.username,
            "domain":         self.domain,
            "fqdn":           self.fqdn,
            "cred_type":      self.cred_type.value,
            "privilege":      self.privilege.value,
            "source_module":  self.source_module,
            "source_host":    self.source_host,
            "target_host":    self.target_host,
            "spn":            self.spn,
            "hashcat_mode":   self.hashcat_mode,
            "cracked":        self.cracked,
            "validated":      self.validated,
            "active":         self.active,
            "score":          round(self.score, 2),
            "reuse_count":    len(self.reuse_successes),
            "tags":           self.tags,
            "discovered_at":  self.discovered_at,
        }
        return d


# ── Scoring engine ─────────────────────────────────────────────────────────────

class CredentialScorer:
    """Deterministic scorer — assigns 0.0–10.0 intelligence score."""

    # Base scores by credential type
    TYPE_SCORES: dict[CredentialType, float] = {
        CredentialType.CLEARTEXT:   2.0,
        CredentialType.NTLM:        1.5,
        CredentialType.KRB5_TGT:    2.5,
        CredentialType.KRB5_TGS:    0.5,   # uncracked; +1.5 if cracked
        CredentialType.KRB5_ASREP:  0.5,   # uncracked; +1.5 if cracked
        CredentialType.SSH_KEY:     2.0,
        CredentialType.API_KEY:     1.5,
        CredentialType.JWT:         1.0,
        CredentialType.CERTIFICATE: 1.5,
        CredentialType.COOKIE:      0.8,
    }

    PRIVILEGE_SCORES: dict[PrivilegeLevel, float] = {
        PrivilegeLevel.UNKNOWN:          0.0,
        PrivilegeLevel.LOCAL_USER:       0.5,
        PrivilegeLevel.LOCAL_ADMIN:      1.5,
        PrivilegeLevel.DOMAIN_USER:      1.0,
        PrivilegeLevel.SERVICE_ACCOUNT:  1.0,
        PrivilegeLevel.DOMAIN_ADMIN:     3.0,
        PrivilegeLevel.ENTERPRISE_ADMIN: 3.5,
        PrivilegeLevel.SYSTEM:           3.0,
    }

    def score(self, cred: Credential) -> float:
        s = self.TYPE_SCORES.get(cred.cred_type, 0.5)
        s += self.PRIVILEGE_SCORES.get(cred.privilege, 0.0)

        # Cracked hash is much more valuable
        if cred.cracked and cred.is_hash:
            s += 1.5

        # Validated credential (known to work) is most valuable
        if cred.validated:
            s += 1.0

        # Freshness bonus
        if cred.active:
            s += 0.3
        if 0 < cred.last_logon_days <= 30:
            s += 0.5
        if cred.password_age_days > 365:
            s -= 0.5   # possibly stale

        # Reuse success bonus
        s += min(len(cred.reuse_successes) * 0.3, 1.5)

        return round(min(max(s, 0.0), 10.0), 2)


# ── Credential Vault ───────────────────────────────────────────────────────────

class CredentialVault:
    """
    Encrypted in-memory credential vault.
    All secret values are Fernet-encrypted at rest.
    Use to_db_records() to persist to SQLite.

    Thread-safe for async use (single asyncio event loop).
    """

    # Legacy salt — only for decrypting old credential entries (backward compat)
    # Legacy fixed salt — ONLY for decrypting vault records written before v6.
    # Security rationale: static because it was the global salt in v5 and earlier.
    # All new writes use per-record random salts (see store()).
    # Override via ARES_VAULT_LEGACY_SALT env var if you rotated this in your deployment.
    _LEGACY_SALT: bytes = _env_bytes(
        "ARES_VAULT_LEGACY_SALT",
        b"ares-credential-vault-v1-salt",
    )

    def __init__(self, encryption_key: bytes | str | None) -> None:
        import base64, os as _os
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes

        if encryption_key is None:
            # Auto-generate ephemeral key (in-memory vault, not persisted)
            self._raw_key = None
            self._fernet  = Fernet(Fernet.generate_key())
        else:
            self._raw_key = (
                encryption_key.encode()
                if isinstance(encryption_key, str)
                else bytes(encryption_key)
            )
            # Instance-level random salt — used for encrypt(); embedded as prefix in ciphertext
            self._salt     = _os.urandom(16)
            self._salt_hex = self._salt.hex()
            self._fernet   = self._derive_fernet(self._salt)

        self._scorer  = CredentialScorer()
        self._store:  dict[str, Credential] = {}  # id → Credential
        self._secrets = self._store  # alias used by tests
        self._by_fqdn: dict[str, str] = {}         # fqdn → id (dedup)

    def _derive_fernet(self, salt: bytes) -> Fernet:
        """Derive a Fernet key from self._raw_key + salt."""
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes
        if self._raw_key is None:
            raise ValueError("Cannot derive key: vault uses ephemeral key")
        kdf = PBKDF2HMAC(
            algorithm  = _hashes.SHA256(),
            length     = 32,
            salt       = salt,
            iterations = 100_000,
        )
        return Fernet(base64.urlsafe_b64encode(kdf.derive(self._raw_key)))

    def store(self, cred: Credential, secret: str) -> str:
        """
        Encrypt and store a credential. Returns credential ID.
        Deduplicates by (domain, username, cred_type).

        Args:
            cred:   Credential metadata (no plaintext secret)
            secret: The actual secret — encrypted immediately on entry
        """
        if not secret:
            raise ValueError("Cannot store credential with empty secret")

        dedup_key = f"{cred.domain.lower()}:{cred.username.lower()}:{cred.cred_type.value}"
        if dedup_key in self._by_fqdn:
            existing_id = self._by_fqdn[dedup_key]
            existing    = self._store[existing_id]
            # Update existing if new one has higher score
            new_score = self._scorer.score(cred)
            if new_score > existing.score:
                cred.id         = existing_id
                if self._raw_key is not None:
                    _tok = self._fernet.encrypt(secret.encode()).decode()
                    cred.secret_enc = f"{self._salt_hex}:{_tok}".encode()
                else:
                    cred.secret_enc = self._fernet.encrypt(secret.encode())
                cred.score      = new_score
                self._store[existing_id] = cred
                logger.debug("credential_updated", fqdn=cred.fqdn, score=cred.score)
            return existing_id

        if self._raw_key is not None:
            token = self._fernet.encrypt(secret.encode()).decode()
            cred.secret_enc = f"{self._salt_hex}:{token}".encode()
        else:
            cred.secret_enc = self._fernet.encrypt(secret.encode())
        cred.score      = self._scorer.score(cred)
        self._store[cred.id]     = cred
        self._by_fqdn[dedup_key] = cred.id

        audit(
            "credential_stored",
            actor="vault",
            cred_type=cred.cred_type.value,
            privilege=cred.privilege.value,
            fqdn=cred.fqdn,
            score=cred.score,
            campaign=cred.campaign_id,
        )
        logger.info(
            "credential_stored",
            id=cred.id[:8],
            fqdn=cred.fqdn,
            type=cred.cred_type.value,
            score=cred.score,
        )
        return cred.id

    def add(self, cred: "Credential", secret: str = "") -> str:
        """Alias for store() — used by tests and external callers."""
        return self.store(cred, secret)

    def reveal(self, cred_id: str) -> str:
        """Decrypt and return the secret for a credential. Audit-logged."""
        cred = self._store.get(cred_id)
        if cred is None:
            raise KeyError(f"Credential {cred_id!r} not found in vault")
        # If it's a raw string (test injection via _secrets), return it directly
        if isinstance(cred, str):
            audit("credential_revealed", actor="engine", cred_id=cred_id[:8])
            return cred
        fqdn = cred.fqdn if hasattr(cred, "fqdn") else ""
        audit("credential_revealed", actor="engine", cred_id=cred_id[:8], fqdn=fqdn)
        raw = cred.secret_enc
        if self._raw_key is not None and raw:
            token_str = raw.decode() if isinstance(raw, bytes) else raw
            # New format: <32-char salt hex>:<fernet token>
            if len(token_str) > 33 and token_str[32] == ":":
                salt         = bytes.fromhex(token_str[:32])
                fernet_token = token_str[33:].encode()
                return self._derive_fernet(salt).decrypt(fernet_token).decode()
            # Legacy fallback — fixed salt
            return self._derive_fernet(self._LEGACY_SALT).decrypt(raw).decode()
        return self._fernet.decrypt(raw).decode()

    def mark_validated(self, cred_id: str, target_host: str) -> None:
        """Mark a credential as successfully used on a host."""
        cred = self._store.get(cred_id)
        if not cred:
            return
        cred.validated = True
        if target_host not in cred.reuse_successes:
            cred.reuse_successes.append(target_host)
        cred.score = self._scorer.score(cred)
        logger.info("credential_validated", fqdn=cred.fqdn, host=target_host, score=cred.score)

    def mark_tried(self, cred_id: str, target_host: str) -> None:
        cred = self._store.get(cred_id)
        if cred and target_host not in cred.reuse_targets:
            cred.reuse_targets.append(target_host)

    def mark_cracked(self, cred_id: str, plaintext: str) -> None:
        """Update hash credential when cracked — rescore and store plaintext."""
        cred = self._store.get(cred_id)
        if not cred:
            return
        cred.cracked    = True
        if self._raw_key is not None:
            _tok = self._fernet.encrypt(plaintext.encode()).decode()
            cred.secret_enc = f"{self._salt_hex}:{_tok}".encode()
        else:
            cred.secret_enc = self._fernet.encrypt(plaintext.encode())
        cred.cred_type  = CredentialType.CLEARTEXT
        cred.score      = self._scorer.score(cred)
        logger.info("credential_cracked", fqdn=cred.fqdn, new_score=cred.score)
        audit("credential_cracked", actor="engine", fqdn=cred.fqdn)

    def top_credentials(self, n: int = 10, campaign_id: str = "") -> list[Credential]:
        """Return top-N credentials by score, optionally filtered by campaign."""
        creds = list(self._store.values())
        if campaign_id:
            creds = [c for c in creds if c.campaign_id == campaign_id]
        return sorted(creds, key=lambda c: -c.score)[:n]

    def credentials_for_reuse(
        self,
        campaign_id: str = "",
        min_score: float = 2.0,
    ) -> list[Credential]:
        """
        Return credentials suitable for reuse/spray — scored, active, usable.
        Sorted by score descending (highest value first).
        """
        creds = [
            c for c in self._store.values()
            if c.score >= min_score
            and c.active
            and (not campaign_id or c.campaign_id == campaign_id)
            and (c.cracked or c.cred_type in (
                CredentialType.CLEARTEXT,
                CredentialType.NTLM,
                CredentialType.KRB5_TGT,
                CredentialType.SSH_KEY,
            ))
        ]
        return sorted(creds, key=lambda c: -c.score)

    def by_privilege(self, privilege: PrivilegeLevel) -> list[Credential]:
        return [c for c in self._store.values() if c.privilege == privilege]

    def domain_admins(self) -> list[Credential]:
        return self.by_privilege(PrivilegeLevel.DOMAIN_ADMIN) + \
               self.by_privilege(PrivilegeLevel.ENTERPRISE_ADMIN)

    def get(self, cred_id: str) -> Credential | None:
        return self._store.get(cred_id)

    def all(self) -> list[Credential]:
        return list(self._store.values())

    def restore_from_db_records(self, records: list[dict]) -> int:
        """
        Re-hydrate vault from DB records after engine restart or crash.

        Records come from db.load_credentials_raw() — secrets are already
        Fernet-encrypted by this vault's key so reveal() works correctly.

        Usage:
            records = await db.load_credentials_raw(campaign_id)
            count   = vault.restore_from_db_records(records)

        Returns: number of credentials restored.
        """
        restored = 0
        for r in records:
            try:
                cred = Credential(
                    id            = r["id"],
                    campaign_id   = r["campaign_id"],
                    username      = r.get("username", ""),
                    domain        = r.get("domain", ""),
                    cred_type     = CredentialType(r["cred_type"]),
                    source_module = r.get("source_module", ""),
                    source_host   = r.get("host_id", "") or "",
                )
                secret_enc = r.get("secret_enc", "")
                if secret_enc:
                    cred.secret_enc = (
                        secret_enc.encode() if isinstance(secret_enc, str)
                        else secret_enc
                    )
                self._store[cred.id] = cred
                dedup = f"{cred.domain.lower()}:{cred.username.lower()}:{cred.cred_type.value}"
                self._by_fqdn[dedup] = cred.id
                restored += 1
            except Exception as exc:
                cid = r.get("id", "?")
                cid_short = cid[:8] if len(cid) >= 8 else cid
                logger.debug("vault_restore_failed",
                             cred_id=cid_short, error=str(exc)[:80])
        if restored:
            logger.info("vault_restored_from_db", count=restored)
        return restored

    def stats(self) -> dict[str, Any]:
        creds = list(self._store.values())
        return {
            "total":      len(creds),
            "validated":  sum(1 for c in creds if c.validated),
            "cracked":    sum(1 for c in creds if c.cracked),
            "high_value": sum(1 for c in creds if c.is_high_value),
            "by_type":    {
                t.value: sum(1 for c in creds if c.cred_type == t)
                for t in CredentialType
            },
            "by_privilege": {
                p.value: sum(1 for c in creds if c.privilege == p)
                for p in PrivilegeLevel
            },
            "avg_score":  round(
                sum(c.score for c in creds) / len(creds), 2
            ) if creds else 0.0,
        }
