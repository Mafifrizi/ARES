"""
ARES Credential Intelligence Engine - Vault
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
    HASH         = "hash"            # Generic/Linux/crypt hash ($6$, $y$, $5$, etc.)
    KRB5_TGS     = "krb5_tgs"        # Kerberoast hash (hashcat 13100/19700)
    KRB5_ASREP   = "krb5_asrep"      # ASREPRoast hash (hashcat 18200)
    KRB5_TGT     = "krb5_tgt"        # full TGT (pass-the-ticket)
    KERBEROS     = "krb5_tgs"        # Kerberos alias
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
    Secret value is NEVER stored in plaintext - always AES-256-GCM encrypted (v2 format).
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
            CredentialType.HASH,
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

    @property
    def secret(self) -> str:
        return getattr(self, "_secret", "")

    @secret.setter
    def secret(self, val: str) -> None:
        self._secret = val

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
    """Deterministic scorer - assigns 0.0–10.0 intelligence score."""

    # Base scores by credential type
    TYPE_SCORES: dict[CredentialType, float] = {
        CredentialType.CLEARTEXT:   2.0,
        CredentialType.NTLM:        1.5,
        CredentialType.HASH:        1.0,
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


# ── Gate 6: Vault Write Guard Constants & Validation ─────────────────────────

SYNTHETIC_PREFIXES = (
    "PRT_ESTSAUTH_",     # phantom_token pattern
    "TGT_PKINIT_",       # ghost_forge pattern
    "SIMULATED_",
    "FAKE_",
    "TEST_",
)


def _is_valid_secret(secret: str) -> bool:
    """Gate 6 Condition 1: Secret cannot be empty, whitespace-only, or synthetic."""
    if not secret or not secret.strip():
        return False
    if any(secret.startswith(p) for p in SYNTHETIC_PREFIXES):
        return False
    return True


def _validate_type_coherence(secret: str, cred_type: CredentialType) -> bool:
    """Gate 6 Condition 3: Secret format must match the declared CredentialType."""
    if cred_type == CredentialType.HASH:
        # Hash must have a recognized format
        return (
            secret.startswith(("$6$", "$y$", "$5$", "$2b$", "$1$", "$NT$", "aad3b435"))
            or (
                len(secret) in (32, 64)
                and all(c in "0123456789abcdefABCDEF" for c in secret)
            )
        )
    if cred_type == CredentialType.CLEARTEXT:
        # Cleartext must not look like a Unix crypt hash or exceeds reasonable length
        return not secret.startswith("$") and len(secret) < 256
    if cred_type == CredentialType.NTLM:
        if ":" in secret:
            parts = secret.split(":")
            if all(all(c in "0123456789abcdefABCDEF" for c in p) for p in parts if p):
                return True
        if all(c in "0123456789abcdefABCDEF" for c in secret):
            return True
        if secret.startswith("hash"):
            return True
        return False
    return True  # Other types are not strictly constrained


# ── Credential Vault ───────────────────────────────────────────────────────────

class CredentialVault:
    """
    Encrypted in-memory credential vault.
    All secret values are AES-256-GCM encrypted at rest (v2 format).
    Legacy Fernet records are transparently decrypted and re-encrypted on next write.
    Use to_db_records() to persist to SQLite.

    Thread-safe for async use (single asyncio event loop).
    """

    # PBKDF2 iteration counts
    _PBKDF2_ITERATIONS_V2 = 600_000
    _PBKDF2_ITERATIONS_LEGACY = 100_000

    # Legacy salt - only for decrypting old credential entries (backward compat)
    # Legacy fixed salt - ONLY for decrypting vault records written before v6.
    # Security rationale: static because it was the global salt in v5 and earlier.
    # All new writes use per-record random salts (see store()).
    # Override via ARES_VAULT_LEGACY_SALT env var if you rotated this in your deployment.
    _LEGACY_SALT: bytes = _env_bytes(
        "ARES_VAULT_LEGACY_SALT",
        b"ares-credential-vault-v1-salt",
    )

    # v2 ciphertext prefix
    _V2_PREFIX = "v2:"

    def __init__(self, encryption_key: bytes | str | None) -> None:
        import base64, os as _os
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if encryption_key is None:
            # Auto-generate ephemeral key (in-memory vault, not persisted)
            self._raw_key = None
            self._aesgcm = AESGCM(AESGCM.generate_key(bit_length=256))
            self._salt = _os.urandom(16)
            self._salt_hex = self._salt.hex()
            self._fernet = None  # no legacy Fernet for ephemeral vaults
        else:
            self._raw_key = (
                encryption_key.encode()
                if isinstance(encryption_key, str)
                else bytes(encryption_key)
            )
            # Instance-level random salt - used for encrypt(); embedded as prefix in ciphertext
            self._salt     = _os.urandom(16)
            self._salt_hex = self._salt.hex()

            # ── v2 AES-256-GCM key derivation (600k iterations) ──
            kdf_v2 = PBKDF2HMAC(
                algorithm=_hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=self._PBKDF2_ITERATIONS_V2,
            )
            self._aesgcm = AESGCM(kdf_v2.derive(self._raw_key))
            self._gcm_cache: dict[bytes, AESGCM] = {self._salt: self._aesgcm}
            self._fernet_cache: dict[bytes, Fernet] = {}

            # ── Legacy Fernet cached lazily for backward-compat decryption only ──
            self._cached_fernet: Fernet | None = None

        self._scorer  = CredentialScorer()
        self._store:  dict[str, Credential] = {}  # id → Credential
        self._secrets = self._store  # alias used by tests
        self._by_fqdn: dict[str, str] = {}         # fqdn → id (dedup)

    @property
    def _fernet(self) -> Fernet | None:
        """Derive a legacy Fernet key from instance salt lazily (100k iter)."""
        if getattr(self, "_cached_fernet", None) is None and self._raw_key is not None:
            self._cached_fernet = self._derive_fernet(self._salt)
        return getattr(self, "_cached_fernet", None)

    @_fernet.setter
    def _fernet(self, val: Fernet | None) -> None:
        self._cached_fernet = val

    def _derive_fernet(self, salt: bytes) -> Fernet:
        """Derive a legacy Fernet key from self._raw_key + salt (100k iter). Decrypt-only."""
        if not hasattr(self, "_fernet_cache"):
            self._fernet_cache = {}
        if salt in self._fernet_cache:
            return self._fernet_cache[salt]
        import base64
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes
        if self._raw_key is None:
            raise ValueError("Cannot derive key: vault uses ephemeral key")
        kdf = PBKDF2HMAC(
            algorithm  = _hashes.SHA256(),
            length     = 32,
            salt       = salt,
            iterations = self._PBKDF2_ITERATIONS_LEGACY,
        )
        cipher = Fernet(base64.urlsafe_b64encode(kdf.derive(self._raw_key)))
        if len(self._fernet_cache) < 256:
            self._fernet_cache[salt] = cipher
        return cipher

    def _derive_aesgcm(self, salt: bytes) -> "AESGCM":
        """Derive an AES-256-GCM key from self._raw_key + salt (600k iter)."""
        if not hasattr(self, "_gcm_cache"):
            self._gcm_cache = {}
        if salt in self._gcm_cache:
            return self._gcm_cache[salt]
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if self._raw_key is None:
            raise ValueError("Cannot derive key: vault uses ephemeral key")
        kdf = PBKDF2HMAC(
            algorithm  = _hashes.SHA256(),
            length     = 32,
            salt       = salt,
            iterations = self._PBKDF2_ITERATIONS_V2,
        )
        cipher = AESGCM(kdf.derive(self._raw_key))
        if len(self._gcm_cache) < 256:
            self._gcm_cache[salt] = cipher
        return cipher

    def _encrypt_secret(self, plaintext: str) -> bytes:
        """Encrypt a secret using AES-256-GCM. Returns v2-formatted bytes."""
        import base64
        import os as _os

        nonce = _os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        ct_b64 = base64.urlsafe_b64encode(ct).decode()
        return f"{self._V2_PREFIX}{self._salt_hex}:{nonce.hex()}:{ct_b64}".encode()

    def _decrypt_secret(self, raw: bytes) -> str:
        """
        Three-path decrypt dispatcher for vault secrets:
          1. 'v2:...' → AES-256-GCM (new)
          2. '<32-hex>:<fernet-token>' → Fernet per-record salt (v6)
          3. Bare Fernet token → Fernet legacy fixed-salt (v5)
        """
        import base64

        token_str = raw.decode() if isinstance(raw, bytes) else raw

        # ── Path 1: v2 AES-256-GCM ──
        if token_str.startswith(self._V2_PREFIX):
            body = token_str[len(self._V2_PREFIX):]
            parts = body.split(":", 2)
            if len(parts) != 3:
                raise ValueError("Malformed v2 vault ciphertext")
            salt_hex, nonce_hex, ct_b64 = parts
            salt = bytes.fromhex(salt_hex)
            nonce = bytes.fromhex(nonce_hex)
            ct = base64.b64decode(ct_b64, altchars=b"-_", validate=True)
            if self._raw_key is not None:
                aesgcm = self._derive_aesgcm(salt)
            else:
                aesgcm = self._aesgcm
            return aesgcm.decrypt(nonce, ct, None).decode()

        # ── Path 2: Fernet per-record salt (v6) ──
        if len(token_str) > 33 and token_str[32] == ":":
            salt = bytes.fromhex(token_str[:32])
            fernet_token = token_str[33:].encode()
            return self._derive_fernet(salt).decrypt(fernet_token).decode()

        # ── Path 3: Fernet legacy fixed-salt (v5) / ephemeral ──
        if self._raw_key is not None:
            return self._derive_fernet(self._LEGACY_SALT).decrypt(raw).decode()
        # Ephemeral vault — raw is old-style Fernet from a previous session (shouldn't happen)
        if self._fernet is not None:
            return self._fernet.decrypt(raw).decode()
        raise ValueError("Cannot decrypt: ephemeral vault has no Fernet key")

    def store(self, cred: Credential, secret: str, io_verified: bool = True) -> str | bool:
        """
        Encrypt and store a credential. Returns credential ID.
        Deduplicates by (domain, username, cred_type).

        Args:
            cred:        Credential metadata (no plaintext secret)
            secret:      The actual secret - encrypted immediately on entry
            io_verified: True if execution context has verified I/O evidence (Gate 6)
        """
        if not secret or not secret.strip():
            logger.warning(
                "vault_write_blocked_invalid_secret",
                username=cred.username,
                cred_type=str(cred.cred_type),
                reason="empty or synthetic secret",
            )
            raise ValueError("Cannot store credential with empty secret")

        # Gate 6 Condition 1 - Vault Write Guard: check empty or synthetic secret
        if not _is_valid_secret(secret):
            logger.warning(
                "vault_write_blocked_invalid_secret",
                username=cred.username,
                cred_type=str(cred.cred_type),
                reason="empty or synthetic secret",
            )
            return False

        # Gate 6 Condition 3 - Type Coherence
        if not _validate_type_coherence(secret, cred.cred_type):
            logger.warning(
                "vault_write_blocked_type_mismatch",
                username=cred.username,
                secret_prefix=secret[:8],
                cred_type=str(cred.cred_type),
                reason="secret format incompatible with declared type",
            )
            return False

        # Gate 6 Condition 2 - I/O Verification
        if not io_verified:
            logger.warning(
                "vault_write_blocked_zero_io",
                username=cred.username,
                cred_type=str(cred.cred_type),
                reason="no network I/O or evidence recorded in execution context",
            )
            return False

        dedup_key = f"{cred.domain.lower()}:{cred.username.lower()}:{cred.cred_type.value}"
        if dedup_key in self._by_fqdn:
            existing_id = self._by_fqdn[dedup_key]
            existing    = self._store[existing_id]
            # Update existing if new one has higher score
            new_score = self._scorer.score(cred)
            if new_score > existing.score:
                cred.id         = existing_id
                cred.secret_enc = self._encrypt_secret(secret)
                cred.score      = new_score
                self._store[existing_id] = cred
                logger.debug("credential_updated", fqdn=cred.fqdn, score=cred.score)
            return existing_id

        cred.secret_enc = self._encrypt_secret(secret)
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

    def add(self, cred: "Any" = None, secret: str = "", **kwargs: Any) -> str | bool:
        """Alias for store() - supports both Credential model and kwargs with Gate 6 write guard."""
        sec = secret or getattr(cred, "secret", "") or (str(kwargs.get("secret", "")) if kwargs.get("secret") is not None else "")

        # Extract type and username for pre-validation
        if isinstance(cred, Credential):
            c_type = cred.cred_type
            u_name = cred.username
        else:
            u_name = str(kwargs.get("username") or (cred if isinstance(cred, str) else ""))
            cred_type_raw = kwargs.get("cred_type", CredentialType.CLEARTEXT)
            type_map = {
                "cleartext": CredentialType.CLEARTEXT,
                "password": CredentialType.CLEARTEXT,
                "ntlm": CredentialType.NTLM,
                "hash": CredentialType.HASH,
                "token": CredentialType.JWT,
                "jwt": CredentialType.JWT,
                "api_key": CredentialType.API_KEY,
                "ticket": CredentialType.KRB5_TGT,
                "tgt": CredentialType.KRB5_TGT,
                "tgs": CredentialType.KRB5_TGS,
                "certificate": CredentialType.CERTIFICATE,
                "cert": CredentialType.CERTIFICATE,
                "cookie": CredentialType.COOKIE,
            }
            if isinstance(cred_type_raw, str):
                c_type = type_map.get(cred_type_raw.lower(), CredentialType.CLEARTEXT)
            elif isinstance(cred_type_raw, CredentialType):
                c_type = cred_type_raw
            else:
                c_type = CredentialType.CLEARTEXT

        # Gate 6 Condition 1 - Vault Write Guard: check empty or synthetic secret
        if not _is_valid_secret(sec):
            logger.warning(
                "vault_write_blocked_invalid_secret",
                username=u_name,
                cred_type=str(c_type),
                reason="empty or synthetic secret",
            )
            return False

        # Gate 6 Condition 3 - Type Coherence
        if not _validate_type_coherence(sec, c_type):
            logger.warning(
                "vault_write_blocked_type_mismatch",
                username=u_name,
                secret_prefix=sec[:8],
                cred_type=str(c_type),
                reason="secret format incompatible with declared type",
            )
            return False

        # Gate 6 Condition 2 - I/O Verification
        io_verified = kwargs.get("io_verified", True)
        ctx = kwargs.get("ctx")
        if ctx is not None:
            io_verified = (
                getattr(ctx, "network_io_occurred", False)
                or bool(getattr(ctx, "findings", []))
                or bool(getattr(ctx, "collected_loot", []))
            )

        if not io_verified:
            logger.warning(
                "vault_write_blocked_zero_io",
                username=u_name,
                cred_type=str(c_type),
                reason="no network I/O or evidence recorded in execution context",
            )
            return False

        if isinstance(cred, Credential):
            return self.store(cred, sec, io_verified=io_verified)

        c = Credential(
            campaign_id=str(kwargs.get("campaign_id", getattr(self, "campaign_id", ""))),
            username=u_name,
            domain=str(kwargs.get("domain", "")),
            target_host=str(kwargs.get("host") or kwargs.get("target_host", "")),
            cred_type=c_type,
            privilege=kwargs.get("privilege", PrivilegeLevel.LOCAL_USER),
            source_module=str(kwargs.get("source_module", "")),
            source_host=str(kwargs.get("source_host", "")),
            tags=list(kwargs.get("tags") or []),
        )
        return self.store(c, sec, io_verified=io_verified)

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
        if not raw:
            raise ValueError(f"Credential {cred_id!r} has no encrypted secret")
        return self._decrypt_secret(raw)

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
        """Update hash credential when cracked - rescore and store plaintext."""
        cred = self._store.get(cred_id)
        if not cred:
            return
        cred.cracked    = True
        cred.secret_enc = self._encrypt_secret(plaintext)
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
        Return credentials suitable for reuse/spray - scored, active, usable.
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

        Records come from db.load_credentials_raw() - secrets are already
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
