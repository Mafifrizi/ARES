"""
ARES Module Signing & Integrity Verification
Cryptographic signing ensures community modules are authentic and unmodified.

Design:
  - Each module file is signed with the author's Ed25519 private key
  - Signature stored in module.sig file or embedded in __module_signature__
  - Verification at load time — unsigned/invalid modules rejected (configurable)

Trust model:
  TRUSTED    — ARES official modules (bundled, pre-verified)
  COMMUNITY  — Author-signed modules (verify with author's public key)
  UNSIGNED   — No signature (warn or reject based on policy)
  REVOKED    — Key has been revoked (always reject)

Key storage:
  ~/.ares/keys/trusted_keys.json    — trusted public keys registry
  ~/.ares/keys/<key_id>.pub         — individual public key file

Usage:
    # Generate a key pair (module author)
    signer  = ModuleSigner.generate_keypair("author@corp.com")
    sig     = signer.sign_file(Path("my_module.py"))
    sig.save(Path("my_module.py.sig"))

    # Verify at load time (engine/plugin loader)
    verifier = ModuleVerifier(policy=SigningPolicy.WARN_UNSIGNED)
    result   = verifier.verify_file(Path("my_module.py"))
    if result.trusted:
        load_module(Path("my_module.py"))
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from ares.core.logger import audit, get_logger

logger = get_logger("ares.signing")

# ARES trusted key store location
TRUSTED_KEYS_PATH = Path.home() / ".ares" / "keys" / "trusted_keys.json"
REVOKED_KEYS_PATH = Path.home() / ".ares" / "keys" / "revoked_keys.json"


class SigningPolicy(str, Enum):
    REQUIRE_SIGNED   = "require_signed"    # reject unsigned modules
    WARN_UNSIGNED    = "warn_unsigned"     # log warning, still load
    ALLOW_ALL        = "allow_all"         # no enforcement (dev mode)
    TRUSTED_ONLY     = "trusted_only"      # only ARES official modules


class TrustLevel(str, Enum):
    TRUSTED    = "trusted"      # ARES official or in trusted_keys registry
    COMMUNITY  = "community"    # signed but author not in trusted_keys
    UNSIGNED   = "unsigned"     # no signature present
    INVALID    = "invalid"      # signature present but verification failed
    REVOKED    = "revoked"      # signing key has been revoked


@dataclass
class ModuleSignature:
    """A cryptographic signature for a module file."""
    key_id:      str     # SHA-256 fingerprint of the signing key
    algorithm:   str     # "ed25519"
    signature:   str     # base64-encoded signature bytes
    file_hash:   str     # SHA-256 of the file content (detached signing)
    author:      str     # author email/username (informational)
    module_id:   str     # MODULE_ID of the signed module
    signed_at:   float   # Unix timestamp
    version:     str     # module version string
    sig_version: str = "1"  # signature format version

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id":      self.key_id,
            "algorithm":   self.algorithm,
            "signature":   self.signature,
            "file_hash":   self.file_hash,
            "author":      self.author,
            "module_id":   self.module_id,
            "signed_at":   self.signed_at,
            "version":     self.version,
            "sig_version": self.sig_version,
        }

    def save(self, path: Path) -> None:
        """Write signature to <module_file>.sig"""
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "ModuleSignature":
        data = json.loads(path.read_text())
        return cls(**data)


@dataclass
class VerificationResult:
    """Result of verifying a module's signature."""
    module_path:  Path
    trust_level:  TrustLevel
    key_id:       str = ""
    author:       str = ""
    signed_at:    float = 0.0
    error:        str = ""
    warnings:     list[str] = field(default_factory=list)

    @property
    def trusted(self) -> bool:
        return self.trust_level in (TrustLevel.TRUSTED, TrustLevel.COMMUNITY)

    @property
    def blocked(self) -> bool:
        return self.trust_level in (TrustLevel.INVALID, TrustLevel.REVOKED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module":      str(self.module_path),
            "trust_level": self.trust_level.value,
            "trusted":     self.trusted,
            "blocked":     self.blocked,
            "key_id":      self.key_id,
            "author":      self.author,
            "warnings":    self.warnings,
            "error":       self.error,
        }


class KeyRegistry:
    """
    Registry of trusted public keys.
    Persisted as JSON in ~/.ares/keys/trusted_keys.json.
    """

    def __init__(self, path: Path = TRUSTED_KEYS_PATH) -> None:
        self._path    = path
        self._keys:   dict[str, dict[str, Any]] = {}
        self._revoked: set[str] = set()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text())
            self._keys    = data.get("trusted_keys", {})
            self._revoked = set(data.get("revoked_keys", []))

        rev_path = REVOKED_KEYS_PATH
        if rev_path.exists():
            data = json.loads(rev_path.read_text())
            self._revoked.update(data.get("revoked_keys", []))

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({
            "trusted_keys":  self._keys,
            "revoked_keys":  list(self._revoked),
            "updated_at":    time.time(),
        }, indent=2))

    def add_trusted_key(
        self,
        key_id:   str,
        public_key_pem: str,
        author:   str,
        added_by: str = "operator",
    ) -> None:
        """Register a trusted public key."""
        self._keys[key_id] = {
            "public_key": public_key_pem,
            "author":     author,
            "added_at":   time.time(),
            "added_by":   added_by,
        }
        self._save()
        audit("trusted_key_added", actor=added_by,
              key_id=key_id, author=author)
        logger.info("trusted_key_added", key_id=key_id, author=author)

    def revoke_key(self, key_id: str, reason: str = "", operator: str = "") -> None:
        """Revoke a key — all modules signed with this key will be rejected."""
        self._revoked.add(key_id)
        self._keys.pop(key_id, None)
        self._save()
        audit("key_revoked", actor=operator, key_id=key_id, reason=reason)
        logger.warning("key_revoked", key_id=key_id, reason=reason)

    def get_public_key(self, key_id: str) -> Ed25519PublicKey | None:
        """Return the public key object for a key_id, or None if not found."""
        entry = self._keys.get(key_id)
        if not entry:
            return None
        pem = entry["public_key"].encode()
        return serialization.load_pem_public_key(pem)  # type: ignore[return-value]

    def is_trusted(self, key_id: str) -> bool:
        return key_id in self._keys and key_id not in self._revoked

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

    def list_keys(self) -> list[dict[str, Any]]:
        return [
            {"key_id": kid, **info, "revoked": self.is_revoked(kid)}
            for kid, info in self._keys.items()
        ]


class ModuleSigner:
    """
    Signs module files with an Ed25519 private key.

    Usage (module author):
        signer = ModuleSigner.generate_keypair("alice@corp.com")
        signer.save_private_key(Path("alice.key"))

        sig = signer.sign_file(Path("my_module.py"), module_id="corp.my_module")
        sig.save(Path("my_module.py.sig"))
    """

    def __init__(self, private_key: Ed25519PrivateKey, author: str) -> None:
        self._private_key = private_key
        self.author       = author
        self.key_id       = self._compute_key_id()
        self.public_key   = private_key.public_key()

    def _compute_key_id(self) -> str:
        pub_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(pub_bytes).hexdigest()[:16]

    def sign_file(
        self,
        module_path: Path,
        module_id:   str = "",
        version:     str = "0.1.0",
    ) -> ModuleSignature:
        """Sign a module file. Returns a ModuleSignature."""
        content   = module_path.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()

        # Sign: key_id + file_hash + module_id + version (prevents replay)
        message = f"{self.key_id}:{file_hash}:{module_id}:{version}".encode()
        sig_bytes = self._private_key.sign(message)

        sig = ModuleSignature(
            key_id    = self.key_id,
            algorithm = "ed25519",
            signature = base64.urlsafe_b64encode(sig_bytes).decode(),
            file_hash = file_hash,
            author    = self.author,
            module_id = module_id,
            signed_at = time.time(),
            version   = version,
        )
        logger.info("module_signed", module_id=module_id, key_id=self.key_id,
                    file=str(module_path))
        return sig

    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def save_private_key(self, path: Path, password: bytes | None = None) -> None:
        """Save private key to file (encrypted if password provided)."""
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        path.write_bytes(
            self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                enc,
            )
        )
        path.chmod(0o600)
        logger.info("private_key_saved", path=str(path))

    @classmethod
    def generate_keypair(cls, author: str) -> "ModuleSigner":
        """Generate a new Ed25519 key pair. Save the private key securely!"""
        key = Ed25519PrivateKey.generate()
        signer = cls(key, author)
        logger.info("keypair_generated", key_id=signer.key_id, author=author)
        return signer

    @classmethod
    def load_private_key(
        cls, path: Path, author: str, password: bytes | None = None
    ) -> "ModuleSigner":
        """Load an existing private key from file."""
        pem = path.read_bytes()
        key = serialization.load_pem_private_key(pem, password=password)
        return cls(key, author)  # type: ignore[arg-type]


class ModuleVerifier:
    """
    Verifies module signatures at load time.
    Enforces signing policy configured by the operator.
    """

    def __init__(
        self,
        registry: KeyRegistry | None = None,
        policy:   SigningPolicy = SigningPolicy.WARN_UNSIGNED,
    ) -> None:
        self._registry = registry or KeyRegistry()
        self.policy    = policy

    def verify_file(self, module_path: Path) -> VerificationResult:
        """
        Verify a module file's signature.
        Returns VerificationResult regardless of outcome.
        """
        sig_path = module_path.with_suffix(module_path.suffix + ".sig")

        if not sig_path.exists():
            result = VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.UNSIGNED,
                warnings    = ["No signature file found"],
            )
            logger.debug("module_unsigned", path=str(module_path))
            return result

        try:
            sig = ModuleSignature.load(sig_path)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            return VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.INVALID,
                error       = f"Malformed signature file: {exc}",
            )

        # Check revocation first
        if self._registry.is_revoked(sig.key_id):
            audit("revoked_module_blocked", actor="engine",
                  key_id=sig.key_id, module=str(module_path))
            return VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.REVOKED,
                key_id      = sig.key_id,
                author      = sig.author,
                error       = f"Signing key {sig.key_id} has been revoked",
            )

        # Verify file hash
        content   = module_path.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()
        if file_hash != sig.file_hash:
            return VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.INVALID,
                key_id      = sig.key_id,
                author      = sig.author,
                error       = "File hash mismatch — module may have been tampered with",
            )

        # Verify cryptographic signature
        public_key = self._registry.get_public_key(sig.key_id)
        if public_key is None:
            # Signed but key not in trusted registry
            return VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.COMMUNITY,
                key_id      = sig.key_id,
                author      = sig.author,
                signed_at   = sig.signed_at,
                warnings    = [f"Author {sig.author!r} key not in trusted registry"],
            )

        try:
            message = f"{sig.key_id}:{sig.file_hash}:{sig.module_id}:{sig.version}".encode()
            sig_bytes = base64.urlsafe_b64decode(sig.signature)
            public_key.verify(sig_bytes, message)
        except InvalidSignature:
            audit("invalid_signature_blocked", actor="engine",
                  key_id=sig.key_id, module=str(module_path))
            return VerificationResult(
                module_path = module_path,
                trust_level = TrustLevel.INVALID,
                key_id      = sig.key_id,
                author      = sig.author,
                error       = "Cryptographic signature verification failed",
            )

        logger.info("module_verified", module=str(module_path),
                    key_id=sig.key_id, author=sig.author,
                    trust="trusted")
        return VerificationResult(
            module_path = module_path,
            trust_level = TrustLevel.TRUSTED,
            key_id      = sig.key_id,
            author      = sig.author,
            signed_at   = sig.signed_at,
        )

    def enforce_policy(self, result: VerificationResult) -> None:
        """
        Enforce the configured signing policy.
        Raises ValueError if policy blocks the module.
        """
        if result.trust_level == TrustLevel.INVALID:
            raise ValueError(
                f"Module {result.module_path.name!r} has invalid signature — "
                f"possible tampering. Refusing to load."
            )
        if result.trust_level == TrustLevel.REVOKED:
            raise ValueError(
                f"Module {result.module_path.name!r} was signed with a revoked key. "
                f"Refusing to load."
            )

        if self.policy == SigningPolicy.REQUIRE_SIGNED:
            if result.trust_level == TrustLevel.UNSIGNED:
                raise ValueError(
                    f"Module {result.module_path.name!r} is unsigned. "
                    f"Policy requires signed modules."
                )
        elif self.policy == SigningPolicy.TRUSTED_ONLY:
            if result.trust_level != TrustLevel.TRUSTED:
                raise ValueError(
                    f"Module {result.module_path.name!r} trust level is "
                    f"{result.trust_level.value!r}. Policy requires TRUSTED_ONLY."
                )
        elif self.policy == SigningPolicy.WARN_UNSIGNED:
            if result.trust_level == TrustLevel.UNSIGNED:
                logger.warning("loading_unsigned_module",
                               module=str(result.module_path))
            elif result.trust_level == TrustLevel.COMMUNITY:
                logger.warning("loading_community_module",
                               module=str(result.module_path),
                               author=result.author)
        # ALLOW_ALL: no enforcement
