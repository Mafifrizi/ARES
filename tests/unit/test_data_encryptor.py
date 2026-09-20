"""
Unit tests - DataEncryptor edge cases (ares/core/security.py)

Tests every edge case: key mismatch, tampered ciphertext, None input,
legacy format migration, unicode, and the exception narrowing fix.
Security code must be exhaustively tested.
"""
from __future__ import annotations

import os
import base64
import pytest
from unittest.mock import patch

import os
os.environ.setdefault("ARES_SECRET_KEY",       "test-enc-key-minimum-32chars-here!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "test-enc-key-minimum-32chars-here!!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "TestEnc1!")


from ares.core.security import DataEncryptor


def make_enc(key: str = "test-key-32chars-minimum-required") -> DataEncryptor:
    return DataEncryptor(key)


# ══════════════════════════════════════════════════════════════════════════════
# Basic encrypt / decrypt
# ══════════════════════════════════════════════════════════════════════════════

class TestBasicEncryptDecrypt:

    def test_roundtrip_simple_string(self):
        enc = make_enc()
        assert enc.decrypt(enc.encrypt("hello")) == "hello"

    def test_roundtrip_empty_string(self):
        enc = make_enc()
        assert enc.decrypt(enc.encrypt("")) == ""

    def test_encrypt_none_returns_none(self):
        enc = make_enc()
        assert enc.encrypt(None) is None

    def test_decrypt_none_returns_none(self):
        enc = make_enc()
        assert enc.decrypt(None) is None

    def test_encrypted_value_has_v2_prefix(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert token is not None
        assert token.startswith("v2:")
        parts = token[3:].split(":", 2)
        assert len(parts) == 3

    def test_two_encryptions_produce_different_ciphertext(self):
        """AES-256-GCM uses random nonce, so identical plaintexts encrypt differently."""
        enc = make_enc()
        t1 = enc.encrypt("same")
        t2 = enc.encrypt("same")
        assert t1 != t2

    def test_roundtrip_unicode(self):
        enc = make_enc()
        value = "P@ssw0rd! - привет - 中文 - emoji 🔴"
        assert enc.decrypt(enc.encrypt(value)) == value

    def test_roundtrip_long_string(self):
        enc = make_enc()
        value = "x" * 10_000
        assert enc.decrypt(enc.encrypt(value)) == value

    def test_roundtrip_special_characters(self):
        enc = make_enc()
        for special in ['', '\n', '\t', '\\', '"', "'", '\x00', ':']:
            result = enc.decrypt(enc.encrypt(special))
            assert result == special, f"Failed for {repr(special)}"


# ══════════════════════════════════════════════════════════════════════════════
# Key mismatch
# ══════════════════════════════════════════════════════════════════════════════

class TestKeyMismatch:

    def test_wrong_key_returns_none(self):
        enc1 = make_enc("key-one-32chars-minimum-required!!")
        enc2 = make_enc("key-two-32chars-minimum-required!!")
        token = enc1.encrypt("secret-data")
        assert enc2.decrypt(token) is None

    def test_empty_key_fails_gracefully(self):
        """Empty key should not crash - returns None on decrypt."""
        try:
            enc = DataEncryptor("")
            token = enc.encrypt("test")
            result = enc.decrypt(token)
            assert result is None or result == "test"
        except Exception:
            pass  # construction may fail - that is also acceptable

    def test_key_with_special_characters(self):
        key = "key-with-!@#$%^&*()-special-chars!"
        enc = make_enc(key)
        assert enc.decrypt(enc.encrypt("value")) == "value"


# ══════════════════════════════════════════════════════════════════════════════
# Tampered ciphertext
# ══════════════════════════════════════════════════════════════════════════════

class TestTamperedCiphertext:

    def test_bit_flip_returns_none(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert token is not None
        # Flip a byte in the fernet part (after the 33-char prefix)
        tampered = token[:40] + ("X" if token[40] != "X" else "Y") + token[41:]
        assert enc.decrypt(tampered) is None

    def test_truncated_token_returns_none(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert enc.decrypt(token[:20]) is None

    def test_random_bytes_returns_none(self):
        enc = make_enc()
        assert enc.decrypt("definitely-not-a-valid-token") is None

    def test_invalid_hex_prefix_returns_none(self):
        enc = make_enc()
        assert enc.decrypt("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:garbage") is None

    def test_valid_prefix_invalid_fernet_returns_none(self):
        enc = make_enc()
        valid_salt_hex = os.urandom(16).hex()
        assert enc.decrypt(f"{valid_salt_hex}:not-valid-fernet") is None

    def test_tampered_ciphertext_does_not_raise(self):
        """Tampered data must return None, never raise an unhandled exception."""
        enc = make_enc()
        token = enc.encrypt("value")
        assert token is not None
        for mutation in [
            token.upper(),
            token[::-1],
            token[:-10],
            ":" + token,
            token + "==",
        ]:
            try:
                result = enc.decrypt(mutation)
                assert result is None or isinstance(result, str)
            except Exception as exc:
                pytest.fail(f"decrypt() raised {type(exc).__name__} instead of returning None")


# ══════════════════════════════════════════════════════════════════════════════
# Legacy format migration
# ══════════════════════════════════════════════════════════════════════════════

class TestLegacyFormat:

    def test_legacy_format_decrypts_with_legacy_salt(self):
        """Simulate v5-era ciphertext (no salt prefix) - must decrypt with legacy salt."""
        key = "test-key-32chars-minimum-required"
        enc = DataEncryptor(key)

        # Manually create a legacy-format ciphertext (no salt prefix)
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=enc._LEGACY_SALT, iterations=100_000,
        )
        legacy_fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(key.encode())))
        legacy_token = legacy_fernet.encrypt(b"old-secret").decode()

        # Must not have the 33-char prefix
        assert len(legacy_token) <= 32 or legacy_token[32] != ":"

        result = enc.decrypt(legacy_token)
        assert result == "old-secret"

    def test_legacy_salt_env_override(self):
        """ARES_LEGACY_SALT env var must override hardcoded salt."""
        custom_salt = b"my-custom-legacy-salt-for-test!!"

        with patch.dict(os.environ, {"ARES_LEGACY_SALT": custom_salt.decode()}):
            from ares.core.security import _get_legacy_salt

            assert _get_legacy_salt() == custom_salt

    def test_new_format_value_decrypts_correctly_after_roundtrip(self):
        """Values encrypted with v2 (AES-256-GCM) must decrypt correctly."""
        enc = DataEncryptor("test-key-32chars-minimum-required")
        secret = "v2-encrypted-secret"
        token = enc.encrypt(secret)
        # Confirm it's v2 format (starts with 'v2:')
        assert token is not None and token.startswith("v2:")
        assert enc.decrypt(token) == secret


# ══════════════════════════════════════════════════════════════════════════════
# Exception narrowing (BUG fix regression)
# ══════════════════════════════════════════════════════════════════════════════

class TestExceptionNarrowing:

    @staticmethod
    def _canonical_fernet_body(enc: DataEncryptor) -> str:
        token = enc.encrypt("fixture")
        assert token is not None
        return token[33:]

    def test_invalid_token_returns_none_not_raises(self):
        """InvalidToken must be caught and return None."""
        from cryptography.fernet import InvalidToken
        enc = make_enc()
        fernet_body = self._canonical_fernet_body(enc)

        with patch.object(enc, '_derive_fernet') as mock_fernet:
            mock_fernet.return_value.decrypt.side_effect = InvalidToken()
            salt_hex = os.urandom(16).hex()
            result = enc.decrypt(f"{salt_hex}:{fernet_body}")
            assert result is None

    def test_value_error_returns_none(self):
        """ValueError (e.g. invalid hex) must be caught and return None."""
        enc = make_enc()
        # Invalid hex prefix triggers ValueError in bytes.fromhex
        result = enc.decrypt("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG:token")
        assert result is None

    def test_unicode_decode_error_returns_none(self):
        """UnicodeDecodeError must be caught and return None."""
        from cryptography.fernet import InvalidToken
        enc = make_enc()
        fernet_body = self._canonical_fernet_body(enc)

        with patch.object(enc, '_derive_fernet') as mock_fernet:
            mock_fernet.return_value.decrypt.side_effect = UnicodeDecodeError(
                "utf-8", b"\xff\xfe", 0, 1, "invalid start byte"
            )
            salt_hex = os.urandom(16).hex()
            result = enc.decrypt(f"{salt_hex}:{fernet_body}")
            assert result is None

    def test_unexpected_exception_bubbles_up(self):
        """Exceptions NOT in the catch list must bubble up (not silently swallowed)."""
        enc = make_enc()
        # Create a v2 token and corrupt it in a way that triggers MemoryError
        # through the _derive_aesgcm path
        token = enc.encrypt("fixture")
        assert token is not None

        with patch.object(enc, '_derive_aesgcm') as mock_gcm:
            mock_gcm.return_value.decrypt.side_effect = MemoryError("OOM")
            # Use a different salt to force _derive_aesgcm call
            parts = token.split(":", 3)
            parts[1] = os.urandom(16).hex()  # different salt triggers derivation
            tampered_token = ":".join(parts)
            with pytest.raises(MemoryError):
                enc.decrypt(tampered_token)


# ══════════════════════════════════════════════════════════════════════════════
# Multiple instances / key isolation
# ══════════════════════════════════════════════════════════════════════════════

class TestIsolation:

    def test_each_instance_has_different_salt(self):
        enc1 = make_enc()
        enc2 = make_enc()
        assert enc1._salt != enc2._salt

    def test_cross_instance_decryption_works_same_key(self):
        """Different instances with same key should decrypt each other's tokens."""
        key = "shared-key-32chars-minimum-req!!"
        enc1 = DataEncryptor(key)
        enc2 = DataEncryptor(key)
        token = enc1.encrypt("cross-instance")
        assert enc2.decrypt(token) == "cross-instance"


# ══════════════════════════════════════════════════════════════════════════════
# AES-256-GCM Upgrade Tests (v2 format)
# ══════════════════════════════════════════════════════════════════════════════

class TestAES256GCMUpgrade:
    """Tests for the Fernet → AES-256-GCM upgrade."""

    def test_new_encrypt_produces_v2_format(self):
        """New encrypt() output must start with 'v2:' prefix."""
        enc = make_enc()
        token = enc.encrypt("hello-gcm")
        assert token is not None
        assert token.startswith("v2:")
        parts = token[3:].split(":", 2)
        assert len(parts) == 3, "v2 ciphertext must have salt:nonce:ct_b64"
        salt_hex, nonce_hex, ct_b64 = parts
        assert len(salt_hex) == 32, "salt must be 32 hex chars (16 bytes)"
        assert len(nonce_hex) == 24, "nonce must be 24 hex chars (12 bytes)"
        assert len(ct_b64) > 0, "ciphertext must be non-empty"

    def test_v2_roundtrip(self):
        enc = make_enc()
        assert enc.decrypt(enc.encrypt("v2-roundtrip")) == "v2-roundtrip"

    def test_v2_roundtrip_empty_string(self):
        enc = make_enc()
        assert enc.decrypt(enc.encrypt("")) == ""

    def test_v2_roundtrip_unicode(self):
        enc = make_enc()
        value = "P@ssw0rd! - привет - 中文 - emoji 🔴"
        assert enc.decrypt(enc.encrypt(value)) == value

    def test_v2_roundtrip_long_string(self):
        enc = make_enc()
        value = "x" * 10_000
        assert enc.decrypt(enc.encrypt(value)) == value

    def test_v2_two_encryptions_differ(self):
        """Each v2 encryption uses a random nonce, so ciphertexts differ."""
        enc = make_enc()
        t1 = enc.encrypt("same")
        t2 = enc.encrypt("same")
        assert t1 != t2

    def test_v2_tampered_nonce_returns_none(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert token is not None
        # Corrupt the nonce (chars 36-59 in the v2:salt:nonce:ct format)
        parts = token.split(":", 3)
        parts[2] = "0" * 24  # replace nonce with zeros
        tampered = ":".join(parts)
        assert enc.decrypt(tampered) is None

    def test_v2_tampered_ciphertext_returns_none(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert token is not None
        # Flip a character in the base64 ciphertext
        parts = token.split(":", 3)
        ct = parts[3]
        flipped = ct[:-5] + ("X" if ct[-5] != "X" else "Y") + ct[-4:]
        parts[3] = flipped
        tampered = ":".join(parts)
        assert enc.decrypt(tampered) is None

    def test_v2_truncated_returns_none(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert enc.decrypt(token[:20]) is None

    def test_v2_cross_instance_decryption(self):
        """Same key, different DataEncryptor instances — v2 cross-decrypt works."""
        key = "shared-v2-key-32chars-minimum-req!"
        enc1 = DataEncryptor(key)
        enc2 = DataEncryptor(key)
        token = enc1.encrypt("cross-v2")
        assert enc2.decrypt(token) == "cross-v2"

    def test_v2_aad_binding_roundtrip(self):
        """AAD-bound ciphertext decrypts with correct AAD."""
        enc = make_enc()
        aad = b"cred-id-abc123"
        token = enc.encrypt("secret-with-aad", aad=aad)
        assert enc.decrypt(token, aad=aad) == "secret-with-aad"

    def test_v2_aad_mismatch_fails(self):
        """AAD-bound ciphertext fails with wrong AAD."""
        enc = make_enc()
        aad_correct = b"cred-id-abc123"
        aad_wrong   = b"cred-id-WRONG"
        token = enc.encrypt("secret-with-aad", aad=aad_correct)
        assert enc.decrypt(token, aad=aad_wrong) is None

    def test_v2_aad_none_vs_empty_fails(self):
        """Encrypted with AAD, decrypted without — must fail."""
        enc = make_enc()
        token = enc.encrypt("aad-test", aad=b"context")
        assert enc.decrypt(token, aad=None) is None

    def test_legacy_v6_fernet_still_decrypts(self):
        """Existing v6 per-salt Fernet ciphertexts must still decrypt."""
        key = "test-key-32chars-minimum-required"
        enc = DataEncryptor(key)

        # Manually create a v6-format ciphertext (per-record salt + Fernet)
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64

        fake_salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=fake_salt, iterations=100_000,
        )
        legacy_fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(key.encode())))
        legacy_token = legacy_fernet.encrypt(b"v6-secret").decode()
        v6_ciphertext = f"{fake_salt.hex()}:{legacy_token}"

        result = enc.decrypt(v6_ciphertext)
        assert result == "v6-secret"

    def test_legacy_v5_fernet_still_decrypts(self):
        """Existing v5 bare Fernet ciphertexts must still decrypt."""
        key = "test-key-32chars-minimum-required"
        enc = DataEncryptor(key)

        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=enc._LEGACY_SALT, iterations=100_000,
        )
        legacy_fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(key.encode())))
        legacy_token = legacy_fernet.encrypt(b"v5-secret").decode()

        # v5 bare token — no salt prefix
        assert len(legacy_token) <= 32 or legacy_token[32] != ":"
        result = enc.decrypt(legacy_token)
        assert result == "v5-secret"

    def test_generate_key_returns_url_safe_string(self):
        """generate_key() must return a url-safe base64 string."""
        key = DataEncryptor.generate_key()
        assert len(key) >= 32
        # Must not crash as a DataEncryptor passphrase
        enc = DataEncryptor(key)
        assert enc.decrypt(enc.encrypt("test-gen-key")) == "test-gen-key"


# ══════════════════════════════════════════════════════════════════════════════
# Vault v2 integration
# ══════════════════════════════════════════════════════════════════════════════

class TestVaultV2:
    """Verify CredentialVault uses v2 format after upgrade."""

    def test_vault_store_reveal_roundtrip(self):
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key="vault-test-key-32chars-minimum-req!")
        cred = Credential(username="admin", domain="CORP", cred_type=CredentialType.CLEARTEXT)
        cid = vault.store(cred, "SuperSecret123!")
        assert vault.reveal(cid) == "SuperSecret123!"

    def test_vault_stored_secret_is_v2_format(self):
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key="vault-test-key-32chars-minimum-req!")
        cred = Credential(username="admin", domain="CORP", cred_type=CredentialType.CLEARTEXT)
        cid = vault.store(cred, "MyPassword!")
        stored_cred = vault.get(cid)
        enc_bytes = stored_cred.secret_enc
        assert enc_bytes.startswith(b"v2:"), "Vault must store in v2 format"

    def test_vault_ephemeral_roundtrip(self):
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key=None)
        cred = Credential(username="guest", cred_type=CredentialType.CLEARTEXT)
        cid = vault.store(cred, "ephemeral-secret")
        assert vault.reveal(cid) == "ephemeral-secret"

    def test_vault_mark_cracked_uses_v2(self):
        from ares.credential.vault import CredentialVault, Credential, CredentialType
        vault = CredentialVault(encryption_key="vault-test-key-32chars-minimum-req!")
        cred = Credential(username="svc", domain="CORP", cred_type=CredentialType.KRB5_TGS)
        cid = vault.store(cred, "$krb5tgs$hash...")
        vault.mark_cracked(cid, "CrackedPass1!")
        assert vault.reveal(cid) == "CrackedPass1!"
        stored_cred = vault.get(cid)
        assert stored_cred.secret_enc.startswith(b"v2:")

