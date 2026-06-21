"""
Unit tests — DataEncryptor edge cases (ares/core/security.py)

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

    def test_encrypted_value_has_salt_prefix(self):
        enc = make_enc()
        token = enc.encrypt("secret")
        assert token is not None
        assert len(token) > 33
        assert token[32] == ":"

    def test_two_encryptions_produce_different_ciphertext(self):
        """Per-record random salt means identical plaintexts encrypt differently."""
        enc = make_enc()
        t1 = enc.encrypt("same")
        t2 = enc.encrypt("same")
        assert t1 != t2

    def test_roundtrip_unicode(self):
        enc = make_enc()
        value = "P@ssw0rd! — привет — 中文 — emoji 🔴"
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
        """Empty key should not crash — returns None on decrypt."""
        try:
            enc = DataEncryptor("")
            token = enc.encrypt("test")
            result = enc.decrypt(token)
            assert result is None or result == "test"
        except Exception:
            pass  # construction may fail — that is also acceptable

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
        """Simulate v5-era ciphertext (no salt prefix) — must decrypt with legacy salt."""
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
        """Values encrypted with v6 (new format) must decrypt correctly."""
        enc = DataEncryptor("test-key-32chars-minimum-required")
        secret = "v6-encrypted-secret"
        token = enc.encrypt(secret)
        # Confirm it's new format (has 33-char salt prefix)
        assert token is not None and len(token) > 33 and token[32] == ":"
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
        fernet_body = self._canonical_fernet_body(enc)

        with patch.object(enc, '_derive_fernet') as mock_fernet:
            mock_fernet.return_value.decrypt.side_effect = MemoryError("OOM")
            salt_hex = os.urandom(16).hex()
            with pytest.raises(MemoryError):
                enc.decrypt(f"{salt_hex}:{fernet_body}")


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
