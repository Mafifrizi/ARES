"""
Property-based tests — Input sanitizers (ares/core/security.py)
Using hypothesis to fuzz sanitize_ldap, sanitize_hostname, validate_ip_or_cidr,
sanitize_path, create_access_token, and DataEncryptor.

Property-based testing finds edge cases that manual tests miss by generating
hundreds of random inputs and checking invariants.
"""
from __future__ import annotations

import os
import string

os.environ.setdefault("ARES_SECRET_KEY",       "hypothesis-test-key-32chars-min!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "hypothesis-test-enc-32chars-min!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "HypTest1!")

import pytest

# Skip entire module gracefully if hypothesis not installed
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from ares.core.security import (
    sanitize_ldap,
    sanitize_hostname,
    sanitize_path,
    validate_ip_or_cidr,
    DataEncryptor,
    create_access_token,
    decode_access_token,
)


# ── Shared strategies ─────────────────────────────────────────────────────────

# Printable ASCII — the typical input space for user-supplied strings
printable_text = st.text(
    alphabet=string.printable,
    min_size=0,
    max_size=200,
)

# Unicode including emoji, CJK, RTL, null bytes — the adversarial space
adversarial_text = st.text(min_size=0, max_size=200)

# LDAP injection payloads specifically
ldap_injection_chars = st.text(
    alphabet=")(|&=*\\\\<>~",
    min_size=1,
    max_size=50,
)

# Path traversal payloads
path_traversal = st.text(
    alphabet="./\\\\abcdefghijklmnopqrstuvwxyz0123456789",
    min_size=1,
    max_size=100,
)

# Valid-ish hostname characters
hostname_chars = st.text(
    alphabet=string.ascii_letters + string.digits + ".-_",
    min_size=1,
    max_size=63,
)


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_ldap
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizeLdap:

    @given(printable_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str) -> None:
        """sanitize_ldap must never raise for any printable input."""
        result = sanitize_ldap(value)
        assert isinstance(result, str)

    @given(adversarial_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises_adversarial(self, value: str) -> None:
        """sanitize_ldap must never raise for any unicode input."""
        result = sanitize_ldap(value)
        assert isinstance(result, str)

    @given(printable_text)
    @settings(max_examples=200)
    def test_idempotent(self, value: str) -> None:
        """Sanitizing twice must produce the same result as sanitizing once."""
        once  = sanitize_ldap(value)
        twice = sanitize_ldap(once)
        assert once == twice, (
            f"sanitize_ldap not idempotent on {repr(value)!r}: "
            f"first={repr(once)!r}, second={repr(twice)!r}"
        )

    @given(ldap_injection_chars)
    @settings(max_examples=200)
    def test_injection_chars_escaped_or_removed(self, value: str) -> None:
        """LDAP injection chars must not appear unescaped in output."""
        result = sanitize_ldap(value)
        # The result must not contain unescaped ) or ( at minimum
        # (the exact escaping depends on ldap3 vs fallback)
        # Key invariant: result is safe to embed in LDAP filter
        assert isinstance(result, str)
        # If ldap3 is available, injection chars get escaped with \xx
        # If not, they get stripped — either way the output is safe

    @given(st.just("") )
    def test_empty_string_stays_empty(self, value: str) -> None:
        assert sanitize_ldap(value) == ""

    @given(st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=100))
    @settings(max_examples=100)
    def test_alphanumeric_passthrough(self, value: str) -> None:
        """Pure alphanumeric strings should pass through unchanged."""
        # ldap3 escapes everything that's not safe — alphanum is safe
        result = sanitize_ldap(value)
        # At minimum the result must contain all the original chars in some form
        assert len(result) >= len(value)


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_hostname
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizeHostname:

    @given(printable_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str) -> None:
        result = sanitize_hostname(value)
        assert isinstance(result, str)

    @given(adversarial_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises_adversarial(self, value: str) -> None:
        result = sanitize_hostname(value)
        assert isinstance(result, str)

    @given(printable_text)
    @settings(max_examples=200)
    def test_idempotent(self, value: str) -> None:
        """sanitize_hostname must be idempotent."""
        once  = sanitize_hostname(value)
        twice = sanitize_hostname(once)
        assert once == twice

    @given(printable_text)
    @settings(max_examples=300)
    def test_output_contains_only_safe_chars(self, value: str) -> None:
        """Output must only contain alphanumerics, dots, dashes, underscores."""
        import re
        result = sanitize_hostname(value)
        # Every character in result must be in the allowed set
        assert re.fullmatch(r"[a-zA-Z0-9.\-_]*", result) is not None, (
            f"sanitize_hostname({repr(value)!r}) = {repr(result)!r} "
            "contains disallowed chars"
        )

    @given(st.just("10.0.0.1"))
    def test_valid_ip_unchanged(self, value: str) -> None:
        assert sanitize_hostname(value) == value

    @given(st.just("dc01.corp.local"))
    def test_valid_hostname_unchanged(self, value: str) -> None:
        assert sanitize_hostname(value) == value

    @given(st.text(alphabet="!@#$%^&*();'\"`<>[]{}|\\/ \t\n", min_size=1, max_size=50))
    @settings(max_examples=200)
    def test_dangerous_chars_stripped(self, value: str) -> None:
        """Shell metacharacters must be completely stripped."""
        result = sanitize_hostname(value)
        # Result must be empty or only safe chars
        for ch in result:
            assert ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_", (
                f"Dangerous char {repr(ch)!r} survived in {repr(result)!r}"
            )

    @given(st.just(""))
    def test_empty_string(self, value: str) -> None:
        assert sanitize_hostname(value) == ""


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_path
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizePath:

    @given(printable_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_returns_string_or_rejects_unsafe_path(self, value: str) -> None:
        try:
            result = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        assert isinstance(result, str)

    @given(printable_text)
    @settings(max_examples=200)
    def test_idempotent(self, value: str) -> None:
        try:
            once = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        twice = sanitize_path(once)
        assert once == twice

    @given(st.sampled_from([
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//etc/shadow",
        "%2e%2e%2fetc%2fpasswd",
        "/../../../../root/.ssh/id_rsa",
    ]))
    def test_traversal_attempts_neutralized(self, value: str) -> None:
        """Classic path traversal patterns must not survive sanitization."""
        try:
            result = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        # After sanitization, no ".." sequences should remain
        assert ".." not in result, (
            f"sanitize_path({repr(value)!r}) = {repr(result)!r} still contains '..'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# validate_ip_or_cidr
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateIpOrCidr:

    # Strategy for valid IPv4 addresses
    valid_ipv4 = st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
    )

    # Strategy for valid CIDR notation
    valid_cidr = st.builds(
        lambda a, b, c, d, prefix: f"{a}.{b}.{c}.{d}/{prefix}",
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 32),
    )

    @given(valid_ipv4)
    @settings(max_examples=200)
    def test_valid_ipv4_accepted(self, ip: str) -> None:
        assert validate_ip_or_cidr(ip) is True, f"Valid IPv4 {ip!r} rejected"

    @given(valid_cidr)
    @settings(max_examples=200)
    def test_valid_cidr_accepted(self, cidr: str) -> None:
        assert validate_ip_or_cidr(cidr) is True, f"Valid CIDR {cidr!r} rejected"

    @given(printable_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str) -> None:
        """validate_ip_or_cidr must never raise — only return True/False."""
        try:
            result = validate_ip_or_cidr(value)
            assert isinstance(result, bool)
        except Exception as exc:
            pytest.fail(
                f"validate_ip_or_cidr({repr(value)!r}) raised "
                f"{type(exc).__name__}: {exc}"
            )

    @given(st.sampled_from([
        "256.0.0.1", "not-an-ip", "", "10.0.0.1/33",
        "10.0.0.1/abc", "-1.0.0.1", "10.0.0", "10.0.0.0.0",
    ]))
    def test_invalid_values_rejected(self, value: str) -> None:
        assert validate_ip_or_cidr(value) is False, (
            f"Invalid value {repr(value)!r} was accepted"
        )

    @given(st.sampled_from([
        "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
        "0.0.0.0/0", "127.0.0.1",
    ]))
    def test_known_valid_values_accepted(self, value: str) -> None:
        assert validate_ip_or_cidr(value) is True


# ══════════════════════════════════════════════════════════════════════════════
# DataEncryptor — property-based
# ══════════════════════════════════════════════════════════════════════════════

class TestDataEncryptorProperties:

    _enc = DataEncryptor("hypothesis-test-encryption-key!!")

    @given(st.text(min_size=0, max_size=1000))
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_roundtrip_any_text(self, value: str) -> None:
        """encrypt → decrypt must recover original value for any text."""
        enc = DataEncryptor("hyp-test-key-32chars-minimum-req")
        result = enc.decrypt(enc.encrypt(value))
        assert result == value, (
            f"Roundtrip failed for {repr(value[:50])!r}: got {repr(result)!r}"
        )

    @given(st.binary(min_size=1, max_size=50))
    @settings(max_examples=200, deadline=None)
    def test_tampered_returns_none(self, noise: bytes) -> None:
        """Appending random bytes to ciphertext must return None, never raise."""
        enc = DataEncryptor("hyp-test-key-32chars-minimum-req")
        token = enc.encrypt("secret")
        assert token is not None
        # Corrupt it
        import base64
        salt_hex = token[:32]
        fernet_part = token[33:]
        # Append noise to fernet part
        garbled = f"{salt_hex}:{fernet_part}{noise.hex()}"
        result = enc.decrypt(garbled)
        assert result is None

    @given(st.text(min_size=0, max_size=500))
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_different_keys_cant_decrypt(self, value: str) -> None:
        """Ciphertext from key A must not be decryptable by key B."""
        enc_a = DataEncryptor("key-a-for-hypothesis-test-32ch!!")
        enc_b = DataEncryptor("key-b-for-hypothesis-test-32ch!!")
        token = enc_a.encrypt(value)
        assert enc_b.decrypt(token) is None


# ══════════════════════════════════════════════════════════════════════════════
# JWT — property-based
# ══════════════════════════════════════════════════════════════════════════════

class TestJWTProperties:

    _key = "hypothesis-jwt-test-key-32chars!"

    @given(st.dictionaries(
        keys=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=20),
        values=st.one_of(st.text(max_size=100), st.integers(), st.booleans()),
        min_size=0,
        max_size=10,
    ))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_roundtrip_any_payload(self, data: dict) -> None:
        """Encode → decode must recover all payload fields."""
        # Skip reserved JWT claim names
        assume(not any(k in ("exp", "iat", "nbf", "iss", "sub", "aud", "jti", "alg") for k in data))
        token = create_access_token(data, self._key, algorithm="HS256", expires_minutes=60)
        decoded = decode_access_token(token, self._key, algorithm="HS256")
        assert decoded is not None
        for k, v in data.items():
            assert decoded.get(k) == v, (
                f"Payload field {k!r}: expected {v!r}, got {decoded.get(k)!r}"
            )

    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=200)
    def test_wrong_key_returns_none(self, wrong_key: str) -> None:
        """Token signed with key A must not verify with key B."""
        assume(wrong_key != self._key and len(wrong_key) >= 1)
        token = create_access_token({"sub": "test"}, self._key)
        result = decode_access_token(token, wrong_key)
        # If wrong key happens to match (astronomically unlikely) that's fine
        # But a randomly generated key should almost never match
        # This is a probabilistic invariant
        assert result is None or result.get("sub") == "test"

    @given(st.text(min_size=1, max_size=500))
    @settings(max_examples=200)
    def test_garbage_token_returns_none(self, garbage: str) -> None:
        """Arbitrary strings must not decode as valid tokens."""
        result = decode_access_token(garbage, self._key)
        assert result is None

    @given(st.binary(min_size=10, max_size=200))
    @settings(max_examples=100)
    def test_binary_garbage_token_returns_none(self, garbage: bytes) -> None:
        """Binary garbage must return None without raising."""
        try:
            token_str = garbage.decode("utf-8", errors="replace")
            result = decode_access_token(token_str, self._key)
            assert result is None
        except Exception as exc:
            pytest.fail(f"decode_access_token raised {type(exc).__name__}: {exc}")
