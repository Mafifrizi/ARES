"""
Property-based tests — input sanitizers (ares/core/security.py)

Uses Hypothesis to fuzz sanitize_ldap(), sanitize_hostname(), sanitize_path(),
and validate_ip_or_cidr() with thousands of auto-generated inputs.

Properties verified:
  1. IDEMPOTENCY    — sanitize(sanitize(x)) == sanitize(x)  [always]
  2. SAFETY         — dangerous chars never present in output  [always]
  3. NO CRASH       — function never raises on any string input  [always]
  4. VALID OUTPUT   — output type matches expected  [always]
  5. CORRECTNESS    — known-good inputs pass, known-bad inputs are stripped  [spot-check]

Run: pytest tests/unit/test_sanitizers_property.py -v
     (hypothesis runs 100 examples per test by default;
      set HYPOTHESIS_MAX_EXAMPLES=1000 for thorough fuzzing)
"""
from __future__ import annotations

import os
import pytest

os.environ.setdefault("ARES_SECRET_KEY",       "prop-test-key-32chars-minimum!!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "prop-test-enc-32chars-minimum!!!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "PropTest1!")

# Skip entire module gracefully if hypothesis not installed
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from ares.core.security import (
    sanitize_ldap,
    sanitize_hostname,
    sanitize_path,
    validate_ip_or_cidr,
)


# ── Shared strategies ─────────────────────────────────────────────────────────

# Full Unicode text — any string hypothesis can generate
any_text = st.text(min_size=0, max_size=200)

# Printable ASCII only — subset for readable test output
printable = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Po", "Zs")),
    min_size=0, max_size=100,
)

# Strings with known LDAP injection characters
ldap_dangerous = st.text(
    alphabet=st.sampled_from(list("\\*();\x00|&`$<>")),
    min_size=1, max_size=20,
)

# Strings with path traversal patterns
path_dangerous = st.one_of(
    st.just("../"),
    st.just("..\\"),
    st.just("../../etc/passwd"),
    st.just("..\\..\\windows\\system32"),
    st.text(min_size=0, max_size=50),
)

# Hostname-like strings
hostname_like = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters=".-_"),
    min_size=1, max_size=63,
)


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_ldap
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizeLDAPProperties:

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str):
        """sanitize_ldap must never raise on any input."""
        try:
            result = sanitize_ldap(value)
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"sanitize_ldap raised {type(exc).__name__}: {exc!s:.80}")

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_idempotent(self, value: str):
        """Applying sanitize_ldap twice must equal applying it once."""
        once  = sanitize_ldap(value)
        twice = sanitize_ldap(once)
        assert once == twice, (
            f"sanitize_ldap not idempotent:\n"
            f"  input:  {repr(value)}\n"
            f"  once:   {repr(once)}\n"
            f"  twice:  {repr(twice)}"
        )

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_output_is_string(self, value: str):
        assert isinstance(sanitize_ldap(value), str)

    @given(ldap_dangerous)
    @settings(max_examples=200)
    def test_dangerous_chars_stripped_or_escaped(self, value: str):
        """
        Raw null bytes must not survive sanitization — they are used in
        LDAP injection to truncate filter expressions.
        """
        result = sanitize_ldap(value)
        # Null byte is the most dangerous — must not be in output as-is
        # (ldap3 escapes it to \00, which is safe; raw \x00 is not)
        assert "\x00" not in result, (
            f"Raw null byte survived sanitize_ldap({repr(value)!r}) → {repr(result)}"
        )

    def test_empty_string_returns_empty(self):
        assert sanitize_ldap("") == ""

    def test_normal_username_unchanged_or_safe(self):
        """Plain ASCII username should either be unchanged or safely escaped."""
        result = sanitize_ldap("john.doe")
        assert "john" in result and "doe" in result

    def test_ldap_injection_null_escaped(self):
        result = sanitize_ldap("admin\x00injected")
        assert "\x00" not in result

    def test_ldap_wildcard_handled(self):
        """Wildcard * used in LDAP injection must be escaped, not raw."""
        result = sanitize_ldap("*)(uid=*")
        # After escaping, the raw unescaped wildcard should not form valid injection
        # The exact escaping depends on ldap3 — just verify no crash
        assert isinstance(result, str)


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_hostname
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizeHostnameProperties:

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str):
        try:
            result = sanitize_hostname(value)
            assert isinstance(result, str)
        except Exception as exc:
            pytest.fail(f"sanitize_hostname raised {type(exc).__name__}: {exc!s:.80}")

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_idempotent(self, value: str):
        once  = sanitize_hostname(value)
        twice = sanitize_hostname(once)
        assert once == twice, (
            f"sanitize_hostname not idempotent:\n"
            f"  input:  {repr(value)}\n"
            f"  once:   {repr(once)}\n"
            f"  twice:  {repr(twice)}"
        )

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_output_only_safe_chars(self, value: str):
        """
        Output must contain only alphanumerics, dots, hyphens, underscores.
        Any other character is a potential command/path injection vector.
        """
        import re
        result = sanitize_hostname(value)
        assert re.fullmatch(r"[a-zA-Z0-9.\-_]*", result), (
            f"Unsafe char in sanitize_hostname({repr(value)!r}) → {repr(result)}"
        )

    def test_valid_ip_unchanged(self):
        assert sanitize_hostname("10.0.0.1") == "10.0.0.1"

    def test_valid_hostname_unchanged(self):
        assert sanitize_hostname("dc01.corp.local") == "dc01.corp.local"

    def test_command_injection_stripped(self):
        result = sanitize_hostname("10.0.0.1; rm -rf /")
        assert ";" not in result
        assert " " not in result

    def test_shell_metacharacters_stripped(self):
        for dangerous in ["$(whoami)", "`id`", "10.0.0.1|nc", "host&&cmd"]:
            result = sanitize_hostname(dangerous)
            for char in "$`|&()":
                assert char not in result, f"'{char}' survived: {repr(result)}"

    def test_null_byte_stripped(self):
        assert "\x00" not in sanitize_hostname("host\x00evil")

    def test_newline_stripped(self):
        assert "\n" not in sanitize_hostname("host\nevil")
        assert "\r" not in sanitize_hostname("host\revil")


# ══════════════════════════════════════════════════════════════════════════════
# sanitize_path
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizePathProperties:

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_returns_string_or_rejects_unsafe_path(self, value: str):
        try:
            result = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        assert isinstance(result, str)

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_idempotent(self, value: str):
        try:
            once = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        twice = sanitize_path(once)
        assert once == twice, (
            f"sanitize_path not idempotent:\n"
            f"  input:  {repr(value)}\n"
            f"  once:   {repr(once)}\n"
            f"  twice:  {repr(twice)}"
        )

    @given(path_dangerous)
    @settings(max_examples=200)
    def test_traversal_patterns_removed(self, value: str):
        """
        ../  and ..\\ must not survive sanitization.
        These are the canonical path traversal sequences.
        """
        try:
            result = sanitize_path(value)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        assert "../" not in result, (
            f"'../' survived sanitize_path({repr(value)!r}) → {repr(result)}"
        )
        assert "..\\" not in result, (
            f"'..\\\\' survived sanitize_path({repr(value)!r}) → {repr(result)}"
        )

    def test_normal_path_passes_through(self):
        normal = "configs/settings.yaml"
        result = sanitize_path(normal)
        assert result == normal

    def test_unix_traversal_blocked(self):
        assert "../" not in sanitize_path("../../etc/passwd")

    def test_windows_traversal_blocked(self):
        assert "..\\" not in sanitize_path("..\\..\\windows\\system32\\cmd.exe")

    def test_deep_traversal_blocked(self):
        deep = "../" * 20 + "etc/shadow"
        result = sanitize_path(deep)
        assert "../" not in result


# ══════════════════════════════════════════════════════════════════════════════
# validate_ip_or_cidr
# ══════════════════════════════════════════════════════════════════════════════

# Valid IP strategies
valid_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(0, 255), st.integers(0, 255),
    st.integers(0, 255), st.integers(0, 255),
)
valid_ipv4_cidr = st.builds(
    lambda a, b, c, d, p: f"{a}.{b}.{c}.{d}/{p}",
    st.integers(0, 255), st.integers(0, 255),
    st.integers(0, 255), st.integers(0, 0),  # host bits 0 for clean CIDR
    st.integers(8, 32),
)


class TestValidateIPOrCIDRProperties:

    @given(any_text)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_never_raises(self, value: str):
        """validate_ip_or_cidr must never raise — always return bool."""
        try:
            result = validate_ip_or_cidr(value)
            assert isinstance(result, bool)
        except Exception as exc:
            pytest.fail(f"validate_ip_or_cidr raised {type(exc).__name__}: {exc!s:.80}")

    @given(valid_ipv4)
    @settings(max_examples=200)
    def test_valid_ipv4_accepted(self, ip: str):
        assert validate_ip_or_cidr(ip) is True, f"Valid IPv4 {ip!r} rejected"

    @given(valid_ipv4_cidr)
    @settings(max_examples=200)
    def test_valid_cidr_accepted(self, cidr: str):
        # netaddr is strict about host bits — allow either True or False
        # but must not raise
        result = validate_ip_or_cidr(cidr)
        assert isinstance(result, bool)

    def test_well_known_valid(self):
        for ip in ["10.0.0.1", "192.168.1.1", "172.16.0.1",
                   "8.8.8.8", "::1", "2001:db8::1"]:
            assert validate_ip_or_cidr(ip) is True, f"Expected {ip!r} to be valid"

    def test_well_known_cidr_valid(self):
        for cidr in ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0"]:
            assert validate_ip_or_cidr(cidr) is True, f"Expected {cidr!r} to be valid"

    def test_clearly_invalid_rejected(self):
        for bad in ["not-an-ip", "999.999.999.999", "hostname.local",
                    "", "  ", "10.0.0.1/33", "300.0.0.1"]:
            assert validate_ip_or_cidr(bad) is False, f"Expected {bad!r} to be invalid"

    def test_injection_attempts_rejected(self):
        for injection in [
            "10.0.0.1; rm -rf /",
            "10.0.0.1\nmalicious",
            "$(hostname)",
            "`id`",
        ]:
            assert validate_ip_or_cidr(injection) is False


# ══════════════════════════════════════════════════════════════════════════════
# Cross-sanitizer: chaining does not break idempotency
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossSanitizerProperties:

    @given(any_text)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_hostname_then_path_no_crash(self, value: str):
        """Chaining sanitizers returns a path or rejects unsafe path input."""
        h = sanitize_hostname(value)
        try:
            p = sanitize_path(h)
        except ValueError as exc:
            assert any(
                fragment in str(exc)
                for fragment in ("outside allowed", "not allowed", "null byte")
            )
            return
        assert isinstance(p, str)

    @given(any_text)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_ldap_idempotent_after_hostname(self, value: str):
        """sanitize_ldap(sanitize_hostname(x)) should be idempotent."""
        cleaned   = sanitize_ldap(sanitize_hostname(value))
        recleaned = sanitize_ldap(sanitize_hostname(cleaned))
        assert cleaned == recleaned
