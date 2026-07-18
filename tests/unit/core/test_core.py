"""Tests for core components."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from ares.core.campaign import Campaign, Finding, NoiseProfile, Severity, ScopeEntry
from ares.core.noise import JitterEngine, NoiseController, RateLimiter, ScopeGuard, ScopeViolationError
from ares.core.security import (
    DataEncryptor,
    hash_password,
    verify_password,
    sanitize_ldap,
    sanitize_hostname,
    create_access_token,
    decode_access_token,
)
from ares.core.validator import FindingValidator, ValidationCheck, ValidationStage


# ── Campaign tests ────────────────────────────────────────────────────────────

class TestCampaign:
    def test_create(self):
        c = Campaign(name="Test", client="ACME", targets=["10.0.0.1"])
        assert c.status.value == "created"
        assert len(c.findings) == 0

    def test_scope_guard_in_scope(self):
        c = Campaign(name="T", scope=[ScopeEntry(cidr="10.0.0.0/24")])
        assert c.is_in_scope("10.0.0.1") is True
        assert c.is_in_scope("10.0.1.1") is False

    def test_scope_guard_no_scope_denies_all(self):
        """No scope = deny all — safe default."""
        c = Campaign(name="T")
        assert c.is_in_scope("10.0.0.1") is False

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            ScopeEntry(cidr="not-a-cidr")

    def test_add_finding_updates_audit(self):
        c = Campaign(name="T")
        f = Finding(title="Test", description="A test finding", severity=Severity.HIGH)
        c.add_finding(f)
        assert len(c.findings) == 1
        assert any(a.action == "finding_added" for a in c.audit_log)

    def test_false_positive_not_in_confirmed(self):
        c = Campaign(name="T")
        f = Finding(title="FP", description="False positive", severity=Severity.HIGH)
        f.mark_false_positive("manually marked")
        c.findings.append(f)  # bypass add_finding filter
        assert len(c.confirmed_findings()) == 0

    def test_risk_score(self):
        c = Campaign(name="T")
        f = Finding(title="T", description="D" * 10, severity=Severity.CRITICAL,
                    confidence=1.0, validated=True)
        c.add_finding(f)
        assert c.risk_score() == 5.0


# ── Noise tests ───────────────────────────────────────────────────────────────

class TestScopeGuard:
    def _campaign_with_scope(self) -> Campaign:
        return Campaign(name="T", scope=[ScopeEntry(cidr="192.168.1.0/24")])

    def test_in_scope_passes(self):
        sg = ScopeGuard(self._campaign_with_scope())
        assert sg.check("192.168.1.50", "scan") is True
        assert sg.blocked_count == 0

    def test_out_of_scope_blocks(self):
        sg = ScopeGuard(self._campaign_with_scope())
        assert sg.check("10.0.0.1", "scan") is False
        assert sg.blocked_count == 1

    def test_assert_raises_on_out_of_scope(self):
        sg = ScopeGuard(self._campaign_with_scope())
        with pytest.raises(ScopeViolationError):
            sg.assert_in_scope("8.8.8.8", "dns")


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_under_limit(self):
        from ares.core.campaign import NoiseProfile
        rl = RateLimiter(NoiseProfile.AGGRESSIVE)
        # Should not block for first N requests
        for _ in range(5):
            await rl.acquire("default")

    @pytest.mark.asyncio
    async def test_jitter_range(self):
        j = JitterEngine(NoiseProfile.STEALTH)
        assert 0 < j.min_ms <= j.max_ms


# ── Security tests ────────────────────────────────────────────────────────────

class TestSecurity:
    def test_password_hash_verify(self):
        h = hash_password("supersecret123")
        assert verify_password("supersecret123", h) is True
        assert verify_password("wrongpassword", h) is False

    def test_jwt_roundtrip(self):
        token = create_access_token({"sub": "alice"}, secret_key="x" * 32)
        payload = decode_access_token(token, secret_key="x" * 32)
        assert payload is not None
        assert payload["sub"] == "alice"

    def test_jwt_wrong_key_fails(self):
        token = create_access_token({"sub": "alice"}, secret_key="a" * 32)
        payload = decode_access_token(token, secret_key="b" * 32)
        assert payload is None

    def test_encryption_roundtrip(self):
        enc = DataEncryptor("test-key-32-characters-long-here")
        ciphertext = enc.encrypt("secret data")
        assert enc.decrypt(ciphertext) == "secret data"

    def test_decryption_wrong_key_fails(self):
        enc1 = DataEncryptor("key-one-32-characters-long-here!")
        enc2 = DataEncryptor("key-two-32-characters-long-here!")
        ct = enc1.encrypt("secret")
        assert enc2.decrypt(ct) is None

    def test_sanitize_ldap_strips_injection(self):
        assert sanitize_ldap("admin)(uid=*)") == "adminuid="

    def test_sanitize_ldap_strips_metachars_and_preserves_safe_chars(self):
        assert sanitize_ldap(r"user\name*(cn=admin)\x00") == r"usernamecn=adminx00"
        assert sanitize_ldap("a\x00b\x1fc\x7fd") == "abcd"
        assert sanitize_ldap("john.doe-user_1@example.com = ok") == "john.doe-user_1@example.com = ok"

    def test_sanitize_hostname_strips_special(self):
        assert sanitize_hostname("host; rm -rf /") == "hostrm-rf"


# ── Validator tests ───────────────────────────────────────────────────────────

class TestValidator:
    @pytest.mark.asyncio
    async def test_validator_confidence_log_is_ascii_safe(self, monkeypatch):
        import ares.core.validator as validator_module
        from unittest.mock import Mock

        logger_info = Mock()
        monkeypatch.setattr(validator_module.logger, "info", logger_info)

        async def always_pass(finding: Finding, context: dict) -> tuple[bool, float, str]:
            return True, 0.95, "confirmed"

        validator = FindingValidator()
        validator.register("test.ascii_log", [
            ValidationCheck(
                stage=ValidationStage.EXISTENCE,
                name="ascii_check",
                check=always_pass,
            )
        ])
        finding = Finding(
            title="ASREPRoast Hashes Captured (1)",
            description="Captured hash evidence",
            severity=Severity.HIGH,
            module_id="test.ascii_log",
        )

        result = await validator.validate(finding, {})

        logged_message = logger_info.call_args.args[0]
        assert logged_message.isascii()
        assert " -> " in logged_message
        assert "confidence=0.95" in logged_message
        assert result.confidence == 0.95

    @pytest.mark.asyncio
    async def test_no_checks_defaults_to_medium_confidence(self):
        v = FindingValidator()
        f = Finding(title="T", description="D" * 10, severity=Severity.HIGH, module_id="unknown.mod")
        result = await v.validate(f, {})
        assert result.confidence == 0.6
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_all_checks_fail_marks_fp(self):
        async def always_fail(finding: Finding, context: dict) -> tuple[bool, float, str]:
            return False, 0.0, "not found"

        v = FindingValidator()
        v.register("test.mod", [
            ValidationCheck(stage=ValidationStage.EXISTENCE, name="test_check",
                            check=always_fail, weight=1.0)
        ])
        f = Finding(title="T", description="D" * 10, severity=Severity.HIGH, module_id="test.mod")
        result = await v.validate(f, {})
        assert result.passed is False
        assert f.false_positive is True

    @pytest.mark.asyncio
    async def test_high_confidence_passes(self):
        async def always_pass(finding: Finding, context: dict) -> tuple[bool, float, str]:
            return True, 1.0, "confirmed"

        v = FindingValidator()
        v.register("test.mod2", [
            ValidationCheck(stage=ValidationStage.EXISTENCE, name="c",
                            check=always_pass, weight=1.0)
        ])
        f = Finding(title="T", description="D" * 10, severity=Severity.CRITICAL, module_id="test.mod2")
        result = await v.validate(f, {})
        assert result.confidence == 1.0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_ad_confidence_uses_module_evidence(self):
        from ares.core.validator import build_default_validator

        validator = build_default_validator()
        captured = Finding(
            title="AS-REP hash",
            description="Captured hash evidence",
            severity=Severity.HIGH,
            module_id="ad.asreproast",
            evidence={"hash_count": 1},
        )
        candidates = Finding(
            title="SPN candidates",
            description="Enumerated service accounts",
            severity=Severity.HIGH,
            module_id="ad.enum_spn",
            evidence={"total_spns": 2},
        )
        tgs = Finding(
            title="TGS hash",
            description="Captured TGS evidence",
            severity=Severity.CRITICAL,
            module_id="ad.kerberoast",
            evidence={"hash_count": 1},
        )

        captured_result = await validator.validate(captured, {})
        candidate_result = await validator.validate(candidates, {})
        tgs_result = await validator.validate(tgs, {})

        assert captured_result.confidence == 0.95
        assert candidates.confidence == 0.6
        assert tgs_result.confidence == 0.95
        assert captured_result.passed is True
        assert candidate_result.passed is True
        assert tgs_result.passed is True
