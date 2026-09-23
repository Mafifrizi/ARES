import pytest
from unittest.mock import MagicMock

from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Severity
from ares.core.config import AresSettings
from ares.core.context import ExecutionContext
from ares.core.noise import NoiseController
from ares.modules.exfil.secrets_scan import (
    SecretsScan,
    _compute_dynamic_confidence,
    _is_placeholder_token,
    calculate_shannon_entropy,
    extract_secret_metadata,
)
from ares.modules.params import SecretsScanParams


def _make_module() -> tuple[SecretsScan, Campaign]:
    settings = AresSettings(
        ares_secret_key="test-secret-key-32chars-minimum!!",
        ares_encryption_key="test-encryption-key-32chars-min!!",
    )
    campaign = Campaign(
        name="Secrets-Scan-Test",
        client="Unit-Testing",
        scope=[ScopeEntry(cidr="192.168.0.0/16")],
        noise_profile=NoiseProfile.NORMAL,
    )
    noise = NoiseController(campaign)
    mod = SecretsScan(settings=settings, campaign=campaign, noise=noise)
    return mod, campaign


class TestShannonEntropyMathematics:
    """Verifies that the Shannon entropy calculation follows mathematical truth."""

    def test_empty_string(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_single_repeated_character(self):
        # A string of identical characters has 0 information content
        assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0

    def test_binary_alphabet_equal_distribution(self):
        # Two equally distributed symbols yield exactly 1.0 bit
        assert calculate_shannon_entropy("abababab") == 1.0

    def test_hexadecimal_equal_distribution(self):
        # 16 distinct symbols equally distributed yield log2(16) = 4.0 bits
        hex_16 = "0123456789abcdef"
        assert calculate_shannon_entropy(hex_16) == 4.0

    def test_realistic_high_entropy_secret(self):
        # Complex token with high variety yields >= 3.5 bits
        token = "K9#mQ2$vL8!zW5@x"
        entropy = calculate_shannon_entropy(token)
        assert entropy >= 3.5


class TestPlaceholderHeuristics:
    """Verifies genuine detection of dummy credentials and test fixtures."""

    def test_exact_placeholder_words(self):
        assert _is_placeholder_token("password") is True
        assert _is_placeholder_token("admin") is True
        assert _is_placeholder_token("changeme") is True

    def test_substring_placeholder_indicators(self):
        assert _is_placeholder_token("dummy_api_key_placeholder") is True
        assert _is_placeholder_token("my_example_key") is True
        assert _is_placeholder_token("sample_token_123") is True

    def test_test_environment_file_paths(self):
        # Even a complex password in a test fixture is classified as placeholder
        assert _is_placeholder_token("X9#vL2!zW5@x8QaP", file_path="tests/fixtures/secrets.env") is True
        assert _is_placeholder_token("X9#vL2!zW5@x8QaP", file_path="src/mocks/auth.mock.ts") is True

    def test_genuine_production_credential(self):
        assert _is_placeholder_token("P@ssw0rd99!Secure", file_path="C:\\inetpub\\wwwroot\\web.config") is False
        assert _is_placeholder_token("AKIA2J5K8L9M0N1P2Q3R", file_path="C:\\Users\\admin\\.aws\\credentials") is False


class TestSecretMetadataExtraction:
    """Verifies parsing, secret value isolation, and dynamic confidence scoring."""

    def test_aws_access_key_extraction(self):
        meta = extract_secret_metadata(
            snippet="aws_access_key_id = AKIA2J5K8L9M0N1P2Q3R",
            file_path="C:\\Users\\deploy\\.aws\\credentials"
        )
        assert meta["pattern"] == "aws_access_key"
        assert meta["extracted_secret"] == "AKIA2J5K8L9M0N1P2Q3R"
        assert meta["secret_value"] == "AKIA2J5K8L9M0N1P2Q3R"
        assert meta["is_placeholder"] is False
        assert meta["confidence"] >= 0.95
        assert meta["entropy"] >= 3.0

    def test_aws_example_key_penalized(self):
        meta = extract_secret_metadata(
            snippet="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            file_path="config.env"
        )
        assert meta["pattern"] == "aws_access_key"
        assert meta["is_placeholder"] is True
        assert meta["confidence"] <= 0.60

    def test_connection_string_with_isolated_password(self):
        meta = extract_secret_metadata(
            snippet='connectionString="Server=db01;Database=prod;User Id=sa;Password=P@ss1234!"',
            file_path="C:\\inetpub\\wwwroot\\web.config"
        )
        assert meta["pattern"] == "connection_string"
        assert meta["secret_value"] == "P@ss1234!"
        assert meta["is_placeholder"] is False
        assert meta["confidence"] >= 0.85

    def test_password_field_in_test_file(self):
        meta = extract_secret_metadata(
            snippet='password = "admin"',
            file_path="tests/test_login.py"
        )
        assert meta["pattern"] == "password_field"
        assert meta["secret_value"] == "admin"
        assert meta["is_placeholder"] is True
        assert meta["confidence"] <= 0.35


class TestSecretsScanModuleExecution:
    """Verifies that the module returns dynamic confidence and non-redacted structured evidence."""

    @pytest.mark.asyncio
    async def test_dry_run_execution(self):
        mod, campaign = _make_module()
        settings = AresSettings(
            ares_secret_key="test-secret-key-32chars-minimum!!",
            ares_encryption_key="test-encryption-key-32chars-min!!",
        )
        noise = NoiseController(campaign)
        ctx = ExecutionContext(
            execution_id="test-exec-secrets",
            campaign_id=campaign.id,
            target="192.168.56.105",
            params=SecretsScanParams(target="192.168.56.105", username="admin"),
            settings=settings,
            campaign=campaign,
            noise=noise,
            dry_run=True,
        )
        res = await mod.execute(ctx)
        assert res.status == "dry_run"
        assert res.raw.get("dry_run") is True

    @pytest.mark.asyncio
    async def test_run_dry_run_produces_dynamic_confidence_and_structured_hits(self):
        mod, _ = _make_module()
        findings, raw = await mod.run(target="192.168.56.105", dry_run=True)
        assert len(findings) == 1
        finding = findings[0]

        # Verify dynamic confidence (NOT hardcoded 0.60 template)
        assert finding.confidence > 0.60
        assert finding.severity == Severity.CRITICAL
        assert "hits" in finding.evidence
        assert len(finding.evidence["hits"]) == 2

        # Verify hit structure includes actual secrets and entropy
        hit1 = finding.evidence["hits"][0]
        assert "extracted_secret" in hit1
        assert "secret_value" in hit1
        assert "entropy" in hit1
        assert "confidence" in hit1
        assert isinstance(hit1["entropy"], float)
        assert isinstance(hit1["confidence"], float)

        # Verify raw output has discovered_secrets for UI fallback
        assert "discovered_secrets" in raw
        assert len(raw["discovered_secrets"]) == 2

    @pytest.mark.asyncio
    async def test_live_execution_pipeline_with_mocked_scan(self, monkeypatch):
        mod, campaign = _make_module()
        settings = AresSettings(
            ares_secret_key="test-secret-key-32chars-minimum!!",
            ares_encryption_key="test-encryption-key-32chars-min!!",
        )
        noise = NoiseController(campaign)
        ctx = ExecutionContext(
            execution_id="test-exec-secrets-live",
            campaign_id=campaign.id,
            target="192.168.1.50",
            params=SecretsScanParams(target="192.168.1.50", username="svc_backup", platform="linux"),
            settings=settings,
            campaign=campaign,
            noise=noise,
            dry_run=False,
        )

        mock_hits = [
            {
                "file": "/etc/vault/config.hcl",
                "line": 14,
                "pattern": "generic_api_key",
                "snippet": "token = 'ares_mock_token_94aZbXq39L1849v9NmqP1928'",
                "extracted_secret": "ares_mock_token_94aZbXq39L1849v9NmqP1928",
                "secret_value": "ares_mock_token_94aZbXq39L1849v9NmqP1928",
                "entropy": 4.12,
                "confidence": 0.95,
                "is_placeholder": False,
            }
        ]

        import ares.modules.exfil.secrets_scan as ss_mod
        monkeypatch.setattr(ss_mod, "_ssh_scan", lambda *args, **kwargs: mock_hits)

        res = await mod.execute(ctx)
        assert res.status == "success"
        assert len(res.findings) == 1
        finding = res.findings[0]
        assert finding.confidence == 0.95
        assert finding.evidence["hits"][0]["secret_value"] == "ares_mock_token_94aZbXq39L1849v9NmqP1928"

        # Verify cryptographic evidence records generated
        assert "evidence_chain" in res.raw
        assert len(res.raw["evidence_chain"]) == 1
        assert "evidence_integrity" in res.raw
        assert len(res.raw["evidence_integrity"]) == 1

        # Verify purple telemetry rules synthesized
        assert "detection_kql" in res.raw["loot"]
        assert "detection_sigma" in res.raw["loot"]

    @pytest.mark.asyncio
    async def test_out_of_scope_target_is_blocked_by_scope_guard(self):
        from ares.core.noise import ScopeViolationError
        mod, campaign = _make_module()
        settings = AresSettings(
            ares_secret_key="test-secret-key-32chars-minimum!!",
            ares_encryption_key="test-encryption-key-32chars-min!!",
        )
        noise = NoiseController(campaign)
        ctx = ExecutionContext(
            execution_id="test-exec-out-of-scope",
            campaign_id=campaign.id,
            target="10.0.0.15",  # Outside 192.168.0.0/16
            params=SecretsScanParams(target="10.0.0.15", username="svc_backup", platform="linux"),
            settings=settings,
            campaign=campaign,
            noise=noise,
            dry_run=False,
        )

        with pytest.raises(ScopeViolationError, match="not in scope"):
            await mod.execute(ctx)


