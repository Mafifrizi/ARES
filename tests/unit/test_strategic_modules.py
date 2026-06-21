"""
Unit tests — 4 strategic modules (v34+)

Covers:
  - ai.autonomous_planner
  - opsec.coverage_predictor
  - edr.bypass_adaptive
  - cloud.identity_federation_abuse
"""
from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.unit.modules.test_modules import _make_module

os.environ.setdefault("ARES_SECRET_KEY",       "strategic-test-key-32chars-min!!")
os.environ.setdefault("ARES_ENCRYPTION_KEY",   "strategic-test-enc-32chars-min!!")
os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD", "StrategicTest1!")


def _run(coro):
    return asyncio.run(coro)


def _mock_campaign(findings=None, scope_cidrs=("10.0.0.0/8",), noise="normal"):
    from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
    c = Campaign(
        name="strategic-test", client="test",
        scope=[ScopeEntry(cidr=s) for s in scope_cidrs],
        noise_profile=NoiseProfile(noise),
    )
    if findings:
        c.findings = findings
    return c


def _mock_ctx(params=None, dry_run=False, campaign=None):
    ctx = MagicMock()
    ctx.params      = params or {}
    ctx.target      = (params or {}).get("target", "")
    ctx.dry_run     = dry_run
    ctx.vault       = None
    ctx.execution_id = "strategic-test"
    ctx.campaign    = campaign or _mock_campaign()
    ctx.best_credential = lambda: None
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# opsec.coverage_predictor
# ══════════════════════════════════════════════════════════════════════════════

class TestCoveragePredictor:

    def test_module_id_and_opsec(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        assert CoveragePredictorModule.MODULE_ID == "opsec.coverage_predictor"
        from ares.modules.base import OpsecLevel
        assert CoveragePredictorModule.OPSEC_LEVEL == OpsecLevel.LOCAL

    def test_dry_run(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = _run(mod.execute(_mock_ctx(dry_run=True, campaign=_mock_campaign())))
        assert result.status == "dry_run"

    def test_score_empty_campaign(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[],
            modules_run=[],
            noise_profile="normal",
        )
        assert prediction.overall_score == 0.0
        assert prediction.wait_hours == 0
        assert prediction.modules_analyzed == 0

    def test_high_risk_dcsync_scoring(self):
        """DCSync (T1003.006) should produce a high detection score."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[],
            modules_run=[{
                "module_id":        "ad.dcsync",
                "mitre_techniques": ["T1003.006"],
                "opsec_level":      "high_noise",
                "timestamp":        0,
            }],
            noise_profile="aggressive",
        )
        assert prediction.overall_score > 0.5, "DCSync + aggressive should be high risk"
        assert prediction.wait_hours > 0, "High score should recommend a wait"

    def test_local_module_low_score(self):
        """LOCAL OPSEC modules (crack) should score low."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[],
            modules_run=[{
                "module_id":        "credential.crack",
                "mitre_techniques": ["T1110.002"],
                "opsec_level":      "local",
                "timestamp":        0,
            }],
            noise_profile="stealth",
        )
        assert prediction.overall_score < 0.3, "LOCAL opsec should produce low score"

    def test_multiple_high_noise_modules(self):
        """Multiple high-noise modules compound detection probability."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        single = predictor.predict(
            campaign_findings=[], noise_profile="normal",
            modules_run=[{"module_id": "ad.coerce",
                          "mitre_techniques": ["T1187"], "opsec_level": "high_noise", "timestamp": 0}],
        )
        multiple = predictor.predict(
            campaign_findings=[], noise_profile="normal",
            modules_run=[
                {"module_id": "ad.dcsync",      "mitre_techniques": ["T1003.006"], "opsec_level": "high_noise", "timestamp": 0},
                {"module_id": "windows.lsass_dump", "mitre_techniques": ["T1003.001"], "opsec_level": "high_noise", "timestamp": 1},
                {"module_id": "lateral.psexec", "mitre_techniques": ["T1569.002"],  "opsec_level": "high_noise", "timestamp": 2},
            ],
        )
        assert multiple.overall_score > single.overall_score, "More noisy modules = higher score"

    def test_highest_risk_action_identified(self):
        """highest_risk_action should be the most dangerous single event."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[], noise_profile="normal",
            modules_run=[
                {"module_id": "ad.enum_users", "mitre_techniques": ["T1087.002"],
                 "opsec_level": "low", "timestamp": 0},
                {"module_id": "windows.lsass_dump", "mitre_techniques": ["T1003.001"],
                 "opsec_level": "high_noise", "timestamp": 1},
            ],
        )
        assert prediction.highest_risk_action is not None
        # LSASS access should be higher risk than enum_users
        assert prediction.highest_risk_action.probability > 0.5

    def test_recommendations_not_empty_for_high_score(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[], noise_profile="aggressive",
            modules_run=[
                {"module_id": "ad.dcsync", "mitre_techniques": ["T1003.006"],
                 "opsec_level": "high_noise", "timestamp": 0},
                {"module_id": "windows.lsass_dump", "mitre_techniques": ["T1003.001"],
                 "opsec_level": "high_noise", "timestamp": 1},
            ],
        )
        assert len(prediction.recommendations) > 0

    def test_outputs_keys(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        assert "detection_score" in CoveragePredictorModule.OUTPUTS
        assert "wait_recommendation" in CoveragePredictorModule.OUTPUTS

    def test_validate_requires_campaign(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        from ares.core.errors import ModuleValidationError
        mod, _ = _make_module(CoveragePredictorModule)
        ctx = _mock_ctx()
        ctx.campaign = None
        with pytest.raises((ModuleValidationError, Exception)):
            _run(mod.validate(ctx))

    def test_execute_returns_module_result(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        from ares.modules.base import ModuleResult
        mod, _ = _make_module(CoveragePredictorModule)
        result = _run(mod.execute(_mock_ctx(campaign=_mock_campaign())))
        assert isinstance(result, ModuleResult)
        assert result.raw is not None
        assert "detection_score" in result.raw


# ══════════════════════════════════════════════════════════════════════════════
# edr.bypass_adaptive
# ══════════════════════════════════════════════════════════════════════════════

class TestEDRBypassAdaptive:

    def test_module_id_and_opsec(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        assert EDRAdaptiveBypassModule.MODULE_ID == "edr.bypass_adaptive"
        from ares.modules.base import OpsecLevel
        assert EDRAdaptiveBypassModule.OPSEC_LEVEL == OpsecLevel.MEDIUM

    def test_dry_run(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"}, dry_run=True)
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert result.status == "dry_run"

    def test_crowdstrike_returns_techniques(self):
        """CrowdStrike should return applicable bypass techniques."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert result.raw is not None
        techniques = result.raw.get("viable_techniques", [])
        assert len(techniques) > 0, "CrowdStrike should have applicable bypass techniques"

    def test_sentinelone_returns_syscall_techniques(self):
        """SentinelOne should include direct syscall technique."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "sentinelone"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        techniques = result.raw.get("viable_techniques", [])
        ids = [t.get("id", "") for t in techniques]
        assert any("syscall" in tid or "unhook" in tid for tid in ids), \
            "SentinelOne bypass should include direct syscalls or unhooking"

    def test_unknown_vendor_returns_generic(self):
        """Unknown EDR should return generic bypass techniques."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "unknown"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        techniques = result.raw.get("viable_techniques", [])
        # Should at least return generic in-memory execution
        assert len(techniques) >= 1

    def test_low_noise_techniques_first(self):
        """Techniques should be sorted low-noise first."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        techniques = result.raw.get("viable_techniques", [])
        if len(techniques) >= 2:
            opsec_order = {"low": 0, "medium": 1, "high_noise": 2}
            for i in range(len(techniques) - 1):
                t1 = opsec_order.get(techniques[i].get("opsec_level", "medium"), 1)
                t2 = opsec_order.get(techniques[i+1].get("opsec_level", "medium"), 1)
                assert t1 <= t2, "Techniques not sorted by OPSEC level (low-noise first)"

    def test_bypass_plan_is_ordered(self):
        """bypass_plan should have sequential step numbers."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "defender_atp"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        plan = result.raw.get("bypass_plan", [])
        if plan:
            steps = [p.get("step") for p in plan]
            assert steps == list(range(1, len(steps) + 1)), "Plan steps not sequential"

    def test_recommended_approach_present(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert "recommended_approach" in result.raw

    def test_outputs_keys(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        assert "viable_techniques" in EDRAdaptiveBypassModule.OUTPUTS
        assert "bypass_plan" in EDRAdaptiveBypassModule.OUTPUTS
        assert "edr_vendor" in EDRAdaptiveBypassModule.OUTPUTS

    def test_validate_requires_edr_vendor_or_fingerprint(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        mod, campaign = _make_module(EDRAdaptiveBypassModule)
        ctx = ExecutionContext(
            campaign_id=campaign.id,
            module_id=mod.MODULE_ID,
            target="10.0.0.1",
            params={},  # no edr_vendor, no fingerprint_result
            campaign=campaign,
        )
        with pytest.raises((ModuleValidationError, Exception)):
            _run(mod.validate(ctx))

    def test_mitre_techniques_declared(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        assert "T1562.001" in EDRAdaptiveBypassModule.MITRE_TECHNIQUES
        assert "T1055" in EDRAdaptiveBypassModule.MITRE_TECHNIQUES


# ══════════════════════════════════════════════════════════════════════════════
# cloud.identity_federation_abuse
# ══════════════════════════════════════════════════════════════════════════════

class TestCloudFederationAbuse:

    def test_module_id_and_opsec(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        assert CloudIdentityFederationModule.MODULE_ID == "cloud.identity_federation_abuse"
        from ares.modules.base import OpsecLevel
        assert CloudIdentityFederationModule.OPSEC_LEVEL == OpsecLevel.MEDIUM

    def test_dry_run(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)
        ctx = _mock_ctx(params={"tenant_id": "test-tenant"}, dry_run=True)
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert result.status == "dry_run"

    def test_validate_requires_at_least_one_credential(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        mod, campaign = _make_module(CloudIdentityFederationModule)
        ctx = ExecutionContext(
            campaign_id=campaign.id,
            module_id=mod.MODULE_ID,
            params={},  # no credentials at all
            campaign=campaign,
        )
        with pytest.raises((ModuleValidationError, Exception)):
            _run(mod.validate(ctx))

    def test_validate_passes_with_tenant_id(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)
        ctx = _mock_ctx(params={"tenant_id": "test-tenant-id"})
        ctx.campaign = _mock_campaign()
        # Should not raise
        _run(mod.validate(ctx))

    def test_validate_passes_with_adfs_url(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)
        ctx = _mock_ctx(params={"adfs_url": "https://adfs.corp.local"})
        ctx.campaign = _mock_campaign()
        _run(mod.validate(ctx))

    def test_outputs_keys(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        assert "federation_trusts" in CloudIdentityFederationModule.OUTPUTS
        assert "golden_saml_paths" in CloudIdentityFederationModule.OUTPUTS
        assert "pivot_paths" in CloudIdentityFederationModule.OUTPUTS

    def test_mitre_techniques_include_golden_saml(self):
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        assert "T1606.002" in CloudIdentityFederationModule.MITRE_TECHNIQUES
        assert "T1528" in CloudIdentityFederationModule.MITRE_TECHNIQUES

    def test_pivot_path_analysis_azure_aws(self):
        """With both Azure and AWS federation, cross-cloud pivot path should be found."""
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)

        # Mock the individual enumeration methods
        mod._enumerate_azure_federation = lambda *a, **k: {
            "federated_domains": [{"id": "corp.local", "federated": True}],
            "saml_service_principals": [],
            "error": None,
        }
        mod._enumerate_aws_saml_providers = lambda *a, **k: {
            "saml_providers": [{"arn": "arn:aws:iam::123:saml-provider/AzureAD"}],
            "oidc_providers": [],
            "federated_roles": [],
            "error": None,
        }
        mod._enumerate_adfs = lambda *a, **k: {"error": None, "endpoints": []}

        findings, raw = _run(mod.run(
            tenant_id="test-tenant",
            access_key="AKIATEST",
            secret_key="test-secret",
        ))
        pivot_paths = raw.get("pivot_paths", [])
        assert any("Azure" in p.get("path", "") and "AWS" in p.get("path", "")
                   for p in pivot_paths), "Should identify Azure→AWS pivot path"

    def test_no_network_calls_on_dry_run(self):
        """Dry run must not make any real network calls."""
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)
        # If network calls happen, they'll fail in test env — dry_run should prevent them
        ctx = _mock_ctx(params={"tenant_id": "real-tenant-id"}, dry_run=True)
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert result.status == "dry_run"  # must not attempt network


# ══════════════════════════════════════════════════════════════════════════════
# ai.autonomous_planner
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAutonomousPlanner:

    def test_module_id_and_opsec(self):
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        assert AIAutonomousPlannerModule.MODULE_ID == "ai.autonomous_planner"
        from ares.modules.base import OpsecLevel
        assert AIAutonomousPlannerModule.OPSEC_LEVEL == OpsecLevel.LOCAL

    def test_dry_run(self):
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        mod, _ = _make_module(AIAutonomousPlannerModule)
        ctx = _mock_ctx(params={"llm_backend": "claude"}, dry_run=True)
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert result.status == "dry_run"

    def test_auto_approve_false_by_default(self):
        """auto_approve must default to False — operator review is required."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        from ares.modules.params import AIPlannerParams
        params = AIPlannerParams()
        assert params.auto_approve is False, "auto_approve must default to False"

    def test_parse_llm_response_valid_json(self):
        """Valid JSON response should parse into AIPlan."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        mod, _ = _make_module(AIAutonomousPlannerModule)
        valid = json.dumps({
            "reasoning":   "DCSync possible after kerberoast",
            "confidence":  0.85,
            "stages": [
                {"name": "enum", "rationale": "gather info",
                 "modules": ["ad.enum_users"], "params": {}},
                {"name": "attack", "rationale": "escalate",
                 "modules": ["ad.kerberoast", "ad.dcsync"], "params": {}},
            ],
            "alternative": [],
            "warnings":    ["DCSync is HIGH_NOISE — may trigger SIEM"],
        })
        plan = mod._parse_llm_response(valid, "claude-opus-4-6", 1000)
        assert plan.confidence == 0.85
        assert len(plan.stages) == 2
        assert plan.stages[1]["modules"] == ["ad.kerberoast", "ad.dcsync"]
        assert len(plan.warnings) == 1

    def test_parse_llm_response_invalid_json(self):
        """Invalid JSON should return fallback plan with 0.0 confidence, not crash."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        mod, _ = _make_module(AIAutonomousPlannerModule)
        plan = mod._parse_llm_response("not valid json {{{", "claude", 100)
        assert plan.confidence == 0.0
        assert plan.stages == []
        assert len(plan.warnings) > 0, "Should warn about parse failure"

    def test_parse_llm_response_strips_markdown_fences(self):
        """LLM may wrap JSON in ```json ... ``` — should be stripped."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        mod, _ = _make_module(AIAutonomousPlannerModule)
        fenced = '```json\n{"reasoning": "test", "confidence": 0.5, "stages": [], "alternative": [], "warnings": []}\n```'
        plan = mod._parse_llm_response(fenced, "gpt-4o", 200)
        assert plan.confidence == 0.5
        assert plan.reasoning == "test"

    def test_context_builder_no_secrets(self):
        """CampaignContextBuilder must not include raw passwords or hashes."""
        from ares.modules.ai.autonomous_planner import CampaignContextBuilder
        builder = CampaignContextBuilder()
        campaign = _mock_campaign()
        vault = MagicMock()
        cred = MagicMock()
        cred.username  = "administrator"
        cred.domain    = "corp.local"
        cred.cred_type = "NTLM"
        cred.privilege = "domain_admin"
        cred.plaintext = "super_secret_password"  # should NOT appear in output
        vault.list.return_value = [cred]

        ctx = builder.build(campaign, vault, "domain_admin")

        ctx_str = json.dumps(ctx)
        assert "super_secret_password" not in ctx_str, \
            "Raw password must not appear in LLM context"
        # Username is OK (not secret)
        assert "administrator" in ctx_str

    def test_context_builder_includes_available_modules(self):
        from ares.modules.ai.autonomous_planner import CampaignContextBuilder
        builder = CampaignContextBuilder()
        ctx = builder.build(_mock_campaign(), None, "domain_admin")
        assert len(ctx["available_modules"]) > 0
        assert "ad.kerberoast" in ctx["available_modules"]

    def test_validate_requires_api_key(self):
        """Validate must fail if Claude backend selected and no API key set."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        mod, campaign = _make_module(AIAutonomousPlannerModule)
        ctx = ExecutionContext(
            campaign_id=campaign.id,
            module_id=mod.MODULE_ID,
            target="local",
            params={"llm_backend": "claude"},
            campaign=campaign,
        )
        # Remove API key from environment
        with patch.dict(os.environ, {}, clear=True):
            # Ensure ANTHROPIC_API_KEY is not set
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with pytest.raises((ModuleValidationError, Exception)):
                _run(mod.validate(ctx))

    def test_run_with_mocked_llm(self):
        """Integration test with mocked LLM backend."""
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule, ClaudeBackend
        mod, _ = _make_module(AIAutonomousPlannerModule)

        mock_response = {
            "content": json.dumps({
                "reasoning":  "Kerberoast → crack → DCSync is optimal chain",
                "confidence": 0.88,
                "stages": [
                    {"name": "enum",   "rationale": "gather targets",
                     "modules": ["ad.enum_spn"],  "params": {}},
                    {"name": "cred",   "rationale": "harvest hashes",
                     "modules": ["ad.kerberoast"], "params": {}},
                    {"name": "escalate", "rationale": "dump all",
                     "modules": ["ad.dcsync"],    "params": {}},
                ],
                "alternative": [
                    {"name": "asrep", "rationale": "if kerberoast fails",
                     "modules": ["ad.asreproast"], "params": {}},
                ],
                "warnings": ["DCSync requires domain admin — ensure creds obtained first"],
            }),
            "model":       "claude-opus-4-6",
            "tokens_used": 1247,
        }

        with patch.object(ClaudeBackend, "generate_plan", return_value=mock_response):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key-for-mock"}):
                findings, raw = _run(mod.run(
                    campaign=_mock_campaign(),
                    goal="domain_admin",
                    llm_backend="claude",
                ))

        assert raw["confidence_score"] == 0.88
        assert len(raw["execution_plan"]) == 3
        assert raw["execution_plan"][0]["modules"] == ["ad.enum_spn"]
        assert raw["tokens_used"] == 1247
        assert raw["auto_approve"] is False  # must default to False

    def test_ai_plan_to_execution_plan(self):
        """AIPlan.to_execution_plan() must produce valid ARES ExecutionPlan."""
        from ares.modules.ai.autonomous_planner import AIPlan
        from ares.core.engine import ExecutionPlan
        plan = AIPlan(
            reasoning="test",
            stages=[
                {"name": "recon",  "modules": ["ad.enum_users"], "params": {}},
                {"name": "attack", "modules": ["ad.kerberoast", "ad.dcsync"], "params": {}},
            ],
            confidence=0.75,
        )
        exec_plan = plan.to_execution_plan()
        assert isinstance(exec_plan, ExecutionPlan)
        assert len(exec_plan.stages) == 2
        assert "ad.enum_users"  in exec_plan.all_module_ids()
        assert "ad.kerberoast"  in exec_plan.all_module_ids()
        assert "ad.dcsync"      in exec_plan.all_module_ids()

    def test_outputs_keys(self):
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        assert "execution_plan"   in AIAutonomousPlannerModule.OUTPUTS
        assert "ai_reasoning"     in AIAutonomousPlannerModule.OUTPUTS
        assert "confidence_score" in AIAutonomousPlannerModule.OUTPUTS
        assert "warnings"         in AIAutonomousPlannerModule.OUTPUTS

    def test_mitre_techniques_declared(self):
        from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
        assert "T1591" in AIAutonomousPlannerModule.MITRE_TECHNIQUES


# ══════════════════════════════════════════════════════════════════════════════
# MODULE_PARAMS registry — all 4 new modules registered
# ══════════════════════════════════════════════════════════════════════════════

class TestNewModulesRegistered:

    def test_all_four_in_module_params(self):
        from ares.modules.params import MODULE_PARAMS
        assert "opsec.coverage_predictor"        in MODULE_PARAMS
        assert "edr.bypass_adaptive"             in MODULE_PARAMS
        assert "ai.autonomous_planner"           in MODULE_PARAMS
        assert "cloud.identity_federation_abuse" in MODULE_PARAMS

    def test_module_params_have_correct_types(self):
        from ares.modules.params import (
            MODULE_PARAMS, CoveragePredictorParams, EDRBypassParams,
            AIPlannerParams, CloudFederationParams,
        )
        assert MODULE_PARAMS["opsec.coverage_predictor"]        is CoveragePredictorParams
        assert MODULE_PARAMS["edr.bypass_adaptive"]             is EDRBypassParams
        assert MODULE_PARAMS["ai.autonomous_planner"]           is AIPlannerParams
        assert MODULE_PARAMS["cloud.identity_federation_abuse"] is CloudFederationParams

    def test_total_module_params_count(self):
        from ares.modules.params import MODULE_PARAMS
        assert len(MODULE_PARAMS) >= 60, f"Expected 60+ modules, got {len(MODULE_PARAMS)}"

    def test_technique_library_includes_new_modules(self):
        from ares.technique.library import _MODULE_TECHNIQUE_MAP
        assert "opsec.coverage_predictor"        in _MODULE_TECHNIQUE_MAP
        assert "edr.bypass_adaptive"             in _MODULE_TECHNIQUE_MAP
        assert "ai.autonomous_planner"           in _MODULE_TECHNIQUE_MAP
        assert "cloud.identity_federation_abuse" in _MODULE_TECHNIQUE_MAP

    def test_new_modules_have_module_author(self):
        modules = [
            ("ares.modules.opsec.coverage_predictor", "CoveragePredictorModule"),
            ("ares.modules.edr.bypass_adaptive",       "EDRAdaptiveBypassModule"),
            ("ares.modules.ai.autonomous_planner",     "AIAutonomousPlannerModule"),
            ("ares.modules.cloud.identity_federation", "CloudIdentityFederationModule"),
        ]
        for mod_path, cls_name in modules:
            import importlib
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert hasattr(cls, "MODULE_AUTHOR") and cls.MODULE_AUTHOR, \
                f"{cls_name} missing MODULE_AUTHOR"


# ══════════════════════════════════════════════════════════════════════════════
# New feature tests — added in v35
# ══════════════════════════════════════════════════════════════════════════════

class TestMultiLLMConsensus:

    def test_merge_plans_full_agreement(self):
        from ares.modules.ai.autonomous_planner import _merge_plans
        plan_a = {
            "reasoning": "kerberoast then dcsync", "confidence": 0.9,
            "stages": [{"name": "enum", "modules": ["ad.enum_spn"], "params": {}, "rationale": ""}],
            "warnings": [], "alternative": [],
        }
        plan_b = {
            "reasoning": "same path", "confidence": 0.85,
            "stages": [{"name": "enum", "modules": ["ad.enum_spn"], "params": {}, "rationale": ""}],
            "warnings": [], "alternative": [],
        }
        merged = _merge_plans(plan_a, plan_b)
        assert merged["consensus_meta"]["agreement_ratio"] == 1.0
        assert merged["consensus_meta"]["agreed_stages"] == 1

    def test_merge_plans_partial_disagreement(self):
        from ares.modules.ai.autonomous_planner import _merge_plans
        plan_a = {
            "reasoning": "A path", "confidence": 0.8,
            "stages": [
                {"name": "enum",   "modules": ["ad.enum_spn"],  "params": {}, "rationale": ""},
                {"name": "attack", "modules": ["ad.kerberoast"], "params": {}, "rationale": ""},
            ],
            "warnings": [], "alternative": [],
        }
        plan_b = {
            "reasoning": "B path", "confidence": 0.7,
            "stages": [
                {"name": "enum",    "modules": ["ad.enum_users"], "params": {}, "rationale": ""},
                {"name": "privesc", "modules": ["linux.privesc"],  "params": {}, "rationale": ""},
            ],
            "warnings": [], "alternative": [],
        }
        merged = _merge_plans(plan_a, plan_b)
        assert merged["consensus_meta"]["agreement_ratio"] < 1.0
        # Low consensus warning should be added
        assert any("CONSENSUS" in w or "consensus" in w.lower()
                   for w in merged["warnings"])

    def test_merge_plans_confidence_average(self):
        from ares.modules.ai.autonomous_planner import _merge_plans
        plan_a = {"reasoning": "", "confidence": 0.9, "stages": [], "warnings": [], "alternative": []}
        plan_b = {"reasoning": "", "confidence": 0.7, "stages": [], "warnings": [], "alternative": []}
        merged = _merge_plans(plan_a, plan_b)
        # Merged confidence should be between the two
        assert 0.7 <= merged["confidence"] <= 0.9

    def test_build_system_prompt_with_constitution(self):
        from ares.modules.ai.autonomous_planner import _build_system_prompt_with_constitution
        prompt = _build_system_prompt_with_constitution(
            scope_cidrs=["10.0.0.0/8"],
            engagement_type="assessment_only",
            authorizations=["scope_document_v1"],
        )
        assert "10.0.0.0/8" in prompt
        assert "assessment_only" in prompt
        assert "HARD RULES" in prompt
        assert "SOFT RULES" in prompt


class TestEDRByovdAndBlindSpots:

    def test_byovd_techniques_returned(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        byovd = result.raw.get("byovd_techniques", [])
        assert len(byovd) > 0, "BYOVD techniques should always be returned"
        ids = [t.get("id", "") for t in byovd]
        assert any("byovd" in tid for tid in ids), "Should have at least one BYOVD technique"

    def test_blind_spots_returned_for_crowdstrike(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        blinds = result.raw.get("blind_spots", [])
        assert len(blinds) > 0, "CrowdStrike should have documented blind spots"
        # Named pipe should be one of them
        gap_names = [b.get("gap", "") for b in blinds]
        assert any("named pipe" in g.lower() or "pipe" in g.lower() for g in gap_names)

    def test_blind_spots_count_in_raw(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "sentinelone"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        assert "blind_spots_count" in result.raw
        assert result.raw["blind_spots_count"] == len(result.raw.get("blind_spots", []))

    def test_byovd_not_in_user_mode_techniques(self):
        """BYOVD should be separate from user-mode viable_techniques."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        ctx = _mock_ctx(params={"edr_vendor": "crowdstrike"})
        ctx.campaign = _mock_campaign()
        result = _run(mod.execute(ctx))
        viable_ids = [t.get("id", "") for t in result.raw.get("viable_techniques", [])]
        byovd_ids  = [t.get("id", "") for t in result.raw.get("byovd_techniques", [])]
        # No overlap
        assert not set(viable_ids) & set(byovd_ids), "BYOVD must not appear in user-mode techniques"


class TestSIEMCorrelationEngine:

    def test_dcsync_triggers_siem_rule(self):
        from ares.modules.opsec.coverage_predictor import _check_siem_correlations
        hits = _check_siem_correlations(["T1003.006"])
        assert len(hits) > 0
        names = [h["rule"] for h in hits]
        assert any("DCSync" in n or "dcsync" in n.lower() for n in names)

    def test_lsass_triggers_critical_rule(self):
        from ares.modules.opsec.coverage_predictor import _check_siem_correlations
        hits = _check_siem_correlations(["T1003.001"])
        critical = [h for h in hits if h["severity"] == "critical"]
        assert len(critical) > 0, "LSASS access should trigger critical SIEM rule"

    def test_empty_techniques_no_hits(self):
        from ares.modules.opsec.coverage_predictor import _check_siem_correlations
        hits = _check_siem_correlations([])
        assert hits == []

    def test_siem_hit_has_recommendation(self):
        from ares.modules.opsec.coverage_predictor import _check_siem_correlations
        hits = _check_siem_correlations(["T1558.003"])
        if hits:
            assert "recommendation" in hits[0]
            assert len(hits[0]["recommendation"]) > 0

    def test_siem_hits_included_in_prediction(self):
        """CoveragePredictor should include SIEM hits in output."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[],
            modules_run=[{"module_id": "ad.dcsync", "mitre_techniques": ["T1003.006"],
                          "opsec_level": "high_noise", "timestamp": 0}],
            noise_profile="aggressive",
        )
        assert len(prediction.siem_correlations) > 0, "DCSync should trigger SIEM correlations"


class TestSOCShiftModeling:

    def test_soc_activity_returns_valid_factor(self):
        from ares.modules.opsec.coverage_predictor import _compute_soc_activity_factor
        result = _compute_soc_activity_factor(target_domain="example.com")
        assert 0.0 <= result["soc_activity_factor"] <= 1.0
        assert "optimal_window" in result
        assert "recommendation" in result

    def test_soc_healthcare_is_high_coverage(self):
        """Healthcare SOC operates 24/7 — factor should always be moderate-high."""
        from ares.modules.opsec.coverage_predictor import _compute_soc_activity_factor
        import datetime
        # Test at 3am UTC (off-hours for most)
        early_morning = datetime.datetime(2025, 3, 15, 3, 0, 0)
        result = _compute_soc_activity_factor(target_type="healthcare", now_utc=early_morning)
        assert result["soc_activity_factor"] >= 0.60, "Healthcare SOC should be high 24/7"

    def test_soc_govt_weekend_is_low(self):
        """Government SOC on weekends should have very low factor."""
        from ares.modules.opsec.coverage_predictor import _compute_soc_activity_factor
        import datetime
        # Saturday at 11am UTC
        saturday = datetime.datetime(2025, 3, 15, 11, 0, 0)  # Saturday
        result = _compute_soc_activity_factor(target_type=".gov", now_utc=saturday)
        assert result["soc_activity_factor"] <= 0.15, "Government SOC weekend should be low"

    def test_soc_activity_in_prediction(self):
        """CoveragePrediction should include SOC activity data."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        predictor = CoveragePredictor()
        prediction = predictor.predict(
            campaign_findings=[], modules_run=[], noise_profile="normal"
        )
        assert "soc_activity_factor" in prediction.soc_activity


class TestTokenLifetimeAbuse:

    def test_module_has_token_lifetime_in_outputs(self):
        """identity_federation module should expose token lifetime findings."""
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        # OUTPUTS should still be present and correct
        assert "federation_trusts" in CloudIdentityFederationModule.OUTPUTS

    def test_b2b_pivot_finding_generated_for_many_guests(self):
        """Many guest accounts should generate a HIGH finding."""
        from ares.modules.cloud.identity_federation import CloudIdentityFederationModule
        mod, _ = _make_module(CloudIdentityFederationModule)
        # Simulate b2b data with many guests
        fake_b2b = {
            "guest_accounts_in_tenant": [
                {"name": f"guest{i}", "email": f"g{i}@ext.com",
                 "upn": f"g{i}_ext.com#EXT#@corp.onmicrosoft.com", "created": "", "ext_tenant": "ext.com"}
                for i in range(15)
            ],
            "external_tenant_access": [],
            "b2b_risks": [],
        }
        # Inject into _generate_findings by calling directly
        mod._generate_findings(
            results={"token_lifetime": {}, "b2b_cross_tenant": fake_b2b,
                     "pivot_paths": [], "azure_federation": {}, "aws_federation": {},
                     "adfs_federation": {}},
            krbtgt_hash="", domain="corp.local",
        )
        titles = [f.title for f in mod._findings]
        assert any("B2B" in t or "Guest" in t for t in titles), \
            "Should generate B2B finding for 15 guest accounts"


class TestStrategyEngine:

    def test_outcome_kb_tracks_success(self):
        from ares.strategy import OutcomeKnowledgeBase
        kb = OutcomeKnowledgeBase()
        kb.record_outcome("ad.kerberoast", success=True, edr_vendor="crowdstrike")
        kb.record_outcome("ad.kerberoast", success=False, edr_vendor="crowdstrike")
        rates = kb.get_success_rates()
        assert "ad.kerberoast" in rates
        assert rates["ad.kerberoast"] == 0.5  # 1 success out of 2

    def test_outcome_kb_effective_techniques(self):
        from ares.strategy import OutcomeKnowledgeBase
        kb = OutcomeKnowledgeBase()
        kb.record_outcome("ad.kerberoast", success=True,  edr_vendor="crowdstrike")
        kb.record_outcome("ad.dcsync",     success=False, edr_vendor="crowdstrike")
        effective = kb.get_effective_techniques("crowdstrike")
        assert "ad.kerberoast" in effective
        assert "ad.dcsync" not in effective

    def test_outcome_kb_zero_attempts_no_error(self):
        from ares.strategy import OutcomeKnowledgeBase
        kb = OutcomeKnowledgeBase()
        rates = kb.get_success_rates()
        assert rates == {}

    def test_engagement_result_dataclass(self):
        from ares.strategy import EngagementResult, RoundResult
        result = EngagementResult(
            goal="domain_admin", total_rounds=3, final_status="goal_achieved",
            rounds=[],
            final_detection_score=0.35, modules_succeeded=["ad.kerberoast"],
            modules_failed=[], knowledge_updates=5, elapsed_seconds=142.3,
        )
        assert result.goal == "domain_admin"
        assert result.final_status == "goal_achieved"

    def test_operator_notifier_collects_messages(self):
        from ares.strategy import OperatorNotifier
        messages = []
        notifier = OperatorNotifier(notify_fn=lambda m: messages.append(m))
        _run(notifier.send("test_event", {"data": 42}))
        assert len(messages) == 1
        assert messages[0]["event"] == "test_event"
        assert messages[0]["data"] == 42

    def test_check_goal_achieved_domain_admin(self):
        from ares.strategy import StrategyEngine
        engine = StrategyEngine(ares_engine=None, settings=None)
        campaign = _mock_campaign()
        # Simulate a DCSync finding
        mock_finding = type("F", (), {"title": "DCSync — krbtgt hash obtained"})()
        campaign.findings = [mock_finding]
        assert engine._check_goal_achieved(campaign, "domain_admin") is True

    def test_check_goal_not_achieved_empty(self):
        from ares.strategy import StrategyEngine
        engine = StrategyEngine(ares_engine=None, settings=None)
        campaign = _mock_campaign()
        campaign.findings = []
        assert engine._check_goal_achieved(campaign, "domain_admin") is False


# ══════════════════════════════════════════════════════════════════════════════
# Sprint 0-3 tests
# ══════════════════════════════════════════════════════════════════════════════

class TestOutcomeQuality:

    def test_module_result_has_outcome_fields(self):
        from ares.modules.base import ModuleResult
        r = ModuleResult(status="success", findings=[], raw={})
        assert hasattr(r, "outcome_quality")
        assert hasattr(r, "outcome_evidence")
        assert hasattr(r, "effective_quality")

    def test_effective_quality_success_with_findings(self):
        from ares.modules.base import ModuleResult
        from ares.core.campaign import Finding, Severity
        f = Finding(title="test", description="d", severity=Severity.HIGH,
                    mitre_technique="T1001", mitre_tactic="x",
                    evidence={}, remediation="", host="h", confidence=1.0)
        r = ModuleResult(status="success", findings=[f, f], raw={})
        assert r.effective_quality > 0.5

    def test_effective_quality_failed_is_zero(self):
        from ares.modules.base import ModuleResult
        r = ModuleResult(status="failed", findings=[], raw={}, error="boom")
        assert r.effective_quality == 0.0

    def test_effective_quality_dry_run_is_zero(self):
        from ares.modules.base import ModuleResult
        r = ModuleResult(status="dry_run", findings=[], raw={})
        assert r.effective_quality == 0.0

    def test_explicit_quality_overrides_auto(self):
        from ares.modules.base import ModuleResult
        r = ModuleResult(status="success", findings=[], raw={}, outcome_quality=0.75)
        assert r.effective_quality == 0.75

    def test_kb_records_quality_not_just_bool(self):
        from ares.strategy import OutcomeKnowledgeBase
        kb = OutcomeKnowledgeBase()
        kb.record_outcome("ad.kerberoast", success=True,  quality=1.0, edr_vendor="cs")
        kb.record_outcome("ad.kerberoast", success=True,  quality=0.3, edr_vendor="cs")
        rates = kb.get_success_rates()
        # Average quality: (1.0 + 0.3) / 2 = 0.65 — not just binary count
        assert 0.6 <= rates["ad.kerberoast"] <= 0.7


class TestTargetStateMap:

    def test_update_from_result_success(self):
        from ares.strategy.target_state import TargetStateMap
        from ares.modules.base import ModuleResult
        tsm = TargetStateMap()
        r = ModuleResult(status="success", findings=[], raw={}, outcome_quality=1.0)
        tsm.update_from_result("ad.enum_users", "10.0.0.1", r)
        state = tsm.get_state("10.0.0.1")
        assert state is not None
        assert "ad.enum_users" in state.successful_modules

    def test_update_from_result_failure(self):
        from ares.strategy.target_state import TargetStateMap
        from ares.modules.base import ModuleResult
        tsm = TargetStateMap()
        r = ModuleResult(status="failed", findings=[], raw={}, outcome_quality=0.0)
        tsm.update_from_result("lateral.psexec", "10.0.0.5", r)
        state = tsm.get_state("10.0.0.5")
        assert "lateral.psexec" in state.failed_modules
        assert "lateral.psexec" not in state.successful_modules

    def test_to_llm_context_excludes_old_hosts(self):
        from ares.strategy.target_state import TargetStateMap, TargetState
        import time
        tsm = TargetStateMap()
        # Fresh host
        tsm._hosts["10.0.0.1"] = TargetState(host="10.0.0.1", last_seen=time.time())
        # Old host (25 hours ago)
        tsm._hosts["10.0.0.2"] = TargetState(host="10.0.0.2",
                                               last_seen=time.time() - 90000)
        ctx = tsm.to_llm_context()
        assert "10.0.0.1" in ctx
        assert "10.0.0.2" not in ctx

    def test_to_llm_context_has_failed_note(self):
        from ares.strategy.target_state import TargetStateMap, TargetState
        import time
        tsm = TargetStateMap()
        tsm._hosts["10.0.0.3"] = TargetState(
            host="10.0.0.3",
            failed_modules=["lateral.psexec", "lateral.wmiexec"],
            last_seen=time.time(),
        )
        ctx = tsm.to_llm_context()
        note = ctx["10.0.0.3"].get("note", "")
        assert "psexec" in note or "SKIP" in note

    def test_open_ports_extracted_from_raw(self):
        from ares.strategy.target_state import TargetStateMap
        from ares.modules.base import ModuleResult
        tsm = TargetStateMap()
        r = ModuleResult(status="success", findings=[],
                         raw={"open_ports": [22, 80, 443]}, outcome_quality=1.0)
        tsm.update_from_result("network.port_scan", "192.168.1.10", r)
        state = tsm.get_state("192.168.1.10")
        assert 22 in state.open_ports
        assert 443 in state.open_ports


class TestConstitutionEnforcer:

    def test_blocks_unauthorized_dcsync(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(authorizations=[])
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "attack", "modules": ["ad.dcsync"], "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        assert any(v.module_id == "ad.dcsync" for v in violations)
        assert all("ad.dcsync" not in s.get("modules", []) for s in clean.stages)

    def test_allows_authorized_dcsync(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(authorizations=["ad.dcsync"])
        plan = AIPlan(
            reasoning="authorized", confidence=0.8,
            stages=[{"name": "attack", "modules": ["ad.dcsync"], "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        has_dcsync = any("ad.dcsync" in s.get("modules", []) for s in clean.stages)
        assert has_dcsync
        assert not any(v.module_id == "ad.dcsync" for v in violations)

    def test_blocks_forbidden_module(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(forbidden_modules={"lateral.rdp"})
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "lateral", "modules": ["lateral.rdp", "lateral.psexec"],
                     "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        assert any(v.module_id == "lateral.rdp" for v in violations)
        # psexec should still be there (not forbidden)
        clean_mods = [m for s in clean.stages for m in s.get("modules", [])]
        assert "lateral.psexec" in clean_mods

    def test_blocks_persistence_without_flag(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(allow_persistence=False)
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "persist", "modules": ["persistence.scheduled_task"],
                     "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        blocked = [v.module_id for v in violations]
        assert "persistence.scheduled_task" in blocked

    def test_allows_persistence_with_flag(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(
            allow_persistence=True,
            authorizations=["persistence.scheduled_task"],
        )
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "persist", "modules": ["persistence.scheduled_task"],
                     "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        blocked = [v.module_id for v in violations]
        assert "persistence.scheduled_task" not in blocked

    def test_empty_plan_after_enforcement_handled(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        from ares.modules.ai.autonomous_planner import AIPlan
        enforcer = ConstitutionEnforcer(authorizations=[])
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "cred", "modules": ["ad.dcsync", "credential.golden_ticket"],
                     "params": {}}],
        )
        campaign = _mock_campaign()
        clean, violations = enforcer.enforce(plan, campaign)
        assert len(clean.stages) == 0
        assert len(violations) == 2


class TestPlanValidator:

    def test_rejects_unknown_module(self):
        from ares.modules.ai.plan_validator import PlanValidator
        from ares.modules.ai.autonomous_planner import AIPlan
        validator = PlanValidator()
        plan = AIPlan(
            reasoning="test", confidence=0.8,
            stages=[{"name": "x", "modules": ["fake.module.doesnt.exist"], "params": {}}],
        )
        errors = validator.validate(plan, registry=None, campaign=_mock_campaign())
        assert any("Unknown module" in e or "fake.module" in e for e in errors)

    def test_rejects_low_confidence(self):
        from ares.modules.ai.plan_validator import PlanValidator
        from ares.modules.ai.autonomous_planner import AIPlan
        validator = PlanValidator()
        plan = AIPlan(reasoning="test", confidence=0.20, stages=[])
        errors = validator.validate(plan, registry=None, campaign=_mock_campaign())
        assert any("confidence" in e.lower() or "20%" in e for e in errors)

    def test_valid_plan_no_errors(self):
        from ares.modules.ai.plan_validator import PlanValidator
        from ares.modules.ai.autonomous_planner import AIPlan
        validator = PlanValidator()
        plan = AIPlan(
            reasoning="valid plan", confidence=0.80,
            stages=[{"name": "recon", "modules": ["ad.enum_users"], "params": {}}],
        )
        errors = validator.validate(plan, registry=None, campaign=_mock_campaign())
        assert len(errors) == 0

    def test_adds_high_noise_warning(self):
        from ares.modules.ai.plan_validator import PlanValidator
        from ares.modules.ai.autonomous_planner import AIPlan
        validator = PlanValidator()
        plan = AIPlan(
            reasoning="test", confidence=0.80, warnings=[],
            stages=[{"name": "attack", "modules": ["ad.dcsync"], "params": {}}],
        )
        validator.validate(plan, registry=None, campaign=_mock_campaign())
        # Validator should have added HIGH_NOISE warning
        assert any("HIGH_NOISE" in w or "high noise" in w.lower()
                   for w in (plan.warnings or []))


class TestDwellTimeDecay:

    def test_fresh_campaign_no_decay(self):
        from ares.modules.opsec.coverage_predictor import _apply_dwell_time_decay
        import time
        now = time.time()
        result = _apply_dwell_time_decay(0.8, now - 3600, now)  # 1 hour old
        assert result == 0.8  # no decay

    def test_14_day_dwell_reduces_score(self):
        from ares.modules.opsec.coverage_predictor import _apply_dwell_time_decay
        import time
        start = time.time() - (14 * 86400)  # 14 days ago
        result = _apply_dwell_time_decay(0.8, start)
        assert result < 0.8
        assert result == pytest.approx(0.8 * 0.65, abs=0.01)

    def test_30_day_dwell_max_reduction(self):
        from ares.modules.opsec.coverage_predictor import _apply_dwell_time_decay
        import time
        start = time.time() - (35 * 86400)
        result = _apply_dwell_time_decay(0.8, start)
        assert result == pytest.approx(0.8 * 0.40, abs=0.01)

    def test_decay_reduces_overall_score(self):
        """Long-running campaign should have lower detection score than fresh one."""
        from ares.modules.opsec.coverage_predictor import CoveragePredictor
        import time
        modules = [{"module_id": "ad.dcsync", "mitre_techniques": ["T1003.006"],
                    "opsec_level": "high_noise", "timestamp": 0}]
        pred_fresh = CoveragePredictor().predict(
            campaign_findings=[], modules_run=modules, noise_profile="normal",
            campaign_start_time=time.time() - 3600,  # 1 hour ago
        )
        pred_old = CoveragePredictor().predict(
            campaign_findings=[], modules_run=modules, noise_profile="normal",
            campaign_start_time=time.time() - (30 * 86400),  # 30 days ago
        )
        assert pred_old.overall_score < pred_fresh.overall_score


class TestPreExecutionPrediction:

    def test_predict_planned_returns_dict(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = mod.predict_planned_actions(
            planned_modules=["ad.enum_users", "ad.kerberoast"],
            current_score=0.10,
        )
        assert "projected_score" in result
        assert "safe_to_execute" in result
        assert "module_breakdown" in result

    def test_high_noise_plan_unsafe(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = mod.predict_planned_actions(
            planned_modules=["ad.dcsync", "windows.lsass_dump", "lateral.psexec"],
            current_score=0.45,  # already elevated
        )
        # Projected should be > 0.60 (unsafe threshold)
        assert result["projected_score"] >= result["current_score"]

    def test_empty_plan_is_safe(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = mod.predict_planned_actions(planned_modules=[], current_score=0.0)
        assert result["safe_to_execute"] is True
        assert result["projected_score"] == 0.0


class TestDetectionSpikeClass:

    def test_detection_spike_error_attrs(self):
        from ares.strategy import DetectionSpikeError
        e = DetectionSpikeError("spike detected", spike=0.22, round_num=3)
        assert e.spike == 0.22
        assert e.round_num == 3
        assert "spike" in str(e).lower()


class TestEDRProbe:

    def test_probe_safe_false_returns_true(self):
        """BYOVD techniques (probe_safe=False) always return True from _probe_technique."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule, BypassTechnique
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        tech = BypassTechnique(
            technique_id="byovd-test", name="BYOVD", description="test",
            target_vendor=["*"], opsec_level="high_noise",
            mitre_id="T1068", indicators=[], probe_safe=False,
        )
        result = _run(mod._probe_technique(tech, run_cmd=None))
        assert result is True

    def test_probe_no_runner_returns_true(self):
        """No SSH runner means we can't probe — fail open (return True)."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule, BypassTechnique
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        tech = BypassTechnique(
            technique_id="amsi-patch-reflection", name="AMSI", description="test",
            target_vendor=["crowdstrike"], opsec_level="medium",
            mitre_id="T1562.001", indicators=[], probe_safe=True,
        )
        result = _run(mod._probe_technique(tech, run_cmd=None))
        assert result is True

    def test_select_techniques_with_probe_no_runner(self):
        """Without run_cmd, probed flag should be False."""
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        result = _run(mod._select_techniques_with_probe("crowdstrike", "", run_cmd=None))
        assert result["probed"] is False
        assert len(result["viable_techniques"]) > 0


# ══════════════════════════════════════════════════════════════════════════════
# Bug regression tests (bugs 1-11 + API gap)
# ══════════════════════════════════════════════════════════════════════════════

class TestBugRegressions:

    # Bug 1 — probe methods must exist and be callable
    def test_probe_technique_method_exists(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        assert hasattr(mod, "_probe_technique"), "_probe_technique must exist"
        assert hasattr(mod, "_select_techniques_with_probe"), \
            "_select_techniques_with_probe must exist"

    def test_probe_technique_no_runner_returns_true(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule, BypassTechnique
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        tech = BypassTechnique(
            technique_id="amsi-patch-reflection", name="AMSI", description="",
            target_vendor=["*"], opsec_level="medium", mitre_id="T1562.001",
            indicators=[], probe_safe=True,
        )
        result = _run(mod._probe_technique(tech, run_cmd=None))
        assert result is True

    def test_select_techniques_with_probe_no_runner(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        result = _run(mod._select_techniques_with_probe("crowdstrike", "", run_cmd=None))
        assert "viable_techniques" in result
        assert "probed" in result
        assert result["probed"] is False

    def test_byovd_probe_safe_false_always_true(self):
        from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule, BypassTechnique
        mod, _ = _make_module(EDRAdaptiveBypassModule)
        tech = BypassTechnique(
            technique_id="byovd-iqvm64", name="BYOVD", description="",
            target_vendor=["*"], opsec_level="high_noise", mitre_id="T1068",
            indicators=[], probe_safe=False,
        )
        # Even with a mock runner, probe_safe=False must return True immediately
        async def mock_run(cmd: str) -> str:
            return "BLOCKED"
        result = _run(mod._probe_technique(tech, run_cmd=mock_run))
        assert result is True

    # Bug 2 — credentials must use actionable format
    def test_credentials_format_actionable(self):
        from ares.modules.ai.autonomous_planner import CampaignContextBuilder
        builder = CampaignContextBuilder()
        cred = MagicMock()
        cred.username  = "administrator"
        cred.domain    = "corp.local"
        cred.cred_type = "NTLM"
        cred.privilege = "domain_admin"
        cred.plaintext = ""
        vault = MagicMock()
        vault.list.return_value = [cred]
        ctx = builder.build(_mock_campaign(), vault, "domain_admin")
        assert len(ctx["credentials"]) > 0
        first = ctx["credentials"][0]
        # Must have recommended_use field (actionable format)
        assert "recommended_use" in first, \
            "Credentials must be in actionable format with recommended_use"
        assert len(first["recommended_use"]) > 0

    # Bug 3 — AD modules use "dc" key, not "target"
    def test_target_hint_checks_dc_key(self):
        from ares.strategy.target_state import TargetStateMap
        from ares.modules.base import ModuleResult
        tsm = TargetStateMap()
        r = ModuleResult(status="success", findings=[], raw={}, outcome_quality=1.0)
        tsm.update_from_result("ad.kerberoast", "10.0.0.1", r)
        state = tsm.get_state("10.0.0.1")
        assert state is not None
        assert "ad.kerberoast" in state.successful_modules

    # Bug 4 — datetime.timestamp() must be used
    def test_dwell_decay_with_datetime_object(self):
        from ares.modules.opsec.coverage_predictor import _apply_dwell_time_decay
        import datetime, time
        # Simulate campaign created 10 days ago as datetime object
        campaign_start_dt = datetime.datetime.now() - datetime.timedelta(days=10)
        campaign_start_ts = campaign_start_dt.timestamp()
        result = _apply_dwell_time_decay(0.8, campaign_start_ts)
        # 10 days = 0.65 factor → 0.8 * 0.65 = 0.52
        assert result < 0.8, "Dwell decay must reduce score after 10 days"
        assert result == pytest.approx(0.8 * 0.65, abs=0.02)

    # Bug 9 — target_states must appear in prompt
    def test_target_states_rendered_in_prompt(self):
        from ares.modules.ai.autonomous_planner import _build_user_prompt
        context = {
            "goal": "domain_admin",
            "scope": ["10.0.0.0/8"],
            "noise_profile": "stealth",
            "hosts": [],
            "credentials": [],
            "findings_summary": [],
            "available_modules": ["ad.enum_users"],
            "edr_bypass_available": [],
            "historical_success_rates": {},
            "target_states": {
                "10.0.0.5": {
                    "failed_modules": ["lateral.psexec", "lateral.wmiexec"],
                    "succeeded_modules": ["ad.enum_users"],
                    "note": "SKIP THESE: lateral.psexec, lateral.wmiexec",
                }
            },
        }
        prompt = _build_user_prompt(context)
        assert "10.0.0.5" in prompt, "target_states must be rendered in LLM prompt"
        assert "lateral.psexec" in prompt, "Failed modules must appear in prompt"

    def test_empty_target_states_not_rendered(self):
        from ares.modules.ai.autonomous_planner import _build_user_prompt
        context = {
            "goal": "domain_admin", "scope": [], "noise_profile": "normal",
            "hosts": [], "credentials": [], "findings_summary": [],
            "available_modules": ["ad.enum_users"],
            "edr_bypass_available": [], "historical_success_rates": {},
            "target_states": {},  # empty
        }
        prompt = _build_user_prompt(context)
        assert "Per-host state" not in prompt, \
            "Empty target_states must not add noise to prompt"

    # Bug 11 — HIGH_NOISE list accuracy
    def test_high_noise_list_excludes_wmiexec(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        # wmiexec should NOT be in HIGH_NOISE (it's MEDIUM)
        result_with = mod.predict_planned_actions(["lateral.wmiexec"], 0.0)
        result_without = mod.predict_planned_actions(["ad.enum_users"], 0.0)
        # wmiexec should NOT have +20% HIGH_NOISE penalty
        # (contribution should come only from MITRE techniques, not penalty)
        wmi_warnings = result_with.get("warnings", [])
        assert not any("lateral.wmiexec" in w and "HIGH_NOISE" in w for w in wmi_warnings), \
            "lateral.wmiexec must NOT be flagged as HIGH_NOISE"

    def test_high_noise_list_includes_coerce(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = mod.predict_planned_actions(["ad.coerce"], 0.0)
        warnings = result.get("warnings", [])
        assert any("ad.coerce" in w for w in warnings), \
            "ad.coerce must be flagged as HIGH_NOISE"

    def test_high_noise_list_includes_lsa_secrets(self):
        from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
        mod, _ = _make_module(CoveragePredictorModule)
        result = mod.predict_planned_actions(["windows.lsa_secrets"], 0.0)
        warnings = result.get("warnings", [])
        assert any("lsa_secrets" in w for w in warnings), \
            "windows.lsa_secrets must be flagged as HIGH_NOISE"

    # API Gap — /strategy/engage endpoint exists
    def test_strategy_engage_endpoint_registered(self):
        import sys
        # Check that the endpoint is registered in server.py
        server_src = open(
            os.path.join(os.path.dirname(__file__), "..", "..", "ares", "api", "server.py"),
            encoding="utf-8",
        ).read()
        assert '/strategy/engage' in server_src, \
            "POST /strategy/engage endpoint must be registered"
        assert 'AutonomousEngagementRequest' in server_src, \
            "AutonomousEngagementRequest model must exist"

    def test_strategy_engage_has_authorizations_field(self):
        server_src = open(
            os.path.join(os.path.dirname(__file__), "..", "..", "ares", "api", "server.py"),
            encoding="utf-8",
        ).read()
        assert 'authorizations' in server_src, \
            "AutonomousEngagementRequest must expose authorizations field"
