"""
Step 2 — Unit Tests: Strategy Engine

Tests for the autonomous engagement orchestration layer:
  - ModuleOutcome / RoundResult / EngagementResult (models)
  - OutcomeKnowledgeBase (learning, success rates, per-vendor tracking)
  - OperatorNotifier (message collection, callback dispatch)
  - ConstitutionEnforcer (module blocking, scope check, authorization)
  - StrategyEngine._check_goal_achieved (goal detection logic)

All tests use mock dependencies — no real LLM, network, or module execution.

Run: pytest tests/unit/test_strategy_engine.py -v
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass

import pytest

_ROOT = Path(__file__).parent.parent.parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Data Models
# ═══════════════════════════════════════════════════════════════════════════════

class TestModels:
    """Test strategy data model construction and defaults."""

    def test_module_outcome_defaults(self):
        from ares.strategy.models import ModuleOutcome
        o = ModuleOutcome(module_id="ad.kerberoast", success=True)
        assert o.module_id == "ad.kerberoast"
        assert o.success is True
        assert o.quality == 0.0
        assert o.edr_vendor == "unknown"
        assert o.findings_count == 0
        assert o.timestamp > 0

    def test_module_outcome_full(self):
        from ares.strategy.models import ModuleOutcome
        o = ModuleOutcome(
            module_id="ad.dcsync", success=True, quality=0.95,
            evidence="krbtgt hash", edr_vendor="crowdstrike",
            bypass_used="amsi-patch", findings_count=3,
        )
        assert o.quality == 0.95
        assert o.edr_vendor == "crowdstrike"
        assert o.bypass_used == "amsi-patch"

    def test_round_result_defaults(self):
        from ares.strategy.models import RoundResult
        r = RoundResult(
            round_num=1, plan_confidence=0.85,
            detection_score=0.3, modules_executed=["ad.kerberoast"],
            outcomes=[],
        )
        assert r.goal_achieved is False
        assert r.stopped_reason == ""

    def test_engagement_result(self):
        from ares.strategy.models import EngagementResult
        e = EngagementResult(
            goal="domain_admin", total_rounds=5, final_status="goal_achieved",
            rounds=[], final_detection_score=0.45,
            modules_succeeded=["ad.kerberoast", "ad.dcsync"],
            modules_failed=["ad.adcs"],
            knowledge_updates=12, elapsed_seconds=300.5,
        )
        assert e.total_rounds == 5
        assert len(e.modules_succeeded) == 2

    def test_detection_spike_error(self):
        from ares.strategy.models import DetectionSpikeError
        exc = DetectionSpikeError("Spike detected", spike=0.25, round_num=3)
        assert exc.spike == 0.25
        assert exc.round_num == 3
        assert "Spike" in str(exc)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. OutcomeKnowledgeBase
# ═══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeBase:
    """Test per-session learning and success rate tracking."""

    @pytest.fixture
    def kb(self):
        from ares.strategy.knowledge_base import OutcomeKnowledgeBase
        return OutcomeKnowledgeBase()

    def test_empty_kb_returns_empty_rates(self, kb):
        rates = kb.get_success_rates()
        assert rates == {}

    def test_single_success_recorded(self, kb):
        kb.record_outcome("ad.kerberoast", success=True, quality=1.0)
        rates = kb.get_success_rates()
        assert "ad.kerberoast" in rates
        assert rates["ad.kerberoast"] == 1.0

    def test_mixed_outcomes_rate(self, kb):
        kb.record_outcome("ad.kerberoast", success=True, quality=1.0)
        kb.record_outcome("ad.kerberoast", success=False, quality=0.0)
        kb.record_outcome("ad.kerberoast", success=True, quality=0.8)
        rates = kb.get_success_rates()
        # total_quality = 1.0 + 0.0 + 0.8 = 1.8 / 3 attempts = 0.6
        assert abs(rates["ad.kerberoast"] - 0.6) < 0.01

    def test_per_vendor_tracking(self, kb):
        kb.record_outcome("amsi-patch", success=True, edr_vendor="crowdstrike")
        kb.record_outcome("amsi-patch", success=False, edr_vendor="defender")
        kb.record_outcome("amsi-patch", success=True, edr_vendor="crowdstrike")

        effective_cs = kb.get_effective_techniques("crowdstrike")
        effective_def = kb.get_effective_techniques("defender")
        assert "amsi-patch" in effective_cs
        assert "amsi-patch" not in effective_def

    def test_get_effective_unknown_vendor(self, kb):
        kb.record_outcome("mod1", success=True, edr_vendor="sentinelone")
        result = kb.get_effective_techniques("nonexistent")
        assert result == []

    def test_bypass_technique_tracking(self, kb):
        kb.record_outcome("ad.dcsync", success=True, bypass_used="amsi-patch",
                          edr_vendor="crowdstrike")
        kb.record_outcome("ad.dcsync", success=True, bypass_used="etw-blind",
                          edr_vendor="crowdstrike")
        key = ("ad.dcsync", "crowdstrike")
        assert "amsi-patch" in kb._rates[key]["bypass_techniques"]
        assert "etw-blind" in kb._rates[key]["bypass_techniques"]

    def test_multiple_modules_independent(self, kb):
        kb.record_outcome("mod_a", success=True, quality=1.0)
        kb.record_outcome("mod_b", success=False, quality=0.0)
        rates = kb.get_success_rates()
        assert rates["mod_a"] == 1.0
        assert rates["mod_b"] == 0.0

    def test_quality_weighted_rate(self, kb):
        """Quality weighting should affect the rate."""
        kb.record_outcome("mod", success=True, quality=0.5)
        kb.record_outcome("mod", success=True, quality=0.5)
        rates = kb.get_success_rates()
        # total_quality=1.0, attempts=2 → 0.5
        assert rates["mod"] == 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# 3. OperatorNotifier
# ═══════════════════════════════════════════════════════════════════════════════

class TestNotifier:
    """Test notification collection and callback dispatch."""

    @pytest.mark.asyncio
    async def test_messages_collected(self):
        from ares.strategy.notifier import OperatorNotifier
        n = OperatorNotifier()
        await n.send("plan_ready", {"round": 1, "confidence": 0.9})
        await n.send("detection_threshold_exceeded", {"score": 0.7})
        assert len(n.messages) == 2
        assert n.messages[0]["event"] == "plan_ready"
        assert n.messages[1]["event"] == "detection_threshold_exceeded"

    @pytest.mark.asyncio
    async def test_callback_invoked(self):
        from ares.strategy.notifier import OperatorNotifier
        received = []
        n = OperatorNotifier(notify_fn=lambda msg: received.append(msg))
        await n.send("test_event", {"data": 123})
        assert len(received) == 1
        assert received[0]["event"] == "test_event"
        assert received[0]["data"] == 123

    @pytest.mark.asyncio
    async def test_async_callback(self):
        from ares.strategy.notifier import OperatorNotifier
        received = []
        async def callback(msg):
            received.append(msg)
        n = OperatorNotifier(notify_fn=callback)
        await n.send("async_test", {"value": "ok"})
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_callback_exception_does_not_crash(self):
        from ares.strategy.notifier import OperatorNotifier
        def bad_callback(msg):
            raise RuntimeError("callback exploded")
        n = OperatorNotifier(notify_fn=bad_callback)
        await n.send("test", {})  # must not raise
        assert len(n.messages) == 1  # message still collected

    @pytest.mark.asyncio
    async def test_timestamp_present(self):
        from ares.strategy.notifier import OperatorNotifier
        n = OperatorNotifier()
        await n.send("test", {})
        assert "ts" in n.messages[0]
        assert n.messages[0]["ts"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ConstitutionEnforcer
# ═══════════════════════════════════════════════════════════════════════════════

class TestConstitutionEnforcer:
    """Test hard enforcement layer between LLM output and module execution."""

    def _make_plan(self, stages):
        """Build a mock AIPlan."""
        @dataclass
        class FakePlan:
            reasoning: str = "test"
            stages: list = None
            confidence: float = 0.9
            warnings: list = None
            def __post_init__(self):
                if self.stages is None:
                    self.stages = []
                if self.warnings is None:
                    self.warnings = []
        return FakePlan(stages=stages)

    def _make_campaign(self, scope_cidr="10.0.0.0/8"):
        from ares.core.campaign import Campaign, ScopeEntry, NoiseProfile
        return Campaign(
            name="Test", scope=[ScopeEntry(cidr=scope_cidr)],
            noise_profile=NoiseProfile.NORMAL,
        )

    def test_clean_plan_passes_through(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(
            authorizations=["ad.kerberoast"],
        )
        plan = self._make_plan([
            {"name": "recon", "modules": ["ad.kerberoast", "ad.enum_users"]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) == 0
        assert len(cleaned.stages) == 1
        assert "ad.kerberoast" in cleaned.stages[0]["modules"]

    def test_forbidden_module_removed(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(
            forbidden_modules={"ad.dcsync"},
        )
        plan = self._make_plan([
            {"name": "attack", "modules": ["ad.kerberoast", "ad.dcsync"]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) == 1
        assert violations[0].module_id == "ad.dcsync"
        assert violations[0].severity == "HARD"
        assert "ad.dcsync" not in cleaned.stages[0]["modules"]
        assert "ad.kerberoast" in cleaned.stages[0]["modules"]

    def test_unauthorized_high_risk_module_blocked(self):
        from ares.strategy.enforcer import ConstitutionEnforcer, ALWAYS_REQUIRE_AUTH
        enforcer = ConstitutionEnforcer(authorizations=[])
        # Pick a module from ALWAYS_REQUIRE_AUTH
        auth_module = sorted(ALWAYS_REQUIRE_AUTH)[0]
        plan = self._make_plan([
            {"name": "escalate", "modules": [auth_module]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) >= 1
        assert any(v.module_id == auth_module for v in violations)

    def test_authorized_high_risk_module_passes(self):
        from ares.strategy.enforcer import ConstitutionEnforcer, ALWAYS_REQUIRE_AUTH
        auth_module = sorted(ALWAYS_REQUIRE_AUTH)[0]
        enforcer = ConstitutionEnforcer(
            authorizations=[auth_module],
        )
        plan = self._make_plan([
            {"name": "escalate", "modules": [auth_module]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) == 0
        assert auth_module in cleaned.stages[0]["modules"]

    def test_out_of_scope_target_blocked(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer()
        plan = self._make_plan([
            {"name": "lateral", "modules": ["lateral.smb_relay"],
             "params": {"lateral.smb_relay": {"target": "192.168.1.1"}}},
        ])
        campaign = self._make_campaign("10.0.0.0/8")
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) >= 1
        assert any("out of campaign scope" in v.reason for v in violations)

    def test_in_scope_target_passes(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer()
        plan = self._make_plan([
            {"name": "lateral", "modules": ["lateral.smb_relay"],
             "params": {"lateral.smb_relay": {"target": "10.0.0.5"}}},
        ])
        campaign = self._make_campaign("10.0.0.0/8")
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) == 0

    def test_persistence_blocked_without_flag(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(allow_persistence=False)
        plan = self._make_plan([
            {"name": "persist", "modules": ["persistence.scheduled_task"]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) >= 1
        assert any("persistence" in v.reason.lower() for v in violations)

    def test_persistence_allowed_with_flag(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(
            allow_persistence=True,
            authorizations=["persistence.scheduled_task"],
        )
        plan = self._make_plan([
            {"name": "persist", "modules": ["persistence.scheduled_task"]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(violations) == 0

    def test_all_modules_removed_yields_empty_stages(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(
            forbidden_modules={"mod_a", "mod_b"},
        )
        plan = self._make_plan([
            {"name": "attack", "modules": ["mod_a", "mod_b"]},
        ])
        campaign = self._make_campaign()
        cleaned, violations = enforcer.enforce(plan, campaign)
        assert len(cleaned.stages) == 0
        assert len(violations) == 2

    def test_describe_returns_config(self):
        from ares.strategy.enforcer import ConstitutionEnforcer
        enforcer = ConstitutionEnforcer(
            authorizations=["ad.dcsync"],
            forbidden_modules={"evil.module"},
        )
        desc = enforcer.describe()
        assert "ad.dcsync" in desc["authorized_modules"]
        assert "evil.module" in desc["forbidden_modules"]


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Goal Achievement Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestGoalAchieved:
    """Test _check_goal_achieved logic with mock campaigns."""

    def _make_engine(self):
        from ares.strategy.engine import StrategyEngine
        mock_ares = MagicMock()
        mock_settings = MagicMock()
        return StrategyEngine(ares_engine=mock_ares, settings=mock_settings)

    def _make_campaign_with_findings(self, titles):
        campaign = MagicMock()
        findings = []
        for t in titles:
            f = MagicMock()
            f.title = t
            findings.append(f)
        campaign.findings = findings
        return campaign

    def test_domain_admin_achieved_via_dcsync(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([
            "Port Scan Complete",
            "DCSync Attack Successful — krbtgt hash obtained",
        ])
        assert engine._check_goal_achieved(campaign, "domain_admin") is True

    def test_domain_admin_not_achieved(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([
            "Port Scan Complete",
            "Kerberoast: 3 hashes captured",
        ])
        assert engine._check_goal_achieved(campaign, "domain_admin") is False

    def test_cloud_admin_achieved(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([
            "AWS Admin Role Assumed",
        ])
        assert engine._check_goal_achieved(campaign, "cloud_admin") is True

    def test_data_exfil_achieved(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([
            "Sensitive File Found: credentials.xlsx",
        ])
        assert engine._check_goal_achieved(campaign, "data_exfil") is True

    def test_unknown_goal_returns_false(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings(["DCSync"])
        assert engine._check_goal_achieved(campaign, "nonexistent_goal") is False

    def test_empty_findings_returns_false(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([])
        assert engine._check_goal_achieved(campaign, "domain_admin") is False

    def test_case_insensitive_matching(self):
        engine = self._make_engine()
        campaign = self._make_campaign_with_findings([
            "dcsync attack completed",  # lowercase
        ])
        assert engine._check_goal_achieved(campaign, "domain_admin") is True

    def test_dict_findings_supported(self):
        """_check_goal_achieved should handle dict findings (from DB)."""
        engine = self._make_engine()
        campaign = MagicMock()
        campaign.findings = [
            {"title": "DCSync Attack — Domain Admin Achieved"},
        ]
        assert engine._check_goal_achieved(campaign, "domain_admin") is True


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Strategy Module Re-exports
# ═══════════════════════════════════════════════════════════════════════════════

class TestReExports:
    """Verify strategy/__init__.py re-exports all public symbols."""

    def test_all_exports_importable(self):
        from ares.strategy import (
            StrategyEngine,
            ModuleOutcome,
            RoundResult,
            EngagementResult,
            DetectionSpikeError,
            OutcomeKnowledgeBase,
            OperatorNotifier,
        )
        assert StrategyEngine is not None
        assert ModuleOutcome is not None
        assert RoundResult is not None
        assert EngagementResult is not None
        assert DetectionSpikeError is not None
        assert OutcomeKnowledgeBase is not None
        assert OperatorNotifier is not None
