"""
ares.strategy.engine — Autonomous Engagement Strategy Engine

Orchestrates strategic modules in a continuous adaptive engagement loop.
Extracted from strategy/__init__.py for maintainability.

See strategy/models.py for data models, strategy/knowledge_base.py for
outcome tracking, and strategy/notifier.py for operator notifications.
"""
from __future__ import annotations

import asyncio
import time
import json
from typing import Any

from ares.core.logger import get_logger, audit
from ares.strategy.models import (
    ModuleOutcome, RoundResult, EngagementResult, DetectionSpikeError,
)
from ares.strategy.knowledge_base import OutcomeKnowledgeBase
from ares.strategy.notifier import OperatorNotifier
from ares.strategy.target_state import TargetStateMap
from ares.strategy.enforcer import ConstitutionEnforcer

logger = get_logger("ares.strategy.engine")


class StrategyEngine:
    """
    Orchestrates all 4 strategic modules in an adaptive engagement loop.

    Each round:
      1. Check detection probability — stop if too hot
      2. Gather EDR context for bypass planning
      3. AI re-plans with full accumulated context
      4. Execute plan with bypass techniques applied
      5. Record outcomes → KnowledgeBase learns
      6. Check if goal achieved

    The engine is designed to be interruptible:
      - max_detection_probability guard prevents uncontrolled noise
      - confidence_threshold prevents executing uncertain plans
      - max_rounds provides absolute iteration limit
    """

    def __init__(
        self,
        ares_engine:      "Any",     # AresEngine instance
        settings:         "Any",     # AresSettings
        notifier:         OperatorNotifier | None = None,
    ) -> None:
        self._engine       = ares_engine
        self._settings     = settings
        self._notifier     = notifier or OperatorNotifier()
        self._kb           = OutcomeKnowledgeBase()
        self._target_state = TargetStateMap()

    async def run_autonomous_engagement(
        self,
        campaign:                   "Any",
        goal:                       str   = "domain_admin",
        max_rounds:                 int   = 10,
        max_detection_probability:  float = 0.60,
        confidence_threshold:       float = 0.50,
        llm_backend:                str   = "claude",
        secondary_backend:          str   = "",   # for consensus mode
        adversarial_sim:            bool  = False,
        actor_role:                 str   = "operator",
        authorizations:             list  | None = None,   # modules needing auth
        forbidden_modules:          set   | None = None,
        allow_persistence:          bool  = False,
    ) -> EngagementResult:
        """
        Run an autonomous multi-round red team engagement.

        Args:
            campaign:                   Active ARES campaign object
            goal:                       Target objective (domain_admin, etc.)
            max_rounds:                 Hard limit on engagement rounds
            max_detection_probability:  Stop if coverage predictor exceeds this
            confidence_threshold:       Stop if AI plan confidence below this
            llm_backend:                Primary LLM backend (claude/openai/local)
            secondary_backend:          Secondary for consensus mode (optional)
            adversarial_sim:            Run blue-team simulation after each plan
            actor_role:                 RBAC role for module execution
        """
        start_time   = time.monotonic()
        rounds:       list[RoundResult] = []
        succeeded:    list[str] = []
        failed:       list[str] = []
        final_status  = "max_rounds"

        audit("strategy_engine_start", actor="operator",
              detail=f"goal={goal} max_rounds={max_rounds} max_detect={max_detection_probability}")
        logger.info("strategy_engine_start", goal=goal, max_rounds=max_rounds,
                    llm_backend=llm_backend, consensus=bool(secondary_backend))

        for round_num in range(1, max_rounds + 1):
            logger.info("strategy_round_start", round=round_num, goal=goal)

            # ── Step 1: Detection risk check ─────────────────────────────────
            coverage = await self._run_coverage_predictor(campaign)
            det_score = coverage.get("detection_score", 0.0)

            if det_score > max_detection_probability:
                wait_hrs = coverage.get("wait_recommendation", {}).get("hours", 0)
                msg = (
                    f"Round {round_num}: Detection score {det_score:.0%} exceeds "
                    f"threshold {max_detection_probability:.0%}. "
                    f"Recommended pause: {wait_hrs}h"
                )
                logger.warning("strategy_detection_threshold", score=det_score, round=round_num)
                await self._notifier.send("detection_threshold_exceeded", {
                    "round": round_num, "score": det_score,
                    "threshold": max_detection_probability, "wait_hours": wait_hrs,
                    "message": msg,
                })
                rounds.append(RoundResult(
                    round_num=round_num, plan_confidence=0.0,
                    detection_score=det_score, modules_executed=[],
                    outcomes=[], stopped_reason=msg,
                ))
                final_status = "detection_threshold"
                break

            # ── Step 2: EDR context ───────────────────────────────────────────
            edr_context = await self._get_edr_context(campaign)

            # Build reusable extra_context dict for planner calls this round
            round_extra_context = {
                "detection_probability":    det_score,
                "edr_bypass_available":     edr_context.get("viable_techniques", [])[:5],
                "historical_success_rates": self._kb.get_success_rates(),
                "rounds_completed":         round_num - 1,
                "target_states":            self._target_state.to_llm_context(),
                "effective_vs_edr":         self._kb.get_effective_techniques(
                    edr_context.get("edr_vendor", "unknown")
                ),
            }

            # ── Step 3: AI re-plan with full accumulated context ──────────────
            plan_result = await self._run_ai_planner(
                campaign=campaign,
                goal=goal,
                llm_backend=llm_backend,
                secondary_backend=secondary_backend,
                adversarial_sim=adversarial_sim,
                extra_context=round_extra_context,
            )

            plan_confidence = plan_result.get("confidence_score", 0.0)
            exec_plan       = plan_result.get("execution_plan", [])

            if plan_confidence < confidence_threshold:
                msg = (
                    f"Round {round_num}: AI plan confidence {plan_confidence:.0%} "
                    f"below threshold {confidence_threshold:.0%}. "
                    f"Reasoning: {plan_result.get('ai_reasoning', '')[:150]}"
                )
                logger.warning("strategy_low_confidence", confidence=plan_confidence, round=round_num)
                await self._notifier.send("low_confidence_plan", {
                    "round": round_num, "confidence": plan_confidence, "message": msg,
                    "warnings": plan_result.get("warnings", []),
                })
                rounds.append(RoundResult(
                    round_num=round_num, plan_confidence=plan_confidence,
                    detection_score=det_score, modules_executed=[],
                    outcomes=[], stopped_reason=msg,
                ))
                final_status = "low_confidence"
                break

            # ── ConstitutionEnforcer — Python-layer safety, cannot be bypassed ─
            # Build AIPlan object from raw planner output for enforcer
            from ares.modules.ai.autonomous_planner import AIPlan
            ai_plan = AIPlan(
                reasoning=plan_result.get("ai_reasoning", ""),
                stages=exec_plan if isinstance(exec_plan, list) else [],
                confidence=plan_confidence,
                warnings=plan_result.get("warnings", []),
            )
            enforcer = ConstitutionEnforcer(
                authorizations=authorizations,
                forbidden_modules=forbidden_modules,
                allow_persistence=allow_persistence,
            )
            ai_plan, violations = enforcer.enforce(ai_plan, campaign)
            if violations:
                await self._notifier.send("constitution_violations", {
                    "round":      round_num,
                    "violations": [
                        {"module": v.module_id, "reason": v.reason, "severity": v.severity}
                        for v in violations
                    ],
                    "note": "These modules were removed by ConstitutionEnforcer before execution",
                })
            if not ai_plan.stages:
                logger.warning("constitution_all_stages_emptied", round=round_num)
                rounds.append(RoundResult(
                    round_num=round_num, plan_confidence=plan_confidence,
                    detection_score=det_score, modules_executed=[],
                    outcomes=[], stopped_reason="ConstitutionEnforcer removed all modules",
                ))
                final_status = "constitution_blocked"
                break
            # Re-extract exec_plan after enforcer may have modified it
            exec_plan = [
                {"name": s.get("name",""), "modules": s.get("modules",[]),
                 "params": s.get("params",{})}
                for s in ai_plan.stages
            ]

            # Notify operator — plan ready for review
            await self._notifier.send("plan_ready", {
                "round":          round_num,
                "confidence":     plan_confidence,
                "stages":         len(exec_plan),
                "modules":        [m for s in exec_plan for m in s.get("modules", [])],
                "warnings":       plan_result.get("warnings", []),
                "adversarial_sim": plan_result.get("adversarial_sim", {}),
            })

            # ── Step 3.5: Pre-execution detection risk prediction ────────────
            try:
                from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
                from ares.core.noise import NoiseController
                predictor_mod = CoveragePredictorModule(
                    settings=self._settings, campaign=campaign,
                    noise=NoiseController(campaign),
                )
                planned_mids = [m for s in exec_plan for m in s.get("modules", [])]
                projection = predictor_mod.predict_planned_actions(
                    planned_modules=planned_mids,
                    current_score=det_score,
                    campaign=campaign,
                )
                logger.info("pre_exec_projection",
                            round=round_num,
                            projected=projection["projected_score"],
                            safe=projection["safe_to_execute"])
                if not projection["safe_to_execute"]:
                    await self._notifier.send("projected_detection_too_high", {
                        "round": round_num, "projection": projection,
                    })
                    # Request stealth replan instead of stopping immediately
                    logger.warning("pre_exec_replan_requested",
                                   round=round_num,
                                   projected=projection["projected_score"])
                    replan_result = await self._run_ai_planner(
                        campaign=campaign, goal=goal,
                        llm_backend=llm_backend,
                        secondary_backend=secondary_backend,
                        adversarial_sim=False,
                        extra_context={
                            **round_extra_context,
                            "rejected_plan_reason": (
                                f"Plan rejected: projected detection "
                                f"{projection['projected_score']:.0%} — too high. "
                                "Use STEALTH techniques only. "
                                "Avoid HIGH_NOISE modules. "
                                f"Flagged modules: "
                                f"{[b['module'] for b in projection['module_breakdown'][:3]]}"
                            ),
                        },
                    )
                    replan_conf  = replan_result.get("confidence_score", 0.0)
                    replan_plan  = replan_result.get("execution_plan", [])
                    if replan_conf >= confidence_threshold and replan_plan:
                        # Accept revised plan — re-enforce and re-check projection
                        ai_plan.stages = replan_plan
                        ai_plan, _ = enforcer.enforce(ai_plan, campaign)
                        exec_plan = [
                            {"name": s.get("name",""), "modules": s.get("modules",[]),
                             "params": s.get("params",{})}
                            for s in ai_plan.stages
                        ]
                        logger.info("pre_exec_replan_accepted",
                                    round=round_num, confidence=replan_conf)
                    else:
                        # Replan also failed — stop this round
                        logger.warning("pre_exec_replan_failed",
                                       round=round_num, confidence=replan_conf)
                        rounds.append(RoundResult(
                            round_num=round_num, plan_confidence=plan_confidence,
                            detection_score=det_score, modules_executed=[],
                            outcomes=[],
                            stopped_reason=f"Pre-exec blocked and replan failed "
                                           f"(projected: {projection['projected_score']:.0%})",
                        ))
                        final_status = "pre_exec_blocked"
                        break
            except Exception as pe_exc:
                logger.debug("pre_exec_prediction_failed", error=str(pe_exc)[:80])

            # ── Step 4: Execute plan stages ───────────────────────────────────
            round_outcomes: list[ModuleOutcome] = []
            all_modules_this_round: list[str]   = []
            bypass_tech = edr_context.get("recommended_approach", {}) or {}
            bypass_name = bypass_tech.get("id", "") if isinstance(bypass_tech, dict) else ""
            edr_vendor  = edr_context.get("edr_vendor", "unknown")

            for stage in exec_plan:
                stage_modules = stage.get("modules", [])
                stage_params  = stage.get("params", {})

                logger.info("strategy_stage_execute",
                            round=round_num, stage=stage.get("name"),
                            modules=stage_modules)

                # Run modules in parallel within stage
                stage_tasks = [
                    self._run_single_module(
                        module_id=mid,
                        campaign=campaign,
                        params={**self._build_base_params(campaign), **stage_params.get(mid, {})},  # LLM params override base
                        actor_role=actor_role,
                    )
                    for mid in stage_modules
                ]
                stage_results = await asyncio.gather(*stage_tasks, return_exceptions=True)

                for mid, result in zip(stage_modules, stage_results):
                    all_modules_this_round.append(mid)
                    if isinstance(result, Exception):
                        success = False
                        findings_count = 0
                        logger.warning("strategy_module_error", module=mid,
                                       error=str(result)[:100])
                    else:
                        success       = getattr(result, "status", "") in ("success", "partial")
                        findings_count = len(getattr(result, "findings", []))

                    quality = getattr(result, "effective_quality", 0.5 if success else 0.0)
                    evidence = getattr(result, "outcome_evidence", "")
                    outcome = ModuleOutcome(
                        module_id=mid, success=quality >= 0.5,
                        quality=quality, evidence=evidence,
                        edr_vendor=edr_vendor, bypass_used=bypass_name,
                        findings_count=findings_count,
                    )
                    round_outcomes.append(outcome)
                    self._kb.record_outcome(
                        mid, success=quality >= 0.5, quality=quality,
                        evidence=evidence, edr_vendor=edr_vendor, bypass_used=bypass_name
                    )
                    # Persist bypass outcome to DB for cross-session learning
                    if bypass_name and self._engine and hasattr(self._engine, "_db"):
                        _db_ref = getattr(self._engine, "_db", None)
                        if _db_ref and hasattr(_db_ref, "save_bypass_outcome"):
                            try:
                                import asyncio as _aio
                                _aio.ensure_future(_db_ref.save_bypass_outcome(
                                    technique_id=bypass_name,
                                    edr_vendor=edr_vendor,
                                    edr_version="",
                                    success=quality >= 0.5,
                                    campaign_id=getattr(campaign, "id", ""),
                                    notes=evidence[:200] if evidence else "",
                                ))
                            except Exception:
                                pass  # DB persistence is best-effort
                    # Update per-host state memory
                    # AD modules use "dc" key, Linux use "host", others use "target"
                    _mp = stage_params.get(mid, {}) if isinstance(stage_params, dict) else {}
                    target_hint = (
                        _mp.get("target") or _mp.get("dc") or _mp.get("host") or
                        stage_params.get("target") or stage_params.get("dc") or
                        stage_params.get("host", "")
                    )
                    if target_hint and not isinstance(result, Exception):
                        self._target_state.update_from_result(mid, target_hint, result)

                    if success:
                        succeeded.append(mid)
                    else:
                        failed.append(mid)

            # ── Step 4.5: Detection spike rollback ──────────────────────────────
            coverage_after = await self._run_coverage_predictor(campaign)
            det_after      = coverage_after.get("detection_score", 0.0)
            spike          = det_after - det_score

            if spike > 0.15:  # >15% rise in one round = danger
                msg = (
                    f"DETECTION SPIKE: +{spike:.0%} in round {round_num}. "
                    f"Score: {det_score:.0%} → {det_after:.0%}. "
                    "Engagement paused. Manual operator review required."
                )
                logger.critical("detection_spike",
                                spike=spike, round=round_num,
                                before=det_score, after=det_after)
                await self._notifier.send("detection_spike", {
                    "round":        round_num,
                    "spike":        round(spike, 3),
                    "score_before": det_score,
                    "score_after":  det_after,
                    "message":      msg,
                    "safe_actions": [
                        "Do not run any modules for 24+ hours",
                        "Review artifacts from this round for IOCs",
                        "Consider cleaning up persistence if any was established",
                        "Operator manual review required before continuing",
                    ],
                })
                rounds.append(RoundResult(
                    round_num=round_num, plan_confidence=plan_confidence,
                    detection_score=det_after, modules_executed=all_modules_this_round,
                    outcomes=round_outcomes, stopped_reason=msg,
                ))
                final_status = "detection_spike"
                break

            # ── Step 5: Check goal achieved ───────────────────────────────────
            goal_achieved = self._check_goal_achieved(campaign, goal)

            round_result = RoundResult(
                round_num=round_num, plan_confidence=plan_confidence,
                detection_score=det_score, modules_executed=all_modules_this_round,
                outcomes=round_outcomes, goal_achieved=goal_achieved,
                stopped_reason="" if not goal_achieved else "goal_achieved",
            )
            rounds.append(round_result)

            logger.info("strategy_round_complete",
                        round=round_num, modules=len(all_modules_this_round),
                        successes=sum(1 for o in round_outcomes if o.success),
                        goal_achieved=goal_achieved)

            await self._notifier.send("round_complete", {
                "round":          round_num,
                "modules_run":    all_modules_this_round,
                "successes":      sum(1 for o in round_outcomes if o.success),
                "detection_score": det_score,
                "goal_achieved":  goal_achieved,
            })

            if goal_achieved:
                final_status = "goal_achieved"
                logger.info("strategy_goal_achieved", goal=goal, rounds=round_num)
                await self._notifier.send("goal_achieved", {
                    "goal": goal, "rounds_needed": round_num,
                    "total_findings": sum(o.findings_count for r in rounds for o in r.outcomes),
                })
                break

        elapsed = time.monotonic() - start_time
        audit("strategy_engine_complete", actor="operator",
              detail=f"status={final_status} rounds={len(rounds)} elapsed={elapsed:.1f}s")

        return EngagementResult(
            goal=goal,
            total_rounds=len(rounds),
            final_status=final_status,
            rounds=rounds,
            final_detection_score=rounds[-1].detection_score if rounds else 0.0,
            modules_succeeded=list(dict.fromkeys(succeeded)),
            modules_failed=list(dict.fromkeys(failed)),
            knowledge_updates=sum(
                len(r.outcomes) for r in rounds
            ),
            elapsed_seconds=elapsed,
        )

    async def _run_coverage_predictor(self, campaign: "Any") -> dict:
        """Run opsec.coverage_predictor and return raw results."""
        try:
            from ares.modules.opsec.coverage_predictor import CoveragePredictorModule
            from ares.core.noise import NoiseController
            mod = CoveragePredictorModule(
                settings=self._settings, campaign=campaign,
                noise=NoiseController(campaign),
            )
            findings, raw = await mod.run(campaign=campaign)
            return raw
        except Exception as exc:
            logger.warning("coverage_predictor_failed", error=str(exc)[:100])
            return {"detection_score": 0.0, "wait_recommendation": {"hours": 0, "reason": "predictor unavailable"}}

    async def _get_edr_context(self, campaign: "Any") -> dict:
        """Get EDR bypass context from artifact store or return defaults."""
        try:
            from ares.modules.edr.bypass_adaptive import EDRAdaptiveBypassModule
            from ares.core.noise import NoiseController
            # Try to detect EDR vendor from fingerprint artifacts
            edr_vendor = "unknown"
            store = getattr(campaign, "_artifact_store", None)
            if store:
                for art in getattr(store, "_artifacts", []):
                    if hasattr(art, "edr_vendors") and art.edr_vendors:
                        edr_vendor = art.edr_vendors[0].value
                        break
            mod = EDRAdaptiveBypassModule(
                settings=self._settings, campaign=campaign,
                noise=NoiseController(campaign),
            )
            findings, raw = await mod.run(edr_vendor=edr_vendor)
            raw["edr_vendor"] = edr_vendor
            return raw
        except Exception as exc:
            logger.warning("edr_context_failed", error=str(exc)[:100])
            return {"edr_vendor": "unknown", "viable_techniques": [], "recommended_approach": None}

    async def _run_ai_planner(
        self, campaign: "Any", goal: str,
        llm_backend: str, secondary_backend: str,
        adversarial_sim: bool, extra_context: dict,
    ) -> dict:
        """Run ai.autonomous_planner and return raw results."""
        try:
            from ares.modules.ai.autonomous_planner import AIAutonomousPlannerModule
            from ares.core.noise import NoiseController
            mod = AIAutonomousPlannerModule(
                settings=self._settings, campaign=campaign,
                noise=NoiseController(campaign),
            )
            # Build context manually with extra data
            from ares.modules.ai.autonomous_planner import CampaignContextBuilder, _build_user_prompt
            builder = CampaignContextBuilder()
            ctx = builder.build(campaign, vault=None, goal=goal)
            ctx.update(extra_context)
            findings, raw = await mod.run(
                campaign=campaign, goal=goal,
                llm_backend=llm_backend,
                secondary_backend=secondary_backend,
                adversarial_sim=adversarial_sim,
                extra_context=extra_context,
            )
            return raw
        except Exception as exc:
            logger.warning("ai_planner_failed", error=str(exc)[:100])
            return {"confidence_score": 0.0, "execution_plan": [], "warnings": [str(exc)[:100]]}

    async def _run_single_module(
        self, module_id: str, campaign: "Any",
        params: dict, actor_role: str,
    ) -> "Any":
        """Execute a single module via AresEngine."""
        try:
            result = await self._engine.run_module(
                module_id=module_id,
                campaign=campaign,
                params=params,
                actor_role=actor_role,
                timeout_seconds=120,
            )
            return result
        except Exception as exc:
            logger.warning("strategy_module_run_error",
                           module=module_id, error=str(exc)[:100])
            raise

    def _build_base_params(self, campaign: "Any") -> dict:
        """
        Return base params that all modules inherit — intentionally minimal.
        DO NOT set "target" here: CIDR network address (e.g. 10.0.0.0) is not
        a valid scan target. LLM stage_params must specify the actual host.
        If LLM omits target, the module will fail with a validation error
        rather than silently scan the wrong IP.
        """
        params: dict = {}
        # Only inject non-target params that are safe to default
        noise = getattr(campaign, "noise_profile", None)
        if noise:
            params["noise_profile"] = str(noise)
        return params


    async def generate_engagement_report(
        self,
        result:      "EngagementResult",
        campaign:    Any,
        llm_backend: str = "claude",
    ) -> str:
        """
        Generate executive red team report from EngagementResult via LLM.
        Returns markdown ready to paste into engagement report.

        Includes:
          1. Executive Summary (3 sentences, business language)
          2. Attack Chain Timeline (bullet per round)
          3. Key Findings with Business Impact
          4. Priority Recommendations (Critical/High/Medium)
          5. Detection Risk Score
        """
        from ares.modules.ai.autonomous_planner import ClaudeBackend, OpenAIBackend

        summary = {
            "goal":              result.goal,
            "final_status":      result.final_status,
            "total_rounds":      result.total_rounds,
            "elapsed_hours":     round(result.elapsed_seconds / 3600, 1),
            "modules_succeeded": result.modules_succeeded,
            "modules_failed":    result.modules_failed,
            "final_detection":   f"{result.final_detection_score:.0%}",
            "total_findings":    sum(
                o.findings_count for r in result.rounds for o in r.outcomes
            ),
            "knowledge_updates": result.knowledge_updates,
            "rounds_detail": [
                {
                    "round":       r.round_num,
                    "confidence":  r.plan_confidence,
                    "detection":   r.detection_score,
                    "modules":     r.modules_executed,
                    "successes":   sum(1 for o in r.outcomes if o.success),
                    "stopped":     r.stopped_reason or "completed",
                    "outcomes":    [
                        {"module": o.module_id, "quality": getattr(o, "quality", 0),
                         "evidence": getattr(o, "evidence", "")}
                        for o in r.outcomes
                    ],
                }
                for r in result.rounds
            ],
        }

        REPORT_SYSTEM = (
            "You are a professional red team report writer. "
            "Write clear, concise, business-focused reports. "
            "Use markdown formatting. "
            "Be specific about what was found and what business risk it represents. "
            "Avoid technical jargon in the Executive Summary."
        )
        REPORT_USER = (
            "Generate an executive red team engagement report from this data.\n\n"
            "Include these sections:\n"
            "## Executive Summary\n"
            "3 sentences max. Business language. What was achieved, what was the risk level.\n\n"
            "## Attack Chain Timeline\n"
            "Bullet per round showing what happened.\n\n"
            "## Key Findings\n"
            "Top 5 findings with business impact per finding.\n\n"
            "## Priority Recommendations\n"
            "Critical, High, Medium buckets.\n\n"
            "## Detection Risk\n"
            "Final detection probability and what it means.\n\n"
            f"Data:\n{json.dumps(summary, indent=2)}"
        )

        try:
            import json
            backend_map = {
                "claude": lambda: ClaudeBackend(),
                "openai": lambda: OpenAIBackend(),
            }
            backend = backend_map.get(llm_backend, backend_map["claude"])()
            report_result = await backend.generate_plan(REPORT_SYSTEM, REPORT_USER)
            return report_result.get("content", "Report generation failed.")
        except Exception as exc:
            logger.warning("report_generation_failed", error=str(exc)[:100])
            # Fallback: generate simple text report
            lines = [
                "# ARES Red Team Engagement Report",
                "",
                f"**Goal:** {result.goal}",
                f"**Status:** {result.final_status}",
                f"**Rounds:** {result.total_rounds}",
                f"**Duration:** {result.elapsed_seconds/3600:.1f}h",
                f"**Detection Score:** {result.final_detection_score:.0%}",
                "",
                "## Modules Succeeded",
                *[f"- {m}" for m in result.modules_succeeded],
                "",
                "## Modules Failed",
                *[f"- {m}" for m in result.modules_failed],
                "",
                f"*(LLM report failed: {str(exc)[:80]})*",
            ]
            return "\n".join(lines)

    def _check_goal_achieved(self, campaign: "Any", goal: str) -> bool:
        """Check if the engagement goal has been achieved via campaign artifacts."""
        findings = getattr(campaign, "findings", [])
        goal_indicators = {
            "domain_admin":     ["DCSync", "Domain Admin", "krbtgt", "ntlm_hash"],
            "cloud_admin":      ["Global Admin", "AWS Admin", "Storage Admin", "GCP Owner"],
            "data_exfil":       ["Sensitive File", "credential_list", "sensitive_data"],
            "persistence":      ["Scheduled Task Created", "WMI Subscription", "Registry Run"],
            "full_compromise":  ["DCSync", "Global Admin"],
        }
        indicators = goal_indicators.get(goal, [])
        if not indicators:
            return False

        for finding in findings:
            title = (getattr(finding, "title", "") or
                     (finding.get("title", "") if isinstance(finding, dict) else ""))
            if any(ind.lower() in title.lower() for ind in indicators):
                return True
        return False

