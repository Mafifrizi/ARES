"""
ares/modules/ai/plan_validator.py — LLM Plan Validator

Validates AI-generated attack plans before execution:
  1. All module IDs must exist in registry
  2. Params must pass Pydantic schema validation
  3. HIGH_NOISE modules must have warnings
  4. Stages must not be empty
  5. Confidence must meet minimum threshold

Prevents engine crashes from LLM hallucinations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ares.core.logger import get_logger

if TYPE_CHECKING:
    from ares.modules.ai.autonomous_planner import AIPlan
    from ares.core.campaign import Campaign

logger = get_logger("ares.modules.ai.plan_validator")

_MIN_CONFIDENCE = 0.40


class PlanValidator:
    """
    Validates an AIPlan before it reaches engine.run_module().
    Returns list of error strings — empty = plan is valid.
    """

    def validate(
        self,
        plan:     "AIPlan",
        registry: Any,
        campaign: "Campaign",
    ) -> list[str]:
        errors: list[str] = []

        if plan.confidence < _MIN_CONFIDENCE:
            errors.append(
                f"Confidence {plan.confidence:.0%} below minimum {_MIN_CONFIDENCE:.0%} — "
                "plan too uncertain to execute safely."
            )

        if not plan.stages:
            errors.append("Plan has no stages — LLM returned empty plan.")
            return errors  # Nothing else to check

        for stage in plan.stages:
            stage_name = stage.get("name", "unknown")
            mods       = stage.get("modules", [])
            params     = stage.get("params", {})

            if not mods:
                errors.append(f"Stage '{stage_name}' has no modules.")
                continue

            for mid in mods:
                # 1. Module must exist in registry
                if registry is not None:
                    cls = (registry.get(mid) if hasattr(registry, "get")
                           else registry._modules.get(mid) if hasattr(registry, "_modules")
                           else None)
                    if not cls:
                        errors.append(
                            f"Unknown module: '{mid}' (stage: {stage_name}) — "
                            "not in registry. LLM hallucinated module ID."
                        )
                        continue
                else:
                    # No registry available — check technique library as fallback
                    try:
                        from ares.technique.library import _MODULE_TECHNIQUE_MAP
                        if mid not in _MODULE_TECHNIQUE_MAP:
                            errors.append(
                                f"Unknown module: '{mid}' — not in technique library."
                            )
                            continue
                    except ImportError:
                        pass

                # 2. Params must pass Pydantic schema
                mod_params = {}
                if isinstance(params, dict):
                    mod_params = params.get(mid, {}) or {}
                    if not isinstance(mod_params, dict):
                        mod_params = {}

                if mod_params:
                    try:
                        from ares.modules.params import validate_module_params, MODULE_PARAMS
                        if mid in MODULE_PARAMS:
                            validate_module_params(mid, mod_params)
                    except Exception as e:
                        errors.append(
                            f"'{mid}' params invalid (stage: {stage_name}): {str(e)[:120]}"
                        )

                # 3. HIGH_NOISE modules must be warned about
                try:
                    from ares.modules.base import OpsecLevel
                    from ares.technique.library import _MODULE_TECHNIQUE_MAP
                    if mid in _MODULE_TECHNIQUE_MAP:
                        # Check for known HIGH_NOISE modules
                        _HIGH_NOISE = {
                            "ad.dcsync", "lateral.psexec", "lateral.rdp",
                            "windows.lsass_dump", "lateral.wmiexec",
                            "edr.bypass_adaptive",
                        }
                        if mid in _HIGH_NOISE:
                            has_warning = any(
                                mid in w or "HIGH_NOISE" in w or "high noise" in w.lower()
                                for w in (plan.warnings or [])
                            )
                            if not has_warning:
                                # Add warning automatically rather than failing
                                if plan.warnings is None:
                                    plan.warnings = []
                                plan.warnings.append(
                                    f"{mid} is HIGH_NOISE — will generate significant IOCs. "
                                    "Verify SOC shift timing before executing."
                                )
                except Exception:
                    pass

        return errors
