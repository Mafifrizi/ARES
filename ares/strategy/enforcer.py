"""
ares/strategy/enforcer.py — ConstitutionEnforcer

Hard Python-layer enforcement between LLM output and engine execution.
LLM prompt-based constitution can be ignored by hallucinating LLMs —
this layer CANNOT be bypassed by any prompt.

Removes violating modules from plan BEFORE it reaches engine.run_module().
Notifies operator of every removal with reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ares.core.logger import get_logger, audit

if TYPE_CHECKING:
    from ares.modules.ai.autonomous_planner import AIPlan
    from ares.core.campaign import Campaign

logger = get_logger("ares.strategy.enforcer")


# Modules that ALWAYS require explicit written authorization
# These cannot run in any engagement without operator explicitly listing them
ALWAYS_REQUIRE_AUTH: frozenset[str] = frozenset({
    "credential.golden_ticket",
    "ad.dcsync",
    "windows.lsass_dump",
    "persistence.wmi_subscription",
    "persistence.scheduled_task",
    "persistence.registry_run",
    "windows.lsass_dump",
    "edr.bypass_adaptive",
})

# Modules that are absolutely never allowed (data destructive / ransomware-adjacent)
ALWAYS_FORBIDDEN: frozenset[str] = frozenset({
    # Add any engagement-universal hard blocks here
    # Currently empty — per-engagement forbidden_modules handles this
})


@dataclass
class EnforcementViolation:
    module_id:  str
    stage_name: str
    reason:     str
    severity:   str  # "HARD" | "SOFT"


class ConstitutionEnforcer:
    """
    Hard-enforcement layer between LLM output and ARES engine.
    Runs AFTER LLM generates plan, BEFORE engine executes it.
    Cannot be bypassed by any LLM prompt.

    Usage:
        enforcer = ConstitutionEnforcer(
            authorizations=["ad.dcsync", "windows.lsass_dump"],
            forbidden_modules={"lateral.rdp"},  # per-engagement block
            max_exfil_mb=10,
        )
        clean_plan, violations = enforcer.enforce(ai_plan, campaign)
    """

    def __init__(
        self,
        authorizations:    list[str]  | None = None,
        forbidden_modules: set[str]   | None = None,
        max_exfil_mb:      int                = 10,
        allow_persistence: bool               = False,
        engagement_type:   str                = "assessment",
    ) -> None:
        self.authorizations    = set(authorizations or [])
        self.forbidden_modules = (forbidden_modules or set()) | ALWAYS_FORBIDDEN
        self.max_exfil_mb      = max_exfil_mb
        self.allow_persistence = allow_persistence
        self.engagement_type   = engagement_type

        # Persistence modules only allowed if explicitly authorized
        self._persistence_modules: frozenset[str] = frozenset({
            "persistence.wmi_subscription",
            "persistence.scheduled_task",
            "persistence.registry_run",
        })

    def enforce(
        self,
        plan:     "AIPlan",
        campaign: "Campaign",
    ) -> tuple["AIPlan", list[EnforcementViolation]]:
        """
        Enforce constitution rules on a plan.
        Removes violating modules from plan in-place.
        Returns (cleaned_plan, violations_list).
        """
        violations: list[EnforcementViolation] = []
        clean_stages = []

        for stage in plan.stages:
            stage_name  = stage.get("name", "unknown")
            raw_modules = stage.get("modules", [])
            clean_mods  = []

            for mid in raw_modules:

                # ── HARD: universally forbidden ───────────────────────────────
                if mid in self.forbidden_modules:
                    v = EnforcementViolation(
                        module_id=mid, stage_name=stage_name, severity="HARD",
                        reason=f"{mid} is forbidden for this engagement",
                    )
                    violations.append(v)
                    logger.warning("constitution_hard_block", module=mid,
                                   reason=v.reason)
                    continue

                # ── HARD: modules requiring explicit authorization ─────────────
                if mid in ALWAYS_REQUIRE_AUTH and mid not in self.authorizations:
                    v = EnforcementViolation(
                        module_id=mid, stage_name=stage_name, severity="HARD",
                        reason=(
                            f"{mid} requires explicit written authorization. "
                            "Add to ConstitutionEnforcer(authorizations=[...]) to allow."
                        ),
                    )
                    violations.append(v)
                    logger.warning("constitution_auth_required", module=mid)
                    continue

                # ── HARD: persistence without explicit flag ────────────────────
                if mid in self._persistence_modules and not self.allow_persistence:
                    if mid not in self.authorizations:
                        v = EnforcementViolation(
                            module_id=mid, stage_name=stage_name, severity="HARD",
                            reason=(
                                f"{mid} is a persistence module. "
                                "Set allow_persistence=True or add to authorizations."
                            ),
                        )
                        violations.append(v)
                        logger.warning("constitution_persistence_blocked", module=mid)
                        continue

                # ── HARD: target scope check ───────────────────────────────────
                params = stage.get("params", {})
                target = ""
                if isinstance(params, dict):
                    mod_params = params.get(mid, {})
                    if isinstance(mod_params, dict):
                        target = mod_params.get("target", "")
                    # Also check stage-level target
                    if not target:
                        target = params.get("target", "")

                if target and hasattr(campaign, "is_in_scope"):
                    if not campaign.is_in_scope(target):
                        v = EnforcementViolation(
                            module_id=mid, stage_name=stage_name, severity="HARD",
                            reason=(
                                f"{mid} target {target!r} is out of campaign scope. "
                                "LLM hallucinated out-of-scope target."
                            ),
                        )
                        violations.append(v)
                        logger.warning("constitution_out_of_scope",
                                       module=mid, target=target)
                        continue

                clean_mods.append(mid)

            if clean_mods:
                clean_stages.append({**stage, "modules": clean_mods})
            elif raw_modules:
                # All modules in stage were removed — log clearly
                logger.warning("constitution_stage_emptied",
                               stage=stage_name,
                               removed=raw_modules)

        plan.stages = clean_stages

        if violations:
            audit("constitution_enforcer_blocked", actor="system",
                  detail=f"{len(violations)} modules blocked by ConstitutionEnforcer")
            hard_count = sum(1 for v in violations if v.severity == "HARD")
            logger.info("constitution_enforcement_complete",
                        total_violations=len(violations),
                        hard_blocks=hard_count,
                        remaining_stages=len(clean_stages))

        return plan, violations

    def describe(self) -> dict:
        """Return human-readable enforcer configuration."""
        return {
            "authorized_modules":  sorted(self.authorizations),
            "forbidden_modules":   sorted(self.forbidden_modules),
            "always_require_auth": sorted(ALWAYS_REQUIRE_AUTH),
            "allow_persistence":   self.allow_persistence,
            "max_exfil_mb":        self.max_exfil_mb,
            "engagement_type":     self.engagement_type,
        }
