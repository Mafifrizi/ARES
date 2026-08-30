"""
ARES Goal-Based Attack Engine
Operator sets a goal. Engine determines the attack chain automatically.

Usage:
    engine = GoalEngine(registry, session, vault)
    plan = engine.plan(Goal.DOMAIN_ADMIN, context)
    results = await engine.execute(plan)

Goals:
  DOMAIN_ADMIN      — obtain domain admin credential
  ENTERPRISE_ADMIN  — obtain enterprise admin
  DATA_EXFIL        — find and access sensitive data stores
  CLOUD_ADMIN       — obtain cloud administrator access
  PERSISTENCE       — establish persistent access
  FULL_COMPROMISE   — achieve domain admin + cloud admin

Planning algorithm (backward chaining):
  1. Start from goal
  2. Find modules that produce what the goal requires
  3. Check what those modules require
  4. Recurse until all requirements met or unsatisfiable
  5. Topological sort → ExecutionPlan stages
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from ares.core.logger import get_logger
from ares.state.target_state import CompromiseLevel, OperatorSession

if TYPE_CHECKING:
    from ares.core.plugin.loader import ModuleRegistry
    from ares.credential.vault import CredentialVault

logger = get_logger("ares.goal")


class Goal(str, Enum):
    DOMAIN_ADMIN      = "domain_admin"
    ENTERPRISE_ADMIN  = "enterprise_admin"
    DATA_EXFIL        = "data_exfil"
    CLOUD_ADMIN       = "cloud_admin"
    PERSISTENCE       = "persistence"
    INITIAL_ACCESS    = "initial_access"
    FULL_COMPROMISE   = "full_compromise"


# ── Goal definitions ─────────────────────────────────────────────────────────

@dataclass
class GoalDefinition:
    goal:             Goal
    description:      str
    success_indicators: list[str]     # what must be true in session state
    required_outputs:   list[str]     # artifact outputs needed
    preferred_chain:    list[str]     # ordered module IDs (can be overridden)
    fallback_chains:    list[list[str]] = field(default_factory=list)
    mitre_objectives:   list[str] = field(default_factory=list)


GOAL_DEFINITIONS: dict[Goal, GoalDefinition] = {
    Goal.DOMAIN_ADMIN: GoalDefinition(
        goal=Goal.DOMAIN_ADMIN,
        description="Obtain Domain Admin credential or session",
        success_indicators=["domain_admin_cred", "dc_owned"],
        required_outputs=["domain_admin_creds"],
        preferred_chain=[
            "ad.enum_users",
            "ad.enum_spn",
            "ad.enum_acl",
            "ad.asreproast",
            "ad.kerberoast",
            "ad.dcsync",
        ],
        fallback_chains=[
            # ACL abuse path
            ["ad.enum_users", "ad.enum_acl", "ad.dcsync"],
            # AS-REP only
            ["ad.enum_users", "ad.asreproast"],
        ],
        mitre_objectives=["TA0006", "TA0008"],
    ),

    Goal.FULL_COMPROMISE: GoalDefinition(
        goal=Goal.FULL_COMPROMISE,
        description="Full compromise: domain admin + cloud admin + persistence",
        success_indicators=["domain_admin_cred", "cloud_admin_cred", "persistence_established"],
        required_outputs=["domain_admin_creds", "cloud_admin_access"],
        preferred_chain=[
            "ad.enum_users", "ad.enum_spn", "ad.enum_acl",
            "ad.kerberoast", "ad.asreproast", "ad.dcsync",
            "cloud.aws", "cloud.azure", "cloud.gcp",
            "linux.privesc", "linux.container",
        ],
        fallback_chains=[],
        mitre_objectives=["TA0006", "TA0008", "TA0003"],
    ),

    Goal.DATA_EXFIL: GoalDefinition(
        goal=Goal.DATA_EXFIL,
        description="Locate and access sensitive data (file shares, databases, secrets)",
        success_indicators=["sensitive_data_found"],
        required_outputs=["file_share_list", "credential_list"],
        preferred_chain=[
            "ad.enum_users",
            "ad.enum_computers",
            "ad.kerberoast",
            "credential.reuse",
            "exfil.smb_shares",
            "exfil.secrets_scan",
        ],
        fallback_chains=[],
        mitre_objectives=["TA0010", "TA0007"],
    ),

    Goal.PERSISTENCE: GoalDefinition(
        goal=Goal.PERSISTENCE,
        description="Establish persistent access that survives reboot and credential rotation",
        success_indicators=["persistence_established"],
        required_outputs=["persistence_established"],
        preferred_chain=[
            "persistence.scheduled_task",
            "persistence.registry_run",
        ],
        fallback_chains=[],
        mitre_objectives=["TA0003"],
    ),

    Goal.CLOUD_ADMIN: GoalDefinition(
        goal=Goal.CLOUD_ADMIN,
        description="Obtain cloud administrator access across AWS/Azure/GCP",
        success_indicators=["cloud_admin_cred"],
        required_outputs=["cloud_admin_access"],
        preferred_chain=["cloud.aws", "cloud.azure", "cloud.gcp"],
        fallback_chains=[],
        mitre_objectives=["TA0006"],
    ),

    Goal.INITIAL_ACCESS: GoalDefinition(
        goal=Goal.INITIAL_ACCESS,
        description="Establish initial foothold on target network",
        success_indicators=["initial_access_established"],
        required_outputs=["user_list", "host_list"],
        preferred_chain=["ad.enum_users", "ad.enum_computers"],
        fallback_chains=[],
        mitre_objectives=["TA0001"],
    ),
    Goal.ENTERPRISE_ADMIN: GoalDefinition(
        goal=Goal.ENTERPRISE_ADMIN,
        description="Obtain Enterprise Admin privileges across forest",
        success_indicators=["enterprise_admin_hash", "krbtgt_hash", "forest_trust_abuse"],
        required_outputs=["kerberos_hashes", "ntlm_hashes", "golden_ticket"],
        preferred_chain=[
            "ad.enum_users", "ad.enum_spn", "ad.enum_acl",
            "ad.kerberoast", "ad.adcs", "ad.delegation_abuse",
            "ad.dcsync", "credential.golden_ticket",
        ],
        fallback_chains=[
            ["ad.enum_users", "ad.asreproast", "credential.crack",
             "ad.dcsync", "credential.golden_ticket"],
        ],
        mitre_objectives=["TA0004", "TA0006", "TA0008"],
    ),
}


# ── Capability-based planning ─────────────────────────────────────────────────

class CapabilityGraph:
    """
    Maps module REQUIRES/OUTPUTS to build a capability dependency graph.

    This is what makes the goal system a real planner rather than a rule list:
      - Each module declares what capabilities it REQUIRES (inputs)
      - Each module declares what capabilities it OUTPUTS (produces)
      - Given a goal's required_outputs, we backward-chain through the graph
        to find which modules need to run and in which order.

    Example:
        goal: domain_admin  →  required: "domain_admin_creds"
        ad.dcsync    OUTPUTS ["ntlm_hashes", "domain_admin_creds"]
        ad.dcsync    REQUIRES ["domain_admin_creds"]  ← needs DA first
        ad.kerberoast OUTPUTS ["kerberos_hashes"]
        ...

        backward chain resolves: enum_users → enum_spn → kerberoast → dcsync

    Usage:
        cgraph = CapabilityGraph.from_registry(registry)
        chain  = cgraph.resolve_chain(goal_required_outputs=["domain_admin_creds"])
    """

    def __init__(self) -> None:
        # capability → list of module_ids that produce it
        self._producers: dict[str, list[str]] = {}
        # module_id → list of capabilities it requires
        self._requires:  dict[str, list[str]] = {}
        # module_id → list of capabilities it outputs
        self._outputs:   dict[str, list[str]] = {}

    @classmethod
    def from_registry(cls, registry: Any) -> "CapabilityGraph":
        """Build a CapabilityGraph from a loaded module registry."""
        cg = cls()
        for mod_cls in registry.all():
            mid      = getattr(mod_cls, "MODULE_ID", "")
            requires = getattr(mod_cls, "REQUIRES", []) or []
            outputs  = getattr(mod_cls, "OUTPUTS",  []) or []
            cg._requires[mid] = list(requires)
            cg._outputs[mid]  = list(outputs)
            for cap in outputs:
                cg._producers.setdefault(cap, []).append(mid)
        return cg

    def producers_for(self, capability: str) -> list[str]:
        """Return module IDs that produce a given capability."""
        return self._producers.get(capability, [])

    def resolve_chain(
        self,
        goal_required_outputs: list[str],
        available_modules:     list[str] | None = None,
        max_depth:             int = 8,
    ) -> list[str]:
        """
        Backward-chain from goal requirements to produce an ordered execution chain.

        Args:
            goal_required_outputs: capabilities the goal needs
            available_modules: restrict to this set (None = all)
            max_depth: prevent infinite recursion

        Returns:
            Ordered list of module IDs (topological order — safe to run sequentially).
        """
        resolved:  list[str] = []
        visited:   set[str]  = set()

        def _resolve(caps: list[str], depth: int) -> None:
            if depth > max_depth:
                return
            for cap in caps:
                for mid in self.producers_for(cap):
                    if mid in visited:
                        continue
                    if available_modules is not None and mid not in available_modules:
                        continue
                    visited.add(mid)
                    # Recurse: resolve what THIS module needs first
                    sub_requires = self._requires.get(mid, [])
                    _resolve(sub_requires, depth + 1)
                    resolved.append(mid)

        _resolve(goal_required_outputs, depth=0)

        # De-duplicate preserving order (last occurrence wins for dep ordering)
        seen: set[str] = set()
        ordered: list[str] = []
        for mid in reversed(resolved):
            if mid not in seen:
                seen.add(mid)
                ordered.insert(0, mid)
        return ordered

    def capability_summary(self) -> dict[str, Any]:
        """Return a summary of all capabilities and their producers."""
        return {
            "total_capabilities": len(self._producers),
            "total_modules":      len(self._requires),
            "capabilities":       {
                cap: mods for cap, mods in sorted(self._producers.items())
            },
        }


# ── Attack plan ───────────────────────────────────────────────────────────────

@dataclass
class GoalAttackStep:
    step_num:   int
    module_id:  str
    reason:     str
    params:     dict[str, Any] = field(default_factory=dict)
    optional:   bool = False
    depends_on: list[int] = field(default_factory=list)  # step numbers


@dataclass
class GoalAttackPlan:
    goal:         Goal
    definition:   GoalDefinition
    steps:        list[GoalAttackStep]
    context:      dict[str, Any] = field(default_factory=dict)
    created_at:   float = field(default_factory=time.time)
    estimated_duration_min: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "goal":       self.goal.value,
            "description": self.definition.description,
            "steps":      len(self.steps),
            "modules":    [s.module_id for s in self.steps],
            "mitre":      self.definition.mitre_objectives,
        }


# ── Goal Engine ───────────────────────────────────────────────────────────────

class GoalEngine:
    """
    Backward-chaining goal planner.
    Given a goal, produces a complete ExecutionPlan using
    available modules, current session state, and credential vault.

    Adapts the plan to:
      - Skip modules for already-compromised hosts
      - Prefer modules whose requirements are already satisfied
      - Add lateral movement steps if needed to reach target
      - Fall back to alternative chains if primary chain fails
    """

    def __init__(
        self,
        registry: "ModuleRegistry",
        session:  OperatorSession,
        vault:    "CredentialVault | None" = None,
    ) -> None:
        self.registry         = registry
        self.session          = session
        self.vault            = vault
        # Planning infrastructure stays dormant unless the private repository-
        # test planning seam invokes plan().  Production construction and
        # execute() do not call registry/plugin hooks.
        self._capability_graph: CapabilityGraph | None = None
        # Private test-only admission binding.  No production setting, request,
        # plugin, or environment variable can configure this seam while the
        # generation-11 descriptor catalog remains ineligible.
        self._c_live_test_coordinator: Any | None = None
        self._c_live_test_principal: Any | None = None
        self._c_live_test_parent_key: str | None = None
        self._c_live_test_planning_enabled = False

    def _configure_c_live_test_planning(self) -> None:
        """Enable the pure deterministic planner for repository tests only.

        Production settings, requests, plugins, and environment state have no
        route to this leading-underscore seam.  With production descriptors
        ineligible, public Goal planning therefore remains fail-closed.
        """
        self._c_live_test_planning_enabled = True

    def _configure_c_live_test_dispatch(
        self,
        *,
        coordinator: Any,
        principal: Any,
        idempotency_key: str,
    ) -> None:
        """Bind a coordinator to pure, deterministic Goal wiring tests only."""
        from ares.db.execution_lifecycle import TrustedPrincipal, valid_uuid

        if (
            not callable(getattr(coordinator, "execute_module", None))
            or type(principal) is not TrustedPrincipal
            or not valid_uuid(idempotency_key)
        ):
            raise ValueError("invalid C-LIVE Goal test dispatch binding")
        self._c_live_test_coordinator = coordinator
        self._c_live_test_principal = principal
        self._c_live_test_parent_key = idempotency_key

    def plan(
        self,
        goal:    "Goal | str",
        context: dict[str, Any] | None = None,
    ) -> "GoalAttackPlan":
        """
        Build an attack plan for the given goal.
        Context may include: dc, domain, targets, noise_profile, etc.
        """
        if not self._c_live_test_planning_enabled:
            raise PermissionError("C-LIVE Goal planning is non-dispatchable")
        context = context or {}
        # Coerce string → Goal enum
        if isinstance(goal, str):
            try:
                goal = Goal(goal)
            except ValueError:
                # Try by name
                try:
                    goal = Goal[goal.upper()]
                except KeyError:
                    raise ValueError(f"Unknown goal: {goal!r}")
        defn    = GOAL_DEFINITIONS.get(goal)
        if not defn:
            raise ValueError(f"Unknown goal: {goal.value}")

        logger.info("goal_plan_start", goal=goal.value, context_keys=list(context.keys()))

        if self._capability_graph is None:
            self._capability_graph = CapabilityGraph.from_registry(self.registry)

        # Choose chain: prefer primary, fall back if modules not available
        chain = self._select_chain(defn, context)
        steps = self._build_steps(chain, context, defn)

        plan = GoalAttackPlan(
            goal=goal, definition=defn, steps=steps, context=context,
            estimated_duration_min=len(steps) * 3,
        )

        logger.info(
            "goal_plan_ready",
            goal=goal.value,
            steps=len(steps),
            modules=[s.module_id for s in steps],
        )
        return plan

    def _select_chain(
        self,
        defn:    GoalDefinition,
        context: dict[str, Any],
    ) -> list[str]:
        """
        Select best execution chain for the goal.

        Priority:
          1. Primary chain (if all modules available)
          2. Capability-based dynamic chain (backward-chain from goal requirements)
          3. Fallback chains from GoalDefinition
          4. Best-effort: available modules from primary chain
        """
        # 1. Preferred chain — use if fully available
        if self._chain_feasible(defn.preferred_chain):
            return defn.preferred_chain

        # 2. Capability-based dynamic chain from REQUIRES/OUTPUTS
        available_mids = [getattr(cls, "MODULE_ID", "") for cls in self.registry.all()]
        if self._capability_graph is None:
            raise RuntimeError("goal capability graph was not initialized")
        dynamic_chain = self._capability_graph.resolve_chain(
            goal_required_outputs=defn.required_outputs,
            available_modules=available_mids,
        )
        if dynamic_chain:
            logger.info(
                "goal_using_capability_chain",
                goal=defn.goal.value,
                chain=dynamic_chain,
                required_outputs=defn.required_outputs,
            )
            return dynamic_chain

        # 3. Fallback chains defined in GoalDefinition
        for fallback in defn.fallback_chains:
            if self._chain_feasible(fallback):
                logger.info("goal_using_fallback_chain", modules=fallback)
                return fallback

        # 4. Best effort: available modules from primary chain
        available = [
            mid for mid in defn.preferred_chain
            if mid in self.registry
        ]
        if not available:
            logger.warning("goal_no_feasible_chain", goal=defn.goal.value)
        return available

    def _chain_feasible(self, chain: list[str]) -> bool:
        return all(mid in self.registry for mid in chain)

    def _build_steps(
        self,
        chain:   list[str],
        context: dict[str, Any],
        defn:    GoalDefinition,
    ) -> list[GoalAttackStep]:
        steps: list[GoalAttackStep] = []

        for i, module_id in enumerate(chain, start=1):
            cls = self.registry.get(module_id)
            reason = self._explain_step(module_id, defn, context)

            # Check if step should be skipped (already succeeded)
            if self.session.was_tried(module_id, context.get("dc", "")):
                logger.debug("goal_skip_already_tried", module=module_id)
                continue

            step = GoalAttackStep(
                step_num   = i,
                module_id  = module_id,
                reason     = reason,
                params     = self._build_params(module_id, context),
                optional   = getattr(cls, "OPSEC_LEVEL", None) is not None
                             and str(getattr(cls, "OPSEC_LEVEL", "")).endswith("HIGH_NOISE"),
                depends_on = [i - 1] if i > 1 else [],
            )
            steps.append(step)

        return steps

    def _build_params(self, module_id: str, context: dict[str, Any]) -> dict[str, Any]:
        """Extract relevant params from context for each module type."""
        base = {k: v for k, v in context.items()
                if k in ("dc", "domain", "username", "password", "target",
                         "targets", "noise_profile")}
        # Module-specific param enrichment
        if module_id.startswith("ad."):
            base.setdefault("dc", context.get("dc", ""))
            base.setdefault("domain", context.get("domain", ""))
        if module_id.startswith("cloud."):
            base.setdefault("region", context.get("region", "us-east-1"))
        return base

    def _explain_step(
        self,
        module_id: str,
        defn:      GoalDefinition,
        context:   dict[str, Any],
    ) -> str:
        explanations: dict[str, str] = {
            "ad.enum_users":     "Enumerate domain users to identify targets",
            "ad.enum_spn":       "Find kerberoastable SPN accounts",
            "ad.enum_acl":       "Check for dangerous ACL grants (WriteDACL, GenericAll)",
            "ad.kerberoast":     "Request TGS hashes for offline cracking",
            "ad.asreproast":     "Capture AS-REP hashes (no creds needed)",
            "ad.dcsync":         "DCSync NTDS hashes → all domain credentials",
            "ad.enum_computers": "Enumerate domain-joined computers",
            "cloud.aws":         "Enumerate AWS IAM, S3, security groups",
            "cloud.azure":       "Enumerate Azure AAD, storage, RBAC",
            "cloud.gcp":         "Enumerate GCP IAM, GCS, metadata server",
            "linux.privesc":     "Check local privilege escalation vectors",
            "linux.container":   "Check container escape opportunities",
            "lateral.psexec":    "Move laterally via SMB service execution",
            "lateral.wmiexec":   "Move laterally via WMI",
            "lateral.winrm":     "Move laterally via WinRM/PS-Remoting",
        }
        return explanations.get(module_id, f"Execute {module_id} toward goal: {defn.goal.value}")

    def check_goal_achieved(self, goal: Goal) -> bool:
        """Check if current session state satisfies the goal."""
        if goal in (Goal.DOMAIN_ADMIN, Goal.FULL_COMPROMISE, Goal.ENTERPRISE_ADMIN):
            return bool(self.session.domain_controllers() and
                        any(h.owned for h in self.session.domain_controllers()))
        if goal == Goal.INITIAL_ACCESS:
            # Any host with USER-level or above compromise counts as initial access
            from ares.state.target_state import CompromiseLevel
            return any(
                h.compromise_level >= CompromiseLevel.USER
                for h in self.session.all_hosts()
            )
        if goal == Goal.CLOUD_ADMIN:
            # Check for validated cloud credentials (API keys, JWTs, certificates)
            # — NOT domain_admins() which checks AD privilege level
            if self.vault is None:
                return False
            from ares.credential.vault import CredentialType
            cloud_cred_types = {
                CredentialType.API_KEY,
                CredentialType.JWT,
                CredentialType.CERTIFICATE,
            }
            return any(
                c.validated and c.cred_type in cloud_cred_types
                for c in self.vault.all()
            )
        return False

    async def execute(
        self,
        plan:     GoalAttackPlan,
        campaign: Any,
    ) -> dict[str, Any]:
        """Dispatch a completely frozen Goal plan through C-LIVE admission.

        The ordinary production constructor is intentionally non-dispatchable:
        C-LIVE-v1 wires safety but does not activate any descriptor.  Only the
        private deterministic test seam above can exercise this fan-out.
        """
        from ares.core.execution_admission import (
            DispatchDispositionV1,
            DispatchRequestV1,
            canonical_intent_digest,
        )

        def _fixed_non_dispatchable() -> dict[str, Any]:
            return {
                "goal": plan.goal.value,
                "achieved": False,
                "steps_run": 0,
                "duration_s": 0.0,
                "status": "non_dispatchable",
                "results": [],
                "session": {},
            }

        if (
            self._c_live_test_coordinator is None
            or self._c_live_test_principal is None
            or self._c_live_test_parent_key is None
            or getattr(campaign, "id", None) is None
        ):
            return _fixed_non_dispatchable()

        # Freeze every child, occurrence, ordinal, and parameter before any
        # admission can cross the effect boundary.  Appending or changing any
        # later child changes the digest bound into every admission receipt.
        occurrence_by_module: dict[str, int] = {}
        children: list[dict[str, Any]] = []
        for module_ordinal, step in enumerate(plan.steps):
            if (
                type(step) is not GoalAttackStep
                or type(step.module_id) is not str
                or not step.module_id
                or type(step.step_num) is not int
                or step.step_num < 1
                or step.step_num - 1 > 9_007_199_254_740_991
                or module_ordinal > 9_007_199_254_740_991
                or not isinstance(step.params, dict)
            ):
                return _fixed_non_dispatchable()
            occurrence = occurrence_by_module.get(step.module_id, 0)
            occurrence_by_module[step.module_id] = occurrence + 1
            children.append(
                {
                    "module_id": step.module_id,
                    "params": dict(step.params),
                    "occurrence": occurrence,
                    "stage_ordinal": module_ordinal,
                    "decision_ordinal": step.step_num - 1,
                    "module_ordinal": module_ordinal,
                }
            )
        if not children:
            return _fixed_non_dispatchable()
        try:
            # A JSON round trip is the deep-freeze boundary.  It severs every
            # caller-owned nested dict/list reference before the first await,
            # so a completed child cannot mutate a later child's bound bytes.
            frozen_intent = json.loads(
                json.dumps(
                    {
                        "goal": plan.goal.value,
                        "children": children,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
            if (
                type(frozen_intent) is not dict
                or type(frozen_intent.get("children")) is not list
            ):
                raise ValueError
            children = frozen_intent["children"]
            whole_intent_digest = canonical_intent_digest(frozen_intent)
        except (TypeError, ValueError, json.JSONDecodeError):
            return _fixed_non_dispatchable()

        t0 = time.monotonic()
        results: list[dict[str, Any]] = []
        status = "terminal"
        for child in children:
            dispatch_request = DispatchRequestV1(
                campaign_id=campaign.id,
                module_id=child["module_id"],
                ingress_code="goal_api",
                idempotency_key=self._c_live_test_parent_key,
                raw_parameters=child["params"],
                whole_intent_digest=whole_intent_digest,
                occurrence=child["occurrence"],
                stage_ordinal=child["stage_ordinal"],
                decision_ordinal=child["decision_ordinal"],
                module_ordinal=child["module_ordinal"],
            )
            outcome = await self._c_live_test_coordinator.execute_module(
                self._c_live_test_principal,
                dispatch_request,
                campaign,
            )
            identity = outcome.identity
            results.append(
                {
                    "module_id": child["module_id"],
                    "disposition": outcome.disposition.value,
                    "attempt_id": None if identity is None else identity.attempt_id,
                    "logical_execution_id": (
                        None if identity is None else identity.logical_execution_id
                    ),
                    "lifecycle_result": outcome.lifecycle_result.value,
                    "terminal_committed": bool(outcome.terminal_committed),
                }
            )
            if outcome.disposition not in {
                DispatchDispositionV1.TERMINAL,
                DispatchDispositionV1.REPLAYED,
            }:
                status = outcome.disposition.value
                break

        return {
            "goal": plan.goal.value,
            "achieved": self.check_goal_achieved(plan.goal) if status == "terminal" else False,
            "steps_run": len(results),
            "duration_s": round(time.monotonic() - t0, 2),
            "status": status,
            "results": results,
            "session": self.session.stats(),
        }
