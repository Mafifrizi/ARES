"""
ARES Attack AI Planner
Automatically selects the best next technique based on:
  - Current session state (owned hosts, available credentials)
  - Attack graph connectivity (what's reachable)
  - Knowledge base scoring (what's historically effective)
  - Artifact correlation opportunities (what combos create attack paths)
  - MITRE ATT&CK technique relationships (what follows what)
  - OpSec profile (what's allowed in current noise level)

This is ARES's signature differentiator vs. Metasploit/Sliver:
  Active reasoning about the best next step, not just listing modules.

Algorithm:
  1. Score all candidate modules against current context
  2. Filter by: scope, opsec profile, prerequisites, already-tried
  3. Rank by: opportunity score × confidence × opsec cost
  4. Return ordered recommendations with rationale

Scoring factors (each 0.0–1.0):
  prereq_met       — all REQUIRES already satisfied in session
  credential_match — vault has creds matching required privilege
  host_reachable   — target host is in scope and accessible
  technique_value  — MITRE technique effectiveness for this goal
  kb_score         — knowledge base historical success rate
  artifact_match   — artifact correlator found specific opportunity
  novelty          — haven't tried this module yet on this target

Usage:
    planner = AttackPlanner(registry, session, vault, kb)
    suggestions = planner.suggest(
        goal=Goal.DOMAIN_ADMIN,
        targets=["10.0.0.1"],
        limit=5,
    )
    for s in suggestions:
        print(f"{s.module_id} → {s.rationale} (score={s.score:.2f})")
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ares.core.logger import get_logger
from ares.goal.engine import Goal

if TYPE_CHECKING:
    from ares.core.plugin.loader import ModuleRegistry
    from ares.state.target_state import OperatorSession
    from ares.credential.vault import CredentialVault
    from ares.knowledge.base import AttackKnowledgeBase

logger = get_logger("ares.goal.planner")


# ── PlanSuggestion data ────────────────────────────────────────────────────────────

@dataclass
class PlanSuggestion:
    """A ranked attack module recommendation from the planner."""
    module_id:       str
    module_name:     str
    score:           float          # 0.0 – 1.0
    rationale:       str            # human-readable explanation
    suggested_target: str           # which host to run against
    prerequisites:   list[str]      # what must be done first
    mitre_techniques: list[str]     # ATT&CK technique IDs
    opsec_level:     str            # silent | low | medium | high_noise
    estimated_noise: float          # 0.0 = silent, 1.0 = very loud
    score_breakdown: dict[str, float] = field(default_factory=dict)
    goal_relevance:  str = ""       # how this helps reach the goal

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id":        self.module_id,
            "module_name":      self.module_name,
            "score":            round(self.score, 3),
            "rationale":        self.rationale,
            "target":           self.suggested_target,
            "prerequisites":    self.prerequisites,
            "mitre":            self.mitre_techniques,
            "opsec_level":      self.opsec_level,
            "estimated_noise":  round(self.estimated_noise, 2),
            "score_breakdown":  {k: round(v, 3) for k, v in self.score_breakdown.items()},
            "goal_relevance":   self.goal_relevance,
        }


@dataclass
class PlannerContext:
    """Input context for the attack planner."""
    goal:            Goal
    targets:         list[str]          # candidate target IPs
    opsec_profile:   str = "normal"     # stealth | normal | aggressive
    already_tried:   set[str] = field(default_factory=set)  # module_id:target keys
    domain:          str = ""
    campaign_id:     str = ""
    session:         Any = None
    vault:           Any = None
    kb:              Any = None


# ── Scoring weights ────────────────────────────────────────────────────────────

_SCORE_WEIGHTS = {
    "prereq_met":       0.28,   # most important — must have pre-reqs
    "credential_match": 0.18,   # having right creds matters a lot
    "technique_value":  0.18,   # MITRE relevance to current goal
    "artifact_match":   0.15,   # artifact correlator found direct path
    "kb_score":         0.12,   # historical success rate from KB outcomes
    "novelty":          0.05,   # prefer untried modules
    "opsec_cost":       0.04,   # slight penalty for noisy modules in stealth
}

# MITRE technique relevance per goal
_GOAL_TECHNIQUE_MAP: dict[Goal, list[str]] = {
    Goal.DOMAIN_ADMIN: [
        "T1558.003",   # Kerberoasting
        "T1558.004",   # AS-REP Roasting
        "T1003.006",   # DCSync
        "T1078.002",   # Domain Accounts
        "T1484.001",   # ACL modification
        "T1069.002",   # Domain Groups
        "T1087.002",   # Domain Account enumeration
    ],
    Goal.DATA_EXFIL: [
        "T1005",       # Data from Local System
        "T1039",       # Data from Network Shared Drive
        "T1114",       # Email Collection
        "T1530",       # Data from Cloud Storage
    ],
    Goal.CLOUD_ADMIN: [
        "T1552.005",   # Cloud Instance Metadata API
        "T1078.004",   # Cloud Accounts
        "T1537",       # Transfer Data to Cloud Account
        "T1580",       # Cloud Infrastructure Discovery
    ],
    Goal.PERSISTENCE: [
        "T1053.005",   # Scheduled Task
        "T1543.003",   # Windows Service
        "T1136",       # Create Account
        "T1484.002",   # Domain Trust Modification
    ],
    Goal.INITIAL_ACCESS: [
        "T1190",       # Exploit Public-Facing Application
        "T1078",       # Valid Accounts
        "T1566",       # Phishing
    ],
    Goal.FULL_COMPROMISE: [
        "T1003.006", "T1558.003", "T1047", "T1021.002", "T1484",
    ],
}

# Opsec noise cost per level
_OPSEC_NOISE: dict[str, float] = {
    "silent":     0.0,
    "low":        0.2,
    "medium":     0.5,
    "high_noise": 1.0,
}

# Max allowed noise per opsec profile
_MAX_NOISE: dict[str, float] = {
    "stealth":    0.2,
    "normal":     0.7,
    "aggressive": 1.0,
}


# ── Planner ────────────────────────────────────────────────────────────────────

class AttackPlanner:
    """
    Scores and ranks attack modules based on current session state and goal.

    Usage:
        planner = AttackPlanner(registry, session, vault, kb)
        suggestions = planner.suggest(PlannerContext(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            opsec_profile="normal",
        ))
    """

    def __init__(
        self,
        registry: "ModuleRegistry",
        session:  "OperatorSession | None" = None,
        vault:    "CredentialVault | None" = None,
        kb:       "AttackKnowledgeBase | None" = None,
    ) -> None:
        self.registry = registry
        self.session  = session
        self.vault    = vault
        self.kb       = kb

    def suggest(
        self,
        ctx:   PlannerContext,
        limit: int = 5,
    ) -> list[PlanSuggestion]:
        """
        Return top-N ranked module suggestions for the current context.

        Args:
            ctx:   Planner context (goal, targets, opsec profile, etc.)
            limit: Max suggestions to return (default 5)

        Returns:
            List of PlanSuggestion objects, ranked highest-score first.
        """
        t0          = time.monotonic()
        candidates  = list(self.registry.all())
        suggestions = []

        for module_cls in candidates:
            for target in ctx.targets:
                trial_key = f"{module_cls.MODULE_ID}:{target}"
                scored = self._score_module(module_cls, target, ctx)
                if scored is not None:
                    suggestions.append(scored)

        # Sort by score descending
        suggestions.sort(key=lambda s: s.score, reverse=True)
        result = suggestions[:limit]

        logger.info(
            "planner_suggestions",
            goal         = ctx.goal.value,
            candidates   = len(candidates),
            scored       = len(suggestions),
            top_score    = result[0].score if result else 0.0,
            duration_ms  = round((time.monotonic() - t0) * 1000, 1),
        )
        return result

    def _score_module(
        self,
        cls:    Any,
        target: str,
        ctx:    PlannerContext,
    ) -> "PlanSuggestion | None":
        """Score a module for a specific target. Returns None if filtered out."""
        module_id = cls.MODULE_ID

        # ── Hard filters ────────────────────────────────────────────────────
        # Skip non-attack modules (reporting, etc.)
        category = getattr(cls, "MODULE_CATEGORY", "")
        if category in ("reporting",):
            return None

        # Skip if already succeeded on this target
        trial_key = f"{module_id}:{target}"
        already_succeeded = trial_key in (ctx.already_tried or set())
        if already_succeeded:
            return None

        # ── OpSec filter ────────────────────────────────────────────────────
        opsec_level = getattr(getattr(cls, "OPSEC_LEVEL", None), "value", "medium")
        noise_cost  = _OPSEC_NOISE.get(opsec_level, 0.5)
        max_noise   = _MAX_NOISE.get(ctx.opsec_profile, 0.7)
        if noise_cost > max_noise:
            return None  # Module too noisy for current profile

        # ── Scoring ─────────────────────────────────────────────────────────
        breakdown: dict[str, float] = {}

        # prereq_met: are all REQUIRES satisfied?
        requires    = getattr(cls, "REQUIRES", [])
        prereq_score = self._score_prerequisites(requires, target, ctx)
        breakdown["prereq_met"] = prereq_score

        # credential_match: do we have matching creds?
        cred_score = self._score_credentials(cls, ctx)
        breakdown["credential_match"] = cred_score

        # technique_value: MITRE technique relevance to goal
        techniques    = getattr(cls, "MITRE_TECHNIQUES", [])
        goal_techs    = _GOAL_TECHNIQUE_MAP.get(ctx.goal, [])
        tech_overlap  = len(set(techniques) & set(goal_techs))
        tech_score    = min(1.0, tech_overlap * 0.4 + (0.3 if goal_techs and techniques else 0.0))
        breakdown["technique_value"] = tech_score

        # artifact_match: has the correlator flagged a path here?
        artifact_score = self._score_artifact_match(module_id, target, ctx)
        breakdown["artifact_match"] = artifact_score

        # kb_score: historical success rate (AttackKnowledgeBase outcomes)
        if self.kb is not None and hasattr(self.kb, "success_rate"):
            kb_score = self.kb.success_rate(module_id)
        else:
            kb_score = 0.5   # neutral prior when no KB attached
        breakdown["kb_score"] = kb_score

        # novelty: haven't tried this module on this target yet
        novelty_score = 0.0 if trial_key in (ctx.already_tried or set()) else 1.0
        breakdown["novelty"] = novelty_score

        # opsec_cost: slight penalty for noise (lower noise → higher score)
        opsec_score = 1.0 - noise_cost
        breakdown["opsec_cost"] = opsec_score

        # Weighted total
        total = sum(
            _SCORE_WEIGHTS[k] * v
            for k, v in breakdown.items()
        )

        # Filter out very low scores (likely no prerequisites met)
        if total < 0.05:
            return None

        # Build rationale
        rationale = self._build_rationale(module_id, breakdown, ctx.goal, requires)

        return PlanSuggestion(
            module_id        = module_id,
            module_name      = getattr(cls, "MODULE_NAME", module_id),
            score            = round(total, 4),
            rationale        = rationale,
            suggested_target = target,
            prerequisites    = [r for r in requires if not self._has_capability(r, target, ctx)],
            mitre_techniques = techniques,
            opsec_level      = opsec_level,
            estimated_noise  = noise_cost,
            score_breakdown  = breakdown,
            goal_relevance   = self._goal_relevance(module_id, ctx.goal),
        )

    def _score_prerequisites(
        self,
        requires: list[str],
        target:   str,
        ctx:      PlannerContext,
    ) -> float:
        """How many prerequisites are already satisfied (0.0–1.0)."""
        if not requires:
            return 0.8   # No prereqs — slightly prefer prereq-free in recon phase

        met = sum(1 for r in requires if self._has_capability(r, target, ctx))
        return met / len(requires)

    def _has_capability(self, requirement: str, target: str, ctx: PlannerContext) -> bool:
        """Check if a specific requirement is met in current session/vault."""
        session = ctx.session or self.session
        vault   = ctx.vault or self.vault

        # Check session capabilities
        if session:
            host = session.get_host(target) if hasattr(session, "get_host") else None
            if host:
                c_level = getattr(getattr(host, "compromise_level", None), "value", "none")
                level_map = {
                    "local_admin_creds": ["local_admin", "domain_admin", "system"],
                    "domain_creds":      ["user", "local_admin", "domain_admin", "system"],
                    "domain_admin_creds": ["domain_admin"],
                    "system_access":     ["system"],
                }
                for req_key, levels in level_map.items():
                    if requirement == req_key and c_level in levels:
                        return True

        # Check vault
        if vault and hasattr(vault, "_credentials"):
            creds = vault._credentials.values()
            if requirement == "domain_creds":
                return any(getattr(c, "domain", "") != "" for c in creds)
            if requirement == "domain_admin_creds":
                return any(getattr(c, "privilege", "") == "domain_admin" for c in creds)
            if requirement == "local_admin":
                return any(getattr(c, "privilege", "") in ("local_admin", "domain_admin") for c in creds)

        # Check if output was produced by already-run module
        if session and hasattr(session, "outputs"):
            return requirement in getattr(session, "outputs", set())

        return False

    def _score_credentials(self, cls: Any, ctx: PlannerContext) -> float:
        """Score based on credential availability for this module."""
        vault = ctx.vault or self.vault
        if not vault:
            return 0.3   # No vault — neutral

        requires = getattr(cls, "REQUIRES", [])
        cred_reqs = [r for r in requires if "cred" in r or "admin" in r]
        if not cred_reqs:
            return 0.5   # No cred requirement

        return 0.9 if any(
            self._has_capability(r, "", ctx) for r in cred_reqs
        ) else 0.1

    def _score_artifact_match(
        self, module_id: str, target: str, ctx: PlannerContext
    ) -> float:
        """Check if artifact correlator found an opportunity for this module."""
        # Without a live artifact store, return neutral
        try:
            from ares.artifact_intel.correlation import ArtifactCorrelationEngine
            # If session has an artifact store attached, check for opportunities
            session = ctx.session or self.session
            if session and hasattr(session, "artifact_store"):
                engine = ArtifactCorrelationEngine()
                opps   = engine.correlate(session.artifact_store)
                for opp in opps:
                    if module_id in getattr(opp, "recommended_modules", []):
                        return {"critical": 1.0, "high": 0.8, "medium": 0.5}.get(
                            opp.severity, 0.3
                        )
        except (ImportError, AttributeError):
            pass
        return 0.0

    def _goal_relevance(self, module_id: str, goal: Goal) -> str:
        """Return a short string explaining how module helps reach goal."""
        relevance_map: dict[str, dict[str, str]] = {
            Goal.DOMAIN_ADMIN.value: {
                "ad.kerberoast":  "Crack service account passwords → domain admin path",
                "ad.asreproast":  "Crack AS-REP hashes → credential access",
                "ad.dcsync":      "Dump all domain hashes → immediate DA access",
                "ad.enum_acl":    "Find ACL paths → WriteDACL/GenericAll abuse",
                "ad.enum_users":  "Discover attack surface → kerberoast candidates",
                "lateral.psexec": "Lateral movement → reach domain controller",
            },
            Goal.DATA_EXFIL.value: {
                "lateral.wmiexec": "Reach data stores on internal hosts",
            },
        }
        return relevance_map.get(goal.value, {}).get(module_id, "Contributes to goal")

    def _build_rationale(
        self,
        module_id:  str,
        breakdown:  dict[str, float],
        goal:       Goal,
        requires:   list[str],
    ) -> str:
        """Build human-readable rationale for the suggestion."""
        parts = []

        if breakdown.get("prereq_met", 0) >= 0.8:
            parts.append("prerequisites met")
        elif breakdown.get("prereq_met", 0) >= 0.5:
            parts.append(f"partial prerequisites ({len(requires)} needed)")
        else:
            parts.append(f"missing prerequisites: {', '.join(requires[:2])}")

        if breakdown.get("artifact_match", 0) > 0.5:
            parts.append("artifact correlator identified direct opportunity")

        if breakdown.get("technique_value", 0) > 0.5:
            parts.append(f"high MITRE relevance for {goal.value}")

        if breakdown.get("credential_match", 0) > 0.7:
            parts.append("matching credentials available")

        if breakdown.get("opsec_cost", 0) > 0.8:
            parts.append("low noise profile")

        return "; ".join(parts) if parts else "candidate technique"


# ── Convenience function ───────────────────────────────────────────────────────

def auto_suggest(
    goal:          Goal,
    targets:       list[str],
    registry:      Any,
    session:       Any = None,
    vault:         Any = None,
    kb:            Any = None,
    opsec_profile: str = "normal",
    already_tried: set[str] | None = None,
    limit:         int = 5,
) -> list[PlanSuggestion]:
    """
    One-liner interface to the AttackPlanner.

    Usage:
        suggestions = auto_suggest(
            goal=Goal.DOMAIN_ADMIN,
            targets=["10.0.0.1"],
            registry=container.registry(),
            session=session,
            vault=vault,
            opsec_profile="normal",
        )
        next_module = suggestions[0].module_id
    """
    planner = AttackPlanner(registry=registry, session=session, vault=vault, kb=kb)
    ctx     = PlannerContext(
        goal          = goal,
        targets       = targets,
        opsec_profile = opsec_profile,
        already_tried = already_tried or set(),
        session       = session,
        vault         = vault,
        kb            = kb,
    )
    return planner.suggest(ctx, limit=limit)

# Backward-compat alias
Suggestion = PlanSuggestion  # noqa
