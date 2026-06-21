"""
ARES Attack Chain Engine
DAG-based semi-autonomous attack chaining.

Concept:
  Each module declares REQUIRES and OUTPUTS.
  The chain engine builds a directed acyclic graph,
  resolves execution order, and auto-wires outputs → inputs.

Example auto-chain for AD engagement:
  ad.enum_spn      → outputs: ["spn_list", "user_list"]
       ↓
  ad.kerberoast    → requires: ["domain_creds", "spn_list"]
       ↓
  ad.enum_acl      → requires: ["user_list"]
       ↓
  ad.dcsync        → requires: ["domain_admin_creds"]   ← blocked if not satisfied

Manual chains can also be defined explicitly:
  chain = AttackChain("AD Full Compromise")
  chain.add("ad.enum_users")
  chain.add("ad.enum_spn",   after=["ad.enum_users"])
  chain.add("ad.kerberoast", after=["ad.enum_spn"])

AI suggestion integration:
  The ChainAdvisor analyzes confirmed findings
  and suggests what to run next — "found SPN → suggest kerberoast".
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ares.core.logger import get_logger

if TYPE_CHECKING:
    from ares.core.plugin.loader import ModuleRegistry

logger = get_logger("ares.chain")


# ── Chain Node ────────────────────────────────────────────────────────────────

@dataclass
class ChainNode:
    module_id: str
    params:    dict[str, Any] = field(default_factory=dict)
    depends_on: list[str]     = field(default_factory=list)  # explicit deps
    optional:  bool = False   # if True: skip cleanly when deps unmet


# ── Dependency resolver (topological sort) ────────────────────────────────────

class DependencyResolver:
    """
    Kahn's algorithm topological sort on the module DAG.
    Raises CyclicDependencyError if a cycle is detected.
    Groups modules into parallel stages.
    """

    def resolve(self, nodes: list[ChainNode]) -> list[list[str]]:
        """
        Returns a list of stages.
        Modules in the same stage have no dependencies on each other → run in parallel.
        Stages run sequentially.

        Example output:
          [
            ["ad.enum_users", "ad.enum_computers"],   # Stage 1 — parallel
            ["ad.enum_spn", "ad.enum_acl"],            # Stage 2 — parallel
            ["ad.kerberoast", "ad.asreproast"],        # Stage 3 — parallel
          ]
        """
        ids   = {n.module_id for n in nodes}
        graph: dict[str, set[str]] = {n.module_id: set() for n in nodes}
        indegree: dict[str, int]   = {n.module_id: 0 for n in nodes}

        for node in nodes:
            for dep in node.depends_on:
                if dep in ids:
                    graph[dep].add(node.module_id)
                    indegree[node.module_id] += 1

        queue: deque[str] = deque(mid for mid, deg in indegree.items() if deg == 0)
        stages: list[list[str]] = []
        visited: set[str] = set()

        while queue:
            # All modules currently in queue have no unresolved deps → same stage
            stage = list(queue)
            stages.append(stage)
            queue.clear()

            for mid in stage:
                visited.add(mid)
                for successor in graph[mid]:
                    indegree[successor] -= 1
                    if indegree[successor] == 0:
                        queue.append(successor)

        if len(visited) != len(ids):
            unresolved = ids - visited
            raise CyclicDependencyError(f"Cycle detected involving: {unresolved}")

        return stages


class CyclicDependencyError(Exception):
    pass


# ── Capability resolver (auto-wiring from REQUIRES/OUTPUTS) ──────────────────

class CapabilityResolver:
    """
    Automatically builds dependencies from module REQUIRES/OUTPUTS metadata.

    Given a list of module IDs, this determines which ones
    must run before others based on their declared capabilities.
    """

    def __init__(self, registry: "ModuleRegistry") -> None:
        self.registry = registry

    def build_nodes(self, module_ids: list[str]) -> list[ChainNode]:
        """
        Build ChainNodes with auto-calculated depends_on
        from REQUIRES/OUTPUTS metadata.
        """
        # Map: capability → modules that produce it
        producers: dict[str, list[str]] = defaultdict(list)
        for mid in module_ids:
            cls = self.registry.get(mid)
            if cls:
                for output in getattr(cls, "OUTPUTS", []):
                    producers[output].append(mid)

        nodes: list[ChainNode] = []
        for mid in module_ids:
            cls = self.registry.get(mid)
            if not cls:
                logger.warning("chain_module_not_found", module_id=mid)
                continue

            # Compute deps: modules that produce what I require
            deps: list[str] = []
            missing: list[str] = []
            for requirement in getattr(cls, "REQUIRES", []):
                if requirement in producers:
                    deps.extend(producers[requirement])
                else:
                    missing.append(requirement)

            if missing:
                logger.warning(
                    "chain_unmet_requirements",
                    module_id=mid,
                    missing=missing,
                )

            nodes.append(ChainNode(
                module_id  = mid,
                depends_on = list(set(deps)),  # deduplicate
                optional   = bool(missing),
            ))

        return nodes


# ── Attack Chain ──────────────────────────────────────────────────────────────

class AttackChain:
    """
    Named attack chain: ordered set of modules with dependency resolution.

    Usage (manual):
        chain = AttackChain("AD Compromise")
        chain.add("ad.enum_users")
        chain.add("ad.enum_spn",   after=["ad.enum_users"])
        chain.add("ad.kerberoast", after=["ad.enum_spn"])
        stages = chain.resolve()

    Usage (auto from module metadata):
        chain = AttackChain.auto(registry, ["ad.enum_users", "ad.enum_spn", "ad.kerberoast"])
        stages = chain.resolve()
    """

    # Built-in chain templates
    TEMPLATES: dict[str, list[str]] = {
        "ad_full": [
            "ad.enum_users", "ad.enum_computers", "ad.enum_spn", "ad.enum_acl",
            "ad.asreproast", "ad.kerberoast", "ad.dcsync",
        ],
        "ad_recon": [
            "ad.enum_users", "ad.enum_computers", "ad.enum_spn", "ad.enum_acl",
        ],
        "linux_privesc": [
            "linux.privesc", "linux.container",
        ],
        "cloud_aws": [
            "cloud.aws",
        ],
        "cloud_full": [
            "cloud.aws", "cloud.azure", "cloud.gcp",
        ],
        "full_engagement": [
            "ad.enum_users", "ad.enum_computers", "ad.enum_spn", "ad.enum_acl",
            "ad.asreproast", "ad.kerberoast",
            "linux.privesc", "linux.container",
            "cloud.aws", "cloud.azure", "cloud.gcp",
        ],
    }

    def __init__(self, name: str) -> None:
        self.name  = name
        self._nodes: list[ChainNode] = []

    def add(
        self,
        module_id: str,
        params:    dict[str, Any] | None = None,
        after:     list[str] | None = None,
        optional:  bool = False,
    ) -> "AttackChain":
        self._nodes.append(ChainNode(
            module_id  = module_id,
            params     = params or {},
            depends_on = after or [],
            optional   = optional,
        ))
        return self

    def resolve(self) -> list[list[str]]:
        """Resolve dependency order. Returns list of parallel stages."""
        resolver = DependencyResolver()
        return resolver.resolve(self._nodes)

    def node_params(self) -> dict[str, dict[str, Any]]:
        """Return {module_id: params} mapping for engine consumption."""
        return {n.module_id: n.params for n in self._nodes}

    @classmethod
    def auto(cls, registry: "ModuleRegistry", module_ids: list[str], name: str = "auto") -> "AttackChain":
        """
        Build a chain automatically from module REQUIRES/OUTPUTS metadata.
        The engine will figure out the right order — you just list module IDs.
        """
        cap_resolver = CapabilityResolver(registry)
        nodes = cap_resolver.build_nodes(module_ids)
        chain = cls(name)
        chain._nodes = nodes
        return chain

    @classmethod
    def from_template(cls, template: str, registry: "ModuleRegistry") -> "AttackChain":
        """
        Build a chain from a named template.

        Available templates:
          ad_full, ad_recon, linux_privesc, cloud_aws, cloud_full, full_engagement
        """
        if template not in cls.TEMPLATES:
            raise ValueError(f"Unknown template '{template}'. Available: {list(cls.TEMPLATES)}")
        module_ids = cls.TEMPLATES[template]
        logger.info("chain_from_template", template=template, modules=len(module_ids))
        return cls.auto(registry, module_ids, name=template)

    def summary(self) -> dict[str, Any]:
        stages = self.resolve()
        return {
            "name":        self.name,
            "total_modules": len(self._nodes),
            "stage_count": len(stages),
            "stages":      [{"index": i, "modules": s} for i, s in enumerate(stages, 1)],
        }


# ── Chain Advisor (AI-style suggestions from findings) ────────────────────────

@dataclass
class Suggestion:
    module_id:  str
    reason:     str
    confidence: float   # 0.0 – 1.0
    priority:   int     # lower = run first


class ChainAdvisor:
    """
    Analyzes confirmed findings and suggests next attack modules.

    This is rule-based, not ML — but structured so an LLM could
    replace the rule engine later.

    Example:
        advisor = ChainAdvisor(registry)
        suggestions = advisor.suggest(campaign.confirmed_findings())
        # → [Suggestion("ad.kerberoast", "Found SPN accounts", 0.95, 1), ...]
    """

    def __init__(self, registry: "ModuleRegistry") -> None:
        self.registry = registry

    def suggest(self, findings: list[Any]) -> list[Suggestion]:
        """Return ranked list of suggested next modules based on current findings."""
        suggestions: list[Suggestion] = []
        mitre_seen  = {f.mitre_technique for f in findings if f.mitre_technique}
        titles      = {f.title.lower() for f in findings}
        severities  = {f.severity.value for f in findings}

        # Rule set: (condition, suggestion)
        rules = [
            (
                any("spn" in t for t in titles),
                Suggestion("ad.kerberoast", "SPN accounts found — request TGS hashes", 0.95, 1),
            ),
            (
                any("pre-auth disabled" in t or "asrep" in t for t in titles),
                Suggestion("ad.asreproast", "Pre-auth disabled accounts found", 0.95, 1),
            ),
            (
                any("writedacl" in t or "genericall" in t or "dcsync right" in t for t in titles),
                Suggestion("ad.dcsync", "Dangerous ACL grants DCSync capability", 0.90, 2),
            ),
            (
                any("docker socket" in t for t in titles),
                Suggestion("linux.container", "Docker socket found — container escape possible", 0.90, 1),
            ),
            (
                any("suid" in t or "sudo nopasswd" in t for t in titles),
                Suggestion("linux.privesc", "Privilege escalation vector found — enumerate further", 0.85, 1),
            ),
            (
                any("s3 public" in t or "imds" in t for t in titles),
                Suggestion("cloud.aws", "AWS misconfiguration found — expand AWS enumeration", 0.80, 2),
            ),
            (
                "T1558.003" in mitre_seen and "ad.dcsync" in {f.module_id for f in findings if hasattr(f, "module_id")},
                Suggestion("ad.dcsync", "Kerberoast hashes obtained — if cracked, attempt DCSync", 0.70, 3),
            ),
            (
                "critical" in severities,
                Suggestion("ad.enum_acl", "Critical findings present — check for ACL abuse paths", 0.75, 2),
            ),
            # ── New rules for Roadmap modules ─────────────────────────────────
            (
                any("genericwrite" in t and "computer" in t for t in titles),
                Suggestion("ad.delegation_abuse",
                           "GenericWrite on computer found — RBCD attack to local admin", 0.90, 2),
            ),
            (
                any("smb relay" in t or "smb_relay" in t for t in titles) and
                any("domain controller" in t or "is_dc" in t for t in titles),
                Suggestion("ad.coerce",
                           "SMB relay active + DC in scope — force DC authentication via coercion", 0.88, 1),
            ),
            (
                any("kerberoast" in t or "asrep" in t or "ntlm hash" in t for t in titles) and
                not any("cracked" in t for t in titles),
                Suggestion("credential.crack",
                           "Uncracked hashes in vault — run hashcat/john to recover plaintext", 0.95, 1),
            ),
            (
                any("mssql" in t or "sql server" in t or "1433" in t for t in titles),
                Suggestion("lateral.mssql",
                           "MSSQL detected — attempt xp_cmdshell lateral movement", 0.80, 2),
            ),
            (
                any("esc1" in t or "esc2" in t or "adcs" in t or "certificate template" in t
                    for t in titles),
                Suggestion("ad.adcs",
                           "ADCS vulnerability found — exploit ESC1 for Domain Admin certificate", 0.92, 1),
            ),
        ]

        for condition, suggestion in rules:
            if condition and suggestion.module_id in self.registry:
                suggestions.append(suggestion)

        # Deduplicate and sort by priority then confidence
        seen: set[str] = set()
        result: list[Suggestion] = []
        for s in sorted(suggestions, key=lambda x: (x.priority, -x.confidence)):
            if s.module_id not in seen:
                result.append(s)
                seen.add(s.module_id)

        if result:
            logger.info(
                "chain_advisor_suggestions",
                count=len(result),
                top=result[0].module_id if result else None,
            )
        return result
