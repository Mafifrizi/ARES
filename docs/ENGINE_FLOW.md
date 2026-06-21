# ARES Engine Flow

**Version:** 1.0.0

## Overview

This document traces the complete execution pipeline from user input to findings stored in the database.

---

## Pipeline Diagram

```
Operator Input (CLI / API)
         │
         ▼
    GoalEngine.plan(goal, context)
         │  backward-chains via CapabilityGraph
         │  REQUIRES/OUTPUTS → ordered module chain
         ▼
    GoalAttackPlan  (list of GoalAttackStep)
         │
         ▼
    AresEngine.run_plan(plan, campaign)
         │
         ├── For each stage (parallel):
         │       AresEngine.run_module(module_id, campaign, params)
         │              │
         │              ├── Plugin loader resolves module class
         │              ├── ScopeGuard.check(target) — blocks out-of-scope
         │              ├── NoiseController.jitter() — random delay
         │              ├── module.run(**params)
         │              │       └── module.execute(ctx) → findings, raw
         │              ├── CVSS enrichment on each finding
         │              ├── AresDatabase.save_finding()
         │              └── _broadcast_event() → WebSocket subscribers
         │
         ▼
    ArtifactStore.add(artifacts from raw)
         │
         ▼
    AttackGraph.build_from_store(store)
         │  adds nodes + edges from HostArtifact, UserArtifact, etc.
         ▼
    AttackGraph.top_paths()  /  find_path(source, target)
         │  Dijkstra shortest path on weighted DiGraph
         ▼
    path_to_report()  →  human-readable steps + attack modules
```

---

## Key Components

### AresEngine (`ares/core/engine.py`)

Orchestrates module execution. Key methods:

| Method | Description |
|--------|-------------|
| `run_module(id, campaign, params)` | Run single module with timeout + retry |
| `run_plan(plan, campaign, params)` | Run ExecutionPlan (staged, parallel per stage) |
| `dry_run_plan(plan, params)` | Preview without executing |

**Retry logic:** `asyncio.TimeoutError` → retry up to 2 times with exponential backoff (2s, 4s). Original timeout status preserved even if retries fail with other exceptions.

---

### GoalEngine + CapabilityGraph (`ares/goal/engine.py`)

The planner that converts a high-level goal into an ordered execution chain.

**Chain resolution priority:**
1. `preferred_chain` from GoalDefinition (if all modules available)
2. `CapabilityGraph.resolve_chain()` — backward-chain from `required_outputs`
3. `fallback_chains` from GoalDefinition
4. Best-effort: available modules from preferred_chain

**CapabilityGraph** maps module `REQUIRES` → `OUTPUTS` to build a dependency graph. `resolve_chain(required_outputs)` does backward DFS to find which modules must run and in which order.

---

### AttackGraph (`ares/graph/attack_graph.py`)

NetworkX DiGraph of attack relationships. Nodes = artifacts, edges = attack steps.

**Key methods:**

| Method | Description |
|--------|-------------|
| `build_from_store(store)` | Build graph from ArtifactStore |
| `find_path(source_label, target_label)` | Shortest path by human label |
| `shortest_attack_path(src_id, tgt_id)` | Dijkstra by node ID |
| `score_path(path)` | Sum of edge weights (lower = easier) |
| `path_to_report(path)` | Human-readable step-by-step breakdown |
| `top_paths(n)` | Top N easiest paths to high-value nodes |
| `attack_paths_to_domain_admin()` | All paths to DA/DC/high-value nodes |

**Edge weights:** Lower weight = easier for attacker.  
`ASREPRoastable = 0.5`, `ACE abuse = 0.3`, `DCSync = 0.2`

---

### Module Lifecycle

```
BaseModule.__init__(settings, campaign, noise)
    │
    ▼
module.run(**params)          ← called by engine
    │
    ▼
ExecutionContext.for_test(**params)
    │
    ▼
module.validate(ctx)          ← check required params
    │
    ▼
module.execute(ctx)           ← main attack logic
    │
    ├── ctx.dry_run → return dry_run result immediately
    ├── self.before_request(host, protocol) → scope + noise check
    ├── attack work...
    ├── self.finding(...) → creates Finding, adds to self._findings
    └── return ModuleResult(status, findings, raw)
```

---

### Artifact → Graph Pipeline

After a module run, raw output can be normalized into artifacts:

```python
from ares.normalize.artifacts import ArtifactStore, UserArtifact, HostArtifact

store = ArtifactStore()
store.add(UserArtifact(username="svc_sql", domain="CORP", spns=["MSSQLSvc/db01"]))
store.add(HostArtifact(ip_address="10.0.0.1", hostname="DC01", is_dc=True))

graph = AttackGraph()
graph.build_from_store(store)

path = graph.find_path("svc_sql", "Domain Admins")
# → ["user:CORP:svc_sql", "hash:krb5tgs:...", "group:CORP:Domain Admins"]

report = graph.path_to_report(path)
# → {"steps": [{"from": "svc_sql", "to": "TGS:svc_sql", "attack": "ad.kerberoast", ...}], ...}
```
