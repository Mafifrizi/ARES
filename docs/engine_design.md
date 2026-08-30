# ARES Engine Design

**Version:** 1.0.0 | **Status:** C-LIVE-v1 safety wiring; descriptors inactive

## Overview

The engine retains goal, module, and state-management components, but the
pre-C-LIVE adaptive execution design documented below is inactive in
C-LIVE-v1. Reachable effects require the sealed coordinator described in
[C-LIVE-v1 engine ownership](#c-live-v1-engine-ownership); public engine calls
and production Goal/Strategy planning fail closed while descriptors are
ineligible.

---

## Core Components

```
AresEngine
 ├─ AresContainer        (dependency injection)
 ├─ ModuleRegistry       (module catalog + validation)
 ├─ GoalEngine           (backward-chaining planner)
 ├─ AttackPlanner        (AI-scored next-technique suggester)
 ├─ AdaptiveAttackStrategy (fallback chain on failure)
 ├─ ClusterController    (task distribution to workers)
 ├─ OperatorSession      (attack state: hosts, creds, history)
 ├─ CredentialVault      (encrypted credential store)
 ├─ TelemetryCollector   (metrics, alerting)
 └─ CampaignGuardrail    (scope enforcement, safety gate)
```

---

## Legacy execution lifecycle (inactive in C-LIVE-v1)

Every module execution follows this exact sequence:

```
Operator / API
    │
    ▼
CampaignGuardrail.check(module_id, target)
    │  out-of-scope → ABORT immediately
    ▼
AttackPlanner.suggest()         ← AI picks best next technique
    │  or operator specifies module directly
    ▼
AresContainer.build_context()   ← builds ExecutionContext
    │  injects: vault, session, telemetry, settings
    ▼
BaseModule.validate(ctx)         ← parameter + context check
    │  ModuleValidationError → ABORT
    ▼
CampaignGuardrail.check()        ← second check (context has real target)
    │
    ▼
SandboxRunner.run_module(ctx)    ← capability-enforced execution
    │  subprocess isolation + resource limits
    ▼
BaseModule.execute(ctx)          ← module runs, returns ModuleResult
    │
    ▼
ModuleResult processing:
    ├─ findings    → campaign.add_finding()
    ├─ credentials → vault.store()
    ├─ new_hosts   → session.discover_host()
    └─ artifacts   → ArtifactStore.add()
    │
    ▼
ArtifactCorrelationEngine.correlate()  ← find new attack paths
    │
    ▼
AttackPlanner.suggest()                ← re-score next steps
    │
    ▼
TelemetryCollector.record_execution()  ← metrics + alerting
    │
    ▼
CheckpointManager.save()               ← durable state snapshot
```

---

## Module Registry

The registry is populated by `PluginLoader` at startup:

```
Source 1: builtin      ares/modules/**/*.py          always loaded, full trust
Source 2: entrypoint   pip packages with             community trust
                       [ares.modules] entry points
Source 3: external     ~/.ares/plugins/*.py           external trust
                       ARES_PLUGIN_DIR env var
```

**Security controls at load time:**

1. Signature verification (`ModuleVerifier`) — configurable via `ARES_PLUGIN_SIGNING_POLICY`
2. Capability enforcement (`CapabilityPolicy`) — module can only declare allowed caps for trust level
3. Metadata validation (`validate_module_class`) — all required attrs present
4. Duplicate detection — existing module_id from builtin takes priority

---

## Dependency Injection (AresContainer)

All services are resolved through `AresContainer` — never instantiated directly in engine code:

```python
# Production setup (CLI / API startup)
container = AresContainer.production(settings)
engine    = container.engine()

# Testing setup (no network, no disk)
container = AresContainer.for_test()
container.override("vault", MockVault())
```

Services registered by name:

| Key          | Type                   | Notes                        |
|--------------|------------------------|------------------------------|
| `settings`   | AresSettings           | Loaded from env / config     |
| `registry`   | ModuleRegistry         | Lazily populated by loader   |
| `engine`     | AresEngine             | Core orchestrator            |
| `db`         | AresDatabase           | SQLite async                 |
| `vault`      | CredentialVault        | Fernet-encrypted             |
| `telemetry`  | TelemetryCollector     | In-process metrics           |
| `cluster`    | ClusterController      | Redis or in-process queue    |
| `guardrail`  | CampaignGuardrail      | Scope + safety enforcement   |
| `sandbox`    | SandboxRunner          | Subprocess/seccomp/Docker    |
| `kb`         | AttackKnowledgeBase    | Technique library            |

---

## ExecutionContext

A single typed object passed to every module. Replaces scattered `**kwargs`:

```python
@dataclass
class ExecutionContext:
    # Identity
    execution_id:  str      # UUID per execution
    campaign_id:   str
    module_id:     str
    operator:      str

    # Target
    target:        str      # IP or hostname
    domain:        str      # AD domain (CORP.LOCAL)
    port:          int

    # Parameters
    params:        dict     # module-specific params

    # Credentials (ordered by score)
    credentials:   list[Credential]
    primary_credential: Credential | None

    # Shared state (references — mutations visible to engine)
    session:       OperatorSession
    vault:         CredentialVault

    # Engine references
    settings:      AresSettings
    telemetry:     TelemetryCollector
    noise:         NoiseController

    # OpSec
    opsec_profile: str      # stealth | normal | aggressive
    timeout_s:     int

    # Safety
    dry_run:       bool     # True = simulate, no real network calls
```

Context lifecycle:

```
Engine builds context
  → module.validate(ctx)   # raises ModuleValidationError if bad
  → module.execute(ctx)    # runs, returns ModuleResult
  → module.report(result)  # formats for report engine
  → engine updates session state
```

---

## Error Handling

All errors are typed and carry an engine *action hint*:

```
AresError
 ├─ ModuleError       → action: retry
 │   ├─ ModuleValidationError → abort
 │   └─ ModuleTimeoutError    → retry with backoff
 ├─ NetworkError      → retry with jitter
 │   ├─ ConnectionRefused    → fallback module
 │   ├─ HostUnreachable      → skip target
 │   └─ RateLimited          → pause + increase jitter
 ├─ CredentialError   → try next credential in vault
 │   ├─ AuthenticationFailed → retry with next cred
 │   └─ AccountLocked        → ABORT all attempts (lockout risk)
 ├─ ScopeError        → abort immediately (never retry)
 ├─ OpsecError        → pause / escalate stealth
 │   ├─ DetectionSignal      → escalate opsec profile
 │   └─ HoneypotDetected     → abort campaign
 └─ InsufficientPrivilege    → suggest privesc module
```

Engine error dispatch:

```python
try:
    result = await module.execute(ctx)
except AresError as e:
    action = e.action  # "retry" | "skip" | "fallback" | "abort" | "pause"
    if action == "retry":
        task_queue.requeue(task)
    elif action == "fallback":
        next_mod = adaptive_strategy.next_alternative(module_id, target)
    elif action == "abort":
        raise
```

---

## Legacy GoalEngine/AttackPlanner design (production inactive)

**GoalEngine** (`ares/goal/engine.py`) — deterministic backward chaining:
- Operator sets `Goal.DOMAIN_ADMIN`
- Engine looks at `GOAL_DEFINITIONS` to find required outputs
- Finds modules that produce those outputs
- Topological sort → `ExecutionPlan` with ordered stages

**AttackPlanner** (`ares/goal/planner.py`) — probabilistic AI scoring:
- Scores ALL candidate modules against current session state
- 6-factor weighted score: prereqs, credentials, technique value, artifact match, novelty, opsec
- Returns ranked `Suggestion` list with rationale
- Re-runs after each execution (adapts to discovered state)

The following sequence is historical and is not a production C-LIVE-v1 path:

```
GoalEngine.plan() → initial deterministic chain
  → executes stage 1
  → AttackPlanner.suggest() → re-ranks remaining candidates
  → executes best suggestion
  → repeat until goal reached or plan exhausted
```

---

## Legacy AdaptiveAttackStrategy (production inactive)

When a module fails, the engine doesn't stop — it pivots:

```
lateral.psexec  → FAIL (EDR blocked)
               ↓
AdaptiveAttackStrategy.next_alternative("lateral.psexec", target)
               ↓
lateral.wmiexec → FAIL (WMI restricted)
               ↓
lateral.winrm   → SUCCESS
```

Fallback graph is defined in `ares/goal/adaptive.py`:

```python
FALLBACK_GRAPH = {
    "lateral.psexec":  ["lateral.wmiexec", "lateral.winrm", "lateral.ssh"],
    "ad.kerberoast":   ["ad.asreproast", "ad.enum_acl"],
    "ad.dcsync":       ["ad.enum_acl", "ad.privesc"],
    ...
}
```

EDR-blocked modules are permanently disabled for the session. Conditions (port open, creds available) gated before selecting fallback.

---

## State Management

```
OperatorSession
 ├─ hosts{}               # ip → HostState
 │   ├─ compromise_level  # none | recon | user | local_admin | system | domain_admin
 │   ├─ is_dc             # True if Domain Controller
 │   ├─ open_ports[]
 │   ├─ attack_history[]  # ModuleExecution records
 │   └─ credentials_found[]
 ├─ outputs{}             # set of produced capabilities (feeds prereq check)
 └─ attack_graph          # networkx DiGraph (hosts + credential flows)
```

**Compromise level never downgrades.** Once `domain_admin`, always `domain_admin`.

Persistence via `CheckpointManager`:
- Fernet-encrypted `.ares_ckpt` files
- Plaintext secrets never written to disk
- `save(state)` → encrypted JSON
- `load(campaign_id)` → decrypts + deserializes
- `purge_old(keep_last=5)` → cleanup

---

## Campaign Graph

At any point, the engine can generate a full attack graph for visualization:

```
GET /graph/{campaign_id}  →  {nodes: [...], edges: [...], stats: {...}}
```

Node types: `host`, `dc`, `credential`, `finding`, `pivot`
Edge types: `lateral`, `compromise`, `credential`, `discovery`, `pivot`

Frontend renders with D3.js or Cytoscape.js.

---

## C-LIVE-v1 engine ownership

The engine no longer owns admission or implicit retries. A coordinator must
first obtain exact `APPLIED` results for admission, queue, dispatch, and running,
then pass a sealed single-use context to the engine. The engine prepares a
sanitized result; persistence/publication is released only after the V3 terminal
commit succeeds. Exact admission or terminal replay never enters the engine.

Plan occurrences retain stage/module ordinals, including repeated module IDs.
Retry attempts use deterministic child identities and repeat principal
revalidation before queueing. Timeout, disconnect, cancellation, or an ordinary
exception is not by itself settlement proof. Uncertain work is parked without
automatic redispatch; INDETERMINATE recovery remains P1-F.
