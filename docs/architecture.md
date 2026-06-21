# ARES Architecture

**Version:** 0.9.0 | **Status:** Active Development

## Overview

ARES (Automated Red team Engagement System) is an open-source red team automation framework. It automates attack chains, tracks campaign state, and generates professional reports — covering AD/Windows, Linux/Container, and Cloud (AWS/Azure/GCP) environments.

ARES is **not** a C2 framework. It does not include implants, beacons, or persistent agents. It is an orchestration layer for red team techniques executed from the operator's machine.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        OPERATOR INTERFACE                        │
│              CLI (click/rich)    REST API (FastAPI)              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      ARES ENGINE CORE                            │
│  AresEngine ──► ExecutionContext ──► BaseModule.execute(ctx)     │
│       │                                                          │
│       ├── DI Container (AresContainer)                           │
│       ├── Goal Engine (backward-chain planner)                   │
│       ├── Adaptive Strategy (auto-fallback on failure)           │
│       ├── Campaign Guardrail (scope + safety checks)             │
│       └── Telemetry Collector (metrics, alerts)                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      EXECUTION LAYER                             │
│  ClusterController ──► Redis/In-Process Queue                    │
│       │                                                          │
│       ├── ClusterWorkerNode (worker process)                     │
│       │       └── SandboxRunner (subprocess/docker isolation)    │
│       └── IsolatedRunner (legacy subprocess worker)              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                       MODULE LAYER                               │
│  BaseModule (validate → execute → report)                        │
│       ├── ares/modules/ad/         (7 modules)                   │
│       ├── ares/modules/linux/      (2 modules)                   │
│       ├── ares/modules/cloud/      (3 modules: AWS/Azure/GCP)    │
│       ├── ares/lateral/            (5 modules)                   │
│       └── ares/modules/reporting/  (report generator)            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                       STATE & INTELLIGENCE                       │
│  OperatorSession ──► HostState, CompromiseLevel                  │
│  ArtifactStore   ──► HostArtifact, CredentialArtifact, etc.     │
│  CredentialVault ──► Fernet-encrypted, scored, deduped           │
│  NetworkModel    ──► Graph, pivot routing                        │
│  ArtifactCorrelationEngine ──► 7 compound attack rules           │
│  ArtifactIntelEngine ──► auto-queue next modules from artifacts  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      PERSISTENCE LAYER                           │
│  AresDatabase (aiosqlite) ──► campaigns, findings, hosts         │
│  CheckpointManager       ──► encrypted .ares_ckpt files          │
│  EvidenceStore           ──► command output, screenshots, files  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. `ares/core/`

| File | Purpose |
|------|---------|
| `engine.py` | `AresEngine` — async orchestrator, runs `ExecutionPlan` |
| `context.py` | `ExecutionContext` — unified module input object |
| `errors.py` | Standard error hierarchy (`ModuleError`, `NetworkError`, etc.) |
| `di.py` | `AresContainer` — dependency injection / service locator |
| `campaign.py` | `Campaign`, `Finding`, `ScopeEntry`, `NoiseProfile` |
| `config.py` | `AresSettings` (Pydantic), `@lru_cache` singleton |
| `noise.py` | `NoiseController`, `JitterEngine`, `RateLimiter`, `ScopeGuard` |
| `security.py` | JWT, `DataEncryptor` (Fernet), bcrypt, sanitize_* helpers |
| `logger.py` | structlog NDJSON, sensitive data masking |
| `sandbox.py` | `SandboxRunner` — 4-tier module isolation |
| `chain/chain.py` | `AttackChain`, Kahn's dependency resolver, `ChainAdvisor` |
| `opsec/opsec.py` | UA rotation, beacon scheduler, traffic shaping |
| `opsec/adaptive.py` | `AdaptiveOpsecEngine` — sliding window signal detection |
| `plugin/loader.py` | `PluginLoader`, `ModuleRegistry` |
| `validator.py` | `FindingValidator`, confidence scoring, FP filtering |

### 2. `ares/modules/base.py` — SDK Contract

Every module MUST implement this interface:

```python
class BaseModule(ABC):
    # Required metadata
    MODULE_ID:          str          # "ad.kerberoast"
    MODULE_NAME:        str          # "Kerberoasting"
    MODULE_CATEGORY:    str          # "ad"
    MODULE_DESCRIPTION: str          # one-liner

    # Optional metadata
    OPSEC_LEVEL:        OpsecLevel   # SILENT | LOW | MEDIUM | HIGH_NOISE
    REQUIRES:           list[str]    # ["domain_creds", "spn_list"]
    OUTPUTS:            list[str]    # ["kerberos_hashes"]
    MITRE_TECHNIQUES:   list[str]    # ["T1558.003"]
    MODULE_AUTHOR:      str

    # v0.9.0 SDK (preferred)
    async def validate(self, ctx: ExecutionContext) -> None: ...
    async def execute(self, ctx: ExecutionContext) -> ModuleResult: ...
    def report(self, result: ModuleResult) -> dict: ...

    # Legacy (still supported)
    async def run(self, **kwargs) -> tuple[list[Finding], dict]: ...
```

### 3. ExecutionContext

Single object carrying all runtime state for a module execution:

```python
ctx = ExecutionContext.build(
    campaign  = campaign,
    target    = "dc01.corp.local",
    module_id = "ad.kerberoast",
    params    = {"domain": "CORP"},
    credentials = vault.credentials_for_reuse(),
    session   = operator_session,
)
findings, raw = await module.run(**ctx.params)   # legacy
result = await module.execute(ctx)               # v0.9.0
```

### 4. Error Hierarchy

```
AresError
├── ModuleError (retry)
│   ├── ModuleValidationError (abort)
│   ├── ModuleTimeoutError (retry with backoff)
│   └── ModuleNotFoundError (abort)
├── NetworkError (retry with jitter)
│   ├── ConnectionRefused (fallback)
│   ├── ConnectionTimeout (retry)
│   ├── HostUnreachable (skip)
│   └── RateLimited (pause)
├── CredentialError (try next cred)
│   ├── AuthenticationFailed (try next)
│   ├── AccountLocked (ABORT — never retry)
│   └── CredentialExpired (skip)
├── ExecutionError
│   ├── SandboxError (skip)
│   └── WorkerCrashed (requeue)
├── ScopeError (ABORT — never retry)
├── OpsecError (pause/adjust profile)
│   ├── DetectionSignal (escalate profile)
│   └── HoneypotDetected (ABORT campaign)
└── PermissionError (fallback → privesc)
    └── InsufficientPrivilege (suggest privesc module)
```

### 5. DI Container

```python
# Production
container = AresContainer.production(settings)
engine    = container.engine()

# Testing
container = AresContainer.for_test()
container.override("vault", MockVault())
module = container.build_module("ad.kerberoast", campaign)
```

---

## Data Flow

### Single Module Execution

```
CLI: ares module run ad.kerberoast --target dc01
  │
  ▼
AresContainer.build_context(campaign, "dc01", "ad.kerberoast")
  │
  ▼
CampaignGuardrail.check("ad.kerberoast", "dc01")
  │  (abort if out of scope)
  ▼
BaseModule.validate(ctx)
  │  (abort if context insufficient)
  ▼
ClusterController.submit("ad.kerberoast", campaign_id, params)
  │
  ▼
ClusterWorkerNode claims task
  │
  ▼
SandboxRunner.run_module() [TIER_1 subprocess]
  │
  ▼
BaseModule.execute(ctx) → ModuleResult
  │
  ▼
ArtifactIntelEngine.process(artifacts) → queue next modules
  │
  ▼
TelemetryCollector.record_execution(...)
  │
  ▼
CheckpointManager.save(...)
  │
  ▼
BaseModule.report(result) → report fragment
```

### Attack Chain (Goal-Based)

```
GoalEngine("domain_admin")
  │
  ├── Phase 1: Recon
  │     ad.enum_users → ad.enum_spn → ad.enum_computers
  │
  ├── Phase 2: Credential Access
  │     ad.kerberoast → credential.crack → vault.mark_cracked()
  │       └── FALLBACK: ad.asreproast (AdaptiveAttackStrategy)
  │
  ├── Phase 3: Lateral Movement
  │     ArtifactCorrelationEngine finds opportunity
  │     lateral.psexec → OperatorSession.mark_owned()
  │       └── FALLBACK: lateral.wmiexec (if psexec blocked by EDR)
  │
  └── Phase 4: DA Escalation
        ad.dcsync → vault.add() all domain hashes
```

---

## Noise / OpSec Profiles

| Profile | Jitter | RPM | Description |
|---------|--------|-----|-------------|
| `stealth` | 3–15s (Pareto) | 10 | Evade EDR, only SILENT/LOW modules |
| `normal` | 0.5–5s (triangular) | 30 | Balanced (default) |
| `aggressive` | 0–300ms (uniform) | 200 | Speed over stealth |

HIGH_NOISE modules (psexec, dcsync) are automatically blocked in `stealth` profile.

---

## Security Model

See [security-model.md](security-model.md) for full details.

Key properties:
- All credentials encrypted at rest (Fernet)
- All checkpoints encrypted at rest (Fernet)
- JWT for API authentication
- ScopeGuard prevents out-of-scope operations
- CampaignGuardrail requires operator confirmation for HIGH_RISK modules
- SandboxRunner isolates community modules in subprocess/Docker
- Module signatures required for marketplace plugins
- Audit log for all executions (structlog NDJSON)

---

## Directory Structure

```
ARES/
├── ares/
│   ├── core/           Engine, context, errors, DI, config, security
│   ├── modules/        AD, Linux, Cloud, Reporting modules
│   ├── lateral/        Lateral movement (psexec/wmiexec/winrm/ssh/rdp)
│   ├── credential/     Vault, reuse engine, cracking pipeline
│   ├── goal/           Goal engine, adaptive attack strategy
│   ├── state/          OperatorSession, HostState, CompromiseLevel
│   ├── artifact_intel/ Rule engine, correlation engine
│   ├── normalize/      ArtifactStore and all artifact types
│   ├── network/        NetworkModel, pivot routing
│   ├── technique/      MITRE ATT&CK library, technique mapper
│   ├── pivot/          PivotManager, tunnel/port-forward management
│   ├── checkpoint/     Campaign pause/resume with encryption
│   ├── telemetry/      Metrics collection, Prometheus export
│   ├── fingerprint/    Environment fingerprinting (OS/EDR/AV)
│   ├── collab/         Multi-operator sessions and role management
│   ├── knowledge/      Attack KB, evidence store, guardrail, obfuscation
│   ├── worker/         Cluster controller, sandbox isolation
│   ├── replay/         Campaign replay (full/simulate/purple/timeline)
│   ├── graph/          Attack graph (NetworkX DiGraph)
│   ├── marketplace/    Plugin installer, signed registry
│   ├── service_intel/  Port scan + service fingerprint
│   ├── api/            FastAPI server + WebSocket dashboard
│   └── cli/            Click commands (campaign/module/report/target/chain)
├── docs/               Architecture, module SDK, API reference, security
├── tests/
│   ├── unit/           pytest unit tests (test_v5 through test_v9)
│   └── integration/    End-to-end campaign tests
└── docker/             Dockerfile, docker-compose.yml
```
