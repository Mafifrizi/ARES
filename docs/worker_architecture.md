# ARES Worker Architecture

**Version:** 1.0.0 | **Status:** Active

## Overview

ARES executes modules in isolated workers — never in the engine main process. This prevents a buggy or malicious module from crashing the engine.

```
                    ┌─────────────────────────────────────────┐
                    │              Engine Process              │
                    │                                         │
Operator/API  ──→   │  AresEngine → ClusterController         │
                    │                    │                    │
                    │              TaskQueue                  │
                    │           (Redis or asyncio)            │
                    └──────────────────┬──────────────────────┘
                                       │ task dispatch
                    ┌──────────────────┴──────────────────────┐
                    │            Worker Layer                  │
                    │                                         │
                    │  WorkerNode   WorkerNode   WorkerNode   │
                    │      │            │             │       │
                    │  subprocess   subprocess   subprocess   │
                    │  (isolated)   (isolated)   (isolated)   │
                    └─────────────────────────────────────────┘
```

---

## Task Queue

`ClusterController` supports two backends, auto-selected:

| Backend       | When used                              | Config                  |
|---------------|----------------------------------------|-------------------------|
| Redis         | Redis available at `ARES_REDIS_URL`    | Production / multi-node |
| In-process    | No Redis (default)                     | Dev / single-node       |

Both backends have identical API — engine never knows which is active.

**Redis task format:**

```python
@dataclass
class ClusterTask:
    task_id:     str              # UUID
    module_id:   str              # "ad.kerberoast"
    campaign_id: str
    params:      dict[str, Any]
    priority:    int = 5          # 1 (highest) – 10 (lowest)
    max_retries: int = 3
    timeout_s:   int = 300
    state:       TaskState        # QUEUED → CLAIMED → RUNNING → COMPLETE|FAILED
    capabilities: list[str]       # CAP_NET, CAP_EXEC, etc.
    resource_limits: dict         # cpu_time_s, memory_mb, max_procs
```

Tasks stored in Redis sorted set (ZADD by priority). Visibility timeout prevents stuck tasks.

---

## WorkerNode

Each worker node:
1. Registers with capability declaration: `["ad", "linux", "cloud"]`
2. Polls task queue for matching tasks
3. Executes via `SandboxRunner`
4. Reports result back to queue
5. Sends heartbeat every 30s (evicted if missed 3× heartbeats)

```python
class WorkerNode:
    capabilities: list[str]       # which module categories this worker handles
    max_parallel:  int = 4        # concurrent tasks (semaphore-limited)
    worker_id:    str             # UUID
```

---

## Sandbox Tiers

`SandboxRunner` selects the appropriate isolation tier per module:

```
IsolationTier.NONE        → core modules run in-process (no isolation)
IsolationTier.SUBPROCESS  → resource limits via setrlimit
IsolationTier.SECCOMP     → + syscall filter (Linux only)
IsolationTier.DOCKER      → full container isolation
```

Selection logic:

```python
if module.trust_level == "builtin":
    tier = IsolationTier.NONE        # fully trusted core modules
elif module.trust_level == "community":
    tier = IsolationTier.SUBPROCESS  # resource limits
elif module.trust_level == "external":
    tier = IsolationTier.SECCOMP     # syscall filter
else:  # unsigned
    tier = IsolationTier.DOCKER      # full container
```

---

## Subprocess Worker Protocol

When `IsolationTier.SUBPROCESS` is used, ARES spawns:

```
python -m ares.worker._subprocess_worker
```

**Communication protocol (JSON over stdin/stdout):**

```
Engine → Worker (stdin):
{
    "module_id":      "ad.kerberoast",
    "campaign_id":    "abc123",
    "params":         {"dc": "10.0.0.1", "domain": "CORP"},
    "capabilities":   ["cap_net", "cap_db"],
    "resource_limits": {"cpu_time_s": 30, "memory_mb": 256}
}

Worker → Engine (stdout):
{
    "success":  true,
    "findings": [...],
    "raw":      {...}
}
```

**Security controls in subprocess worker (v1.0.0):**

```python
# 1. Apply resource limits FIRST (before module code loads)
apply_capability_limits(caps, limits)
  → resource.setrlimit(RLIMIT_CPU)
  → resource.setrlimit(RLIMIT_AS)
  → resource.setrlimit(RLIMIT_NPROC)  # 1 if no CAP_EXEC
  → resource.setrlimit(RLIMIT_NOFILE)

# 2. Load module from registry

# 3. Check capability boundary AFTER load
check_capability_boundary(module_id, caps)
  → detect if module loaded subprocess/os.system without CAP_EXEC
  → exit(2) on violation

# 4. Execute module
```

**Exit codes:**

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | Success (even if module found nothing) |
| 1    | Unhandled exception                  |
| 2    | Capability boundary violation        |

---

## Capability System

Each module declares `CAPABILITIES`:

```python
class KerberoastModule(BaseModule):
    CAPABILITIES = {Capability.CAP_NET, Capability.CAP_DB}
```

If not declared, defaults are inferred from `MODULE_CATEGORY`.

**Capability → allowed syscalls (seccomp):**

| Capability    | Added syscalls                                     |
|---------------|----------------------------------------------------|
| `CAP_NET`     | socket, connect, bind, sendto, recvfrom, ...       |
| `CAP_EXEC`    | execve, fork, vfork, clone, pipe, wait4, ...       |
| `CAP_FS`      | mkdir, unlink, rename, chmod, truncate, ...        |
| `CAP_PROCESS` | ptrace, kill, tkill, getdents, ...                 |
| `CAP_UNSAFE`  | all syscalls (no filter — builtin only)            |

**Capability allowed per trust level:**

| Trust level   | Allowed capabilities                               |
|---------------|----------------------------------------------------|
| `builtin`     | All (including CAP_UNSAFE)                        |
| `community`   | CAP_NET, CAP_DB, CAP_FS                           |
| `external`    | CAP_NET, CAP_DB                                   |
| `unsigned`    | CAP_NET only                                      |

Violations at load time → module rejected, error logged.
Violations at runtime → subprocess exits(2), engine logs alert.

---

## Resource Limits

Default limits applied to all subprocess workers:

| Limit         | Default  | With CAP_EXEC |
|---------------|----------|---------------|
| CPU time      | 30s      | 120s          |
| Memory (AS)   | 256 MB   | 512 MB        |
| Max processes | 1        | 8             |
| Max open FDs  | 64       | 64            |

Override via `ClusterTask.resource_limits`.

---

## Worker Health & Telemetry

`TelemetryCollector` tracks per-worker:

```python
@dataclass
class TelemetrySnapshot:
    total_modules_run:   int
    successful_modules:  int
    failed_modules:      int
    p50_execution_ms:    float
    p95_execution_ms:    float
    p99_execution_ms:    float
    error_rate:          float
    worker_health:       dict[str, str]   # worker_id → healthy|degraded|offline
    queue_depth:         int
    findings_total:      int
    alerts:              list[str]
```

Prometheus endpoint: `GET /telemetry/prometheus`

Alerts triggered when:
- Error rate > 20%
- Worker offline (missed 3 heartbeats)
- Queue depth > 100 (backlog)

---

## Adding a Worker Node

To add capacity, start another worker process:

```bash
# Local worker
ares worker start --capabilities ad linux --parallel 4

# Remote worker (connects to Redis)
ARES_REDIS_URL=redis://redis:6379 ares worker start --capabilities cloud
```

Workers auto-register and receive tasks matching their capability set.
For Docker deployment, see `docker/docker-compose.prod.yml`; for local Docker
development, see `docker/docker-compose.dev.yml`.
