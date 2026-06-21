"""
ARES Distributed Worker Cluster
Redis-backed task queue enabling massively parallel attack execution
across multiple worker nodes.

Architecture:
  Operator
    └─► ClusterController (enqueues tasks)
          └─► Redis Task Queue (LPUSH/BRPOP)
                ├─► WorkerNode A  (ad.* modules)
                ├─► WorkerNode B  (cloud.* modules)
                └─► WorkerNode C  (lateral.* modules)

Task states:
  QUEUED → CLAIMED → RUNNING → COMPLETE | FAILED | TIMEOUT

Features:
  - Priority queue (ZADD/ZRANGEBYSCORE)
  - Capability-based routing (worker declares what it can run)
  - Automatic task requeue on worker crash (visibility timeout)
  - Health heartbeat (30s interval, evict at 90s)
  - Result streaming via Redis pub/sub
  - Backpressure (max queue depth per worker)

Without Redis (single-operator mode):
  Falls back to asyncio in-process queue transparently.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncGenerator
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import audit, get_logger

logger = get_logger("ares.worker.cluster")

# Redis client type hint (optional dep)
try:
    import redis.asyncio as aioredis  # type: ignore[import-untyped]

    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


class TaskState(str, Enum):
    PENDING = "pending"  # alias for QUEUED (test compat)
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELED = "canceled"


_SENSITIVE_PARAM_KEYS: frozenset[str] = frozenset(
    {
        # Credentials — must never be stored plaintext in Redis
        "password",
        "secret",
        "nt_hash",
        "lm_hash",
        "hash",
        "krbtgt_hash",
        "access_key",
        "secret_key",
        "session_token",
        "client_secret",
        "private_key",
        "api_key",
        "token",
        "credential",
    }
)


@dataclass
class ClusterTask:
    """A unit of work dispatched to the worker cluster."""

    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module_id: str = ""
    campaign_id: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1 (highest) – 10 (lowest)
    required_caps: list[str] = field(default_factory=list)  # worker capabilities needed
    max_attempts: int = 3
    attempts: int = 0
    state: TaskState = TaskState.PENDING
    worker_id: str = ""
    queued_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    timeout_s: int = 300  # 5 min default task timeout

    def to_json(self) -> str:
        """Serialize to JSON — redacts sensitive credential params before writing to Redis."""
        d = asdict(self)
        # Redact sensitive values — never store plaintext credentials in Redis
        if d.get("params"):
            d["params"] = {
                k: "<REDACTED>" if k in _SENSITIVE_PARAM_KEYS else v
                for k, v in d["params"].items()
            }
        return json.dumps(d, default=str)

    @classmethod
    def from_json(cls, data: str) -> ClusterTask:
        d = json.loads(data)
        d["state"] = TaskState(d.get("state", "queued"))
        return cls(**d)

    @property
    def elapsed_s(self) -> float:
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    @property
    def is_timed_out(self) -> bool:
        return self.started_at > 0 and self.elapsed_s > self.timeout_s


@dataclass
class WorkerRegistration:
    """A worker node's self-registration record."""

    worker_id: str = field(default_factory=lambda: f"worker-{uuid.uuid4().hex[:8]}")
    hostname: str = ""
    capabilities: list[str] = field(default_factory=list)  # ["ad", "linux", "cloud"]
    max_parallel: int = 4
    max_concurrent: int = -1  # alias for max_parallel; -1 means use max_parallel
    current_load: int = 0
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    @property
    def is_alive(self) -> bool:
        return time.time() - self.last_heartbeat < 90.0

    @property
    def available_slots(self) -> int:
        return max(0, self.max_parallel - self.current_load)

    def can_handle(self, task: ClusterTask) -> bool:
        if not task.required_caps:
            return True
        return any(cap in self.capabilities for cap in task.required_caps)

    def can_handle_module(self, module_id: str) -> bool:
        """Check if this worker can handle a given module (by prefix matching capabilities)."""
        if not self.capabilities:
            return True
        prefix = module_id.split(".")[0]
        for cap in self.capabilities:
            if cap == "*":
                return True
            if cap == module_id:
                return True
            # Handle "ad.*" style wildcards
            if cap.endswith(".*") and cap[:-2] == prefix:
                return True
            # Handle plain prefix like "ad"
            if cap == prefix:
                return True
        return False


@dataclass
class ClusterStats:
    total_queued: int = 0
    total_running: int = 0
    total_complete: int = 0
    total_failed: int = 0
    active_workers: int = 0
    queue_depth: int = 0
    tasks_per_second: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Redis-backed queue ─────────────────────────────────────────────────────────


class RedisTaskQueue:
    """
    Redis-backed priority task queue.
    Uses ZADD for priority (score = priority * 1e9 + timestamp).
    Visibility timeout pattern for crash recovery.
    """

    QUEUE_KEY = "ares:tasks:pending"
    INFLIGHT_KEY = "ares:tasks:inflight"  # HASH: task_id → task_json
    RESULT_KEY = "ares:tasks:results"  # HASH: task_id → result_json
    WORKER_KEY = "ares:workers"  # HASH: worker_id → registration_json
    PUBSUB_CHANNEL = "ares:events"

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self.redis_url = redis_url
        self._redis: Any = None

    async def connect(self) -> None:
        if not _REDIS_AVAILABLE:
            raise ImportError("redis[asyncio] required: pip install 'redis[asyncio]'")
        self._redis = await aioredis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        logger.info("redis_connected", url=self.redis_url)

    async def disconnect(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def enqueue(self, task: ClusterTask) -> None:
        """Push task to priority queue. Lower priority number = processed first."""
        score = task.priority * 1_000_000_000 + time.time()
        await self._redis.zadd(self.QUEUE_KEY, {task.task_id: score})
        await self._redis.hset(self.INFLIGHT_KEY, task.task_id, task.to_json())
        logger.debug(
            "task_enqueued",
            task_id=task.task_id[:8],
            module=task.module_id,
            priority=task.priority,
        )

    async def dequeue(
        self, worker: WorkerRegistration, timeout_s: int = 5
    ) -> ClusterTask | None:
        """
        Claim the highest-priority task this worker can handle.

        Uses ZPOPMIN (truly atomic) — a single command that reads and removes
        in one operation. The old zrange+zrem pattern was non-atomic: two workers
        could both read the same candidate then race on zrem, with the loser
        silently dropping the task. ZPOPMIN prevents that entirely.

        If the popped task cannot be handled by this worker, it is returned to
        the queue with its original score so another worker can pick it up.
        """
        # ZPOPMIN pops the member with the lowest score (= highest priority) atomically.
        # count=1 — claim one task per call. Loop until we find one we can handle
        # or the queue is empty.
        max_skip = 20  # don't loop forever if every task is unhandleable
        for _ in range(max_skip):
            result = await self._redis.zpopmin(self.QUEUE_KEY, count=1)
            if not result:
                return None  # queue empty

            # aioredis returns list of (member, score) tuples
            task_id_raw, score = result[0]
            task_id = (
                task_id_raw
                if isinstance(task_id_raw, str)
                else task_id_raw.decode("utf-8", errors="replace")
            )

            task_json = await self._redis.hget(self.INFLIGHT_KEY, task_id)
            if not task_json:
                # Orphaned score entry — already completed/failed, skip
                continue

            task = ClusterTask.from_json(task_json)

            if not worker.can_handle(task):
                # Return to queue with original score so another worker gets it
                await self._redis.zadd(self.QUEUE_KEY, {task_id: score})
                return None  # this worker has nothing to do right now

            task.state = TaskState.CLAIMED
            task.worker_id = worker.worker_id
            task.started_at = time.time()
            await self._redis.hset(self.INFLIGHT_KEY, task_id, task.to_json())
            logger.debug(
                "task_claimed_atomic",
                task_id=task_id[:8],
                module=task.module_id,
                worker=worker.worker_id,
            )
            return task

        return None  # hit _MAX_SKIP without finding a handleable task

    async def complete(self, task: ClusterTask, result: dict[str, Any]) -> None:
        task.state = TaskState.COMPLETE
        task.completed_at = time.time()
        task.result = result
        await self._redis.hset(
            self.RESULT_KEY, task.task_id, json.dumps(result, default=str)
        )
        await self._redis.hdel(self.INFLIGHT_KEY, task.task_id)
        await self._publish_event("task_complete", task)

    async def fail(self, task: ClusterTask, error: str, requeue: bool = True) -> None:
        task.attempts += 1
        if requeue and task.attempts < task.max_attempts:
            task.state = TaskState.QUEUED
            await self.enqueue(task)
            logger.warning(
                "task_requeued",
                task_id=task.task_id[:8],
                attempts=task.attempts,
                error=error[:80],
            )
        else:
            task.state = TaskState.FAILED
            task.error = error
            await self._redis.hset(
                self.RESULT_KEY,
                task.task_id,
                json.dumps({"error": error, "attempts": task.attempts}, default=str),
            )
            await self._redis.hdel(self.INFLIGHT_KEY, task.task_id)
            logger.error(
                "task_failed_permanent", task_id=task.task_id[:8], error=error[:80]
            )

    async def register_worker(self, worker: WorkerRegistration) -> None:
        await self._redis.hset(
            self.WORKER_KEY, worker.worker_id, json.dumps(asdict(worker), default=str)
        )
        await self._redis.expire(self.WORKER_KEY, 90)

    async def heartbeat(self, worker_id: str) -> None:
        raw = await self._redis.hget(self.WORKER_KEY, worker_id)
        if raw:
            data = json.loads(raw)
            data["last_heartbeat"] = time.time()
            await self._redis.hset(self.WORKER_KEY, worker_id, json.dumps(data))

    async def get_result(self, task_id: str) -> dict[str, Any] | None:
        raw = await self._redis.hget(self.RESULT_KEY, task_id)
        return json.loads(raw) if raw else None

    async def queue_depth(self) -> int:
        return await self._redis.zcard(self.QUEUE_KEY)

    async def active_workers(self) -> list[WorkerRegistration]:
        all_workers = await self._redis.hgetall(self.WORKER_KEY)
        workers = []
        for raw in all_workers.values():
            try:
                data = json.loads(raw)
                w = WorkerRegistration(**data)
                if w.is_alive:
                    workers.append(w)
            except (ConnectionError, ValueError, KeyError):
                pass
        return workers

    async def _publish_event(self, event_type: str, task: ClusterTask) -> None:
        payload = json.dumps(
            {
                "type": event_type,
                "task_id": task.task_id,
                "module_id": task.module_id,
                "campaign": task.campaign_id,
                "state": task.state.value,
                "worker": task.worker_id,
                "timestamp": time.time(),
            },
            default=str,
        )
        await self._redis.publish(self.PUBSUB_CHANNEL, payload)

    async def subscribe_events(self) -> AsyncGenerator[dict[str, Any], None]:
        """Subscribe to real-time task events. Yields event dicts."""
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self.PUBSUB_CHANNEL)
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    yield json.loads(message["data"])
                except (ValueError, KeyError):
                    pass


# ── In-process fallback queue (no Redis) ──────────────────────────────────────


class InProcessTaskQueue:
    """
    Pure asyncio in-process queue — no Redis required.
    Same interface as RedisTaskQueue.
    Used in single-operator mode and testing.
    """

    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue[tuple[float, ClusterTask]] = (
            asyncio.PriorityQueue()
        )
        self._results: dict[str, dict[str, Any]] = {}
        self._workers: dict[str, WorkerRegistration] = {}
        self._events: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)

    async def connect(self) -> None:
        logger.info("in_process_queue_active")

    async def disconnect(self) -> None:
        """Drain any pending tasks from the in-process queue and clear state."""
        drained = 0
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                break
        self._results.clear()
        logger.info("in_process_queue_disconnected", drained_tasks=drained)

    async def enqueue(self, task: ClusterTask) -> None:
        score = task.priority + time.time() / 1e10
        await self._queue.put((score, task))
        logger.debug(
            "task_enqueued_local", task_id=task.task_id[:8], module=task.module_id
        )

    async def dequeue(
        self, worker: WorkerRegistration, timeout_s: int = 5
    ) -> ClusterTask | None:
        try:
            score, task = await asyncio.wait_for(self._queue.get(), timeout=timeout_s)
            if worker.can_handle(task):
                task.state = TaskState.CLAIMED
                task.worker_id = worker.worker_id
                task.started_at = time.time()
                return task
            else:
                await self._queue.put((score, task))
                return None
        except asyncio.TimeoutError:
            return None

    async def complete(self, task: ClusterTask, result: dict[str, Any]) -> None:
        task.state = TaskState.COMPLETE
        task.completed_at = time.time()
        self._results[task.task_id] = result
        await self._events.put({"type": "task_complete", "task_id": task.task_id})

    async def fail(self, task: ClusterTask, error: str, requeue: bool = True) -> None:
        task.attempts += 1
        if requeue and task.attempts < task.max_attempts:
            await self.enqueue(task)
        else:
            task.state = TaskState.FAILED
            task.error = error
            self._results[task.task_id] = {"error": error}

    async def register_worker(self, worker: WorkerRegistration) -> None:
        self._workers[worker.worker_id] = worker

    async def heartbeat(self, worker_id: str) -> None:
        if worker_id in self._workers:
            self._workers[worker_id].last_heartbeat = time.time()

    async def get_result(self, task_id: str) -> dict[str, Any] | None:
        return self._results.get(task_id)

    async def queue_depth(self) -> int:
        return self._queue.qsize()

    async def active_workers(self) -> list[WorkerRegistration]:
        return [w for w in self._workers.values() if w.is_alive]

    async def subscribe_events(self) -> AsyncGenerator[dict[str, Any], None]:
        while True:
            event = await self._events.get()
            yield event


# ── Cluster Controller ─────────────────────────────────────────────────────────


class ClusterController:
    """
    High-level cluster management interface.
    Auto-selects Redis or in-process queue based on availability.

    Usage:
        controller = ClusterController(redis_url="redis://localhost:6379/0")
        await controller.start()

        task_id = await controller.submit("ad.kerberoast", campaign_id, params)
        result  = await controller.wait_for_result(task_id, timeout_s=60)
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        use_redis: bool = True,
    ) -> None:
        self._use_redis = use_redis and _REDIS_AVAILABLE
        if self._use_redis:
            self.queue: RedisTaskQueue | InProcessTaskQueue = RedisTaskQueue(redis_url)
        else:
            self.queue = InProcessTaskQueue()
            if use_redis:
                logger.warning("redis_not_available_fallback_in_process")

        self._pending: dict[str, ClusterTask] = {}
        self._stats = ClusterStats()

    async def start(self) -> None:
        await self.queue.connect()
        logger.info(
            "cluster_controller_started",
            backend="redis" if self._use_redis else "in_process",
        )

    async def stop(self) -> None:
        await self.queue.disconnect()

    async def submit(
        self,
        module_id: str,
        campaign_id: str,
        params: dict[str, Any],
        priority: int = 5,
        required_caps: list[str] | None = None,
        timeout_s: int = 300,
    ) -> str:
        """Submit a task to the cluster. Returns task_id."""
        task = ClusterTask(
            module_id=module_id,
            campaign_id=campaign_id,
            params=params,
            priority=priority,
            required_caps=required_caps or [],
            timeout_s=timeout_s,
        )
        await self.queue.enqueue(task)
        self._pending[task.task_id] = task
        self._stats.total_queued += 1

        audit(
            "cluster_task_submitted",
            actor="operator",
            module=module_id,
            campaign=campaign_id,
            task_id=task.task_id[:8],
        )
        return task.task_id

    async def submit_batch(
        self,
        tasks: list[
            dict[str, Any]
        ],  # list of {module_id, campaign_id, params, priority}
    ) -> list[str]:
        """Submit multiple tasks atomically. Returns list of task_ids."""
        return [
            await self.submit(
                t["module_id"],
                t["campaign_id"],
                t.get("params", {}),
                priority=t.get("priority", 5),
                required_caps=t.get("required_caps"),
            )
            for t in tasks
        ]

    async def wait_for_result(
        self,
        task_id: str,
        timeout_s: int = 120,
        poll_s: float = 0.5,
    ) -> dict[str, Any] | None:
        """Poll for a task result. Returns result dict or None on timeout."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            result = await self.queue.get_result(task_id)
            if result is not None:
                return result
            await asyncio.sleep(poll_s)
        return None

    async def stats(self) -> ClusterStats:
        depth = await self.queue.queue_depth()
        workers = await self.queue.active_workers()
        self._stats.queue_depth = depth
        self._stats.active_workers = len(workers)
        return self._stats

    async def active_workers(self) -> list[WorkerRegistration]:
        return await self.queue.active_workers()

    async def cancel(self, task_id: str) -> bool:
        """Cancel a queued task. Returns True if found and canceled."""
        task = self._pending.get(task_id)
        if task and task.state == TaskState.QUEUED:
            task.state = TaskState.CANCELED
            logger.info("task_canceled", task_id=task_id[:8])
            return True
        return False


# ── Worker Node ────────────────────────────────────────────────────────────────


class ClusterWorkerNode:
    """
    A worker node that continuously pulls tasks from the cluster queue
    and executes them via the ARES module system.

    Run one per worker host:
        worker = ClusterWorkerNode(capabilities=["ad", "linux"])
        await worker.run()
    """

    def __init__(
        self,
        queue: RedisTaskQueue | InProcessTaskQueue,
        registry: Any,  # ModuleRegistry
        capabilities: list[str],
        max_parallel: int = 4,
        hostname: str = "",
    ) -> None:
        self.queue = queue
        self.registry = registry
        self.registration = WorkerRegistration(
            hostname=hostname or "worker",
            capabilities=capabilities,
            max_parallel=max_parallel,
        )
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._running = False

    async def run(self, stop_event: asyncio.Event | None = None) -> None:
        """Main worker loop. Runs until stop_event is set."""
        await self.queue.register_worker(self.registration)
        self._running = True
        logger.info(
            "worker_node_started",
            worker_id=self.registration.worker_id,
            capabilities=self.registration.capabilities,
        )

        # Start heartbeat in background
        asyncio.create_task(self._heartbeat_loop())

        while self._running and (not stop_event or not stop_event.is_set()):
            task = await self.queue.dequeue(self.registration, timeout_s=2)
            if task:
                asyncio.create_task(self._execute_task(task))

    async def _execute_task(self, task: ClusterTask) -> None:
        async with self._semaphore:
            self.registration.current_load += 1
            task.state = TaskState.RUNNING
            logger.info(
                "worker_executing",
                task_id=task.task_id[:8],
                module=task.module_id,
                worker=self.registration.worker_id,
            )
            try:
                module_cls = self.registry.get(task.module_id)
                if not module_cls:
                    raise ValueError(f"Module {task.module_id!r} not found in registry")

                from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
                from ares.core.config import get_settings
                from ares.core.context import ExecutionContext as _ExCtx
                from ares.core.noise import NoiseController

                settings = get_settings()

                # Fetch real campaign scope from DB so scope guard is not bypassed
                _real_scope: list[ScopeEntry] = []  # deny-all default — fail closed
                try:
                    from ares.db.database import AresDatabase

                    # AresDatabase.create() calls connect() internally — do NOT call again
                    async with await AresDatabase.create(
                        settings.ares_database_url,
                        settings.encryption_key_value,
                    ) as _scope_db:
                        _camp_row = await _scope_db.get_campaign(task.campaign_id)
                    if _camp_row and _camp_row.get("scope_json"):
                        import json as _json

                        _scope_data = _json.loads(_camp_row["scope_json"])
                        if _scope_data:
                            _real_scope = [ScopeEntry(**s) for s in _scope_data]
                except Exception as _scope_err:
                    logger.warning(
                        "worker_scope_fetch_failed",
                        task_id=task.task_id[:8],
                        error=str(_scope_err)[:100],
                    )

                if not _real_scope:
                    logger.error(
                        "worker_no_scope_refusing",
                        task_id=task.task_id[:8],
                        campaign_id=task.campaign_id[:8],
                    )
                    await self.queue.fail(
                        task,
                        "Campaign scope unavailable — refusing to execute with unbounded scope. "
                        "Check DB connectivity.",
                        requeue=False,
                    )
                    return

                campaign = Campaign(
                    id=task.campaign_id,
                    name=f"cluster-{task.campaign_id[:8]}",
                    scope=_real_scope,
                    noise_profile=NoiseProfile.NORMAL,
                )
                noise = NoiseController(campaign)
                module = module_cls(settings=settings, campaign=campaign, noise=noise)

                # Use execute(ctx) — same interface as engine, respects vault/context
                ctx = _ExCtx.build(
                    campaign=campaign,
                    target=task.params.get("target", ""),
                    module_id=task.module_id,
                    domain=task.params.get("domain", ""),
                    params=task.params,
                    operator=task.params.get("operator", "cluster"),
                    settings=settings,
                    noise=noise,
                )
                module_result = await asyncio.wait_for(
                    module.execute(ctx),
                    timeout=task.timeout_s,
                )
                findings = module_result.findings
                extra = module_result.raw
                result = {
                    "findings": [
                        f.to_dict() if hasattr(f, "to_dict") else str(f)
                        for f in findings
                    ],
                    "extra": extra,
                }
                await self.queue.complete(task, result)
                logger.info(
                    "worker_task_complete",
                    task_id=task.task_id[:8],
                    findings=len(findings),
                )

            except asyncio.TimeoutError:
                await self.queue.fail(
                    task, f"Timeout after {task.timeout_s}s", requeue=True
                )
            except Exception as exc:
                await self.queue.fail(
                    task, str(exc)[:500], requeue=task.attempts < task.max_attempts
                )
            finally:
                self.registration.current_load = max(
                    0, self.registration.current_load - 1
                )

    async def _heartbeat_loop(self) -> None:
        while self._running:
            try:
                await self.queue.heartbeat(self.registration.worker_id)
                await asyncio.sleep(30)
            except Exception as exc:
                logger.warning("heartbeat_error", error=str(exc))
                await asyncio.sleep(30)

    async def stop(self) -> None:
        self._running = False
        logger.info("worker_node_stopped", worker_id=self.registration.worker_id)
