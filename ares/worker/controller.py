"""
ARES Distributed Worker System
Controller–Worker architecture for distributed red team scanning.

Architecture:
  ┌─────────────────────────────────────────────────────────┐
  │                    Controller Node                       │
  │  WorkerController                                        │
  │   ├── TaskQueue (asyncio.Queue + persistence)           │
  │   ├── WorkerRegistry (tracks live workers + heartbeat)  │
  │   └── ResultCollector (merges findings into campaign)   │
  └──────────────────────┬──────────────────────────────────┘
                         │ HTTP/WebSocket (FastAPI)
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         Worker-1    Worker-2    Worker-3
         (AD ops)    (Cloud)     (Linux)

Workers register with the controller on startup.
Controller distributes tasks based on worker capabilities.
Workers send results back + heartbeat every 30s.
Dead workers are evicted; tasks are requeued.

Transport: HTTP (simple, firewall-friendly).
Authentication: shared API key per engagement (rotated per campaign).
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.worker.controller")


# ── Task model ────────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    QUEUED     = "queued"
    ASSIGNED   = "assigned"
    RUNNING    = "running"
    DONE       = "done"
    FAILED     = "failed"
    REQUEUED   = "requeued"


@dataclass
class WorkerTask:
    task_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    module_id:   str = ""
    params:      dict[str, Any] = field(default_factory=dict)
    priority:    int = 5           # 1 = highest, 10 = lowest
    status:      TaskStatus = TaskStatus.QUEUED
    assigned_to: str | None = None
    created_at:  float = field(default_factory=time.monotonic)
    started_at:  float | None = None
    done_at:     float | None = None
    attempts:    int = 0
    max_attempts: int = 3
    result:      dict[str, Any] | None = None
    error:       str | None = None


# ── Worker registry ───────────────────────────────────────────────────────────

@dataclass
class WorkerInfo:
    worker_id:    str
    hostname:     str
    capabilities: list[str]     # module categories this worker can run: ["ad", "linux"]
    current_tasks: list[str] = field(default_factory=list)
    max_tasks:    int = 3
    last_heartbeat: float = field(default_factory=time.monotonic)
    registered_at: float = field(default_factory=time.monotonic)
    total_completed: int = 0
    total_failed:    int = 0

    @property
    def is_alive(self) -> bool:
        return (time.monotonic() - self.last_heartbeat) < 90  # 90s timeout

    @property
    def available_slots(self) -> int:
        return max(0, self.max_tasks - len(self.current_tasks))

    def can_handle(self, module_category: str) -> bool:
        return not self.capabilities or module_category in self.capabilities


class WorkerRegistry:
    """Tracks all registered workers and their health."""

    def __init__(self) -> None:
        self._workers: dict[str, WorkerInfo] = {}

    def register(self, info: WorkerInfo) -> None:
        self._workers[info.worker_id] = info
        logger.info("worker_registered", worker_id=info.worker_id,
                    hostname=info.hostname, capabilities=info.capabilities)

    def heartbeat(self, worker_id: str) -> bool:
        if worker_id in self._workers:
            self._workers[worker_id].last_heartbeat = time.monotonic()
            return True
        return False

    def deregister(self, worker_id: str) -> None:
        self._workers.pop(worker_id, None)
        logger.info("worker_deregistered", worker_id=worker_id)

    def evict_dead(self) -> list[str]:
        """Remove workers that missed too many heartbeats. Returns evicted IDs."""
        dead = [wid for wid, w in self._workers.items() if not w.is_alive]
        for wid in dead:
            logger.warning("worker_evicted_dead", worker_id=wid)
            self.deregister(wid)
        return dead

    def best_worker_for(self, category: str) -> WorkerInfo | None:
        """Return the least-loaded alive worker that can handle this category."""
        candidates = [
            w for w in self._workers.values()
            if w.is_alive and w.available_slots > 0 and w.can_handle(category)
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda w: len(w.current_tasks))

    def all_workers(self) -> list[WorkerInfo]:
        return list(self._workers.values())

    def alive_count(self) -> int:
        return sum(1 for w in self._workers.values() if w.is_alive)


# ── Task Queue ────────────────────────────────────────────────────────────────

class TaskQueue:
    """Priority-based async task queue with requeue-on-worker-death."""

    def __init__(self) -> None:
        self._pending:  list[WorkerTask] = []
        self._active:   dict[str, WorkerTask] = {}   # task_id → task
        self._done:     dict[str, WorkerTask] = {}
        self._lock:     asyncio.Lock = asyncio.Lock()
        self._event:    asyncio.Event = asyncio.Event()

    async def enqueue(self, task: WorkerTask) -> str:
        async with self._lock:
            self._pending.append(task)
            self._pending.sort(key=lambda t: t.priority)
            self._event.set()
        logger.info("task_enqueued", task_id=task.task_id, module_id=task.module_id,
                    priority=task.priority)
        return task.task_id

    async def dequeue_for(self, worker: WorkerInfo) -> WorkerTask | None:
        """Get the next task this worker can handle."""
        async with self._lock:
            for i, task in enumerate(self._pending):
                module_cat = task.module_id.split(".")[0] if "." in task.module_id else task.module_id
                if worker.can_handle(module_cat) and worker.available_slots > 0:
                    self._pending.pop(i)
                    task.status      = TaskStatus.ASSIGNED
                    task.assigned_to = worker.worker_id
                    task.started_at  = time.monotonic()
                    task.attempts   += 1
                    self._active[task.task_id] = task
                    worker.current_tasks.append(task.task_id)
                    return task
        return None

    async def complete(self, task_id: str, result: dict[str, Any]) -> None:
        async with self._lock:
            task = self._active.pop(task_id, None)
            if not task:
                return
            task.status  = TaskStatus.DONE
            task.done_at = time.monotonic()
            task.result  = result
            self._done[task_id] = task
            # Remove from worker's current tasks
            if task.assigned_to:
                for w in []:   # injected reference needed — see WorkerController
                    if w.worker_id == task.assigned_to:
                        w.current_tasks = [t for t in w.current_tasks if t != task_id]
        logger.info("task_complete", task_id=task_id)

    async def fail(self, task_id: str, error: str) -> None:
        async with self._lock:
            task = self._active.pop(task_id, None)
            if not task:
                return
            task.error = error
            if task.attempts < task.max_attempts:
                task.status      = TaskStatus.REQUEUED
                task.assigned_to = None
                self._pending.append(task)
                self._pending.sort(key=lambda t: t.priority)
                logger.warning("task_requeued", task_id=task_id, attempts=task.attempts)
            else:
                task.status     = TaskStatus.FAILED
                self._done[task_id] = task
                logger.error("task_permanently_failed", task_id=task_id, error=error)

    async def requeue_worker_tasks(self, worker_id: str) -> int:
        """Called when a worker dies — requeue all its active tasks."""
        async with self._lock:
            requeued = 0
            for task_id, task in list(self._active.items()):
                if task.assigned_to == worker_id:
                    self._active.pop(task_id)
                    task.status      = TaskStatus.REQUEUED
                    task.assigned_to = None
                    self._pending.append(task)
                    requeued += 1
            if requeued:
                self._pending.sort(key=lambda t: t.priority)
        logger.warning("tasks_requeued_dead_worker", worker_id=worker_id, count=requeued)
        return requeued

    def stats(self) -> dict[str, int]:
        return {
            "pending":  len(self._pending),
            "active":   len(self._active),
            "done":     len([t for t in self._done.values() if t.status == TaskStatus.DONE]),
            "failed":   len([t for t in self._done.values() if t.status == TaskStatus.FAILED]),
        }


# ── Controller ────────────────────────────────────────────────────────────────

class WorkerController:
    """
    Central controller: dispatches tasks, monitors workers, collects results.

    Run with: asyncio.run(controller.start())
    Add tasks: await controller.submit(module_id, campaign_id, params)
    """

    def __init__(self, heartbeat_interval: int = 30) -> None:
        self.queue    = TaskQueue()
        self.registry = WorkerRegistry()
        self._heartbeat_interval = heartbeat_interval
        self._running = False
        self._result_callbacks: list[Any] = []

    def on_result(self, callback: Any) -> None:
        """Register a callback for when a task completes."""
        self._result_callbacks.append(callback)

    async def submit(
        self,
        module_id:   str,
        campaign_id: str,
        params:      dict[str, Any],
        priority:    int = 5,
    ) -> str:
        """Submit a module task. Returns task_id."""
        task = WorkerTask(
            campaign_id=campaign_id,
            module_id=module_id,
            params=params,
            priority=priority,
        )
        return await self.queue.enqueue(task)

    async def start(self) -> None:
        """Start the controller event loop."""
        self._running = True
        logger.info("controller_started")
        await asyncio.gather(
            self._dispatch_loop(),
            self._health_check_loop(),
        )

    async def stop(self) -> None:
        self._running = False
        logger.info("controller_stopped", stats=self.queue.stats())

    async def _dispatch_loop(self) -> None:
        """Continuously assign pending tasks to available workers."""
        while self._running:
            dispatched = False
            for worker in self.registry.all_workers():
                if not worker.is_alive or worker.available_slots == 0:
                    continue
                task = await self.queue.dequeue_for(worker)
                if task:
                    asyncio.create_task(self._execute_on_worker(task, worker))
                    dispatched = True
            if not dispatched:
                await asyncio.sleep(0.5)

    async def _execute_on_worker(self, task: WorkerTask, worker: WorkerInfo) -> None:
        """Send task to worker via HTTP POST and collect result."""
        import httpx
        url = f"http://{worker.hostname}/execute"
        try:
            async with httpx.AsyncClient(timeout=300) as client:
                resp = await client.post(url, json={
                    "task_id":    task.task_id,
                    "module_id":  task.module_id,
                    "campaign_id": task.campaign_id,
                    "params":     task.params,
                })
            if resp.status_code == 200:
                result = resp.json()
                await self.queue.complete(task.task_id, result)
                for cb in self._result_callbacks:
                    await cb(task, result)
            else:
                await self.queue.fail(task.task_id, f"HTTP {resp.status_code}")
        except Exception as e:
            await self.queue.fail(task.task_id, str(e))
        finally:
            if task.task_id in worker.current_tasks:
                worker.current_tasks.remove(task.task_id)

    async def _health_check_loop(self) -> None:
        """Evict dead workers and requeue their tasks every N seconds."""
        while self._running:
            await asyncio.sleep(self._heartbeat_interval)
            dead = self.registry.evict_dead()
            for worker_id in dead:
                requeued = await self.queue.requeue_worker_tasks(worker_id)
                logger.warning("worker_tasks_requeued", worker_id=worker_id, count=requeued)

    def dashboard_data(self) -> dict[str, Any]:
        """Snapshot for the web dashboard."""
        return {
            "queue":   self.queue.stats(),
            "workers": [
                {
                    "id":           w.worker_id,
                    "hostname":     w.hostname,
                    "capabilities": w.capabilities,
                    "alive":        w.is_alive,
                    "active_tasks": len(w.current_tasks),
                    "completed":    w.total_completed,
                    "failed":       w.total_failed,
                    "last_beat":    round(time.monotonic() - w.last_heartbeat, 1),
                }
                for w in self.registry.all_workers()
            ],
        }
