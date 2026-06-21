"""
ARES Telemetry & Health Monitoring
Real-time operational health for the framework and all components.

Metrics collected:
  - Module execution times (p50, p95, p99)
  - Task queue depth and throughput
  - Worker node health (CPU, memory, load)
  - Error rates per module
  - Credential discovery rate
  - Network I/O per protocol
  - Findings rate over time

All metrics are:
  - Stored in-memory (circular buffer)
  - Exportable as Prometheus-compatible text format
  - Available via GET /api/v1/telemetry (REST)
  - Streamed via WebSocket /ws/telemetry
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import mean, median, quantiles
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.telemetry")

_MAX_SAMPLES = 1000   # max samples per metric


@dataclass
class ExecutionMetric:
    """Single module execution timing sample."""
    module_id:   str
    duration_ms: float
    success:     bool
    timestamp:   float = field(default_factory=time.time)
    campaign_id: str = ""
    worker_id:   str = ""


@dataclass
class WorkerHealthSnapshot:
    worker_id:    str
    hostname:     str
    cpu_pct:      float = 0.0
    memory_mb:    float = 0.0
    load_avg:     float = 0.0
    active_tasks: int = 0
    queued_tasks: int = 0
    error_count:  int = 0
    uptime_s:     float = 0.0
    last_seen:    float = field(default_factory=time.time)

    @property
    def is_healthy(self) -> bool:
        return (
            time.time() - self.last_seen < 90
            and self.cpu_pct < 90
            and self.memory_mb < 1800
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id":    self.worker_id,
            "hostname":     self.hostname,
            "cpu_pct":      self.cpu_pct,
            "memory_mb":    round(self.memory_mb, 1),
            "load_avg":     self.load_avg,
            "active_tasks": self.active_tasks,
            "queued_tasks": self.queued_tasks,
            "error_count":  self.error_count,
            "uptime_s":     round(self.uptime_s),
            "healthy":      self.is_healthy,
            "last_seen_s":  round(time.time() - self.last_seen),
        }


@dataclass
class TelemetrySnapshot:
    """Point-in-time telemetry snapshot for dashboard and alerting."""
    timestamp:           float = field(default_factory=time.time)
    campaign_id:         str = ""
    total_modules_run:   int = 0
    successful_modules:  int = 0
    failed_modules:      int = 0
    error_rate:          float = 0.0
    queue_depth:         int = 0
    active_workers:      int = 0
    unhealthy_workers:   int = 0
    findings_total:      int = 0
    credentials_found:   int = 0
    hosts_discovered:    int = 0
    hosts_owned:         int = 0
    p50_execution_ms:    float = 0.0
    p95_execution_ms:    float = 0.0
    p99_execution_ms:    float = 0.0
    tasks_per_minute:    float = 0.0
    bytes_sent:          int = 0
    bytes_recv:          int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp":          self.timestamp,
            "campaign_id":        self.campaign_id,
            "modules": {
                "total":     self.total_modules_run,
                "success":   self.successful_modules,
                "failed":    self.failed_modules,
                "error_rate": round(self.error_rate, 3),
            },
            "queue":   {"depth": self.queue_depth},
            "workers": {
                "active":    self.active_workers,
                "unhealthy": self.unhealthy_workers,
            },
            "findings":     self.findings_total,
            "credentials":  self.credentials_found,
            "hosts": {
                "discovered": self.hosts_discovered,
                "owned":      self.hosts_owned,
            },
            "latency_ms": {
                "p50": round(self.p50_execution_ms, 1),
                "p95": round(self.p95_execution_ms, 1),
                "p99": round(self.p99_execution_ms, 1),
            },
            "throughput": {
                "tasks_per_min": round(self.tasks_per_minute, 2),
                "bytes_sent":    self.bytes_sent,
                "bytes_recv":    self.bytes_recv,
            },
        }

    def to_prometheus(self) -> str:
        """Export as Prometheus exposition format text."""
        lines = [
            f'# HELP ares_modules_total Total module executions',
            f'# TYPE ares_modules_total counter',
            f'ares_modules_total{{campaign="{self.campaign_id}",status="success"}} {self.successful_modules}',
            f'ares_modules_total{{campaign="{self.campaign_id}",status="failed"}} {self.failed_modules}',
            f'',
            f'# HELP ares_queue_depth Current task queue depth',
            f'# TYPE ares_queue_depth gauge',
            f'ares_queue_depth{{campaign="{self.campaign_id}"}} {self.queue_depth}',
            f'',
            f'# HELP ares_workers_active Active worker nodes',
            f'# TYPE ares_workers_active gauge',
            f'ares_workers_active {self.active_workers}',
            f'',
            f'# HELP ares_findings_total Total findings discovered',
            f'# TYPE ares_findings_total counter',
            f'ares_findings_total{{campaign="{self.campaign_id}"}} {self.findings_total}',
            f'',
            f'# HELP ares_hosts_owned Total hosts owned',
            f'# TYPE ares_hosts_owned gauge',
            f'ares_hosts_owned{{campaign="{self.campaign_id}"}} {self.hosts_owned}',
            f'',
            f'# HELP ares_execution_duration_ms Module execution duration percentiles',
            f'# TYPE ares_execution_duration_ms summary',
            f'ares_execution_duration_ms{{quantile="0.5"}} {self.p50_execution_ms:.1f}',
            f'ares_execution_duration_ms{{quantile="0.95"}} {self.p95_execution_ms:.1f}',
            f'ares_execution_duration_ms{{quantile="0.99"}} {self.p99_execution_ms:.1f}',
        ]
        return "\n".join(lines)


class TelemetryCollector:
    """
    Central telemetry store for ARES.
    Collects metrics from all engines and workers.

    Thread-safe for single asyncio loop (no locks needed).
    """

    def __init__(self) -> None:
        # Execution samples per module
        self._exec_samples: deque[ExecutionMetric] = deque(maxlen=_MAX_SAMPLES)

        # Module counters
        self._module_success: defaultdict[str, int] = defaultdict(int)
        self._module_failure: defaultdict[str, int] = defaultdict(int)

        # Worker snapshots
        self._workers: dict[str, WorkerHealthSnapshot] = {}

        # Operational counters
        self._findings_total:     int = 0
        self._credentials_found:  int = 0
        self._hosts_discovered:   int = 0
        self._hosts_owned:        int = 0
        self._bytes_sent:         int = 0
        self._bytes_recv:         int = 0
        self._queue_depth:        int = 0

        # Time-series for throughput calc
        self._completion_times: deque[float] = deque(maxlen=200)

        self._started_at = time.time()

    # ── Record events ──────────────────────────────────────────────────────

    def record_execution(
        self,
        module_id:   str,
        duration_ms: float,
        success:     bool,
        campaign_id: str = "",
        worker_id:   str = "",
    ) -> None:
        m = ExecutionMetric(
            module_id=module_id, duration_ms=duration_ms,
            success=success, campaign_id=campaign_id, worker_id=worker_id,
        )
        self._exec_samples.append(m)
        self._completion_times.append(time.time())
        if success:
            self._module_success[module_id] += 1
        else:
            self._module_failure[module_id] += 1

    def record_finding(self, count: int = 1) -> None:
        self._findings_total += count

    def record_credential(self, count: int = 1) -> None:
        self._credentials_found += count

    def record_host_discovered(self, count: int = 1) -> None:
        self._hosts_discovered += count

    def record_host_owned(self, count: int = 1) -> None:
        self._hosts_owned += count

    def record_network_io(self, sent: int = 0, recv: int = 0) -> None:
        self._bytes_sent += sent
        self._bytes_recv += recv

    def update_queue_depth(self, depth: int) -> None:
        self._queue_depth = depth

    def update_worker(self, snapshot: WorkerHealthSnapshot) -> None:
        self._workers[snapshot.worker_id] = snapshot
        logger.debug("worker_health_updated",
                     worker=snapshot.worker_id, healthy=snapshot.is_healthy)

    # ── Compute snapshots ──────────────────────────────────────────────────

    def snapshot(self, campaign_id: str = "") -> TelemetrySnapshot:
        samples = list(self._exec_samples)
        durations = [s.duration_ms for s in samples]

        p50 = p95 = p99 = 0.0
        if len(durations) >= 2:
            qs = quantiles(durations, n=100)
            p50 = qs[49] if len(qs) > 49 else median(durations)
            p95 = qs[94] if len(qs) > 94 else qs[-1]
            p99 = qs[98] if len(qs) > 98 else qs[-1]
        elif len(durations) == 1:
            p50 = p95 = p99 = durations[0]

        total   = sum(self._module_success.values()) + sum(self._module_failure.values())
        success = sum(self._module_success.values())
        failed  = sum(self._module_failure.values())
        error_rate = failed / total if total else 0.0

        workers = list(self._workers.values())
        unhealthy = sum(1 for w in workers if not w.is_healthy)

        # Tasks per minute over last 60 seconds
        now = time.time()
        recent_completions = sum(1 for t in self._completion_times if now - t < 60)
        tpm = recent_completions  # completions in last minute

        return TelemetrySnapshot(
            campaign_id        = campaign_id,
            total_modules_run  = total,
            successful_modules = success,
            failed_modules     = failed,
            error_rate         = error_rate,
            queue_depth        = self._queue_depth,
            active_workers     = len(workers),
            unhealthy_workers  = unhealthy,
            findings_total     = self._findings_total,
            credentials_found  = self._credentials_found,
            hosts_discovered   = self._hosts_discovered,
            hosts_owned        = self._hosts_owned,
            p50_execution_ms   = p50,
            p95_execution_ms   = p95,
            p99_execution_ms   = p99,
            tasks_per_minute   = tpm,
            bytes_sent         = self._bytes_sent,
            bytes_recv         = self._bytes_recv,
        )

    def module_stats(self) -> list[dict[str, Any]]:
        """Per-module success/failure breakdown."""
        all_mods = set(self._module_success) | set(self._module_failure)
        result = []
        for mod in sorted(all_mods):
            s = self._module_success.get(mod, 0)
            f = self._module_failure.get(mod, 0)
            samples = [m.duration_ms for m in self._exec_samples if m.module_id == mod]
            result.append({
                "module_id": mod,
                "success":   s,
                "failure":   f,
                "total":     s + f,
                "error_rate": round(f / (s + f), 3) if (s + f) else 0.0,
                "avg_ms":    round(mean(samples), 1) if samples else 0.0,
            })
        return result

    def worker_health(self) -> list[dict[str, Any]]:
        return [w.to_dict() for w in self._workers.values()]

    def uptime_s(self) -> float:
        return round(time.time() - self._started_at, 0)

    def alerts(self) -> list[dict[str, Any]]:
        """Return active health alerts that require operator attention."""
        issues: list[dict[str, Any]] = []
        snap = self.snapshot()

        if snap.error_rate > 0.30:
            issues.append({
                "level":   "warning",
                "message": f"High error rate: {snap.error_rate:.0%} of modules failing",
                "metric":  "error_rate",
            })
        if snap.unhealthy_workers > 0:
            issues.append({
                "level":   "warning",
                "message": f"{snap.unhealthy_workers} worker(s) unhealthy or unresponsive",
                "metric":  "worker_health",
            })
        if snap.queue_depth > 100:
            issues.append({
                "level":   "info",
                "message": f"Task queue backlog: {snap.queue_depth} tasks pending",
                "metric":  "queue_depth",
            })
        for w in self._workers.values():
            if w.cpu_pct > 90:
                issues.append({
                    "level":   "warning",
                    "message": f"Worker {w.worker_id} CPU at {w.cpu_pct:.0f}%",
                    "metric":  "worker_cpu",
                })
        return issues


# Global singleton (one per ARES process)
_global_collector: TelemetryCollector | None = None


def get_collector() -> TelemetryCollector:
    global _global_collector
    if _global_collector is None:
        _global_collector = TelemetryCollector()
    return _global_collector


# Backward-compatible alias
MetricsCollector = TelemetryCollector
