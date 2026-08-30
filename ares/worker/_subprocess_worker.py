"""
ARES Subprocess Worker
This script is executed as a child process by IsolatedRunner.
It reads a JSON payload from stdin, runs the requested module,
and writes a JSON result to stdout.

Parent process reads stdout — stderr is logged separately.
Exit code 0 = success (even if module found nothing).
Exit code 1 = crash (parent will log stderr).
"""

from __future__ import annotations

import asyncio
import json
import sys
import traceback
from typing import Any

try:
    import resource as _resource

    _HAS_RESOURCE = True
except ImportError:
    _resource = None  # type: ignore[assignment]
    _HAS_RESOURCE = False  # Windows — resource limits not available


def apply_memory_limit(max_mb: int | None) -> None:
    """Set process memory limit (Linux only)."""
    if max_mb is None or not _HAS_RESOURCE:
        return
    try:
        limit = max_mb * 1024 * 1024
        _resource.setrlimit(_resource.RLIMIT_AS, (limit, limit))
    except (AttributeError, ValueError):
        pass  # Windows / limit below current usage


def apply_capability_limits(caps: set[str], limits: dict[str, int]) -> None:
    """
    Enforce resource limits derived from module capability set.
    Called before executing module code in the subprocess.

    v1.0.0: Integrates with CapabilityPolicy.resource_limits_for()
    to apply CPU, memory, process, and file descriptor limits.
    """
    if not _HAS_RESOURCE:
        return  # Windows — resource limits not supported
    try:
        cpu_s = limits.get("cpu_time_s", 30)
        mem_mb = limits.get("memory_mb", 256)
        nproc = limits.get("max_procs", 8)
        nfiles = limits.get("max_files", 64)

        # CPU time (hard+soft)
        _resource.setrlimit(_resource.RLIMIT_CPU, (cpu_s, cpu_s + 5))

        # Memory address space
        mem_bytes = mem_mb * 1024 * 1024
        _resource.setrlimit(_resource.RLIMIT_AS, (mem_bytes, mem_bytes))

        # Max subprocesses (CAP_EXEC modules get more; others just 1)
        if "cap_exec" not in caps:
            _resource.setrlimit(_resource.RLIMIT_NPROC, (1, 1))
        else:
            _resource.setrlimit(_resource.RLIMIT_NPROC, (nproc, nproc))

        # Open file descriptors
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (nfiles, nfiles))

    except (AttributeError, ValueError, OSError):
        pass  # Platform doesn't support — fail open (log in parent)


def check_capability_boundary(module_id: str, caps: set[str]) -> None:
    """
    Validate that no forbidden capabilities are being exercised.
    CAP_UNSAFE modules skip all checks (builtin only).
    Raises SystemExit(2) to signal boundary violation to parent.

    FIX: Hanya aktif saat ARES_WORKER_MODE=1 (subprocess sungguhan).
    Pytest sudah load subprocess duluan sehingga cek ini false-positive
    di test environment.
    """
    if "cap_unsafe" in caps:
        return  # builtin modules — no restrictions

    import os

    if os.environ.get("ARES_WORKER_MODE") != "1":
        return  # skip di luar worker subprocess (contoh: unit test)

    forbidden_in_env = set()
    if "cap_exec" not in caps:
        import sys

        for mod_name in list(sys.modules.keys()):
            if mod_name in ("subprocess", "os.system", "commands"):
                forbidden_in_env.add(mod_name)

    if forbidden_in_env:
        import sys

        sys.stderr.write(
            f"[worker] CAPABILITY VIOLATION: module {module_id!r} "
            f"loaded forbidden modules {forbidden_in_env} "
            f"without CAP_EXEC. Terminating.\n"
        )
        sys.exit(2)


def serialize_finding(f: Any) -> dict[str, Any]:
    """Convert Finding pydantic model to JSON-serializable dict."""
    return {
        "id": str(f.id),
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "confidence": f.confidence,
        "mitre_technique": f.mitre_technique,
        "mitre_tactic": f.mitre_tactic,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "host": f.host,
        "module_id": f.module_id,
        "validated": f.validated,
        "false_positive": f.false_positive,
        "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
    }


_WORKER_ADMISSION_ERROR = (
    "subprocess stdin execution requires a non-serializable coordinator capability"
)


class _PrivateWorkerConsumer:
    """Process-local consumer used only by the sealed in-process test seam."""

    def __init__(self) -> None:
        self.pending: dict[str, tuple[str, ...]] = {}

    def _register_admitted_dispatch_context(self, context: Any) -> None:
        self.pending[context._dispatch_nonce] = (
            context.campaign_id,
            context.submission_id,
            context.logical_execution_id,
            context.attempt_id,
            context.module_id,
            str(context.attempt_revision),
            str(context._store_id),
            context._signature,
        )

    def _consume_registered_dispatch_context(self, context: Any) -> bool:
        expected = self.pending.pop(context._dispatch_nonce, None)
        return expected == (
            context.campaign_id,
            context.submission_id,
            context.logical_execution_id,
            context.attempt_id,
            context.module_id,
            str(context.attempt_revision),
            str(context._store_id),
            context._signature,
        )


_PRIVATE_WORKER_CONSUMER = _PrivateWorkerConsumer()


async def _run_module_in_process(
    payload: dict[str, Any],
    dispatch_context: Any,
    executor: Any,
) -> dict[str, Any]:
    """Private capability consumer; it is unreachable from serialized stdin."""
    from ares.core.execution_admission import consume_dispatch_context, mark_effect_started

    module_id = payload.get("module_id")
    campaign_id = payload.get("campaign_id")
    if type(module_id) is not str or type(campaign_id) is not str:
        raise PermissionError(_WORKER_ADMISSION_ERROR)
    context = consume_dispatch_context(
        dispatch_context,
        consumer=_PRIVATE_WORKER_CONSUMER,
        campaign_id=campaign_id,
        module_id=module_id,
    )
    mark_effect_started(context)
    result = executor(payload)
    if asyncio.iscoroutine(result):
        result = await result
    if type(result) is not dict:
        raise TypeError("private worker executor must return a dict")
    return result


async def run_module(payload: dict[str, Any]) -> dict[str, Any]:
    """Reject every serializable payload; sealed capabilities cannot cross stdin."""
    del payload
    return {
        "success": False,
        "error": _WORKER_ADMISSION_ERROR,
        "code": "EXECUTION_ADMISSION_REQUIRED",
        "findings": [],
        "raw": {},
    }


def main() -> None:
    """Entry point: read JSON from stdin, write JSON to stdout."""
    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input)
    except Exception as e:
        sys.stderr.write(f"[worker] Failed to parse payload: {e}\n")
        sys.exit(1)

    try:
        result = asyncio.run(run_module(payload))
        sys.stdout.write(json.dumps(result))
        sys.stdout.flush()
        sys.exit(0)
    except Exception:  # top-level subprocess handler — must catch all
        err = traceback.format_exc()
        sys.stderr.write(f"[worker] Unhandled exception:\n{err}\n")
        error_result = {
            "success": False,
            "error": err[-500:],  # last 500 chars
            "findings": [],
            "raw": {},
        }
        sys.stdout.write(json.dumps(error_result))
        sys.stdout.flush()
        sys.exit(1)


if __name__ == "__main__":
    main()
