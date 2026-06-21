"""
ARES Module Isolation
Run each module in a subprocess so engine stays alive if a module crashes,
hangs, or triggers an OS-level exception (segfault from native libs, etc).

Architecture:
  Engine process                   Worker subprocess
  ─────────────────────────────    ──────────────────────────────────
  IsolatedRunner.run_isolated() →  _subprocess_worker.py (spawned)
                                       load module
                                       run module
                                       serialize findings → stdout (JSON)
  ← receive JSON result            exit (clean or crash — engine unaffected)

Communication: stdin/stdout JSON (no shared memory, no IPC sockets).
Timeout:       enforced by asyncio.wait_for + proc.kill()
Memory limit:  optional via resource.setrlimit in subprocess
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.isolation")

# Path to the worker entrypoint script
_WORKER_SCRIPT = Path(__file__).parent / "_subprocess_worker.py"


class IsolationMode(str, Enum):
    NONE       = "none"       # run in-process (fast, unsafe)
    SUBPROCESS = "subprocess" # run in subprocess (safe, ~100ms overhead)
    # CONTAINER = "container"  # future: docker run --rm


@dataclass
class IsolatedResult:
    success:      bool
    findings_raw: list[dict[str, Any]]  # serialized Finding dicts
    raw_output:   dict[str, Any]
    error:        str | None = None
    exit_code:    int = 0
    duration_ms:  float = 0.0
    killed:       bool = False          # True if killed due to timeout


class IsolatedRunner:
    """
    Runs a module in an isolated subprocess.

    Engine stays alive even if the module:
      - raises an unhandled exception
      - segfaults (native lib crash)
      - hangs indefinitely (timeout kills it)
      - tries to call sys.exit()
    """

    def __init__(
        self,
        mode:    IsolationMode = IsolationMode.SUBPROCESS,
        timeout: int = 120,
        max_memory_mb: int | None = None,  # subprocess memory limit
    ) -> None:
        self.mode          = mode
        self.timeout       = timeout
        self.max_memory_mb = max_memory_mb

    async def run_isolated(
        self,
        module_id:   str,
        campaign_id: str,
        params:      dict[str, Any],
        settings_env: dict[str, str] | None = None,
    ) -> IsolatedResult:
        """
        Execute a module in isolation. Returns IsolatedResult regardless of crash.
        """
        if self.mode == IsolationMode.NONE:
            raise RuntimeError("Call engine.run_module() directly for non-isolated execution")

        logger.info("isolation_run_start", module_id=module_id, mode=self.mode.value)

        payload = json.dumps({
            "module_id":   module_id,
            "campaign_id": campaign_id,
            "params":      params,
            "max_memory_mb": self.max_memory_mb,
        })

        import time
        t0 = time.monotonic()

        try:
            result = await asyncio.wait_for(
                self._spawn(payload, settings_env or {}),
                timeout=self.timeout,
            )
            result.duration_ms = round((time.monotonic() - t0) * 1000, 2)
            logger.info(
                "isolation_run_complete",
                module_id=module_id,
                success=result.success,
                findings=len(result.findings_raw),
                duration_ms=result.duration_ms,
            )
            return result

        except asyncio.TimeoutError:
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            logger.error("isolation_timeout", module_id=module_id, timeout_s=self.timeout)
            return IsolatedResult(
                success=False, findings_raw=[], raw_output={},
                error=f"Module timed out after {self.timeout}s",
                killed=True, duration_ms=duration_ms,
            )

    async def _spawn(
        self,
        payload:      str,
        settings_env: dict[str, str],
    ) -> IsolatedResult:
        """Spawn a subprocess, send payload via stdin, read result from stdout."""
        import os
        env = {**os.environ, **settings_env}

        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(_WORKER_SCRIPT),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        try:
            # Defense-in-depth: direct timeout on communicate.
            # run_isolated() already wraps _spawn in wait_for(timeout=self.timeout),
            # but this inner timeout ensures safety even if _spawn is called directly.
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=payload.encode()),
                timeout=self.timeout + 30,  # +30s buffer beyond outer timeout
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # Outer wait_for or inner timeout fired.
            # MUST kill subprocess or it becomes an orphan zombie.
            proc.kill()
            await proc.wait()
            raise  # re-raise so run_isolated() catches TimeoutError
        exit_code = proc.returncode or 0

        if stderr_b:
            logger.debug("isolation_stderr", content=stderr_b.decode(errors="replace")[:500])

        if exit_code != 0 or not stdout_b:
            err = stderr_b.decode(errors="replace")[:500] if stderr_b else f"exit {exit_code}"
            logger.error("isolation_worker_crash", exit_code=exit_code, error=err)
            return IsolatedResult(
                success=False, findings_raw=[], raw_output={},
                error=err, exit_code=exit_code,
            )

        try:
            data = json.loads(stdout_b.decode())
            return IsolatedResult(
                success      = data.get("success", False),
                findings_raw = data.get("findings", []),
                raw_output   = data.get("raw", {}),
                error        = data.get("error"),
                exit_code    = exit_code,
            )
        except json.JSONDecodeError as e:
            return IsolatedResult(
                success=False, findings_raw=[], raw_output={},
                error=f"Invalid JSON from worker: {e}",
            )
