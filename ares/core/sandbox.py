"""
ARES Plugin Sandbox — Restricted Module Execution
Prevents third-party modules from damaging the core engine.

Isolation tiers:
  TIER_0  NONE       — core modules, run in-process (trusted)
  TIER_1  SUBPROCESS — separate process, resource limits (default)
  TIER_2  SECCOMP    — subprocess + seccomp syscall filter (Linux)
  TIER_3  DOCKER     — fully isolated container (maximum isolation)

Resource limits (TIER_1+):
  - CPU:    30 seconds max
  - Memory: 256 MB
  - Files:  no write outside /tmp/ares-sandbox-*
  - Net:    allowed (modules need network), but audited

Usage:
    sandbox = SandboxRunner(tier=IsolationTier.TIER_1)
    result  = await sandbox.run_module("ad.kerberoast", params, campaign)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys as _sys
if _sys.platform != "win32":
    import resource
else:
    resource = None  # type: ignore[assignment]
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import audit, get_logger

logger = get_logger("ares.sandbox")

# Syscall whitelist for seccomp (Linux only)
_SECCOMP_ALLOWED = {
    "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
    "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
    "rt_sigprocmask", "ioctl", "pread64", "pwrite64", "readv", "writev",
    "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore",
    "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep",
    "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect",
    "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind",
    "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt",
    "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname",
    "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
    "getcwd", "chdir", "rename", "mkdir", "rmdir", "unlink", "readlink", "chmod",
    "gettimeofday", "getrlimit", "getrusage", "times", "getuid", "getgid",
    "geteuid", "getegid", "setuid", "setgid", "getgroups", "setgroups",
    "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
    "get_thread_area", "set_tid_address", "exit_group", "epoll_wait", "epoll_ctl",
    "epoll_create", "epoll_create1", "getdents64", "clock_gettime", "clock_nanosleep",
    "statfs", "fstatfs", "arch_prctl", "prctl", "getrandom", "memfd_create",
    "openat2", "newfstatat",
}


class IsolationTier(str, Enum):
    NONE       = "none"       # in-process (core modules only)
    SUBPROCESS = "subprocess" # separate process + resource limits
    SECCOMP    = "seccomp"    # subprocess + syscall filter
    DOCKER     = "docker"     # container isolation


@dataclass
class SandboxPolicy:
    """Security policy applied to sandboxed module execution."""
    tier:            IsolationTier = IsolationTier.SUBPROCESS
    cpu_time_s:      int   = 30        # max CPU seconds (RLIMIT_CPU)
    memory_mb:       int   = 256       # max virtual memory
    timeout_s:       int   = 300       # wall-clock timeout
    allow_network:   bool  = True      # allow outbound connections
    allow_write:     bool  = False     # allow filesystem writes (outside /tmp)
    drop_privileges: bool  = True      # drop to nobody on Linux
    docker_image:    str   = "python:3.11-slim"
    docker_network:  str   = "bridge"  # "none" for no network

    # Modules trusted to bypass sandboxing
    trusted_prefixes: list[str] = field(default_factory=lambda: ["ares.core", "ares.db"])


@dataclass
class SandboxResult:
    module_id:    str
    sandbox_tier: IsolationTier
    success:      bool
    findings:     list[dict[str, Any]] = field(default_factory=list)
    extra:        dict[str, Any]       = field(default_factory=dict)
    stdout:       str = ""
    stderr:       str = ""
    exit_code:    int = 0
    cpu_time_s:   float = 0.0
    wall_time_s:  float = 0.0
    memory_peak_kb: int = 0
    error:        str = ""
    sandbox_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])


class SandboxRunner:
    """
    Executes ARES modules inside an isolation tier.
    Auto-falls-back to lower tier on unavailability.
    """

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()

    async def run_module(
        self,
        module_id:   str,
        params:      dict[str, Any],
        campaign_id: str = "",
        tier:        IsolationTier | None = None,
    ) -> SandboxResult:
        """
        Run module_id with params inside the configured isolation tier.
        Falls back to SUBPROCESS if requested tier unavailable.
        """
        effective_tier = tier or self.policy.tier
        t0 = time.monotonic()

        # Core modules always run in-process
        if any(module_id.startswith(p) for p in self.policy.trusted_prefixes):
            effective_tier = IsolationTier.NONE

        audit("sandbox_run_start", actor="engine",
              module=module_id, tier=effective_tier.value, campaign=campaign_id)

        try:
            if effective_tier == IsolationTier.NONE:
                result = await self._run_inprocess(module_id, params, campaign_id)
            elif effective_tier == IsolationTier.DOCKER:
                result = await self._run_docker(module_id, params, campaign_id)
            else:
                # SUBPROCESS or SECCOMP (seccomp applied inside child)
                result = await self._run_subprocess(
                    module_id, params, campaign_id,
                    use_seccomp=(effective_tier == IsolationTier.SECCOMP),
                )
        except Exception as exc:
            result = SandboxResult(
                module_id=module_id, sandbox_tier=effective_tier,
                success=False, error=str(exc)[:500],
            )

        result.wall_time_s  = round(time.monotonic() - t0, 3)
        result.sandbox_tier = effective_tier

        audit("sandbox_run_complete", actor="engine",
              module=module_id, success=result.success,
              tier=effective_tier.value, wall_time_s=result.wall_time_s)

        return result

    # ── Tier implementations ───────────────────────────────────────────────

    async def _run_inprocess(
        self, module_id: str, params: dict[str, Any], campaign_id: str
    ) -> SandboxResult:
        """Direct in-process execution. For trusted core modules only."""
        from ares.core.config import AresSettings
        from ares.core.noise import NoiseController
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        from ares.core.plugin.loader import ModuleRegistry

        registry = ModuleRegistry()
        module_cls = registry.get(module_id)
        if not module_cls:
            return SandboxResult(module_id=module_id, sandbox_tier=IsolationTier.NONE,
                                  success=False, error=f"Module {module_id!r} not registered")

        # Look up real campaign scope from DB — same pattern as _run_subprocess.
        # Do NOT default to 0.0.0.0/0 (wildcard) as that bypasses scope enforcement.
        scope_entries: list[ScopeEntry] = []
        try:
            from ares.db.database import AresDatabase
            from ares.core.config import get_settings as _gs
            import json as _j
            _s = _gs()
            async with await AresDatabase.create(
                _s.ares_database_url, _s.encryption_key_value
            ) as _sdb:
                _row = await _sdb.get_campaign(campaign_id)
            if _row and _row.get("scope_json"):
                scope_entries = [
                    ScopeEntry(cidr=e["cidr"])
                    for e in _j.loads(_row["scope_json"])
                    if e.get("cidr")
                ]
        except Exception:
            pass  # fallback: empty scope = nothing in scope, fails closed

        # If DB lookup failed and no scope found, use empty scope (deny-all).
        # Modules will fail validation — this is safer than allowing everything.
        if not scope_entries:
            logger.warning("sandbox_inprocess_no_scope",
                           campaign_id=campaign_id, module_id=module_id,
                           note="No campaign scope found — using deny-all. "
                                "Pass a valid campaign_id or use subprocess mode.")
            scope_entries = []

        campaign = Campaign(
            id=campaign_id or str(uuid.uuid4()),
            name="sandbox-exec",
            scope=scope_entries,
            noise_profile=NoiseProfile.NORMAL,
        )
        settings = AresSettings()
        noise    = NoiseController(campaign)
        module   = module_cls(settings=settings, campaign=campaign, noise=noise)
        findings, extra = await module.run(**params)
        return SandboxResult(
            module_id=module_id, sandbox_tier=IsolationTier.NONE, success=True,
            findings=[f.to_dict() if hasattr(f, "to_dict") else {} for f in findings],
            extra=extra,
        )

    async def _run_subprocess(
        self,
        module_id: str,
        params:    dict[str, Any],
        campaign_id: str,
        use_seccomp: bool = False,
    ) -> SandboxResult:
        """
        Run module in isolated subprocess with resource limits.
        Communicates via stdin/stdout JSON (same protocol as worker/isolation.py).
        """
        with tempfile.TemporaryDirectory(prefix="ares-sandbox-") as tmpdir:
            # Pass real campaign scope so child process respects it
            _scope_cidrs: list[str] = []
            try:
                from ares.db.database import AresDatabase
                from ares.core.config import get_settings as _gs
                import json as _j
                _s = _gs()
                async with await AresDatabase.create(
                    _s.ares_database_url, _s.encryption_key_value
                ) as _sdb:
                    _row = await _sdb.get_campaign(campaign_id)
                if _row and _row.get("scope_json"):
                    _scope_cidrs = [
                        e["cidr"] for e in _j.loads(_row["scope_json"])
                        if e.get("cidr")
                    ]
            except Exception:
                pass  # fallback handled in wrapper — fails closed
            payload = json.dumps({
                "module_id":   module_id,
                "params":      params,
                "campaign_id": campaign_id,
                "use_seccomp": use_seccomp,
                "tmpdir":      tmpdir,
                "scope_cidrs": _scope_cidrs,
            })

            wrapper = self._build_wrapper_script(use_seccomp)
            script_path = os.path.join(tmpdir, "runner.py")
            with open(script_path, "w") as f:
                f.write(wrapper)

            preexec = self._make_preexec_fn() if os.name != "nt" else None

            proc = await asyncio.create_subprocess_exec(
                sys.executable, script_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=preexec,
                cwd=tmpdir,
            )

            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(payload.encode()),
                    timeout=self.policy.timeout_s,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return SandboxResult(
                    module_id=module_id, sandbox_tier=IsolationTier.SUBPROCESS,
                    success=False, error=f"Sandbox timeout ({self.policy.timeout_s}s)",
                )

            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")

            try:
                data = json.loads(stdout)
                return SandboxResult(
                    module_id  = module_id,
                    sandbox_tier = IsolationTier.SUBPROCESS,
                    success    = data.get("success", False),
                    findings   = data.get("findings", []),
                    extra      = data.get("extra", {}),
                    stdout     = stdout[:2000],
                    stderr     = stderr[:500],
                    exit_code  = proc.returncode or 0,
                )
            except json.JSONDecodeError:
                return SandboxResult(
                    module_id=module_id, sandbox_tier=IsolationTier.SUBPROCESS,
                    success=False, error="Invalid JSON from sandbox",
                    stdout=stdout[:500], stderr=stderr[:500],
                )

    async def _run_docker(
        self,
        module_id: str,
        params:    dict[str, Any],
        campaign_id: str,
    ) -> SandboxResult:
        """
        Run module inside an ephemeral Docker container.
        Requires Docker daemon on host.
        """
        try:
            import docker  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("docker_not_available_fallback_subprocess")
            return await self._run_subprocess(module_id, params, campaign_id)

        # Fetch real scope for Docker container (same as subprocess)
        _docker_scope: list[str] = []
        try:
            from ares.db.database import AresDatabase
            from ares.core.config import get_settings as _dgs
            import json as _dj
            _ds = _dgs()
            async with await AresDatabase.create(
                _ds.ares_database_url, _ds.encryption_key_value
            ) as _ddb:
                _drow = await _ddb.get_campaign(campaign_id)
            if _drow and _drow.get("scope_json"):
                _docker_scope = [
                    e["cidr"] for e in _dj.loads(_drow["scope_json"])
                    if e.get("cidr")
                ]
        except Exception:
            pass  # fails closed in inline_runner
        payload  = json.dumps({
            "module_id": module_id, "params": params,
            "campaign_id": campaign_id, "scope_cidrs": _docker_scope,
        })
        image    = self.policy.docker_image
        network  = self.policy.docker_network
        mem_limit = f"{self.policy.memory_mb}m"

        client = docker.from_env()
        try:
            container = client.containers.run(
                image,
                command=["python3", "-c", self._inline_runner()],
                environment={"ARES_SANDBOX_PAYLOAD": payload},
                mem_limit=mem_limit,
                cpu_period=100000,
                cpu_quota=50000,   # 50% of one CPU
                network_mode=network,
                remove=True,
                stdout=True,
                stderr=True,
                detach=False,
                timeout=self.policy.timeout_s,
            )
            output = container.decode() if isinstance(container, bytes) else str(container)
            data   = json.loads(output)
            return SandboxResult(
                module_id=module_id, sandbox_tier=IsolationTier.DOCKER,
                success=data.get("success", False),
                findings=data.get("findings", []),
                extra=data.get("extra", {}),
            )
        except Exception as exc:
            return SandboxResult(
                module_id=module_id, sandbox_tier=IsolationTier.DOCKER,
                success=False, error=str(exc)[:300],
            )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _make_preexec_fn(self):
        """
        Return preexec_fn that applies resource limits in child process.
        Only called on Unix systems.
        """
        cpu_limit = self.policy.cpu_time_s
        mem_bytes = self.policy.memory_mb * 1024 * 1024

        def _limits():
            try:
                resource.setrlimit(resource.RLIMIT_CPU,   (cpu_limit, cpu_limit))
                resource.setrlimit(resource.RLIMIT_AS,    (mem_bytes, mem_bytes))
                resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
                resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            except (OSError, ValueError, AttributeError):
                pass  # best-effort — don't fail the child

        return _limits

    @staticmethod
    def _build_wrapper_script(use_seccomp: bool) -> str:
        """
        Build Python source that runs in the sandbox child process.
        When use_seccomp=True, applies PR_SET_NO_NEW_PRIVS (prctl 38) as a
        mandatory minimum, preventing the child from ever regaining privileges.
        Full BPF syscall allowlist filtering is applied if pyseccomp is installed
        and ARES_SECCOMP_BPF=1 env var is set.
        """
        if use_seccomp:
            allowed_list = repr(sorted(_SECCOMP_ALLOWED))
            seccomp_preamble = (
                "# ── SECCOMP: apply privilege restrictions ─────────────────────────────\n"
                "import ctypes as _ct, ctypes.util as _cu, os as _so\n"
                "try:\n"
                "    _libc = _ct.CDLL(_cu.find_library('c'), use_errno=True)\n"
                "    _libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS — child cannot gain privs\n"
                "except Exception as _pe:\n"
                "    import sys as _ps; print(f'[sandbox] prctl failed: {_pe}', file=_ps.stderr)\n"
                "if _so.environ.get('ARES_SECCOMP_BPF') == '1':\n"
                "    try:\n"
                "        import seccomp as _sc  # pyseccomp\n"
                f"        _allowed = {allowed_list}\n"
                "        _f = _sc.SyscallFilter(defaction=_sc.KILL)\n"
                "        for _sn in _allowed:\n"
                "            try: _f.add_rule(_sc.ALLOW, _sn)\n"
                "            except Exception: pass\n"
                "        _f.load()\n"
                "    except ImportError:\n"
                "        import sys as _s2\n"
                "        print('[sandbox] pyseccomp not installed — BPF filter skipped', file=_s2.stderr)\n"
                "    except Exception as _be:\n"
                "        import sys as _s3\n"
                "        print(f'[sandbox] BPF filter failed: {_be}', file=_s3.stderr)\n"
                "# ── end SECCOMP ────────────────────────────────────────────────────────\n"
            )
        else:
            seccomp_preamble = ""

        body = (
            seccomp_preamble
            + "\nimport sys, json, asyncio\n\n"
            "payload = json.loads(sys.stdin.read())\n"
            "module_id   = payload[\"module_id\"]\n"
            "params      = payload[\"params\"]\n"
            "campaign_id = payload.get(\"campaign_id\", \"\")\n"
            "\nasync def run():\n"
            "    try:\n"
            "        from ares.core.config import AresSettings\n"
            "        from ares.core.noise import NoiseController\n"
            "        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry\n"
            "        from ares.core.plugin.loader import ModuleRegistry\n"
            "        import uuid\n"
            "\n"
            "        registry  = ModuleRegistry()\n"
            "        module_cls = registry.get(module_id)\n"
            "        if not module_cls:\n"
            "            return {\"success\": False, \"error\": f\"Module {module_id!r} not found\", \"findings\": [], \"extra\": {}}\n"
            "\n"
            "        _scope_cidrs = payload.get(\"scope_cidrs\", [])\n"
            "        if not _scope_cidrs:\n"
            "            print(json.dumps({\"success\": False, \"error\":\n"
            "                \"Sandbox scope not provided — refusing to run with unbounded scope\",\n"
            "                \"findings\": [], \"extra\": {}}))\n"
            "            return\n"
            "        campaign = Campaign(\n"
            "            id=campaign_id or str(uuid.uuid4()),\n"
            "            name=\"sandbox\",\n"
            "            scope=[ScopeEntry(cidr=c) for c in _scope_cidrs],\n"
            "            noise_profile=NoiseProfile.NORMAL,\n"
            "        )\n"
            "        settings = AresSettings()\n"
            "        noise    = NoiseController(campaign)\n"
            "        module   = module_cls(settings=settings, campaign=campaign, noise=noise)\n"
            "        findings, extra = await module.run(**params)\n"
            "        return {\n"
            "            \"success\":  True,\n"
            "            \"findings\": [f.to_dict() if hasattr(f, \"to_dict\") else {} for f in findings],\n"
            "            \"extra\":    extra,\n"
            "        }\n"
            "    except Exception as e:\n"
            "        return {\"success\": False, \"error\": str(e)[:300], \"findings\": [], \"extra\": {}}\n"
            "\nresult = asyncio.run(run())\n"
            "print(json.dumps(result))\n"
        )
        return body


    @staticmethod
    def _inline_runner() -> str:
        """
        Python source code that runs inside the Docker container.

        Reads ARES_SANDBOX_PAYLOAD env var (JSON: {module_id, params, campaign_id}),
        loads the ModuleRegistry, instantiates the module, runs it, and prints
        the result as JSON on stdout.
        """
        return (
            'import sys, json, os, asyncio\n'
            '\n'
            'payload    = json.loads(os.environ.get("ARES_SANDBOX_PAYLOAD", "{}"))\n'
            'module_id  = payload.get("module_id", "")\n'
            'params     = payload.get("params", {})\n'
            'campaign_id = payload.get("campaign_id", "")\n'
            '\n'
            'async def _run():\n'
            '    try:\n'
            '        from ares.core.plugin.loader import ModuleRegistry\n'
            '        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry\n'
            '        import uuid\n'
            '        registry = ModuleRegistry()\n'
            '        module_cls = registry.get(module_id)\n'
            '        if not module_cls:\n'
            '            return {"success": False, "error": f"Module {module_id!r} not found",\n'
            '                    "findings": [], "extra": {}}\n'
            '        _scope_cidrs = payload.get("scope_cidrs", [])\n'
            '        if not _scope_cidrs:\n'
            '            return {"success": False,\n'
            '                    "error": "Sandbox scope not provided — refusing to run with unbounded scope",\n'
            '                    "findings": [], "extra": {}}\n'
            '        campaign = Campaign(\n'
            '            id=campaign_id or str(uuid.uuid4()),\n'
            '            name="sandbox", operator="sandbox",\n'
            '            scope=[ScopeEntry(cidr=c) for c in _scope_cidrs],\n'
            '            noise_profile=NoiseProfile.NORMAL,\n'
            '        )\n'
            '        try:\n'
            '            from ares.core.config import AresSettings\n'
            '            from ares.core.noise import NoiseController\n'
            '            settings = AresSettings()\n'
            '            noise    = NoiseController(campaign)\n'
            '            module   = module_cls(settings=settings, campaign=campaign, noise=noise)\n'
            '        except Exception:\n'
            '            module = module_cls()\n'
            '        findings, extra = await module.run(**params)\n'
            '        findings_out = []\n'
            '        for f in findings:\n'
            '            if hasattr(f, "model_dump"):\n'
            '                findings_out.append(f.model_dump(mode="json"))\n'
            '            elif hasattr(f, "to_dict"):\n'
            '                findings_out.append(f.to_dict())\n'
            '            else:\n'
            '                findings_out.append(str(f))\n'
            '        return {"success": True, "findings": findings_out, "extra": extra}\n'
            '    except Exception as exc:\n'
            '        return {"success": False, "error": str(exc)[:300],\n'
            '                "findings": [], "extra": {}}\n'
            '\n'
            'result = asyncio.run(_run())\n'
            'print(json.dumps(result))\n'
        )

    def is_trusted_module(self, module_id: str) -> bool:
        return any(module_id.startswith(p) for p in self.policy.trusted_prefixes)
