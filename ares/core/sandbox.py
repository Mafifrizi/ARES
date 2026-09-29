"""
ARES Plugin Sandbox - Restricted Module Execution
Provides defense-in-depth isolation tiers to protect engine integrity during module execution.

Isolation tiers & security boundaries:
  TIER_0 NONE       - trusted core modules only, run in-process under ScopeFirewall.
  TIER_1 SUBPROCESS - separate Python process:
                      * Network: allow_network=False enforces Linux network namespace (CLONE_NEWNET)
                        fail-closed, or deny-all ScopeFirewall socket interception.
                        allow_network=True enforces ScopeFirewall egress boundary.
                      * Filesystem: working directory locked to ephemeral temporary directory;
                        Unix RLIMIT_FSIZE=(0,0) inhibits file enlargement; application-level
                        open/write hooks provide defense-in-depth within Python. Note: Subprocess
                        tier does not provide complete OS-level mount namespace isolation.
                      * Privileges: drop_privileges=True drops root (EUID 0) to 'nobody' on Linux
                        fail-closed; unsupported on Windows while elevated (aborts execution).
  TIER_2 SECCOMP    - Linux SUBPROCESS + PR_SET_NO_NEW_PRIVS + BPF syscall allowlist filter.
  TIER_3 DOCKER     - Complete OS container isolation: read-only root filesystem (allow_write=False),
                      network namespace isolation ('none' or 'bridge'), CPU & memory cgroups.

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
    """Security policy applied to sandboxed module execution.

    Semantic definitions by isolation tier:
      allow_network:
        - Linux SUBPROCESS: Mandatory network namespace isolation via unshare(CLONE_NEWNET).
        - Windows SUBPROCESS: Mandatory deny-all egress via ScopeFirewall socket hooks.
        - DOCKER: Container network mode 'none' (kernel namespace isolation).
      allow_write:
        - DOCKER: Read-only container rootfs (read_only=True via container mount options).
        - SUBPROCESS: Ephemeral sandbox working directory, RLIMIT_FSIZE=(0,0) on Unix, and
          application-level open/write hooks within Python. NOTE: For complete OS filesystem
          isolation, IsolationTier.DOCKER is required.
      drop_privileges:
        - Linux SUBPROCESS: Drops root (EUID 0) to 'nobody' and verifies non-root UID (mandatory).
        - Windows SUBPROCESS: Privilege dropping from Administrator is unsupported; execution aborts if elevated.
    """
    tier:            IsolationTier = IsolationTier.SUBPROCESS
    cpu_time_s:      int   = 30        # max CPU seconds (RLIMIT_CPU, best-effort)
    memory_mb:       int   = 256       # max virtual memory (RLIMIT_AS, best-effort)
    timeout_s:       int   = 300       # wall-clock timeout
    allow_network:   bool  = True      # outbound network allowed within campaign scope
    allow_write:     bool  = False     # allow filesystem writes
    drop_privileges: bool  = True      # drop root privileges to nobody on Linux
    docker_image:    str   = "python:3.11-slim"
    docker_network:  str   = "bridge"  # container network mode when allow_network=True

    # Strict mode & tier integrity controls
    strict_mode:                      bool = True        # enforce fail-closed security invariants across all tiers
    allow_tier_downgrade:             bool = False       # reject silent fallback from DOCKER to SUBPROCESS when Docker is unavailable
    allow_unconfined_docker_binaries: bool = False       # in strict mode, reject DOCKER allow_network=True unless explicitly allowed
    sandbox_uid:                      int | None = None  # dedicated sandbox UID for Linux parent firewall & child privilege drop

    # Modules trusted to bypass sandboxing
    trusted_prefixes: list[str] = field(default_factory=lambda: ["ares.core", "ares.db"])


@dataclass
class SandboxResult:
    module_id:       str
    sandbox_tier:    IsolationTier
    success:         bool
    findings:        list[dict[str, Any]] = field(default_factory=list)
    extra:           dict[str, Any]       = field(default_factory=dict)
    stdout:          str = ""
    stderr:          str = ""
    exit_code:       int = 0
    cpu_time_s:      float = 0.0
    wall_time_s:     float = 0.0
    memory_peak_kb:  int = 0
    error:           str = ""
    sandbox_id:      str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    requested_tier:  IsolationTier = IsolationTier.SUBPROCESS
    effective_tier:  IsolationTier = IsolationTier.SUBPROCESS
    downgraded:      bool = False
    downgrade_reason: str = ""
    guarantees_lost: list[str] = field(default_factory=list)


class SandboxRunner:
    """
    Executes ARES modules inside an isolation tier.
    In strict mode (allow_tier_downgrade=False), fails closed if the requested tier is unavailable.
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
        In strict mode (allow_tier_downgrade=False), fails closed if requested tier is unavailable.
        """
        requested_tier = tier or self.policy.tier
        effective_tier = requested_tier
        t0 = time.monotonic()

        # Core modules always run in-process
        if self.is_trusted_module(module_id):
            effective_tier = IsolationTier.NONE

        audit("sandbox_run_start", actor="engine",
              module=module_id, requested_tier=requested_tier.value,
              tier=effective_tier.value, campaign=campaign_id)

        try:
            if effective_tier == IsolationTier.NONE:
                result = await self._run_inprocess(module_id, params, campaign_id)
            elif effective_tier == IsolationTier.DOCKER:
                result = await self._run_docker(
                    module_id, params, campaign_id, requested_tier=requested_tier
                )
            else:
                # SUBPROCESS or SECCOMP (seccomp applied inside child)
                result = await self._run_subprocess(
                    module_id, params, campaign_id,
                    use_seccomp=(effective_tier == IsolationTier.SECCOMP),
                    requested_tier=requested_tier,
                )
        except Exception as exc:
            result = SandboxResult(
                module_id=module_id, sandbox_tier=effective_tier,
                requested_tier=requested_tier, effective_tier=effective_tier,
                success=False, error=str(exc)[:500],
            )

        result.wall_time_s = round(time.monotonic() - t0, 3)
        if not getattr(result, "requested_tier", None):
            result.requested_tier = requested_tier
        if not getattr(result, "effective_tier", None):
            result.effective_tier = effective_tier
        result.sandbox_tier = result.effective_tier

        audit("sandbox_run_complete", actor="engine",
              module=module_id, success=result.success,
              requested_tier=result.requested_tier.value,
              effective_tier=result.effective_tier.value,
              downgraded=result.downgraded,
              tier=result.sandbox_tier.value, wall_time_s=result.wall_time_s)

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
        from ares.core.scope_firewall import scope_firewall_guard

        registry = ModuleRegistry()
        module_cls = registry.get(module_id)
        if not module_cls:
            return SandboxResult(module_id=module_id, sandbox_tier=IsolationTier.NONE,
                                  success=False, error=f"Module {module_id!r} not registered")

        # Look up real campaign scope from DB - same pattern as _run_subprocess.
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
        # Modules will fail validation - this is safer than allowing everything.
        if not scope_entries:
            logger.warning("sandbox_inprocess_no_scope",
                           campaign_id=campaign_id, module_id=module_id,
                           note="No campaign scope found - using deny-all. "
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
        async with scope_firewall_guard(campaign=campaign, module_id=module_id):
            findings, extra = await module.run(**params)
        return SandboxResult(
            module_id=module_id,
            sandbox_tier=IsolationTier.NONE,
            requested_tier=IsolationTier.NONE,
            effective_tier=IsolationTier.NONE,
            success=True,
            findings=[f.to_dict() if hasattr(f, "to_dict") else {} for f in findings],
            extra=extra,
        )

    async def _run_subprocess(
        self,
        module_id: str,
        params:    dict[str, Any],
        campaign_id: str,
        use_seccomp: bool = False,
        requested_tier: IsolationTier = IsolationTier.SUBPROCESS,
    ) -> SandboxResult:
        """
        Run module in isolated subprocess with resource limits.
        Communicates via stdin/stdout JSON (same protocol as worker/isolation.py).
        """
        sub_tier = IsolationTier.SECCOMP if use_seccomp else IsolationTier.SUBPROCESS
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
                pass  # fallback handled in wrapper - fails closed
            if os.name == "nt" and self.policy.drop_privileges:
                from ares.core.scope_firewall import OSFirewallController
                if OSFirewallController.is_elevated():
                    return SandboxResult(
                        module_id=module_id,
                        sandbox_tier=sub_tier,
                        requested_tier=requested_tier,
                        effective_tier=sub_tier,
                        success=False,
                        error="Privilege dropping (drop_privileges=True) is unsupported on Windows while running as Administrator; execution aborted to prevent unconfined privileged execution.",
                    )

            payload = json.dumps({
                "module_id":     module_id,
                "params":        params,
                "campaign_id":   campaign_id,
                "use_seccomp":   use_seccomp,
                "tmpdir":        tmpdir,
                "scope_cidrs":   _scope_cidrs,
                "allow_network": self.policy.allow_network,
                "allow_write":   self.policy.allow_write,
            })

            wrapper = self._build_wrapper_script(use_seccomp)
            script_path = os.path.join(tmpdir, "runner.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(wrapper)

            preexec = self._make_preexec_fn() if os.name != "nt" else None

            # If drop_privileges is requested on Linux while running as root, the parent
            # orchestrator installs the UID-based OS firewall rules before spawning the child,
            # ensuring that the child is restricted by Netfilter the instant it drops privileges.
            parent_uid_firewall = None
            if os.name != "nt" and self.policy.drop_privileges and getattr(os, "geteuid", lambda: -1)() == 0:
                if self.policy.sandbox_uid is not None:
                    parent_uid_firewall = self.policy.sandbox_uid
                else:
                    try:
                        import pwd
                        parent_uid_firewall = pwd.getpwnam("nobody").pw_uid
                    except Exception:
                        parent_uid_firewall = 65534

            from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
            from ares.core.scope_firewall import scope_firewall_guard

            parent_scope = [ScopeEntry(cidr=c) for c in _scope_cidrs] if self.policy.allow_network else []
            parent_campaign = Campaign(
                id=campaign_id or str(uuid.uuid4()),
                name="sandbox-subprocess-parent",
                scope=parent_scope,
                noise_profile=NoiseProfile.NORMAL,
            )

            async with scope_firewall_guard(
                campaign=parent_campaign,
                enable_os_firewall=(parent_uid_firewall is not None),
                uid_owner=parent_uid_firewall,
            ):
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
                        module_id=module_id,
                        sandbox_tier=sub_tier,
                        requested_tier=requested_tier,
                        effective_tier=sub_tier,
                        success=False,
                        error=f"Sandbox timeout ({self.policy.timeout_s}s)",
                    )

            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")

            try:
                data = json.loads(stdout)
                return SandboxResult(
                    module_id    = module_id,
                    sandbox_tier = sub_tier,
                    requested_tier = requested_tier,
                    effective_tier = sub_tier,
                    success      = data.get("success", False),
                    findings     = data.get("findings", []),
                    extra        = data.get("extra", {}),
                    stdout       = stdout[:2000],
                    stderr       = stderr[:500],
                    exit_code    = proc.returncode or 0,
                )
            except json.JSONDecodeError:
                return SandboxResult(
                    module_id=module_id,
                    sandbox_tier=sub_tier,
                    requested_tier=requested_tier,
                    effective_tier=sub_tier,
                    success=False,
                    error="Invalid JSON from sandbox",
                    stdout=stdout[:500],
                    stderr=stderr[:500],
                )

    async def _run_docker(
        self,
        module_id: str,
        params:    dict[str, Any],
        campaign_id: str,
        requested_tier: IsolationTier = IsolationTier.DOCKER,
    ) -> SandboxResult:
        """
        Run module inside an ephemeral Docker container.
        Requires Docker daemon on host.
        """
        # 1. Strict mode online network limitation for external binaries
        if self.policy.strict_mode and self.policy.allow_network:
            if not self.policy.allow_unconfined_docker_binaries:
                return SandboxResult(
                    module_id=module_id,
                    sandbox_tier=IsolationTier.DOCKER,
                    requested_tier=requested_tier,
                    effective_tier=IsolationTier.DOCKER,
                    success=False,
                    error=(
                        "Docker online mode cannot guarantee scope containment for external binaries inside the container. "
                        "In strict mode, use allow_network=False (network_mode='none') for kernel network namespace isolation, "
                        "or explicitly set allow_unconfined_docker_binaries=True."
                    ),
                )

        # 2. Check docker availability & client connection
        try:
            import docker  # type: ignore[import-untyped]
        except ImportError:
            docker = None

        if docker is None:
            if not self.policy.allow_tier_downgrade:
                audit(
                    "sandbox_tier_downgrade_rejected",
                    actor="engine",
                    requested_tier=requested_tier.value,
                    reason="docker_package_not_installed",
                )
                return SandboxResult(
                    module_id=module_id,
                    sandbox_tier=IsolationTier.DOCKER,
                    requested_tier=requested_tier,
                    effective_tier=IsolationTier.DOCKER,
                    success=False,
                    error="Security tier downgrade from DOCKER to SUBPROCESS rejected (allow_tier_downgrade=False): 'docker' package not installed.",
                )
            lost_guarantees = [
                "read_only_rootfs_mount_namespace",
                "container_cgroups",
                "network_namespace_isolation",
            ]
            audit(
                "sandbox_tier_downgrade",
                actor="engine",
                requested_tier=requested_tier.value,
                effective_tier=IsolationTier.SUBPROCESS.value,
                reason="docker_package_not_installed",
                guarantees_lost=lost_guarantees,
            )
            sub_res = await self._run_subprocess(
                module_id, params, campaign_id, requested_tier=requested_tier
            )
            sub_res.requested_tier = requested_tier
            sub_res.effective_tier = IsolationTier.SUBPROCESS
            sub_res.sandbox_tier = IsolationTier.SUBPROCESS
            sub_res.downgraded = True
            sub_res.downgrade_reason = "docker_package_not_installed"
            sub_res.guarantees_lost = lost_guarantees
            return sub_res

        try:
            client = docker.from_env()
            if hasattr(client, "ping"):
                client.ping()
        except Exception as exc:
            if not self.policy.allow_tier_downgrade:
                audit(
                    "sandbox_tier_downgrade_rejected",
                    actor="engine",
                    requested_tier=requested_tier.value,
                    reason=f"docker_daemon_unavailable: {exc}",
                )
                return SandboxResult(
                    module_id=module_id,
                    sandbox_tier=IsolationTier.DOCKER,
                    requested_tier=requested_tier,
                    effective_tier=IsolationTier.DOCKER,
                    success=False,
                    error=f"Security tier downgrade from DOCKER to SUBPROCESS rejected (allow_tier_downgrade=False): Docker daemon unavailable ({exc}).",
                )
            lost_guarantees = [
                "read_only_rootfs_mount_namespace",
                "container_cgroups",
                "network_namespace_isolation",
            ]
            audit(
                "sandbox_tier_downgrade",
                actor="engine",
                requested_tier=requested_tier.value,
                effective_tier=IsolationTier.SUBPROCESS.value,
                reason=f"docker_daemon_unavailable: {exc}",
                guarantees_lost=lost_guarantees,
            )
            sub_res = await self._run_subprocess(
                module_id, params, campaign_id, requested_tier=requested_tier
            )
            sub_res.requested_tier = requested_tier
            sub_res.effective_tier = IsolationTier.SUBPROCESS
            sub_res.sandbox_tier = IsolationTier.SUBPROCESS
            sub_res.downgraded = True
            sub_res.downgrade_reason = f"docker_daemon_unavailable: {exc}"
            sub_res.guarantees_lost = lost_guarantees
            return sub_res

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
            "module_id":     module_id,
            "params":        params,
            "campaign_id":   campaign_id,
            "scope_cidrs":   _docker_scope,
            "allow_network": self.policy.allow_network,
        })
        image    = self.policy.docker_image
        network  = "none" if not self.policy.allow_network else self.policy.docker_network
        read_only = not self.policy.allow_write
        mem_limit = f"{self.policy.memory_mb}m"

        try:
            container = client.containers.run(
                image,
                command=["python3", "-c", self._inline_runner()],
                environment={"ARES_SANDBOX_PAYLOAD": payload},
                mem_limit=mem_limit,
                cpu_period=100000,
                cpu_quota=50000,   # 50% of one CPU
                network_mode=network,
                read_only=read_only,
                remove=True,
                stdout=True,
                stderr=True,
                detach=False,
                timeout=self.policy.timeout_s,
            )
            output = container.decode() if isinstance(container, bytes) else str(container)
            data   = json.loads(output)
            return SandboxResult(
                module_id=module_id,
                sandbox_tier=IsolationTier.DOCKER,
                requested_tier=requested_tier,
                effective_tier=IsolationTier.DOCKER,
                success=data.get("success", False),
                findings=data.get("findings", []),
                extra=data.get("extra", {}),
            )
        except Exception as exc:
            return SandboxResult(
                module_id=module_id,
                sandbox_tier=IsolationTier.DOCKER,
                requested_tier=requested_tier,
                effective_tier=IsolationTier.DOCKER,
                success=False,
                error=str(exc)[:300],
            )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _make_preexec_fn(self):
        """
        Return preexec_fn that applies resource limits and mandatory security privileges.
        Executed in the child process immediately after fork() and before exec().
        Only called on Unix systems.
        """
        cpu_limit = self.policy.cpu_time_s
        mem_bytes = self.policy.memory_mb * 1024 * 1024
        allow_network = self.policy.allow_network
        drop_privileges = self.policy.drop_privileges
        allow_write = self.policy.allow_write
        target_uid = self.policy.sandbox_uid
        _parent_pid = os.getpid()

        def _limits():
            # 1. Best-effort resource limits (only applied in child process after fork)
            in_child = (os.getpid() != _parent_pid)
            if resource is not None and in_child:
                try:
                    resource.setrlimit(resource.RLIMIT_CPU,   (cpu_limit, cpu_limit))
                    resource.setrlimit(resource.RLIMIT_AS,    (mem_bytes, mem_bytes))
                    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
                    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
                    if not allow_write:
                        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
                except (OSError, ValueError, AttributeError):
                    pass  # best-effort resource limits

            # 2. MANDATORY SECURITY CONTROL: Network isolation (fail-closed)
            if not allow_network:
                import ctypes
                import ctypes.util
                libc_name = ctypes.util.find_library("c") or "libc.so.6"
                try:
                    _libc = ctypes.CDLL(libc_name, use_errno=True)
                    # CLONE_NEWNET = 0x40000000
                    ret = _libc.unshare(0x40000000)
                    if ret != 0:
                        errno_val = ctypes.get_errno()
                        raise RuntimeError(
                            f"unshare(CLONE_NEWNET) returned {ret} (errno={errno_val})"
                        )
                except Exception as exc:
                    raise RuntimeError(
                        f"Mandatory security control failed: allow_network=False requires network namespace isolation: {exc}"
                    )

            # 3. MANDATORY SECURITY CONTROL: Privilege dropping (fail-closed)
            if drop_privileges and getattr(os, "geteuid", lambda: -1)() == 0:
                try:
                    if target_uid is not None:
                        drop_uid = target_uid
                        drop_gid = target_uid
                    else:
                        import pwd
                        nobody = pwd.getpwnam("nobody")
                        drop_uid = nobody.pw_uid
                        drop_gid = nobody.pw_gid
                    os.setgroups([])
                    os.setgid(drop_gid)
                    os.setuid(drop_uid)
                except Exception as exc:
                    target_label = "nobody" if target_uid is None else str(target_uid)
                    raise RuntimeError(
                        f"Mandatory security control failed: drop_privileges=True failed to drop root to {target_label}: {exc}"
                    )
                if getattr(os, "geteuid", lambda: -1)() == 0 or getattr(os, "getuid", lambda: -1)() == 0:
                    raise RuntimeError(
                        "Mandatory security control failed: process retains root privileges (uid/euid == 0) after drop"
                    )

        return _limits

    @staticmethod
    def _build_wrapper_script(use_seccomp: bool) -> str:
        """
        Build Python source that runs in the sandbox child process.
        When use_seccomp=True, applies PR_SET_NO_NEW_PRIVS (prctl 38) as a
        mandatory minimum, preventing the child from ever regaining privileges.
        Full BPF syscall allowlist filtering is applied via pyseccomp.
        Fails closed with RuntimeError if seccomp enforcement cannot be established.
        """
        if use_seccomp:
            allowed_list = repr(sorted(_SECCOMP_ALLOWED))
            seccomp_preamble = (
                "# ── SECCOMP: apply mandatory privilege restrictions ───────────────────\n"
                "import ctypes as _ct, ctypes.util as _cu, os as _so, sys as _sys\n"
                "try:\n"
                "    _libc = _ct.CDLL(_cu.find_library('c'), use_errno=True)\n"
                "    if _libc.prctl(38, 1, 0, 0, 0) != 0:\n"
                "        raise RuntimeError('prctl PR_SET_NO_NEW_PRIVS returned non-zero')\n"
                "except Exception as _pe:\n"
                "    print(f'[sandbox] prctl failed: {_pe}', file=_sys.stderr)\n"
                "    raise RuntimeError(f'Seccomp PR_SET_NO_NEW_PRIVS enforcement failed: {_pe}')\n"
                "try:\n"
                "    import seccomp as _sc  # pyseccomp\n"
                f"    _allowed = {allowed_list}\n"
                "    _f = _sc.SyscallFilter(defaction=_sc.KILL)\n"
                "    for _sn in _allowed:\n"
                "        try: _f.add_rule(_sc.ALLOW, _sn)\n"
                "        except Exception: pass\n"
                "    _f.load()\n"
                "except Exception as _be:\n"
                "    print(f'[sandbox] BPF filter failed: {_be}', file=_sys.stderr)\n"
                "    raise RuntimeError(f'IsolationTier.SECCOMP failed to load BPF syscall filter: {_be}')\n"
                "# ── end SECCOMP ────────────────────────────────────────────────────────\n"
            )
        else:
            seccomp_preamble = ""

        body = (
            seccomp_preamble
            + "\nimport sys, json, asyncio, os\n\n"
            "payload = json.loads(sys.stdin.read())\n"
            "module_id   = payload[\"module_id\"]\n"
            "params      = payload[\"params\"]\n"
            "campaign_id = payload.get(\"campaign_id\", \"\")\n"
            "\n# ── Defense-in-depth: Python-level write hooks (when allow_write=False) ──\n"
            "# Classification: DEFENSE-IN-DEPTH for Python stdlib. Complete filesystem sandboxing\n"
            "# requires the DOCKER tier (read_only=True rootfs mount).\n"
            "_allow_write = payload.get(\"allow_write\", False)\n"
            "_tmpdir = payload.get(\"tmpdir\", \"\")\n"
            "if not _allow_write and _tmpdir:\n"
            "    import builtins\n"
            "    def _is_contained_in_sandbox(target_path, sandbox_dir):\n"
            "        try:\n"
            "            real_sandbox = os.path.normcase(os.path.realpath(sandbox_dir))\n"
            "            target_str = str(target_path)\n"
            "            if not os.path.exists(target_str):\n"
            "                parent = os.path.dirname(target_str) or \".\"\n"
            "                real_target = os.path.normcase(os.path.join(os.path.realpath(parent), os.path.basename(target_str)))\n"
            "            else:\n"
            "                real_target = os.path.normcase(os.path.realpath(target_str))\n"
            "            return os.path.commonpath([real_sandbox, real_target]) == real_sandbox\n"
            "        except (ValueError, OSError, TypeError):\n"
            "            return False\n"
            "\n"
            "    _orig_open = builtins.open\n"
            "    def _sandboxed_open(file, mode=\"r\", *args, **kwargs):\n"
            "        if any(m in mode for m in (\"w\", \"a\", \"+\", \"x\")):\n"
            "            if not _is_contained_in_sandbox(file, _tmpdir):\n"
            "                raise PermissionError(f\"[Sandbox] Write prohibited outside sandbox directory: {file}\")\n"
            "        return _orig_open(file, mode, *args, **kwargs)\n"
            "    builtins.open = _sandboxed_open\n"
            "\n"
            "    _orig_os_open = os.open\n"
            "    def _sandboxed_os_open(path, flags, *args, **kwargs):\n"
            "        write_flags = (\n"
            "            getattr(os, \"O_WRONLY\", 1) |\n"
            "            getattr(os, \"O_RDWR\", 2) |\n"
            "            getattr(os, \"O_CREAT\", 64) |\n"
            "            getattr(os, \"O_TRUNC\", 512) |\n"
            "            getattr(os, \"O_APPEND\", 1024)\n"
            "        )\n"
            "        if flags & write_flags:\n"
            "            if not _is_contained_in_sandbox(path, _tmpdir):\n"
            "                raise PermissionError(f\"[Sandbox] os.open write prohibited outside sandbox directory: {path}\")\n"
            "        return _orig_os_open(path, flags, *args, **kwargs)\n"
            "    os.open = _sandboxed_os_open\n"
            "\n"
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
            "        _allow_net   = payload.get(\"allow_network\", True)\n"
            "        _scope_cidrs = payload.get(\"scope_cidrs\", [])\n"
            "        if not _allow_net:\n"
            "            campaign = Campaign(\n"
            "                id=campaign_id or str(uuid.uuid4()),\n"
            "                name=\"sandbox\",\n"
            "                scope=[],\n"
            "                noise_profile=NoiseProfile.NORMAL,\n"
            "            )\n"
            "        elif not _scope_cidrs:\n"
            "            print(json.dumps({\"success\": False, \"error\":\n"
            "                \"Sandbox scope not provided - refusing to run with unbounded scope\",\n"
            "                \"findings\": [], \"extra\": {}}))\n"
            "            return\n"
            "        else:\n"
            "            campaign = Campaign(\n"
            "                id=campaign_id or str(uuid.uuid4()),\n"
            "                name=\"sandbox\",\n"
            "                scope=[ScopeEntry(cidr=c) for c in _scope_cidrs],\n"
            "                noise_profile=NoiseProfile.NORMAL,\n"
            "            )\n"
            "        settings = AresSettings()\n"
            "        noise    = NoiseController(campaign)\n"
            "        module   = module_cls(settings=settings, campaign=campaign, noise=noise)\n"
            "        from ares.core.scope_firewall import scope_firewall_guard\n"
            "        _current_uid = getattr(os, 'getuid', lambda: None)()\n"
            "        async with scope_firewall_guard(campaign=campaign, module_id=module_id, enable_os_firewall=False, uid_owner=_current_uid):\n"
            "            findings, extra = await module.run(**params)\n"
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
            '        _allow_net   = payload.get("allow_network", True)\n'
            '        _scope_cidrs = payload.get("scope_cidrs", [])\n'
            '        if not _allow_net:\n'
            '            campaign = Campaign(\n'
            '                id=campaign_id or str(uuid.uuid4()),\n'
            '                name="sandbox", operator="sandbox",\n'
            '                scope=[],\n'
            '                noise_profile=NoiseProfile.NORMAL,\n'
            '            )\n'
            '        elif not _scope_cidrs:\n'
            '            return {"success": False,\n'
            '                    "error": "Sandbox scope not provided - refusing to run with unbounded scope",\n'
            '                    "findings": [], "extra": {}}\n'
            '        else:\n'
            '            campaign = Campaign(\n'
            '                id=campaign_id or str(uuid.uuid4()),\n'
            '                name="sandbox", operator="sandbox",\n'
            '                scope=[ScopeEntry(cidr=c) for c in _scope_cidrs],\n'
            '                noise_profile=NoiseProfile.NORMAL,\n'
            '            )\n'
            '        try:\n'
            '            from ares.core.config import AresSettings\n'
            '            from ares.core.noise import NoiseController\n'
            '            settings = AresSettings()\n'
            '            noise    = NoiseController(campaign)\n'
            '            module   = module_cls(settings=settings, campaign=campaign, noise=noise)\n'
            '        except Exception:\n'
            '            module = module_cls()\n'
            '        from ares.core.scope_firewall import scope_firewall_guard\n'
            '        async with scope_firewall_guard(campaign=campaign, module_id=module_id):\n'
            '            findings, extra = await module.run(**params)\n'
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
        return any(
            module_id == p or module_id.startswith(f"{p}.")
            for p in self.policy.trusted_prefixes
        )
