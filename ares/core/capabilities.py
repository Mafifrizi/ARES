"""
ARES Module Capability System
Declares and enforces what system resources each module is allowed to access.

Each module declares its capabilities:
    class KerberoastModule(BaseModule):
        CAPABILITIES = {Capability.CAP_NET}     # needs network only

The sandbox enforces these at runtime:
    - CAP_NET    → allowed outbound connections
    - CAP_EXEC   → allowed to spawn subprocesses
    - CAP_FS     → allowed to read/write local filesystem
    - CAP_DB     → allowed to query ARES internal database
    - CAP_PROCESS → allowed to inspect/kill local processes (linux privesc)
    - CAP_UNSAFE  → no restrictions (HIGH_NOISE modules only — must be explicit)

Policy enforcement points:
    1. PluginLoader  — verifies declared capabilities are acceptable for trust level
    2. SandboxRunner — enforces caps via seccomp + resource limits
    3. WorkerNode    — worker dispatches to capability-matched workers
    4. API endpoint  — operator role must have >= module's required caps

Principles:
    - Default: DENY ALL capabilities not explicitly declared
    - Core modules (builtin) can declare CAP_UNSAFE
    - Community modules cannot declare CAP_UNSAFE (rejected at load)
    - External/unsigned modules: only CAP_NET + CAP_DB allowed
"""
from __future__ import annotations

from enum import Enum, auto
from typing import Any


class Capability(str, Enum):
    """
    Fine-grained capability flags for module resource access.
    """
    CAP_NET     = "cap_net"      # outbound network connections (LDAP, SMB, SSH, etc.)
    CAP_EXEC    = "cap_exec"     # spawn subprocesses / execute commands on target
    CAP_FS      = "cap_fs"       # read/write local filesystem (not just /tmp)
    CAP_DB      = "cap_db"       # read/write ARES internal database (findings, creds)
    CAP_PROCESS = "cap_process"  # inspect/kill local processes (used by linux.privesc)
    CAP_UNSAFE  = "cap_unsafe"   # bypass all restrictions (builtin core modules only)


# ── Capability profiles (bundles) ──────────────────────────────────────────────

# What most AD/network modules need
CAP_NETWORK_MODULE = frozenset({Capability.CAP_NET, Capability.CAP_DB})

# What lateral movement modules need
CAP_LATERAL_MODULE = frozenset({
    Capability.CAP_NET, Capability.CAP_EXEC, Capability.CAP_DB
})

# What local privesc modules need
CAP_PRIVESC_MODULE = frozenset({
    Capability.CAP_NET, Capability.CAP_EXEC, Capability.CAP_FS,
    Capability.CAP_PROCESS, Capability.CAP_DB,
})

# What recon/enum modules need (read-only)
CAP_ENUM_MODULE = frozenset({Capability.CAP_NET, Capability.CAP_DB})

# What reporting modules need
CAP_REPORT_MODULE = frozenset({Capability.CAP_DB, Capability.CAP_FS})

# Max allowed for community/external modules (cannot exceed this)
CAP_COMMUNITY_MAX = frozenset({
    Capability.CAP_NET, Capability.CAP_DB, Capability.CAP_FS,
})

# Capabilities always forbidden for external/unsigned modules
CAP_EXTERNAL_FORBIDDEN = frozenset({
    Capability.CAP_EXEC, Capability.CAP_PROCESS, Capability.CAP_UNSAFE,
})


# ── Policy enforcement ─────────────────────────────────────────────────────────

class CapabilityViolation(Exception):
    """Raised when a module declares forbidden capabilities."""
    def __init__(self, module_id: str, forbidden: set[Capability]) -> None:
        super().__init__(
            f"Module {module_id!r} declares forbidden capabilities: "
            f"{[c.value for c in forbidden]}. "
            f"Community/external modules cannot use CAP_EXEC, CAP_PROCESS, or CAP_UNSAFE."
        )
        self.module_id = module_id
        self.forbidden = forbidden


class CapabilityPolicy:
    """
    Enforces capability policy at module load time and execution time.

    Trust levels:
        builtin    — full capabilities including CAP_UNSAFE
        community  — CAP_NET, CAP_DB, CAP_FS only
        external   — CAP_NET, CAP_DB only (no filesystem writes)
        unsigned   — CAP_NET only (strictest)
    """

    TRUST_LEVEL_CAPS: dict[str, frozenset[Capability]] = {
        "builtin":   frozenset(Capability),          # all capabilities
        "community": CAP_COMMUNITY_MAX,
        "external":  frozenset({Capability.CAP_NET, Capability.CAP_DB}),
        "unsigned":  frozenset({Capability.CAP_NET}),
    }

    @classmethod
    def allowed_for_trust(cls, trust_level: str) -> frozenset[Capability]:
        return cls.TRUST_LEVEL_CAPS.get(trust_level, frozenset({Capability.CAP_NET}))

    @classmethod
    def validate(
        cls,
        module_id:    str,
        declared:     set[Capability] | frozenset[Capability],
        trust_level:  str,
    ) -> list[str]:
        """
        Validate a module's declared capabilities against its trust level.
        Returns list of violation messages (empty = valid).
        """
        allowed  = cls.allowed_for_trust(trust_level)
        declared = frozenset(declared)
        forbidden = declared - allowed

        if forbidden:
            return [
                f"Module {module_id!r} (trust={trust_level!r}) declares "
                f"forbidden capability {c.value!r}"
                for c in forbidden
            ]
        return []

    @classmethod
    def enforce(
        cls,
        module_id:   str,
        declared:    set[Capability] | frozenset[Capability],
        trust_level: str,
    ) -> None:
        """Validate and raise CapabilityViolation if any cap is forbidden."""
        violations = cls.validate(module_id, declared, trust_level)
        if violations:
            allowed  = cls.allowed_for_trust(trust_level)
            declared = frozenset(declared)
            raise CapabilityViolation(module_id, declared - allowed)

    @classmethod
    def seccomp_syscalls_for(cls, caps: frozenset[Capability]) -> set[str]:
        """
        Map capability set to allowed seccomp syscalls.
        Used by SandboxRunner when applying seccomp filter.
        """
        # Base syscalls always allowed (process lifecycle)
        base = {
            "read", "write", "close", "fstat", "mmap", "mprotect", "munmap",
            "brk", "rt_sigaction", "rt_sigprocmask", "exit", "exit_group",
            "futex", "nanosleep", "getpid", "gettimeofday", "clock_gettime",
            "clock_nanosleep", "getcwd", "getuid", "getgid", "getpgrp",
            "arch_prctl", "set_tid_address", "prctl", "getrandom",
            "openat", "open", "stat", "lstat", "ioctl", "select", "poll",
            "epoll_wait", "epoll_ctl", "epoll_create1", "fcntl",
        }

        extra: set[str] = set()

        if Capability.CAP_NET in caps:
            extra.update({
                "socket", "connect", "bind", "listen", "accept", "sendto",
                "recvfrom", "sendmsg", "recvmsg", "setsockopt", "getsockopt",
                "getpeername", "getsockname", "shutdown", "socketpair", "dup2",
            })

        if Capability.CAP_EXEC in caps:
            extra.update({
                "execve", "execveat", "fork", "vfork", "clone", "clone3",
                "wait4", "waitpid", "kill", "pipe", "pipe2",
            })

        if Capability.CAP_FS in caps:
            extra.update({
                "mkdir", "rmdir", "unlink", "unlinkat", "rename", "renameat",
                "chmod", "fchmod", "truncate", "ftruncate", "fsync",
                "readlink", "readlinkat", "lseek", "pread64", "pwrite64",
                "getdents64", "statfs",
            })

        if Capability.CAP_PROCESS in caps:
            extra.update({
                "ptrace", "getdents", "openat", "readdir",
                "kill", "tkill", "tgkill",
            })

        if Capability.CAP_UNSAFE in caps:
            # Unsafe = no seccomp filter (all syscalls allowed)
            return set()  # empty = no filter

        return base | extra

    @classmethod
    def resource_limits_for(cls, caps: frozenset[Capability]) -> dict[str, int]:
        """
        Return resource limits (RLIMIT values) appropriate for the capability set.
        Used by SandboxRunner._make_preexec_fn().
        """
        if Capability.CAP_UNSAFE in caps:
            return {}  # no limits

        limits = {
            "cpu_time_s": 30,
            "memory_mb":  256,
            "max_procs":  8 if Capability.CAP_EXEC in caps else 1,
            "max_files":  64,
        }

        # Execution-heavy modules (DCSync, lateral) get more time
        if Capability.CAP_EXEC in caps:
            limits["cpu_time_s"] = 120
            limits["memory_mb"]  = 512

        return limits


def default_capabilities_for_category(category: str) -> frozenset[Capability]:
    """
    Infer a sensible default capability set from module category.
    Used when a module doesn't explicitly declare CAPABILITIES.
    """
    mapping: dict[str, frozenset[Capability]] = {
        "ad":        CAP_NETWORK_MODULE,
        "lateral":   CAP_LATERAL_MODULE,
        "linux":     CAP_PRIVESC_MODULE,
        "cloud":     CAP_NETWORK_MODULE,
        "reporting": CAP_REPORT_MODULE,
        "execution": CAP_LATERAL_MODULE,
    }
    return mapping.get(category, CAP_NETWORK_MODULE)
