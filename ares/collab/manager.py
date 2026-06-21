"""
ARES Multi-Operator Collaboration
Supports multiple red team operators working on the same campaign.

Roles:
  TEAM_LEAD   — full access: start/stop campaign, manage operators
  OPERATOR    — run modules, view findings, create artifacts
  RECON       — recon modules only (enumeration, no lateral/exploit)
  REPORTER    — read-only access to findings and artifacts

Operator session tracking:
  - Each operator has independent local session state
  - Findings and artifacts are shared across all operators
  - OperatorJournal: timestamped log of who did what

Conflict prevention:
  - Module locking: operator claims target before running
  - Lock expires after 10 minutes (prevents dead locks)
  - Warning emitted if two operators target same host

State synchronization:
  - In-memory (single ARES process) — direct Python references
  - Multi-process (Redis pub/sub) — JSON delta events
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import audit, get_logger

logger = get_logger("ares.collab")


class OperatorRole(str, Enum):
    TEAM_LEAD = "team_lead"
    OPERATOR  = "operator"
    RECON     = "recon"
    REPORTER  = "reporter"


# Module access matrix: role → allowed module prefixes
ROLE_PERMISSIONS: dict[OperatorRole, list[str]] = {
    OperatorRole.TEAM_LEAD: ["*"],                              # all
    OperatorRole.OPERATOR:  ["ad.", "lateral.", "linux.",       # no teardown
                              "cloud.", "credential.", "execution.",
                              "network.", "windows.", "persistence.",
                              "exfil.", "reporting."],
    OperatorRole.RECON:     ["ad.enum_", "service_intel.",      # enumeration only
                              "fingerprint.", "network."],
    OperatorRole.REPORTER:  [],                                  # read-only
}

# Ordered list for role level comparisons (lowest → highest)
ROLE_ORDER: list[OperatorRole] = [
    OperatorRole.REPORTER,
    OperatorRole.RECON,
    OperatorRole.OPERATOR,
    OperatorRole.TEAM_LEAD,
]


def can_role_run_module(
    role: "OperatorRole | str",
    module_id: str,
    registry: "Any | None" = None,
) -> bool:
    """
    Single source of truth for module-level RBAC.
    Used by both the engine (pre-execution check) and HTTP RBAC layer.

    Priority:
      1. ROLE_PERMISSIONS prefix-based fast path
      2. Registry OPSEC_LEVEL fallback for RECON — LOW-opsec modules allowed
         even if their prefix isn't in RECON's list

    Args:
        role:      OperatorRole enum or plain string (e.g. "operator")
        module_id: Dotted module ID (e.g. "ad.kerberoast")
        registry:  Optional ModuleRegistry — enables dynamic OPSEC fallback

    Returns True if the role may run the module.
    """
    if isinstance(role, str):
        try:
            role = OperatorRole(role)
        except ValueError:
            role = OperatorRole.REPORTER   # unknown role → most restrictive

    allowed = ROLE_PERMISSIONS.get(role, [])
    if not allowed:
        return False
    if "*" in allowed:
        return True

    # Prefix-based check (fast path)
    if any(module_id.startswith(prefix) for prefix in allowed):
        return True

    # Fallback: RECON may run LOW-opsec modules not in their prefix list
    if role == OperatorRole.RECON and registry is not None:
        cls = registry.get(module_id) if hasattr(registry, "get") else None
        if cls is not None:
            try:
                from ares.core.opsec.opsec import OpsecLevel
                if getattr(cls, "OPSEC_LEVEL", None) == OpsecLevel.LOW:
                    return True
            except Exception:
                pass

    return False


@dataclass
class OperatorProfile:
    """Profile of a single team operator."""
    operator_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    username:    str = ""
    name:        str = ""   # display name alias
    role:        OperatorRole = OperatorRole.OPERATOR
    joined_at:   float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    active_targets: list[str] = field(default_factory=list)
    modules_run:    int = 0
    findings_added: int = 0
    notes:          str = ""

    @property
    def is_active(self) -> bool:
        return time.time() - self.last_active < 1800   # 30 min inactivity

    def can_run_module(self, module_id: str) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, [])
        if "*" in allowed:
            return True
        return any(module_id.startswith(prefix) for prefix in allowed)

    def touch(self) -> None:
        self.last_active = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator_id":    self.operator_id,
            "username":       self.username,
            "role":           self.role.value,
            "is_active":      self.is_active,
            "modules_run":    self.modules_run,
            "findings_added": self.findings_added,
            "active_targets": self.active_targets,
        }


@dataclass
class TargetLock:
    """Exclusive lock on a target host+module combination."""
    lock_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    operator_id: str = ""
    target_host: str = ""
    target:     str = ""   # alias for target_host
    module_id:   str = ""
    acquired_at: float = field(default_factory=time.time)
    ttl_s:       int = 600    # 10 minutes
    ttl_seconds: int = -1   # alias: if set, overrides ttl_s

    def __post_init__(self) -> None:
        # Sync aliases
        if self.target and not self.target_host:
            object.__setattr__(self, "target_host", self.target)
        elif self.target_host and not self.target:
            object.__setattr__(self, "target", self.target_host)
        if self.ttl_seconds >= 0:
            object.__setattr__(self, "ttl_s", self.ttl_seconds)

    @property
    def is_expired(self) -> bool:
        return time.time() - self.acquired_at > self.ttl_s

    @property
    def is_locked(self) -> bool:
        """True if lock is still active (not expired). Use as property, not method."""
        return not self.is_expired

    @property
    def owner_key(self) -> str:
        return f"{self.target_host}:{self.module_id}"


@dataclass
class JournalEntry:
    """Audit trail entry for multi-operator campaigns."""
    entry_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    operator_id: str = ""
    username:    str = ""
    action:      str = ""      # "module_started", "finding_added", "lateral_moved", etc.
    target:      str = ""
    module_id:   str = ""
    success:     bool | None = None
    details:     str = ""
    timestamp:   float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id":    self.entry_id,
            "operator":    self.username,
            "action":      self.action,
            "target":      self.target,
            "module_id":   self.module_id,
            "success":     self.success,
            "details":     self.details,
            "timestamp":   self.timestamp,
        }


class CollaborationManager:
    """
    Manages multi-operator collaboration for a campaign.
    Handles role enforcement, target locking, and shared journal.
    """

    def __init__(self, campaign_id: str) -> None:
        self.campaign_id = campaign_id
        self._operators: dict[str, OperatorProfile] = {}  # operator_id → profile
        self._locks:     dict[str, TargetLock]      = {}  # owner_key   → lock
        self._lock_mutex: "asyncio.Lock | None"     = None  # init lazily (event loop may not exist yet)
        self._journal:   list[JournalEntry]          = []

    def _get_mutex(self) -> "asyncio.Lock":
        """Return (or lazily create) the asyncio.Lock protecting _locks dict."""
        import asyncio
        if self._lock_mutex is None:
            self._lock_mutex = asyncio.Lock()
        return self._lock_mutex

    # ── Operator management ────────────────────────────────────────────────

    def register_operator(
        self,
        operator_id: str = "",
        username_or_role: "str | OperatorRole" = "",
        name:     str = "",
        role:     OperatorRole = OperatorRole.OPERATOR,
        username: str = "",
    ) -> OperatorProfile:
        # Handle positional: register_operator("alice", OperatorRole.RECON)
        if isinstance(username_or_role, OperatorRole):
            role = username_or_role
            username = username or ""
        else:
            username = username or str(username_or_role)
        display = name or username
        op = OperatorProfile(
            username=display, name=display, role=role,
            operator_id=operator_id if operator_id else str(uuid.uuid4())[:8]
        )
        self._operators[op.operator_id] = op
        audit("operator_joined", actor=username, campaign=self.campaign_id,
              role=role.value, operator_id=op.operator_id)
        logger.info("operator_registered", username=username, role=role.value,
                    operator_id=op.operator_id)
        self._journal_entry(op, "joined", details=f"role={role.value}")
        return op

    def log_event(
        self,
        operator_id: str,
        event_type:  str,
        target:      str = "",
        module_id:   str = "",
        success:     bool | None = None,
        details:     str = "",
    ) -> None:
        """Append a structured event to the campaign journal."""
        op = self._operators.get(operator_id)
        entry = JournalEntry(
            operator_id = operator_id,
            username    = op.username if op else operator_id,
            action      = event_type,
            target      = target,
            module_id   = module_id,
            success     = success,
            details     = details,
        )
        self._journal.append(entry)

    def get_operator(self, operator_id: str) -> OperatorProfile | None:
        return self._operators.get(operator_id)

    def active_operators(self) -> list[OperatorProfile]:
        return [op for op in self._operators.values() if op.is_active]

    # ── Permission checking ────────────────────────────────────────────────

    def check_permission(self, operator_id: str, module_id: str) -> tuple[bool, str]:
        """
        Returns (allowed, reason).
        Call before every module execution.
        """
        op = self._operators.get(operator_id)
        if not op:
            return False, "Operator not registered"
        if not op.can_run_module(module_id):
            return False, f"Role {op.role.value!r} cannot run {module_id!r}"
        op.touch()
        return True, "ok"

    def list_operators(self) -> "list[OperatorProfile]":
        """Return all registered operators."""
        return list(self._operators.values())

    def is_locked(self, target: str) -> bool:
        """Check if any active lock exists for the given target host."""
        self._evict_expired_locks()
        return any(
            lock.target_host == target
            for lock in self._locks.values()
            if not lock.is_expired
        )

    # ── Target locking ─────────────────────────────────────────────────────

    async def acquire_lock_async(
        self,
        arg1: str,
        arg2: str = "",
        module_id: str = "",
    ) -> "tuple[bool, str] | str | None":
        """Async-safe version of acquire_lock — use this from coroutines."""
        async with self._get_mutex():
            return self.acquire_lock(arg1, arg2, module_id)

    def acquire_lock(
        self,
        arg1: str,
        arg2: str = "",
        module_id: str = "",
    ) -> "tuple[bool, str] | str | None":
        """
        Acquire exclusive lock on a target+module.

        Accepts two calling conventions:
          - operator_first:  acquire_lock(operator_id, target, module_id)
            → returns (True, lock_id) on success, (False, reason) on fail
          - target_first:    acquire_lock(target, operator_id, module_id)
            → returns lock_id string on success, None on fail
        """
        self._evict_expired_locks()
        # Auto-detect calling convention by checking if arg1 is a registered operator
        if arg1 in self._operators:
            operator_id = arg1
            target_host = arg2
            operator_first = True
        else:
            target_host = arg1
            operator_id = arg2
            operator_first = False

        op = self._operators.get(operator_id)
        if not op:
            return (False, "Unknown operator") if operator_first else None

        # Check any lock on this target (regardless of module)
        existing = next(
            (l for l in self._locks.values()
             if l.target_host == target_host and not l.is_expired
             and l.operator_id != operator_id),
            None,
        )
        if existing:
            owner_op = self._operators.get(existing.operator_id)
            owner = owner_op.username if owner_op else existing.operator_id
            reason = f"Target locked by operator {owner!r}"
            return (False, reason) if operator_first else None

        lock = TargetLock(operator_id=operator_id, target_host=target_host,
                          module_id=module_id)
        lock_key = f"{target_host}:{module_id or '_'}:{operator_id}"
        self._locks[lock_key] = lock
        if target_host not in op.active_targets:
            op.active_targets.append(target_host)

        logger.debug("target_lock_acquired", operator=op.username,
                     target=target_host, module=module_id)
        return (True, lock.lock_id) if operator_first else lock.lock_id

    def release_lock(self, lock_id_or_target: str, operator_id: str = "") -> bool:
        """Release lock by lock_id (integration style) or by (target, operator_id) (unit style)."""
        if operator_id:
            # target-first style: release_lock(target, operator_id)
            target = lock_id_or_target
            to_del = [k for k, l in self._locks.items()
                      if l.target_host == target and l.operator_id == operator_id]
        else:
            # lock_id style: release_lock(lock_id)
            to_del = [k for k, l in self._locks.items() if l.lock_id == lock_id_or_target]

        for key in to_del:
            lock = self._locks.pop(key, None)
            if lock:
                op = self._operators.get(lock.operator_id)
                if op and lock.target_host in op.active_targets:
                    op.active_targets.remove(lock.target_host)
        return bool(to_del)

    def _evict_expired_locks(self) -> None:
        expired = [k for k, l in self._locks.items() if l.is_expired]
        for k in expired:
            del self._locks[k]

    # ── Journal ────────────────────────────────────────────────────────────

    def log(
        self,
        operator_id: str,
        action:      str,
        target:      str = "",
        module_id:   str = "",
        success:     bool | None = None,
        details:     str = "",
    ) -> JournalEntry:
        op = self._operators.get(operator_id)
        entry = JournalEntry(
            operator_id = operator_id,
            username    = op.username if op else operator_id,
            action      = action,
            target      = target,
            module_id   = module_id,
            success     = success,
            details     = details,
        )
        self._journal.append(entry)
        if op:
            op.touch()
            if action == "module_completed" and success:
                op.modules_run += 1
            if action == "finding_added":
                op.findings_added += 1
        return entry

    def _journal_entry(
        self, op: OperatorProfile, action: str, details: str = ""
    ) -> None:
        self._journal.append(JournalEntry(
            operator_id=op.operator_id, username=op.username,
            action=action, details=details,
        ))

    def journal(
        self,
        operator_id: str = "",
        action:      str = "",
        since:       float = 0.0,
    ) -> list[JournalEntry]:
        entries = self._journal
        if operator_id:
            entries = [e for e in entries if e.operator_id == operator_id]
        if action:
            entries = [e for e in entries if e.action == action]
        if since:
            entries = [e for e in entries if e.timestamp >= since]
        return entries

    # ── Status ─────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        return {
            "campaign_id":      self.campaign_id,
            "total_operators":  len(self._operators),
            "active_operators": len(self.active_operators()),
            "active_locks":     len([l for l in self._locks.values() if not l.is_expired]),
            "journal_entries":  len(self._journal),
            "operators":        [op.to_dict() for op in self._operators.values()],
        }
