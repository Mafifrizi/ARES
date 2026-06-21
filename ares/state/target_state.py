"""
ARES Operator Session & Target State Engine
Tracks the full operational state of a red team engagement.

State hierarchy:
  OperatorSession
    ├── NetworkState (discovered hosts, subnets)
    ├── HostState × N (per-host compromise status)
    ├── CredentialIndex (cross-reference creds to hosts)
    └── AttackHistory (what was tried, when, result)
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.state")


class CompromiseLevel(str, Enum):
    NONE             = "none"
    IDENTIFIED       = "identified"
    SCANNED          = "scanned"
    ACCESSED         = "accessed"
    LOCAL_USER       = "local_user"
    LOCAL_ADMIN      = "local_admin"
    SERVICE_ACCOUNT  = "service_account"
    SYSTEM           = "system"
    DOMAIN_USER      = "domain_user"
    DOMAIN_ADMIN     = "domain_admin"

    # Convenience aliases used in tests
    USER             = "local_user"
    DOMAIN           = "domain_user"
    ENTERPRISE_ADMIN = "enterprise_admin"

    def score(self) -> int:
        return {
            "none": 0, "identified": 1, "scanned": 2, "accessed": 3,
            "local_user": 4, "local_admin": 5, "service_account": 6,
            "system": 7, "domain_user": 5, "domain_admin": 9,
            "enterprise_admin": 10,
        }.get(self.value, 0)

    def __gt__(self, other: "CompromiseLevel") -> bool:
        return self.score() > other.score()

    def __ge__(self, other: "CompromiseLevel") -> bool:
        return self.score() >= other.score()


@dataclass
class ServiceEntry:
    """A discovered service on a host."""
    port:       int
    protocol:   str = "tcp"
    service:    str = ""
    banner:     str = ""
    version:    str = ""
    vulnerable: bool = False


@dataclass
class HostState:
    """Full state of a single target host."""
    ip_address:  str = ""
    ip:          str = field(default="", repr=False)   # alias — set either ip_address or ip
    hostname:    str = ""
    fqdn:        str = ""
    domain:      str = ""
    os:          str = ""
    os_version:  str = ""
    is_dc:       bool = False
    is_in_scope: bool = True

    compromise_level: CompromiseLevel = CompromiseLevel.NONE
    owned:            bool = False
    privilege:        str  = ""
    owned_at:         float | None = None
    owned_via:        str = ""

    services:        list[ServiceEntry] = field(default_factory=list)
    open_ports:      list[int]          = field(default_factory=list)
    users:           list[str]          = field(default_factory=list)
    local_admins:    list[str]          = field(default_factory=list)
    shares:          list[str]          = field(default_factory=list)

    valid_credential_ids: list[str] = field(default_factory=list)

    reachable_from:  list[str] = field(default_factory=list)
    can_reach:       list[str] = field(default_factory=list)

    first_seen:   float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    tags:         list[str] = field(default_factory=list)
    notes:        str = ""
    os_type:      str = ""   # e.g. "Windows Server", "Linux"
    domain_role:  str = ""   # e.g. "domain_controller", "member"
    attack_history: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.ip and not self.ip_address:
            self.ip_address = self.ip
        elif self.ip_address and not self.ip:
            self.ip = self.ip_address

    @property
    def owned_by(self) -> str:
        """Username of the operator/user who owns this host."""
        return self.privilege

    def is_owned(self) -> bool:
        return self.owned

    def mark_owned(
        self,
        level:    CompromiseLevel,
        via:      str = "",
        username: str = "",
        method:   str = "",  # alias for via
    ) -> None:
        if method and not via:
            via = method
        if level > self.compromise_level:
            self.compromise_level = level
            self.owned_via        = via
            self.privilege        = username
            self.last_updated     = time.time()
            if level >= CompromiseLevel.LOCAL_ADMIN:
                self.owned     = True
                self.owned_at  = time.time()
            logger.info(
                "host_state_updated",
                host=self.ip_address or self.hostname,
                level=level.value,
                via=via,
            )

    def add_service(self, port: int, service: str, version: str = "") -> None:
        if port not in self.open_ports:
            self.open_ports.append(port)
        existing = next((s for s in self.services if s.port == port), None)
        if not existing:
            self.services.append(ServiceEntry(port=port, service=service, version=version))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address":       self.ip_address,
            "hostname":         self.hostname,
            "fqdn":             self.fqdn,
            "domain":           self.domain,
            "os":               self.os,
            "is_dc":            self.is_dc,
            "compromise_level": self.compromise_level.value,
            "owned":            self.owned,
            "privilege":        self.privilege,
            "owned_via":        self.owned_via,
            "open_ports":       self.open_ports,
            "services":         [
                {"port": s.port, "service": s.service, "version": s.version}
                for s in self.services
            ],
            "local_admins":          self.local_admins,
            "valid_credential_ids":  self.valid_credential_ids,
            "reachable_from":        self.reachable_from,
            "can_reach":             self.can_reach,
            "tags":                  self.tags,
        }


@dataclass
class AttackHistoryEntry:
    """Record of a single attack attempt."""
    entry_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:   float = field(default_factory=time.time)
    module_id:   str = ""
    technique:   str = ""
    source_host: str = "operator"
    target_host: str = ""
    username:    str = ""
    success:     bool = False
    finding_ids: list[str] = field(default_factory=list)
    output:      str = ""
    notes:       str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id":   self.entry_id,
            "timestamp":  self.timestamp,
            "module_id":  self.module_id,
            "technique":  self.technique,
            "source":     self.source_host,
            "target":     self.target_host,
            "username":   self.username,
            "success":    self.success,
            "findings":   self.finding_ids,
        }


# ── Operator Session ───────────────────────────────────────────────────────────

class OperatorSession:
    """
    Full state of an active red team engagement.
    Tracks every discovered host, credential, and attack attempt.
    """

    def __init__(self, campaign_id: str, operator: str = "unknown") -> None:
        self.session_id:  str = str(uuid.uuid4())
        self.campaign_id: str = campaign_id
        self.operator:    str = operator
        self.started_at:  float = time.time()

        self._hosts:   dict[str, HostState] = {}
        self._history: list[AttackHistoryEntry] = []
        self._pivot_proxies: list[dict[str, Any]] = []

        logger.info("session_created",
                    session_id=self.session_id[:8],
                    campaign=campaign_id,
                    operator=operator)

    # ── Host management ────────────────────────────────────────────────────

    def add_host(self, ip: str, hostname: str = "", **kwargs: Any) -> HostState:
        key = ip or hostname
        if key not in self._hosts:
            self._hosts[key] = HostState(ip_address=ip, hostname=hostname, **kwargs)
            logger.info("session_host_added", host=key)
        else:
            h = self._hosts[key]
            if hostname and not h.hostname:
                h.hostname = hostname
            for k, v in kwargs.items():
                if hasattr(h, k) and v:
                    setattr(h, k, v)
            h.last_updated = time.time()
        return self._hosts[key]

    def discover_host(self, ip: str, hostname: str = "", **kwargs: Any) -> HostState:
        return self.add_host(ip, hostname, **kwargs)

    def get_or_create_host(self, ip: str, hostname: str = "", **kwargs: Any) -> HostState:
        return self.add_host(ip, hostname, **kwargs)

    def get_host(self, ip_or_hostname: str) -> HostState | None:
        return self._hosts.get(ip_or_hostname)

    def mark_host_owned(
        self,
        ip_or_hostname: str,
        level:          CompromiseLevel,
        via_module:     str = "",
        username:       str = "",
    ) -> None:
        host = self._hosts.get(ip_or_hostname)
        if host:
            host.mark_owned(level, via=via_module, username=username)

    def mark_owned(
        self,
        ip_or_hostname: str,
        level:          CompromiseLevel,
        via_module:     str = "",
        username:       str = "",
        credentials:    list | None = None,
        **kwargs: Any,
    ) -> None:
        """Alias untuk mark_host_owned — auto-create host jika belum ada."""
        if ip_or_hostname not in self._hosts:
            self.add_host(ip_or_hostname)
        self.mark_host_owned(ip_or_hostname, level, via_module=via_module, username=username)

    def record_attack(
        self,
        module_id_or_target: str = "",
        target_or_module_id: str = "",
        success:     bool = False,
        technique:   str = "",
        username:    str = "",
        module_id:   str = "",   # explicit kwarg
        target_host: str = "",   # explicit kwarg
        **kwargs:    Any,
    ) -> "AttackHistoryEntry":
        """Record attack attempt. Accepts both positional and keyword args."""
        import re
        # Resolve explicit kwargs first
        if module_id and target_host:
            _module_id, _target = module_id, target_host
        elif module_id_or_target or target_or_module_id:
            # Auto-detect order: if first arg looks like an IP, it's target
            if re.match(r"^\d{1,3}\.\d{1,3}", module_id_or_target):
                _target    = module_id_or_target
                _module_id = target_or_module_id
            else:
                _module_id = module_id_or_target
                _target    = target_or_module_id
        else:
            _module_id, _target = "", ""
        entry = self.record(module_id=_module_id, target_host=_target,
                            success=success, technique=technique, username=username)
        host = self._hosts.get(_target)
        if host:
            host.attack_history.append(entry.to_dict())
        return entry

    def hosts_by_level(self, level: CompromiseLevel) -> list[HostState]:
        return [h for h in self._hosts.values() if h.compromise_level >= level]

    def owned_hosts(self) -> list[HostState]:
        return [h for h in self._hosts.values() if h.owned]

    def uncompromised_hosts(self) -> list[HostState]:
        return [
            h for h in self._hosts.values()
            if h.compromise_level == CompromiseLevel.NONE
            or h.compromise_level == CompromiseLevel.IDENTIFIED
        ]

    def domain_controllers(self) -> list[HostState]:
        return [h for h in self._hosts.values() if h.is_dc]

    # ── Pivot management ──────────────────────────────────────────────────

    def add_pivot(self, proxy_config: dict[str, Any]) -> None:
        self._pivot_proxies.append({**proxy_config, "added_at": time.time()})
        logger.info("session_pivot_added", proxy=proxy_config)

    def active_pivots(self) -> list[dict[str, Any]]:
        return list(self._pivot_proxies)

    # ── History ───────────────────────────────────────────────────────────

    def record(
        self,
        module_id:   str,
        target_host: str,
        success:     bool,
        technique:   str = "",
        username:    str = "",
        finding_ids: list[str] | None = None,
        output:      str = "",
    ) -> AttackHistoryEntry:
        entry = AttackHistoryEntry(
            module_id=module_id, target_host=target_host, success=success,
            technique=technique, username=username,
            finding_ids=finding_ids or [], output=output[:500],
        )
        self._history.append(entry)
        return entry

    def history(self, target_host: str = "", module_id: str = "") -> list[AttackHistoryEntry]:
        h = self._history
        if target_host:
            h = [e for e in h if e.target_host == target_host]
        if module_id:
            h = [e for e in h if e.module_id == module_id]
        return h

    def was_tried(self, module_id: str, target_host: str) -> bool:
        return any(
            e.module_id == module_id and e.target_host == target_host
            for e in self._history
        )

    # ── Snapshot ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id":   self.session_id,
            "campaign_id":  self.campaign_id,
            "operator":     self.operator,
            "started_at":   self.started_at,
            "hosts":        {k: v.to_dict() for k, v in self._hosts.items()},
            "pivot_proxies": self._pivot_proxies,
            "history":      [e.to_dict() for e in self._history],
            "stats": {
                "total_hosts":     len(self._hosts),
                "owned_hosts":     len(self.owned_hosts()),
                "total_attempts":  len(self._history),
                "successful":      sum(1 for e in self._history if e.success),
                "pivot_count":     len(self._pivot_proxies),
            },
        }

    def stats(self) -> dict[str, Any]:
        owned = self.owned_hosts()
        return {
            "total_hosts":    len(self._hosts),
            "owned_hosts":    len(owned),
            "dcs_found":      len(self.domain_controllers()),
            "dcs_owned":      sum(1 for h in self.domain_controllers() if h.owned),
            "total_attempts": len(self._history),
            "successful":     sum(1 for e in self._history if e.success),
            "pivots":         len(self._pivot_proxies),
        }

    def update_host(self, host: "HostState") -> None:
        """
        Upsert a HostState object into the session (replace if same IP exists).
        Useful when external code builds a HostState and wants to store it.
        """
        self._hosts[host.ip_address] = host
        # Mirror by hostname for quick lookup
        if host.hostname:
            self._hosts[host.hostname] = host

    def all_hosts(self) -> list["HostState"]:
        """Return deduplicated list of all tracked hosts."""
        seen: set[str] = set()
        result: list[HostState] = []
        for h in self._hosts.values():
            if h.ip_address not in seen:
                seen.add(h.ip_address)
                result.append(h)
        return result

    def to_json(self) -> str:
        """JSON-serialise the full session snapshot."""
        import json
        return json.dumps(self.snapshot(), default=str, indent=2)

    @classmethod
    def from_snapshot(
        cls,
        data: dict[str, Any],
    ) -> "OperatorSession":
        """Reconstruct an OperatorSession from a snapshot dict."""
        sess = cls(
            campaign_id = data.get("campaign_id", ""),
            operator    = data.get("operator", "unknown"),
        )
        sess.session_id = data.get("session_id", sess.session_id)
        sess.started_at = data.get("started_at", sess.started_at)
        for ip, h in data.get("hosts", {}).items():
            level = CompromiseLevel(
                h.get("compromise_level", CompromiseLevel.NONE.value)
            )
            hs = HostState(
                ip_address  = h.get("ip_address", ip),
                hostname    = h.get("hostname", ""),
                os_type     = h.get("os_type", ""),
                compromise_level = level,
                owned       = h.get("owned", level >= CompromiseLevel.LOCAL_ADMIN),
                privilege   = h.get("privilege", ""),
                owned_via   = h.get("owned_via", ""),
                owned_at    = h.get("owned_at"),
                attack_history = h.get("attack_history", []),
            )
            sess._hosts[ip] = hs
        sess._pivot_proxies = data.get("pivot_proxies", [])
        for e in data.get("history", []):
            entry = AttackHistoryEntry(
                module_id   = e.get("module_id", ""),
                target_host = e.get("target_host", ""),
                success     = e.get("success", False),
                technique   = e.get("technique", ""),
                username    = e.get("username", ""),
                finding_ids = e.get("finding_ids", []),
                output      = e.get("output", ""),
            )
            sess._history.append(entry)
        return sess


# ── Public aliases (backward compatibility + test convenience) ─────────────────

#: Alias for HostState — used in tests and external tooling that prefer the name TargetHost
TargetHost = HostState
