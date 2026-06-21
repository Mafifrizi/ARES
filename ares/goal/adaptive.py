"""
ARES Adaptive Attack Strategy Engine
When primary attack path fails, automatically selects alternative.

Decision tree (simplified):
  kerberoast fails (no SPN accounts)
    ├─► asreproast (no pre-auth accounts?)
    ├─► password spray (if allowed)
    └─► credential reuse (if creds in vault)

  lateral.psexec fails (EDR blocks service creation)
    ├─► lateral.wmiexec (stealthier WMI)
    ├─► lateral.winrm (if port 5985 open)
    └─► lateral.ssh_pivot (if port 22 open)

  ad.dcsync fails (insufficient privileges)
    ├─► ad.enum_acl (find another path to DA)
    └─► linux.privesc (if on domain-joined Linux)

Engine maintains:
  - Per-module failure history (with error context)
  - Tried alternatives per goal per session
  - Module compatibility matrix
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ares.core.logger import get_logger

if TYPE_CHECKING:
    from ares.state.target_state import OperatorSession

logger = get_logger("ares.goal.adaptive")


@dataclass
class FailureRecord:
    module_id:   str
    target_host: str
    error:       str
    timestamp:   float = field(default_factory=time.time)
    error_class: str = ""   # auth_failure | network | permission | timeout | edr_blocked


@dataclass
class FallbackOption:
    """An alternative module to try when primary fails."""
    module_id:     str
    reason:        str
    conditions:    list[str] = field(default_factory=list)   # conditions that must hold
    priority:      int = 5    # lower = try first
    params_update: dict[str, Any] = field(default_factory=dict)


# Fallback graph: module_id → ordered list of fallbacks
FALLBACK_GRAPH: dict[str, list[FallbackOption]] = {

    # Credential Access fallbacks
    "ad.kerberoast": [
        FallbackOption("ad.asreproast",   "No SPN accounts; try no-preauth accounts",
                       priority=1),
        FallbackOption("credential.reuse","No crackable hashes; try existing creds",
                       priority=2),
        FallbackOption("ad.enum_acl",     "Find ACL abuse path to DA instead",
                       priority=3),
    ],
    "ad.asreproast": [
        FallbackOption("ad.kerberoast",   "No no-preauth accounts; try SPN kerberoast",
                       priority=1),
        FallbackOption("credential.reuse","Try credential reuse with existing vault",
                       priority=2),
    ],
    "ad.dcsync": [
        FallbackOption("ad.enum_acl",     "Insufficient DCSync rights; look for ACL path",
                       priority=1),
        FallbackOption("ad.kerberoast",   "Try kerberoasting path instead",
                       priority=2),
        FallbackOption("linux.privesc",   "Try local escalation on domain-joined host",
                       priority=3),
    ],

    # Lateral movement fallbacks
    "lateral.psexec": [
        FallbackOption("lateral.wmiexec", "PsExec blocked (EDR/AV); try WMI instead",
                       priority=1),
        FallbackOption("lateral.winrm",   "Try WinRM if port 5985 open",
                       conditions=["port_5985_open"],
                       priority=2),
        FallbackOption("lateral.ssh_pivot","Try SSH if port 22 open",
                       conditions=["port_22_open"],
                       priority=3),
    ],
    "lateral.wmiexec": [
        FallbackOption("lateral.winrm",   "WMI blocked; try WinRM",
                       conditions=["port_5985_open"],
                       priority=1),
        FallbackOption("lateral.psexec",  "Try PsExec as last resort",
                       priority=2),
    ],
    "lateral.winrm": [
        FallbackOption("lateral.psexec",  "WinRM blocked; try PsExec",
                       priority=1),
        FallbackOption("lateral.wmiexec", "Try WMI execution",
                       priority=2),
    ],
    "lateral.ssh_pivot": [
        FallbackOption("lateral.winrm",   "SSH blocked; try WinRM (Windows host?)",
                       conditions=["port_5985_open"],
                       priority=1),
    ],

    # Privilege escalation fallbacks
    "linux.privesc": [
        FallbackOption("linux.container", "Try container escape if in container",
                       priority=1),
        FallbackOption("credential.reuse","Try reusing discovered creds locally",
                       priority=2),
    ],
    "linux.container": [
        FallbackOption("linux.privesc",   "Not in container; try host privesc",
                       priority=1),
    ],

    # Cloud fallbacks
    "cloud.aws": [
        FallbackOption("credential.reuse","Try credential reuse with discovered IAM creds",
                       priority=1),
    ],

    # AD enumeration fallbacks
    "ad.enum_users": [
        FallbackOption("ad.enum_computers","Try computer enumeration instead",
                       priority=1),
    ],
    "ad.enum_acl": [
        FallbackOption("ad.enum_spn",     "Try SPN enumeration to find attack path",
                       priority=1),
    ],
}

# Error → alternative strategy hints
ERROR_STRATEGY_MAP: dict[str, list[str]] = {
    "access_denied":     ["reduce_opsec", "try_stealth_variant"],
    "edr_blocked":       ["switch_technique", "use_stealth_profile"],
    "account_locked":    ["stop_account", "use_alternative_account"],
    "auth_failure":      ["check_credentials", "try_hash_relay"],
    "timeout":           ["increase_jitter", "try_different_port"],
    "not_found":         ["enumerate_more", "try_adjacent_module"],
    "permission_denied": ["escalate_first", "find_acl_path"],
}


class AdaptiveAttackStrategy:
    """
    Automatic fallback engine.
    When a module fails, determines the best alternative attack path.

    Maintains a session-scoped tried-set to avoid infinite loops.
    """

    def __init__(self, session: "OperatorSession") -> None:
        self.session    = session
        self._failures: list[FailureRecord] = []
        self._tried:    set[str] = set()    # "module_id:target_host" tried combinations
        self._disabled: set[str] = set()    # permanently disabled module IDs

    def record_failure(
        self,
        module_id:   str,
        target_host: str,
        error:       str,
        error_class: str = "",
    ) -> None:
        """Record a module execution failure."""
        record = FailureRecord(
            module_id=module_id, target_host=target_host,
            error=error[:300], error_class=error_class,
        )
        self._failures.append(record)
        self._tried.add(f"{module_id}:{target_host}")

        if error_class in ("edr_blocked", "honeypot_detected"):
            self._disabled.add(module_id)
            logger.warning("module_disabled_adaptive",
                           module=module_id, reason=error_class)

        logger.info("failure_recorded",
                    module=module_id, target=target_host, class_=error_class)

    def next_alternative(
        self,
        failed_module_id: str,
        target_host:      str,
        context:          dict[str, Any] | None = None,
        error:            str = "",   # optional error message from failed module
    ) -> "FallbackOption | None":
        """
        Return the best untried fallback for a failed module.
        Returns None if all alternatives exhausted.
        """
        context   = context or {}
        fallbacks = FALLBACK_GRAPH.get(failed_module_id, [])

        for fb in sorted(fallbacks, key=lambda f: f.priority):
            # Skip if already tried or permanently disabled
            tried_key = f"{fb.module_id}:{target_host}"
            if tried_key in self._tried:
                continue
            if fb.module_id in self._disabled:
                continue
            # Check conditions
            if not self._conditions_met(fb.conditions, context, target_host):
                continue

            logger.info(
                "adaptive_fallback_selected",
                failed=failed_module_id, next=fb.module_id,
                reason=fb.reason,
            )
            return fb

        logger.warning("no_fallback_available", failed=failed_module_id, target=target_host)
        return None

    def alternative_chain(
        self,
        failed_module_id: str,
        target_host:      str,
        context:          dict[str, Any] | None = None,
        max_depth:        int = 3,
    ) -> list[FallbackOption]:
        """
        Return full ordered fallback chain (up to max_depth alternatives).
        """
        chain:   list[FallbackOption] = []
        current = failed_module_id

        for _ in range(max_depth):
            fb = self.next_alternative(current, target_host, context)
            if not fb:
                break
            chain.append(fb)
            self._tried.add(f"{fb.module_id}:{target_host}")
            current = fb.module_id

        return chain

    def strategy_hints(self, error: str) -> list[str]:
        """Return strategy hints based on error message."""
        error_lower = error.lower()
        for key, hints in ERROR_STRATEGY_MAP.items():
            if key in error_lower:
                return hints
        return ["try_alternative_technique"]

    def failure_summary(self) -> dict[str, Any]:
        by_module: dict[str, int] = {}
        for f in self._failures:
            by_module[f.module_id] = by_module.get(f.module_id, 0) + 1
        return {
            "total_failures":  len(self._failures),
            "by_module":       by_module,
            "disabled_modules": list(self._disabled),
            "tried_combos":    len(self._tried),
        }

    def _conditions_met(
        self,
        conditions:  list[str],
        context:     dict[str, Any],
        target_host: str,
    ) -> bool:
        if not conditions:
            return True
        host_state = self.session.get_host(target_host)
        open_ports = getattr(host_state, "open_ports", []) if host_state else []
        for cond in conditions:
            if cond == "port_5985_open" and 5985 not in open_ports:
                return False
            if cond == "port_22_open" and 22 not in open_ports:
                return False
            if cond == "port_445_open" and 445 not in open_ports:
                return False
            if cond == "has_domain_creds" and not context.get("domain_creds"):
                return False
        return True


# ── Public aliases ────────────────────────────────────────────────────────────
#: AdaptiveStrategy is the short alias for AdaptiveAttackStrategy.
#: Both names are valid; prefer AdaptiveAttackStrategy in new code.
AdaptiveStrategy = AdaptiveAttackStrategy
