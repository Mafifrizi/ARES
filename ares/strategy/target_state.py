"""
ares/strategy/target_state.py — Per-Host Memory for StrategyEngine

Tracks what ARES knows about each target host across rounds:
- Which modules succeeded / failed here
- Confirmed credentials
- Open ports, OS, EDR, domain role
- Last activity timestamp (24h window)

Injected into every LLM call so planner never re-recommends
techniques already proven to fail on a specific host.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.modules.base import ModuleResult


@dataclass
class TargetState:
    host:               str
    open_ports:         list[int]  = field(default_factory=list)
    confirmed_creds:    list[str]  = field(default_factory=list)  # "domain\\user"
    failed_modules:     list[str]  = field(default_factory=list)
    successful_modules: list[str]  = field(default_factory=list)
    edr_confirmed:      str        = ""    # "crowdstrike" if detected
    domain_role:        str        = ""    # "dc", "workstation", "server"
    os_version:         str        = ""
    last_seen:          float      = field(default_factory=time.time)


class TargetStateMap:
    """
    Per-host state tracking across all rounds of an engagement.
    Prevents LLM from recommending techniques already proven to fail.
    """

    def __init__(self) -> None:
        self._hosts: dict[str, TargetState] = {}

    def update_from_result(
        self,
        module_id: str,
        target:    str,
        result:    "ModuleResult",
    ) -> None:
        """Update host state from a module execution result."""
        if not target:
            return

        state = self._hosts.setdefault(target, TargetState(host=target))
        quality = getattr(result, "effective_quality", 0.0)

        if quality >= 0.5:
            if module_id not in state.successful_modules:
                state.successful_modules.append(module_id)
            # Remove from failed if it succeeded this time
            state.failed_modules = [m for m in state.failed_modules if m != module_id]
        else:
            if module_id not in state.failed_modules:
                state.failed_modules.append(module_id)

        raw = getattr(result, "raw", {}) or {}

        # Extract open ports
        if "open_ports" in raw:
            ports = raw["open_ports"]
            if isinstance(ports, list):
                state.open_ports = [p for p in ports if isinstance(p, int)][:50]

        # Extract service map to infer open ports
        if "service_map" in raw and isinstance(raw["service_map"], dict):
            svc_ports = [int(p) for p in raw["service_map"].keys()
                         if str(p).isdigit()]
            if svc_ports:
                state.open_ports = list(dict.fromkeys(state.open_ports + svc_ports))[:50]

        # Extract EDR info from fingerprint
        if "edr_vendor" in raw and raw["edr_vendor"] != "unknown":
            state.edr_confirmed = raw["edr_vendor"]

        # Extract domain role
        if "domain_role" in raw:
            state.domain_role = raw["domain_role"]

        # Extract OS version
        if "os_version" in raw:
            state.os_version = raw["os_version"]

        # Extract confirmed credentials
        if "valid_credentials" in raw and isinstance(raw["valid_credentials"], list):
            for cred in raw["valid_credentials"][:5]:
                if isinstance(cred, dict):
                    user = cred.get("username", "")
                    dom  = cred.get("domain", "")
                    key  = f"{dom}\\{user}" if dom else user
                    if key and key not in state.confirmed_creds:
                        state.confirmed_creds.append(key)

        state.last_seen = time.time()

    def to_llm_context(self) -> dict[str, dict]:
        """
        Return compact per-host context for LLM prompt injection.
        Only includes hosts seen in last 24 hours.
        """
        cutoff = time.time() - 86400  # 24h window
        return {
            host: {
                "open_ports":        s.open_ports[:20],
                "creds_work_here":   s.confirmed_creds[:5],
                "failed_modules":    s.failed_modules[-5:],   # last 5 failures
                "succeeded_modules": s.successful_modules[-5:],
                "edr":               s.edr_confirmed,
                "role":              s.domain_role,
                "os":                s.os_version,
                "note": (
                    f"SKIP THESE: {', '.join(s.failed_modules[-3:])}"
                    if s.failed_modules else "No attempts yet"
                ),
            }
            for host, s in self._hosts.items()
            if s.last_seen >= cutoff
        }

    def get_state(self, host: str) -> TargetState | None:
        return self._hosts.get(host)

    def all_failed_for(self, host: str) -> list[str]:
        state = self._hosts.get(host)
        return state.failed_modules if state else []

    def all_succeeded_for(self, host: str) -> list[str]:
        state = self._hosts.get(host)
        return state.successful_modules if state else []
