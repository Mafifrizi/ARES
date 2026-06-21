"""
ARES Adaptive OPSEC Engine
Monitors attack feedback and automatically adjusts operational security posture.

Detection signals monitored:
  - failed_login      → possible credential lockout or wrong password
  - timeout           → host may be rate-limiting or blocking
  - rate_limited      → explicit HTTP 429 or LDAP rate limit
  - connection_reset  → firewall dropping connection (IPS/EDR rule hit)
  - auth_failure      → protocol-level auth rejection
  - scan_detected     → honeypot hit or IDS/APS alert detected

Response actions:
  1. Increase jitter (slow down)
  2. Switch technique (SMB → WMI, LDAP → LDAPS, HTTP → HTTPS)
  3. Rotate user agent
  4. Escalate noise profile (aggressive → normal → stealth)
  5. Blacklist problematic host temporarily
  6. Alert operator

Thresholds (configurable):
  - 3 timeouts in 60s → escalate to stealth profile
  - 5 connection resets → blacklist host for N minutes
  - 3 auth failures on same account → stop attempting that account (lockout protection)
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.opsec.adaptive")


class DetectionLevel(str, Enum):
    FAILED_LOGIN      = "failed_login"
    TIMEOUT           = "timeout"
    RATE_LIMITED      = "rate_limited"
    CONNECTION_RESET  = "connection_reset"
    AUTH_FAILURE      = "auth_failure"
    SCAN_DETECTED     = "scan_detected"
    UNEXPECTED_CLOSE  = "unexpected_close"
    CERT_ERROR        = "cert_error"


class ResponseAction(str, Enum):
    INCREASE_JITTER   = "increase_jitter"
    ROTATE_UA         = "rotate_ua"
    SWITCH_TECHNIQUE  = "switch_technique"
    ESCALATE_PROFILE  = "escalate_profile"   # aggressive → normal → stealth
    BLACKLIST_HOST    = "blacklist_host"
    STOP_ACCOUNT      = "stop_account"       # lockout protection
    ALERT_OPERATOR    = "alert_operator"
    PAUSE_ALL         = "pause_all"          # severe: full stop


@dataclass
class SignalEvent:
    signal:     DetectionLevel
    host:       str
    username:   str = ""
    module_id:  str = ""
    timestamp:  float = field(default_factory=time.monotonic)


@dataclass
class OpsecAdaptation:
    """Adaptation decision made in response to signals."""
    action:       ResponseAction
    reason:       str
    triggered_by: list[SignalEvent]
    new_profile:  str | None = None     # if ESCALATE_PROFILE
    new_jitter_s: float | None = None   # if INCREASE_JITTER
    blacklist_host: str | None = None   # if BLACKLIST_HOST
    stop_account:   str | None = None   # if STOP_ACCOUNT
    timestamp:    float = field(default_factory=time.monotonic)


# ── Adaptive OPSEC Engine ──────────────────────────────────────────────────────

class AdaptiveOpsecEngine:
    """
    Real-time OPSEC adaptation based on attack feedback signals.

    Designed to run alongside the main execution engine.
    Each module calls engine.signal() after each attempt.
    Engine evaluates rules and issues adaptations.
    """

    NOISE_PROFILE_ORDER = ["aggressive", "normal", "stealth"]

    def __init__(
        self,
        current_profile:     str   = "normal",
        window_s:            float = 60.0,   # sliding window for signal counting
        timeout_threshold:   int   = 3,
        reset_threshold:     int   = 5,
        auth_fail_threshold: int   = 3,
        jitter_increment_s:  float = 2.0,
    ) -> None:
        self.current_profile      = current_profile
        self.window_s             = window_s
        self.timeout_threshold    = timeout_threshold
        self.reset_threshold      = reset_threshold
        self.auth_fail_threshold  = auth_fail_threshold
        self.jitter_increment_s   = jitter_increment_s

        # Signal event buffers — deque of (timestamp, event) per signal type
        self._signals: defaultdict[str, deque[SignalEvent]] = defaultdict(
            lambda: deque(maxlen=200)
        )
        # Per-host failure counters
        self._host_failures:    defaultdict[str, int] = defaultdict(int)
        # Per-account auth failure counters
        self._account_failures: defaultdict[str, int] = defaultdict(int)

        # State
        self._blacklisted_hosts:    dict[str, float] = {}   # host → expiry timestamp
        self._stopped_accounts:     set[str] = set()
        self._paused:               bool = False
        self._current_jitter_boost: float = 0.0

        self.adaptations: list[OpsecAdaptation] = []

    def signal(
        self,
        signal_type: DetectionLevel,
        host:        str,
        username:    str = "",
        module_id:   str = "",
    ) -> list[OpsecAdaptation]:
        """
        Report a detection signal. Returns list of adaptations triggered.
        Call this after every failed/suspicious network operation.
        """
        event = SignalEvent(
            signal=signal_type, host=host, username=username, module_id=module_id
        )
        self._signals[signal_type.value].append(event)

        if username:
            self._account_failures[username.lower()] += 1
        if host:
            self._host_failures[host] += 1

        triggered: list[OpsecAdaptation] = []
        triggered.extend(self._check_timeout_rule(event))
        triggered.extend(self._check_connection_reset_rule(event))
        triggered.extend(self._check_auth_failure_rule(event, username))
        triggered.extend(self._check_rate_limited_rule(event))
        triggered.extend(self._check_scan_detected_rule(event))

        for a in triggered:
            self.adaptations.append(a)
            self._apply(a)
            logger.warning(
                "opsec_adaptation",
                action=a.action.value,
                reason=a.reason,
                host=host,
                new_profile=a.new_profile,
                new_jitter=a.new_jitter_s,
            )

        return triggered

    def is_host_blacklisted(self, host: str) -> bool:
        expiry = self._blacklisted_hosts.get(host)
        if expiry and time.monotonic() < expiry:
            return True
        if host in self._blacklisted_hosts:
            del self._blacklisted_hosts[host]
        return False

    def is_account_stopped(self, username: str) -> bool:
        return username.lower() in self._stopped_accounts

    def is_paused(self) -> bool:
        return self._paused

    def resume(self) -> None:
        self._paused = False
        logger.info("opsec_resumed_by_operator")

    def current_jitter_boost(self) -> float:
        """Additional jitter seconds to add on top of base profile jitter."""
        return self._current_jitter_boost

    def effective_profile(self) -> str:
        return self.current_profile

    # ── Rules ─────────────────────────────────────────────────────────────

    def _check_timeout_rule(self, event: SignalEvent) -> list[OpsecAdaptation]:
        if event.signal != DetectionLevel.TIMEOUT:
            return []
        recent = self._count_recent(DetectionLevel.TIMEOUT)
        if recent >= self.timeout_threshold:
            return [OpsecAdaptation(
                action=ResponseAction.ESCALATE_PROFILE,
                reason=f"{recent} timeouts in {self.window_s}s — escalating to stealth",
                triggered_by=[event],
                new_profile=self._next_stealth_profile(),
                new_jitter_s=self._current_jitter_boost + self.jitter_increment_s,
            )]
        return []

    def _check_connection_reset_rule(self, event: SignalEvent) -> list[OpsecAdaptation]:
        if event.signal != DetectionLevel.CONNECTION_RESET:
            return []
        host_resets = sum(
            1 for e in self._signals[DetectionLevel.CONNECTION_RESET.value]
            if e.host == event.host and time.monotonic() - e.timestamp < self.window_s
        )
        if host_resets >= self.reset_threshold:
            return [OpsecAdaptation(
                action=ResponseAction.BLACKLIST_HOST,
                reason=f"{host_resets} connection resets from {event.host} — possible IPS/EDR",
                triggered_by=[event],
                blacklist_host=event.host,
            )]
        return []

    def _check_auth_failure_rule(
        self, event: SignalEvent, username: str
    ) -> list[OpsecAdaptation]:
        if event.signal not in (DetectionLevel.AUTH_FAILURE, DetectionLevel.FAILED_LOGIN):
            return []
        if not username:
            return []
        count = self._account_failures.get(username.lower(), 0)
        if count >= self.auth_fail_threshold:
            return [OpsecAdaptation(
                action=ResponseAction.STOP_ACCOUNT,
                reason=f"{count} auth failures for {username} — lockout protection",
                triggered_by=[event],
                stop_account=username,
            )]
        return []

    def _check_rate_limited_rule(self, event: SignalEvent) -> list[OpsecAdaptation]:
        if event.signal != DetectionLevel.RATE_LIMITED:
            return []
        return [OpsecAdaptation(
            action=ResponseAction.INCREASE_JITTER,
            reason="Rate limit detected — increasing inter-request jitter",
            triggered_by=[event],
            new_jitter_s=self._current_jitter_boost + self.jitter_increment_s * 2,
        )]

    def _check_scan_detected_rule(self, event: SignalEvent) -> list[OpsecAdaptation]:
        if event.signal != DetectionLevel.SCAN_DETECTED:
            return []
        return [OpsecAdaptation(
            action=ResponseAction.PAUSE_ALL,
            reason="Scan detected (honeypot/IDS alert) — pausing all operations",
            triggered_by=[event],
            new_profile="stealth",
        )]

    # ── Apply adaptations ──────────────────────────────────────────────────

    def _apply(self, adaptation: OpsecAdaptation) -> None:
        if adaptation.action == ResponseAction.ESCALATE_PROFILE:
            if adaptation.new_profile:
                self.current_profile = adaptation.new_profile
            if adaptation.new_jitter_s is not None:
                self._current_jitter_boost = adaptation.new_jitter_s

        elif adaptation.action == ResponseAction.INCREASE_JITTER:
            if adaptation.new_jitter_s is not None:
                self._current_jitter_boost = adaptation.new_jitter_s

        elif adaptation.action == ResponseAction.BLACKLIST_HOST:
            if adaptation.blacklist_host:
                blacklist_duration = 300.0  # 5 minutes
                self._blacklisted_hosts[adaptation.blacklist_host] = (
                    time.monotonic() + blacklist_duration
                )
                logger.warning("host_blacklisted",
                               host=adaptation.blacklist_host,
                               duration_s=blacklist_duration)

        elif adaptation.action == ResponseAction.STOP_ACCOUNT:
            if adaptation.stop_account:
                self._stopped_accounts.add(adaptation.stop_account.lower())
                logger.warning("account_stopped", username=adaptation.stop_account)

        elif adaptation.action == ResponseAction.PAUSE_ALL:
            self._paused = True
            self.current_profile = "stealth"
            logger.critical("opsec_paused_all_operations")

        elif adaptation.action == ResponseAction.ROTATE_UA:
            pass  # handled by OpSecProfile.ua_rotator

    def _next_stealth_profile(self) -> str:
        current_idx = self.NOISE_PROFILE_ORDER.index(self.current_profile) \
            if self.current_profile in self.NOISE_PROFILE_ORDER else 1
        new_idx = min(current_idx + 1, len(self.NOISE_PROFILE_ORDER) - 1)
        return self.NOISE_PROFILE_ORDER[new_idx]

    def _count_recent(self, signal_type: DetectionLevel) -> int:
        cutoff = time.monotonic() - self.window_s
        return sum(
            1 for e in self._signals[signal_type.value]
            if e.timestamp >= cutoff
        )

    def summary(self) -> dict[str, Any]:
        return {
            "current_profile":    self.current_profile,
            "jitter_boost_s":     self._current_jitter_boost,
            "paused":             self._paused,
            "blacklisted_hosts":  list(self._blacklisted_hosts.keys()),
            "stopped_accounts":   list(self._stopped_accounts),
            "total_adaptations":  len(self.adaptations),
            "recent_signals": {
                sig.value: self._count_recent(sig)
                for sig in DetectionLevel
            },
        }

# Backward-compat alias
DetectionSignal = DetectionLevel  # noqa
