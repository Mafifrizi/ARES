"""
ARES Noise Controller
Controls timing, rate limiting, and scope enforcement.
This is what keeps engagements under the radar in production.
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from typing import Any

from ares.core.logger import get_logger

logger = get_logger("ares.core.noise")

from ares.core.errors import ScopeError
from ares.core.campaign import Campaign, NoiseProfile


# ── Noise profiles ────────────────────────────────────────────────────────────

NOISE_PROFILES: dict[str, dict[str, Any]] = {
    NoiseProfile.STEALTH: {
        "jitter_min_ms": 1500,
        "jitter_max_ms": 5000,
        "requests_per_minute": 10,
        "ldap_page_size": 50,       # Small LDAP pages → less visible
        "kerberos_tgs_rpm": 2,      # Max TGS requests/min
        "cloud_api_rpm": 5,
        "port_scan_rate": 0,        # No port scanning in stealth
        "use_existing_sessions": True,
    },
    NoiseProfile.NORMAL: {
        "jitter_min_ms": 300,
        "jitter_max_ms": 1500,
        "requests_per_minute": 30,
        "ldap_page_size": 200,
        "kerberos_tgs_rpm": 10,
        "cloud_api_rpm": 20,
        "port_scan_rate": 100,
        "use_existing_sessions": True,
    },
    NoiseProfile.AGGRESSIVE: {
        "jitter_min_ms": 0,
        "jitter_max_ms": 100,
        "requests_per_minute": 200,
        "ldap_page_size": 1000,
        "kerberos_tgs_rpm": 50,
        "cloud_api_rpm": 100,
        "port_scan_rate": 1000,
        "use_existing_sessions": False,
    },
}


# ── Jitter Engine ─────────────────────────────────────────────────────────────

class JitterEngine:
    """
    Randomizes timing between actions.
    Prevents pattern-based detection by SIEM/EDR.
    """

    def __init__(self, profile: NoiseProfile) -> None:
        cfg = NOISE_PROFILES[profile]
        self.min_ms = cfg["jitter_min_ms"]
        self.max_ms = cfg["jitter_max_ms"]
        self.profile = profile

    async def sleep(self, override_min: int | None = None, override_max: int | None = None) -> None:
        lo = override_min if override_min is not None else self.min_ms
        hi = override_max if override_max is not None else self.max_ms
        if lo >= hi:
            delay_ms = lo
        else:
            # Use triangular distribution — more realistic than uniform
            delay_ms = int(random.triangular(lo, hi, (lo + hi) // 2))
        logger.debug("noise_jitter_sleep_ms", delay_ms=delay_ms, profile=self.profile)
        await asyncio.sleep(delay_ms / 1000)

    async def sleep_between_hosts(self) -> None:
        """Longer pause when moving between hosts — mimics human behavior."""
        multiplier = {"stealth": 3, "normal": 1.5, "aggressive": 0.5}[self.profile]
        await self.sleep(
            override_min=int(self.min_ms * multiplier),
            override_max=int(self.max_ms * multiplier),
        )


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter per action type.
    Prevents bursts that trigger SIEM correlation rules.
    """

    def __init__(self, profile: NoiseProfile) -> None:
        cfg = NOISE_PROFILES[profile]
        self._limits: dict[str, int] = {
            "default": cfg["requests_per_minute"],
            "kerberos_tgs": cfg["kerberos_tgs_rpm"],
            "cloud_api": cfg["cloud_api_rpm"],
            "ldap": cfg["requests_per_minute"],
        }
        # Sliding window: stores timestamps of recent requests
        self._windows: dict[str, deque[float]] = {k: deque() for k in self._limits}

    async def acquire(self, action: str = "default") -> None:
        """Block until the rate limit allows the action."""
        limit = self._limits.get(action, self._limits["default"])
        window = self._windows.setdefault(action, deque())

        while True:
            now = time.monotonic()
            # Remove entries older than 60 seconds
            while window and window[0] < now - 60:
                window.popleft()

            if len(window) < limit:
                window.append(now)
                return

            # Calculate wait time until oldest entry expires
            wait = 60 - (now - window[0]) + 0.05
            logger.debug("rate_limit_hit", action=action, wait_s=round(wait, 1))
            await asyncio.sleep(wait)

    def get_config(self) -> dict[str, int]:
        return dict(self._limits)


# ── Scope Guard ──────────────────────────────────────────────────────────────

class ScopeGuard:
    """
    HARD STOP — prevents any action outside defined scope.
    This protects operators from accidental out-of-scope activity.
    """

    def __init__(self, campaign: Campaign) -> None:
        self.campaign = campaign
        self._blocked_attempts: list[dict[str, Any]] = []

    def check(self, target: str, action: str = "unknown") -> bool:
        """
        Returns True if target is in scope.
        Logs and raises if not.
        """
        in_scope = self.campaign.is_in_scope(target)

        if not in_scope:
            self._blocked_attempts.append({
                "target": target,
                "action": action,
                "timestamp": time.time(),
            })
            logger.warning(
                f"[scope_guard] BLOCKED: '{action}' against '{target}' — OUT OF SCOPE"
            )

        return in_scope

    def assert_in_scope(self, target: str, action: str = "unknown") -> None:
        """Raises ScopeViolationError if target is out of scope."""
        if not self.check(target, action):
            raise ScopeViolationError(
                f"Target '{target}' is not in scope for campaign '{self.campaign.name}'"
            )

    @property
    def blocked_count(self) -> int:
        return len(self._blocked_attempts)


class ScopeViolationError(ScopeError):  # alias for backward compat — use ScopeError directly
    """Raised when an action targets an out-of-scope host."""


# ── Noise Controller (master) ─────────────────────────────────────────────────

class NoiseController:
    """
    Master controller — combines jitter + rate limiter + scope guard.
    Every module must use this before making any network call.
    """

    def __init__(self, campaign: Campaign) -> None:
        self.profile = campaign.noise_profile
        self.jitter = JitterEngine(self.profile)
        self.rate_limiter = RateLimiter(self.profile)
        self.scope_guard = ScopeGuard(campaign)
        self.cfg = NOISE_PROFILES[self.profile]

    async def before_action(
        self,
        target: str,
        action: str = "default",
        check_scope: bool = True,
    ) -> None:
        """
        Call this BEFORE every network action in a module.
        Handles scope check + rate limit + jitter automatically.
        """
        if check_scope:
            self.scope_guard.assert_in_scope(target, action)
        await self.rate_limiter.acquire(action)
        await self.jitter.sleep()

    def get_ldap_page_size(self) -> int:
        return int(self.cfg["ldap_page_size"])
