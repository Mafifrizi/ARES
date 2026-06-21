"""
ARES OpSec Layer
Professional-grade operational security controls for red team engagements.

Components:
  UserAgentRotator   — realistic browser/tool UA pool, weighted random selection
  HeaderMutator      — randomize HTTP header order + add realistic noise headers
  ProtocolSelector   — SMB→HTTP, LDAP→LDAPS, automatic protocol fallback chain
  BeaconScheduler    — jittered sleep profiles (uniform, gaussian, triangular, pareto)
  TrafficShaper      — token bucket + burst control per protocol
  OpSecProfile       — master config object tying all controls together

Usage in a module:
    opsec = OpSecProfile.from_noise_profile(campaign.noise_profile)
    ua = opsec.user_agent()
    headers = opsec.mutate_headers({"Content-Type": "application/json"})
    await opsec.beacon()                     # smart sleep
    proto = opsec.select_protocol("ldap")    # → "ldaps" or "ldap"
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ares.core.campaign import NoiseProfile
from ares.core.logger import get_logger

logger = get_logger("ares.opsec")


# ── User Agent Rotator ────────────────────────────────────────────────────────

# Weighted pool: (user_agent_string, weight)
# Higher weight = more likely to be selected. Real-world browser share as weights.
_UA_POOL: list[tuple[str, int]] = [
    # Chrome (most common — highest weight)
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 35),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36", 20),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", 15),
    # Firefox
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", 10),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", 5),
    # Edge
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", 8),
    # Safari
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", 5),
    # Curl / tool-like (used in aggressive profile only — lower weight)
    ("python-requests/2.31.0", 1),
    ("curl/7.88.1", 1),
]

_UA_STRINGS = [ua for ua, _ in _UA_POOL]
_UA_WEIGHTS = [w for _, w in _UA_POOL]


class UserAgentRotator:
    """Weighted random UA selection. Maintains per-session history to avoid repetition."""

    def __init__(self, tool_like_ok: bool = False) -> None:
        pool = _UA_POOL if tool_like_ok else [p for p in _UA_POOL if "python" not in p[0] and "curl" not in p[0]]
        self._uas     = [ua for ua, _ in pool]
        self._weights = [w  for _,  w in pool]
        self._last:   str | None = None

    def get(self) -> str:
        """Return a weighted-random UA, never the same twice in a row."""
        choices = self._uas if not self._last else [u for u in self._uas if u != self._last]
        weights = self._weights if not self._last else [
            w for ua, w in zip(self._uas, self._weights) if ua != self._last
        ]
        ua = random.choices(choices, weights=weights, k=1)[0]
        self._last = ua
        return ua

    def get_batch(self, n: int) -> list[str]:
        """Return n unique UAs (for testing multiple endpoints in parallel)."""
        return random.sample(self._uas, min(n, len(self._uas)))


# ── Header Mutator ────────────────────────────────────────────────────────────

_NOISE_HEADERS: list[tuple[str, list[str]]] = [
    ("Accept-Language", ["en-US,en;q=0.9", "en-GB,en;q=0.8,en-US;q=0.7", "en-US,en;q=0.5"]),
    ("Accept-Encoding", ["gzip, deflate, br", "gzip, deflate", "br, gzip"]),
    ("Accept",          [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "application/json, text/plain, */*",
        "*/*",
    ]),
    ("DNT",             ["1"]),
    ("Cache-Control",   ["no-cache", "max-age=0"]),
    ("Pragma",          ["no-cache"]),
    ("Upgrade-Insecure-Requests", ["1"]),
]


class HeaderMutator:
    """
    Randomize header order and inject realistic noise headers.
    Makes traffic fingerprinting harder.
    """

    def __init__(self, inject_noise: bool = True, randomize_order: bool = True) -> None:
        self.inject_noise     = inject_noise
        self.randomize_order  = randomize_order

    def mutate(self, headers: dict[str, str]) -> dict[str, str]:
        """Return mutated headers dict."""
        result = dict(headers)

        if self.inject_noise:
            for header, values in _NOISE_HEADERS:
                # random.random/choice here is intentional — used for OpSec HTTP
                # header noise injection (probabilistic mutation), NOT for any
                # cryptographic or authentication purpose.  # noqa: S311
                if header not in result and random.random() < 0.6:  # noqa: S311
                    result[header] = random.choice(values)  # noqa: S311

        if self.randomize_order:
            items = list(result.items())
            random.shuffle(items)
            result = dict(items)

        return result


# ── Protocol Selector ─────────────────────────────────────────────────────────

_PROTOCOL_FALLBACK: dict[str, list[str]] = {
    # primary → fallback chain (left = most preferred)
    "ldap":  ["ldaps", "ldap"],
    "smb":   ["smbs",  "smb",  "http"],
    "http":  ["https", "http"],
    "kerberos": ["kerberos"],
    "rdp":   ["rdp"],
    "winrm": ["winrm-https", "winrm-http"],
}

_OPSEC_PREFERRED: dict[str, str] = {
    # In stealth/normal, always prefer encrypted variant
    "ldap":  "ldaps",
    "smb":   "smbs",
    "http":  "https",
    "winrm": "winrm-https",
}


class ProtocolSelector:
    """
    Choose most opsec-appropriate protocol.
    Falls back down the chain if the preferred one is unavailable.
    """

    def __init__(self, prefer_encrypted: bool = True) -> None:
        self.prefer_encrypted = prefer_encrypted
        self._unavailable: set[str] = set()

    def select(self, protocol: str) -> str:
        """Return the best available protocol variant."""
        chain = _PROTOCOL_FALLBACK.get(protocol, [protocol])
        if self.prefer_encrypted and protocol in _OPSEC_PREFERRED:
            preferred = _OPSEC_PREFERRED[protocol]
            chain = [preferred] + [p for p in chain if p != preferred]

        for proto in chain:
            if proto not in self._unavailable:
                return proto

        logger.warning("all_protocols_unavailable", protocol=protocol, chain=chain)
        return protocol  # last resort

    def mark_unavailable(self, protocol: str) -> None:
        """Call this when a connection attempt fails — removes from future selection."""
        self._unavailable.add(protocol)
        logger.info("protocol_marked_unavailable", protocol=protocol)

    def reset(self) -> None:
        self._unavailable.clear()


# ── Beacon Scheduler ──────────────────────────────────────────────────────────

class BeaconDistribution(str, Enum):
    UNIFORM    = "uniform"     # flat random — obvious in logs
    GAUSSIAN   = "gaussian"    # normal distribution around mean
    TRIANGULAR = "triangular"  # triangular — ARES default, realistic
    PARETO     = "pareto"      # long-tail: mostly short, occasional long pause


@dataclass
class BeaconProfile:
    """
    Sleep timing profile.
    All times in seconds.
    """
    min_sleep:     float              # absolute minimum
    max_sleep:     float              # absolute maximum
    mean_sleep:    float              # target average
    distribution:  BeaconDistribution = BeaconDistribution.TRIANGULAR
    # Optional: work-hours simulation (None = always active)
    active_hours:  tuple[int, int] | None = None  # (start_hour, end_hour) UTC

    @classmethod
    def stealth(cls) -> "BeaconProfile":
        return cls(min_sleep=3.0, max_sleep=15.0, mean_sleep=7.0,
                   distribution=BeaconDistribution.PARETO)

    @classmethod
    def normal(cls) -> "BeaconProfile":
        return cls(min_sleep=0.5, max_sleep=5.0, mean_sleep=2.0,
                   distribution=BeaconDistribution.TRIANGULAR)

    @classmethod
    def aggressive(cls) -> "BeaconProfile":
        return cls(min_sleep=0.0, max_sleep=0.3, mean_sleep=0.1,
                   distribution=BeaconDistribution.UNIFORM)


class BeaconScheduler:
    """
    Jittered sleep scheduler.
    Supports multiple distributions and work-hours clamping.
    """

    def __init__(self, profile: BeaconProfile) -> None:
        self.profile = profile

    def next_interval(self) -> float:
        """Calculate next sleep duration (seconds)."""
        p = self.profile
        dist = p.distribution

        if dist == BeaconDistribution.UNIFORM:
            t = random.uniform(p.min_sleep, p.max_sleep)
        elif dist == BeaconDistribution.GAUSSIAN:
            sigma = (p.max_sleep - p.min_sleep) / 6
            t = random.gauss(p.mean_sleep, sigma)
        elif dist == BeaconDistribution.TRIANGULAR:
            t = random.triangular(p.min_sleep, p.max_sleep, p.mean_sleep)
        elif dist == BeaconDistribution.PARETO:
            # Pareto: heavy tail — mostly fast, occasionally very long pauses
            alpha = 1.5
            t = (random.paretovariate(alpha) - 1) * p.mean_sleep + p.min_sleep
        else:
            t = p.mean_sleep

        # Clamp to [min, max]
        return max(p.min_sleep, min(p.max_sleep, t))

    async def sleep(self) -> None:
        """Async sleep for the next jittered interval."""
        interval = self.next_interval()
        logger.debug("beacon_sleep", seconds=round(interval, 3))
        await asyncio.sleep(interval)

    def sleep_sync(self) -> None:
        """Sync version for non-async contexts."""
        time.sleep(self.next_interval())


# ── Traffic Shaper ────────────────────────────────────────────────────────────

@dataclass
class _Bucket:
    capacity:   float
    tokens:     float
    refill_rate: float  # tokens per second
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    async def wait_and_consume(self, cost: float = 1.0) -> None:
        while not self.consume(cost):
            await asyncio.sleep(0.1)


class TrafficShaper:
    """
    Per-protocol token bucket rate limiter.
    Prevents burst traffic that would trigger IDS/ATA/MDI alerts.
    """

    PROFILES: dict[str, dict[str, dict[str, float]]] = {
        "stealth": {
            "default":      {"capacity": 5,   "rate": 0.17},   # 10 req/min
            "kerberos_tgs": {"capacity": 2,   "rate": 0.03},   # 2 req/min
            "ldap":         {"capacity": 5,   "rate": 0.17},   # 10 req/min
            "cloud_api":    {"capacity": 3,   "rate": 0.10},   # 6 req/min
            "smb":          {"capacity": 3,   "rate": 0.10},
        },
        "normal": {
            "default":      {"capacity": 15,  "rate": 0.5},    # 30 req/min
            "kerberos_tgs": {"capacity": 10,  "rate": 0.17},   # 10 req/min
            "ldap":         {"capacity": 20,  "rate": 0.67},
            "cloud_api":    {"capacity": 10,  "rate": 0.33},
            "smb":          {"capacity": 10,  "rate": 0.33},
        },
        "aggressive": {
            "default":      {"capacity": 100, "rate": 3.33},   # 200 req/min
            "kerberos_tgs": {"capacity": 50,  "rate": 0.83},   # 50 req/min
            "ldap":         {"capacity": 200, "rate": 6.67},
            "cloud_api":    {"capacity": 50,  "rate": 1.67},
            "smb":          {"capacity": 50,  "rate": 1.67},
        },
    }

    def __init__(self, noise_profile: str = "stealth") -> None:
        profile_cfg = self.PROFILES.get(noise_profile, self.PROFILES["stealth"])
        self._buckets: dict[str, _Bucket] = {
            proto: _Bucket(
                capacity=cfg["capacity"],
                tokens=cfg["capacity"],
                refill_rate=cfg["rate"],
            )
            for proto, cfg in profile_cfg.items()
        }

    async def acquire(self, action: str = "default") -> None:
        """Wait until a token is available for this action type."""
        bucket = self._buckets.get(action, self._buckets["default"])
        await bucket.wait_and_consume()


# ── Master OpSec Profile ──────────────────────────────────────────────────────

@dataclass
class OpSecProfile:
    """
    Master OpSec configuration. Ties all controls together.
    One instance per module run.
    """
    noise_profile:     str
    ua_rotator:        UserAgentRotator
    header_mutator:    HeaderMutator
    protocol_selector: ProtocolSelector
    beacon:            BeaconScheduler
    traffic_shaper:    TrafficShaper

    @classmethod
    def from_noise_profile(cls, profile: NoiseProfile | str) -> "OpSecProfile":
        pname = profile.value if isinstance(profile, NoiseProfile) else profile

        is_stealth    = pname == "stealth"
        is_aggressive = pname == "aggressive"

        beacon_profile = {
            "stealth":    BeaconProfile.stealth(),
            "normal":     BeaconProfile.normal(),
            "aggressive": BeaconProfile.aggressive(),
        }.get(pname, BeaconProfile.normal())

        return cls(
            noise_profile     = pname,
            ua_rotator        = UserAgentRotator(tool_like_ok=is_aggressive),
            header_mutator    = HeaderMutator(inject_noise=not is_aggressive, randomize_order=True),
            protocol_selector = ProtocolSelector(prefer_encrypted=not is_aggressive),
            beacon            = BeaconScheduler(beacon_profile),
            traffic_shaper    = TrafficShaper(pname),
        )

    # Convenience shortcuts
    def user_agent(self) -> str:
        return self.ua_rotator.get()

    def mutate_headers(self, base: dict[str, str]) -> dict[str, str]:
        return self.header_mutator.mutate({**base, "User-Agent": self.user_agent()})

    def select_protocol(self, protocol: str) -> str:
        return self.protocol_selector.select(protocol)

    async def sleep(self) -> None:
        await self.beacon.sleep()

    async def acquire(self, action: str = "default") -> None:
        await self.traffic_shaper.acquire(action)

    async def before_request(self, action: str = "default") -> None:
        """Call before every network request: rate-limit + jitter."""
        await self.acquire(action)
        await self.sleep()
