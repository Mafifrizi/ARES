"""Intelligent Resilience & Circuit Breaker for ARES SDK.

Protects target infrastructure and campaigns from catastrophic operational accidents
such as domain-wide Active Directory account lockouts and runaway noise storms.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any

from ares.core.errors import AresError, AccountLocked
from ares.core.logger import get_logger

logger = get_logger("ares.sdk.resilience")


class CircuitBreakerState(str, Enum):
    CLOSED = "closed"        # Normal operation: executions allowed
    OPEN = "open"            # Tripped: all executions blocked
    HALF_OPEN = "half_open"  # Testing recovery with single probe


class CircuitBreakerTripped(AresError):
    """Raised when an execution is blocked because the circuit breaker has tripped."""

    def __init__(self, message: str, breaker_name: str = "", state: str = "open") -> None:
        super().__init__(message)
        self.breaker_name = breaker_name
        self.state = state


class CircuitBreaker:
    """Configurable failure and timeout circuit breaker."""

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout_s: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.state = CircuitBreakerState.CLOSED
        self.consecutive_failures = 0
        self.last_failure_time = 0.0

    def allow_execution(self) -> bool:
        """Check whether execution is allowed. Raises CircuitBreakerTripped if open."""
        now = time.time()
        if self.state == CircuitBreakerState.OPEN:
            if now - self.last_failure_time >= self.recovery_timeout_s:
                self.state = CircuitBreakerState.HALF_OPEN
                logger.info(f"[CircuitBreaker:{self.name}] Transitioned to HALF_OPEN (probing recovery)")
                return True
            raise CircuitBreakerTripped(
                f"Circuit breaker '{self.name}' is OPEN. Execution blocked to protect target safety.",
                breaker_name=self.name,
                state=self.state.value,
            )
        return True

    def record_success(self) -> None:
        """Record successful execution. Resets failure counters."""
        self.consecutive_failures = 0
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            logger.info(f"[CircuitBreaker:{self.name}] Transitioned to CLOSED (recovered)")

    def record_failure(self, exc: Exception | None = None) -> None:
        """Record a failure event. Trips circuit if threshold is reached."""
        self.consecutive_failures += 1
        self.last_failure_time = time.time()

        if self.consecutive_failures >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(
                f"[CircuitBreaker:{self.name}] Tripped to OPEN after {self.consecutive_failures} failures. "
                f"Halting executions for {self.recovery_timeout_s}s."
            )


class LockoutCircuitBreaker(CircuitBreaker):
    """Specialized Active Directory & IAM Account Lockout Protection Gate.

    Immediately trips upon detecting any account lockout indicator, preventing
    domain-wide user lockouts across the entire engagement.
    """

    LOCKOUT_INDICATORS = (
        "account locked",
        "account_locked",
        "status_account_locked_out",
        "0xc0000234",
        "kdc_err_client_revoked",
        "account is currently locked out",
        "1909",  # Windows Event ID for account lockout
    )

    def __init__(self, name: str = "ad_lockout", recovery_timeout_s: float = 300.0) -> None:
        # A single lockout event trips immediately (threshold = 1)
        super().__init__(name=name, failure_threshold=1, recovery_timeout_s=recovery_timeout_s)
        self.locked_accounts: set[str] = set()

    def record_failure(self, exc: Exception | None = None) -> None:
        """Record a failure event. Trips circuit ONLY if lockout indicators are detected."""
        if exc is not None:
            self.inspect_error(exc)

    def inspect_error(self, exc: Exception, username: str = "") -> None:
        """Inspects exception for lockout signatures and trips instantly if detected."""
        if isinstance(exc, AccountLocked):
            self._trip_for_account(username, str(exc))
            return

        msg = str(exc).lower()
        if any(ind in msg for ind in self.LOCKOUT_INDICATORS):
            self._trip_for_account(username, str(exc))

    def _trip_for_account(self, username: str, reason: str) -> None:
        if username:
            self.locked_accounts.add(username.lower())
        self.state = CircuitBreakerState.OPEN
        self.last_failure_time = time.time()
        logger.error(
            f"[LockoutCircuitBreaker] CRITICAL: Account lockout detected for '{username}'! "
            f"Halting all further operations. Reason: {reason}"
        )
