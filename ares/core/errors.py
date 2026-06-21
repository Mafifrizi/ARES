"""
ARES Standard Error Hierarchy
All ARES exceptions inherit from AresError.

Design principles:
  - Every exception carries: message, module_id, target, context dict
  - Engine uses error TYPE to decide: retry | skip | fallback | abort
  - Structured logging automatically includes all fields
  - HTTP API maps errors to correct status codes

Error categories and engine behavior:

  AresError                   (base)
  ├─ ModuleError              retry up to max_attempts, then skip
  │   ├─ ModuleValidationError  abort immediately — bad config, skip module
  │   ├─ ModuleTimeoutError     retry with backoff
  │   └─ ModuleNotFoundError    abort — no retry possible
  ├─ NetworkError             retry with jitter
  │   ├─ ConnectionRefused      retry × 3, then fallback module
  │   ├─ ConnectionTimeout      retry with exponential backoff
  │   ├─ HostUnreachable        skip target, mark unreachable in session
  │   └─ DnsResolutionError     skip target
  ├─ CredentialError          try next credential, then mark host as auth-failed
  │   ├─ AuthenticationFailed   try next cred in vault
  │   ├─ AccountLocked          stop ALL attempts against this account immediately
  │   └─ CredentialExpired      mark cred invalid in vault
  ├─ ExecutionError           engine-level failures
  │   ├─ SandboxError           log + skip module
  │   ├─ WorkerCrashed          requeue task
  │   └─ PayloadError           log + skip
  ├─ ScopeError               abort immediately — never retry out-of-scope
  ├─ OpsecError               engine pauses or switches profile
  │   ├─ DetectionSignal        escalate opsec profile
  │   └─ HoneypotDetected       abort campaign, alert operator
  └─ PermissionError          skip module or escalate first
      └─ InsufficientPrivilege   suggest privesc module
"""

from __future__ import annotations

from typing import Any


class AresError(Exception):
    """
    Base exception for all ARES errors.
    Always carries structured context for logging and engine decisions.
    """

    # Engine behavior hint
    RETRY: str = "retry"
    SKIP: str = "skip"
    FALLBACK: str = "fallback"
    ABORT: str = "abort"
    PAUSE: str = "pause"

    default_action: str = SKIP

    def __init__(
        self,
        message: str,
        module_id: str = "",
        target: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.module_id = module_id
        self.target = target
        self.context = context or {}

    @property
    def action(self) -> str:
        """Engine behavior hint for this error."""
        return self.default_action

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "module_id": self.module_id,
            "target": self.target,
            "action": self.action,
            "context": self.context,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"module={self.module_id!r}, "
            f"target={self.target!r}, "
            f"action={self.action!r})"
        )


# ── Module Errors ──────────────────────────────────────────────────────────────


class ModuleError(AresError):
    """Module-level failure. Engine retries up to max_attempts then skips."""

    default_action = AresError.RETRY


class ModuleValidationError(ModuleError):
    """
    Module metadata or parameter validation failed.
    Engine aborts immediately — bad config means retry won't help.

    Raised by:
      BaseModule.validate()
      ModuleRegistry.validate_module()
    """

    default_action = AresError.ABORT

    def __init__(
        self, message: str, module_id: str = "", field: str = "", **kwargs: Any
    ) -> None:
        super().__init__(message, module_id=module_id, **kwargs)
        self.field = field


class ModuleTimeoutError(ModuleError):
    """
    Module exceeded wall-clock or CPU time limit.
    Engine retries with exponential backoff.
    """

    default_action = AresError.RETRY

    def __init__(self, message: str, timeout_s: float = 0, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.timeout_s = timeout_s


class ModuleNotFoundError(ModuleError):
    """
    Module ID not in registry.
    Engine aborts — cannot retry a missing module.
    """

    default_action = AresError.ABORT


# ── Network Errors ─────────────────────────────────────────────────────────────


class NetworkError(AresError):
    """Network-level failure. Engine retries with jitter."""

    default_action = AresError.RETRY


class ConnectionRefused(NetworkError):
    """
    TCP connection actively refused by target.
    Engine retries × 3 then tries fallback module (different port/protocol).
    """

    default_action = AresError.FALLBACK

    def __init__(self, message: str, port: int = 0, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.port = port


class ConnectionTimeout(NetworkError):
    """
    TCP connection timed out.
    Engine retries with exponential backoff (2s → 4s → 8s).
    """

    default_action = AresError.RETRY

    def __init__(self, message: str, timeout_s: float = 0, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.timeout_s = timeout_s


class HostUnreachable(NetworkError):
    """
    Host is unreachable (ICMP unreachable / no route).
    Engine marks host as unreachable in OperatorSession and skips it.
    """

    default_action = AresError.SKIP


class DnsResolutionError(NetworkError):
    """
    Hostname could not be resolved.
    Engine skips this target entirely.
    """

    default_action = AresError.SKIP


class RateLimited(NetworkError):
    """
    Target is rate-limiting our requests.
    Engine pauses and increases jitter before retrying.
    """

    default_action = AresError.PAUSE

    def __init__(self, message: str, retry_after_s: float = 60, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.retry_after_s = retry_after_s


# ── Credential Errors ──────────────────────────────────────────────────────────


class CredentialError(AresError):
    """Credential-related failure. Engine tries next credential in vault."""

    default_action = AresError.RETRY


class AuthenticationFailed(CredentialError):
    """
    Invalid credentials for this target/service.
    Engine marks this cred as failed for this host and tries next vault entry.
    """

    default_action = AresError.RETRY

    def __init__(
        self, message: str, username: str = "", service: str = "", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.username = username
        self.service = service


class AccountLocked(CredentialError):
    """
    Account is locked out.
    Engine IMMEDIATELY stops all attempts against this account across ALL targets.
    This is the most important lockout protection trigger.
    """

    default_action = AresError.ABORT  # never retry locked accounts

    def __init__(
        self, message: str, username: str = "", domain: str = "", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.username = username
        self.domain = domain


class CredentialExpired(CredentialError):
    """
    Credentials are valid but expired (must change password).
    Engine marks credential as expired in vault.
    """

    default_action = AresError.SKIP


class NoCredentialsAvailable(CredentialError):
    """
    Vault has no credentials that meet the required privilege level.
    Engine suggests running a credential discovery module first.
    """

    default_action = AresError.FALLBACK


# ── Execution Errors ───────────────────────────────────────────────────────────


class ExecutionError(AresError):
    """Engine-level execution failure."""

    default_action = AresError.RETRY


class SandboxError(ExecutionError):
    """
    Module failed inside sandbox (crashed, OOM, seccomp violation).
    Engine logs and skips module.
    """

    default_action = AresError.SKIP

    def __init__(
        self, message: str, exit_code: int = -1, stderr: str = "", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.exit_code = exit_code
        self.stderr = stderr[:500]


class WorkerCrashed(ExecutionError):
    """
    Worker node crashed mid-execution.
    Engine requeues the task with same parameters.
    """

    default_action = AresError.RETRY

    def __init__(self, message: str, worker_id: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.worker_id = worker_id


class PayloadError(ExecutionError):
    """
    Payload generation or delivery failed.
    Engine logs and skips this execution attempt.
    """

    default_action = AresError.SKIP


class InvalidContext(ExecutionError):
    """
    ExecutionContext is missing required fields.
    Engine aborts module — bad context means logic error, not transient failure.
    """

    default_action = AresError.ABORT

    def __init__(self, message: str, missing_field: str = "", **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.missing_field = missing_field


# ── Scope Errors ───────────────────────────────────────────────────────────────


class ScopeError(AresError):
    """
    Operation would target an out-of-scope host or resource.
    Engine ABORTS immediately. Never retries or falls back.
    The guardrail caught this — the operator must fix scope config.
    """

    default_action = AresError.ABORT

    def __init__(
        self,
        message: str,
        target: str = "",
        scope_cidrs: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, target=target, **kwargs)
        self.scope_cidrs = scope_cidrs or []


# ── OpSec Errors ───────────────────────────────────────────────────────────────


class OpsecError(AresError):
    """OpSec concern detected. Engine adjusts profile."""

    default_action = AresError.PAUSE


class DetectionSignal(OpsecError):
    """
    Signs that our activity is being detected (rate limiting, IDS alerts,
    unusual error patterns).
    Engine escalates to higher stealth profile and increases jitter.
    """

    default_action = AresError.PAUSE

    def __init__(
        self,
        message: str,
        signal_type: str = "",
        confidence: float = 0.5,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.signal_type = signal_type
        self.confidence = confidence


class HoneypotDetected(OpsecError):
    """
    High-confidence honeypot detection.
    Engine ABORTS the campaign and alerts the operator.
    Do NOT retry — further interaction makes IR worse.
    """

    default_action = AresError.ABORT

    def __init__(
        self, message: str, indicators: list[str] | None = None, **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.indicators = indicators or []


# ── Permission Errors ──────────────────────────────────────────────────────────


class PermissionError(AresError):
    """Insufficient privileges on target."""

    default_action = AresError.FALLBACK


class InsufficientPrivilege(PermissionError):
    """
    Module requires higher privilege than currently held.
    Engine suggests running a privilege escalation module first,
    then retrying this module.
    """

    default_action = AresError.FALLBACK

    def __init__(
        self, message: str, required: str = "", current: str = "", **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.required = required
        self.current = current


# ── Engine Action Resolver ─────────────────────────────────────────────────────


def resolve_action(error: AresError) -> str:
    """
    Return the engine's response action for a given error.
    Call this in the engine's exception handler.

    Usage:
        try:
            findings, extra = await module.run(**ctx.params)
        except AresError as e:
            action = resolve_action(e)
            if action == AresError.RETRY:
                task_queue.requeue(task)
            elif action == AresError.FALLBACK:
                next_mod = adaptive_strategy.next_alternative(module.MODULE_ID, target)
            elif action == AresError.ABORT:
                raise
    """
    return error.action


def is_lockout_risk(error: AresError) -> bool:
    """
    Returns True if error indicates account lockout risk.
    Engine should stop ALL further auth attempts against this account.
    """
    return (
        isinstance(error, (AccountLocked, AuthenticationFailed))
        and getattr(error, "username", "") != ""
    )


HTTP_STATUS_MAP: dict[type, int] = {
    ModuleValidationError: 400,
    ModuleNotFoundError: 404,
    AuthenticationFailed: 401,
    AccountLocked: 423,  # Locked
    ScopeError: 403,
    HoneypotDetected: 403,
    ModuleTimeoutError: 408,
    ConnectionTimeout: 408,
    HostUnreachable: 503,
    RateLimited: 429,
    SandboxError: 500,
    WorkerCrashed: 503,
    InsufficientPrivilege: 403,
}


def http_status(error: AresError) -> int:
    """Map an AresError to an HTTP status code for the API."""
    for error_type, status in HTTP_STATUS_MAP.items():
        if isinstance(error, error_type):
            return status
    return 500


# Backward-compatible public names imported by ares.core.__init__.
ScopeViolationError = ScopeError
RateLimitError = RateLimited
ValidationError = ModuleValidationError
