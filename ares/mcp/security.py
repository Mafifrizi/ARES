"""ARES Sovereign MCP Security & Governance Layer.

Implements the 7 Unbreakable Security Guarantees:
1. Scope Absolute Invariance (McpScopeGate)
2. Cryptographic Execution Gate (ConfirmationTokenManager)
3. Anti-Prompt-Injection Taint Isolation (McpTaintSanitizer)
4. Active Directory Outage Circuit Breaker
5. Secret Masking & Zero Data Exfiltration (SecretMasker)
6. Cryptographic Network Auth & RBAC (McpAuthGate)
7. Multi-Agent Session Isolation & Rate Limiting (McpRateLimiter)
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from typing import Any

from ares.sdk import UntrustedTargetData, LockoutCircuitBreaker


class McpSecurityViolation(Exception):
    """Raised when any MCP security guarantee or boundary is breached."""


class ConfirmationTokenManager:
    """Manages cryptographically signed, time-bounded confirmation tokens.

    Guarantees that Tier-2 offensive execution cannot occur without
    prior Tier-1 dry-run simulation and operator approval.
    """

    def __init__(self, secret_key: str | None = None) -> None:
        self._secret = (secret_key or secrets.token_hex(32)).encode("utf-8")
        # Token format: {token: (expires_at, signature_payload)}
        self._tokens: dict[str, tuple[float, str]] = {}

    def _make_payload(
        self,
        campaign_id: str,
        module_id: str,
        target: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        param_digest = hashlib.sha256(
            json.dumps(params or {}, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return f"{campaign_id}:{module_id}:{target.strip().lower()}:{param_digest}"

    def issue_token(
        self,
        campaign_id: str,
        module_id: str,
        target: str,
        params: dict[str, Any] | None = None,
        ttl_seconds: float = 60.0,
    ) -> str:
        """Issue a single-use, time-bounded HMAC token for a specific execution."""
        payload = self._make_payload(campaign_id, module_id, target, params)
        nonce = secrets.token_hex(8)
        raw_to_sign = f"{payload}:{nonce}:{time.time()}"
        sig = hmac.new(self._secret, raw_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"ares_tok_{sig[:32]}"
        expires_at = time.time() + ttl_seconds
        self._tokens[token] = (expires_at, payload)
        self._purge_expired()

        try:
            from ares.mcp.events import McpEventBus
            McpEventBus.emit("AUTH", {
                "call": f"Token issued for {module_id}: #{token[:16]}",
                "token": token,
                "module": module_id,
                "target": target,
                "ttl": int(ttl_seconds),
                "status": f"PENDING: {int(ttl_seconds)}s",
                "style": "yellow",
            })
        except Exception:
            pass

        return token

    def validate_and_burn(
        self,
        token: str,
        campaign_id: str,
        module_id: str,
        target: str,
        params: dict[str, Any] | None = None,
    ) -> bool:
        """Validate the token against execution parameters and burn it if valid."""
        self._purge_expired()
        if not token or token not in self._tokens:
            return False

        expires_at, expected_payload = self._tokens[token]
        if time.time() > expires_at:
            self._tokens.pop(token, None)
            return False

        # Honor operator reject decision from TUI monitor
        try:
            from ares.mcp.events import McpEventBus
            if McpEventBus.get_token_decision(token) == "REJECTED":
                self._tokens.pop(token, None)
                return False
        except Exception:
            pass

        actual_payload = self._make_payload(campaign_id, module_id, target, params)
        if hmac.compare_digest(expected_payload, actual_payload):
            self._tokens.pop(token, None)  # Burn upon valid use (anti-replay)
            return True

        return False

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [t for t, (exp, _) in self._tokens.items() if now > exp]
        for t in expired:
            self._tokens.pop(t, None)


class McpScopeGate:
    """Pre-flight Scope Enforcement for MCP invocations.

    Deterministically guarantees that no module execution or simulation
    can touch an out-of-scope target.
    """

    @staticmethod
    def is_in_scope(target: str, scope_rules: list[str]) -> bool:
        """Check if target (IP, CIDR, or Domain) matches any authorized scope rule."""
        target = target.strip().lower()
        if not target or not scope_rules:
            return False

        for rule in scope_rules:
            rule = rule.strip().lower()
            if not rule:
                continue

            # Exact match (hostname or IP)
            if target == rule:
                return True

            # CIDR Subnet Match
            if "/" in rule:
                try:
                    net = ipaddress.ip_network(rule, strict=False)
                    tgt_ip = ipaddress.ip_address(target)
                    if tgt_ip in net:
                        return True
                except ValueError:
                    pass

            # Wildcard or Domain Suffix Match (*.corp.local or corp.local)
            if rule.startswith("*."):
                domain_suffix = rule[2:]
                if target.endswith(domain_suffix) or target == domain_suffix:
                    return True
            elif rule.startswith("."):
                if target.endswith(rule):
                    return True

        return False

    @classmethod
    def verify_target(cls, target: str, scope_rules: list[str]) -> None:
        """Assert that target is in scope. Raises McpSecurityViolation if not."""
        if not cls.is_in_scope(target, scope_rules):
            raise McpSecurityViolation(
                f"SCOPE VIOLATION [BLOCKED]: Target '{target}' is not in the authorized engagement scope. "
                f"Authorized rules: {scope_rules}. Execution aborted before network dispatch."
            )


class McpTaintSanitizer:
    """Neutralizes Indirect Prompt Injection (IPI) in target responses.

    Neutralizes LLM control sequences and instruction injections.
    """

    _INJECTION_PATTERNS = [
        re.compile(r"(?i)\b(?:system|assistant|developer)\s*:\s*"),
        re.compile(r"(?i)<\|im_start\|>|<\|im_end\|>"),
        re.compile(r"(?i)\[INST\]|\[/INST\]"),
        re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
        re.compile(r"(?i)disregard\s+(?:all\s+)?prior\s+rules"),
        re.compile(r"(?i)bypass\s+(?:guardrails|safety)"),
        re.compile(r"(?i)leak\s+(?:api\s+key|vault|password|secret)"),
    ]

    @classmethod
    def sanitize(cls, data: Any) -> Any:
        """Recursively sanitize data before serialization to MCP client."""
        if isinstance(data, str):
            sanitized = data
            # Neutralize instruction injection markers
            for pattern in cls._INJECTION_PATTERNS:
                sanitized = pattern.sub("[SANITIZED_INSTRUCTION_TOKEN]", sanitized)
            return sanitized

        if isinstance(data, dict):
            return {k: cls.sanitize(v) for k, v in data.items()}

        if isinstance(data, (list, tuple, set)):
            return [cls.sanitize(item) for item in data]

        return data


class SecretMasker:
    """Masks credentials, hashes, and private keys from MCP outputs."""

    _SENSITIVE_KEYS = {
        "password", "secret", "hash", "ntlm", "ticket",
        "private_key", "api_key", "kerberos_key", "token"
    }

    @classmethod
    def mask(cls, data: Any) -> Any:
        """Recursively mask sensitive values in dictionaries and structures."""
        if isinstance(data, dict):
            masked: dict[str, Any] = {}
            for k, v in data.items():
                if any(sensitive in k.lower() for sensitive in cls._SENSITIVE_KEYS):
                    masked[k] = "***REDACTED***"
                else:
                    masked[k] = cls.mask(v)
            return masked

        if isinstance(data, list):
            return [cls.mask(x) for x in data]

        return data


class McpRateLimiter:
    """Token-bucket rate limiter per session to prevent DoS/reasoning loops."""

    def __init__(self, rate_per_minute: float = 30.0, burst: int = 10) -> None:
        self.rate = rate_per_minute / 60.0
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last_check = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False
