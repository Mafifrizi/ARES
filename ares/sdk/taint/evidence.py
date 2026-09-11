"""Taint-Tracked Target Data & Tamper-Evident Evidence Records.

Protects against Indirect Prompt Injection when findings/banners are inspected
by AI agents or operators, and establishes a cryptographic Chain of Custody (Merkle proof)
for verified red team deliverables.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")

# Characters commonly abused in prompt injection delimiters and shell escapes
_PROMPT_INJECTION_PATS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*:\s*execute", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
]


class UntrustedTargetData(Generic[T]):
    """Wrapper that demarcates external data retrieved from a target host.

    Forces callers to acknowledge whether they want sanitized representation
    or raw dangerous access, defending against Indirect Prompt Injection.
    """

    def __init__(self, value: T, source: str = "target_network") -> None:
        self._value: T = value
        self.source: str = source
        self._tainted: bool = True

    @property
    def is_tainted(self) -> bool:
        return self._tainted

    def raw_dangerous(self) -> T:
        """Returns the raw un-sanitized data. Use with caution."""
        return self._value

    def sanitized_text(self) -> str:
        """Returns a string representation with prompt injection delimiters scrubbed."""
        val_str = str(self._value)
        cleaned = val_str
        for pat in _PROMPT_INJECTION_PATS:
            cleaned = pat.sub("[REDACTED_SUSPICIOUS_PAYLOAD]", cleaned)
        # Wrap with explicit untrusted boundaries
        return f"<<<UNTRUSTED_TARGET_DATA source='{self.source}'>>>\n{cleaned}\n<<<END_UNTRUSTED_DATA>>>"

    def __repr__(self) -> str:
        return f"<UntrustedTargetData source={self.source!r} type={type(self._value).__name__}>"

    def __str__(self) -> str:
        return self.sanitized_text()


@dataclass(frozen=True)
class EvidenceRecord:
    """Cryptographically sealed, tamper-evident evidence item.

    Each evidence record computes a SHA-256 hash of its payload and can be chained
    to the preceding evidence hash to establish an unbroken audit trail.
    """

    evidence_id: str = ""
    source_target: str = ""
    payload: Any = None
    timestamp_ns: int = field(default_factory=time.time_ns)
    parent_hash: str = ""
    artifact_id: str = ""
    collected_by: str = ""
    data: Any = None
    tags: list[str] = field(default_factory=list)
    sha256_hash: str = field(init=False)
    chain_hash: str = field(init=False)

    def __post_init__(self) -> None:
        eff_id = self.evidence_id or self.artifact_id or "evidence"
        object.__setattr__(self, "evidence_id", eff_id)
        object.__setattr__(self, "artifact_id", eff_id)

        eff_payload = self.payload if self.payload is not None else (self.data if self.data is not None else {})
        object.__setattr__(self, "payload", eff_payload)
        object.__setattr__(self, "data", eff_payload)

        # 1. Compute payload digest
        serialized = json.dumps(eff_payload, sort_keys=True, default=str)
        payload_digest = hashlib.sha256(
            f"{eff_id}:{self.source_target}:{self.timestamp_ns}:{serialized}".encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "sha256_hash", payload_digest)

        # 2. Compute chain hash (Merkle link)
        chain = hashlib.sha256(f"{self.parent_hash}:{payload_digest}".encode("utf-8")).hexdigest()
        object.__setattr__(self, "chain_hash", chain)

    @property
    def record_hash(self) -> str:
        return self.sha256_hash

    def verify_integrity(self) -> bool:
        """Verify that the evidence payload matches its cryptographic digest."""
        eff_id = self.evidence_id or self.artifact_id
        eff_payload = self.payload if self.payload is not None else (self.data if self.data is not None else {})
        serialized = json.dumps(eff_payload, sort_keys=True, default=str)
        recomputed = hashlib.sha256(
            f"{eff_id}:{self.source_target}:{self.timestamp_ns}:{serialized}".encode("utf-8")
        ).hexdigest()
        return hmac_equal(recomputed, self.sha256_hash)


def hmac_equal(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    import hmac
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
