"""Immutable contracts for authoritative refresh-token families."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final, Protocol

FAMILY_ABSOLUTE_LIFETIME_DAYS: Final[int] = 30
FAMILY_RETENTION_DAYS: Final[int] = 30
REFRESH_TOKEN_RANDOM_BYTES: Final[int] = 48

_FAMILY_ID_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_REFRESH_HASH_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_COORDINATION_DOMAIN: Final[bytes] = b"ARES-REFRESH-COORDINATION-V1\0"


class RefreshFamilyState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class RefreshTokenState(str, Enum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    RETIRED = "retired"


class RefreshRevocationReason(str, Enum):
    REPLAY = "replay"
    LOGOUT_CURRENT = "logout_current"
    LOGOUT_ALL = "logout_all"
    PASSWORD_CHANGE = "password_change"  # noqa: S105 - fixed event identifier
    PASSWORD_RESET = "password_reset"  # noqa: S105 - fixed event identifier
    ROLE_CHANGE = "role_change"
    USER_STATUS_CHANGE = "user_status_change"
    ROLLOUT_RESET = "rollout_reset"
    EXPIRED = "expired"
    OPERATOR_REVOKE = "operator_revoke"


class SessionIssueStatus(str, Enum):
    ISSUED = "issued"
    INVALID = "invalid"
    BACKEND_UNAVAILABLE = "backend_unavailable"


class RefreshRotationStatus(str, Enum):
    ROTATED = "rotated"
    INVALID = "invalid"
    REPLAYED = "replayed"
    BACKEND_UNAVAILABLE = "backend_unavailable"


class SessionRevocationStatus(str, Enum):
    REVOKED = "revoked"
    ALREADY_REVOKED = "already_revoked"
    INVALID = "invalid"
    BACKEND_UNAVAILABLE = "backend_unavailable"


class AccessTokenFactory(Protocol):
    """Build one access token from already-authoritative claims."""

    def __call__(self, claims: Mapping[str, Any]) -> str: ...


def generate_family_id() -> str:
    value = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    if not is_canonical_family_id(value):
        raise RuntimeError("family identifier generation failed")
    return value


def is_canonical_family_id(value: object) -> bool:
    if not isinstance(value, str) or _FAMILY_ID_RE.fullmatch(value) is None:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return False
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    return len(decoded) == 32 and hmac.compare_digest(canonical, value)


def require_family_id(value: object) -> str:
    if not is_canonical_family_id(value):
        raise ValueError("invalid family identifier")
    return value


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_RANDOM_BYTES)


def hash_refresh_token(raw_token: str) -> str:
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError("invalid refresh token")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def is_canonical_refresh_hash(value: object) -> bool:
    return isinstance(value, str) and _REFRESH_HASH_RE.fullmatch(value) is not None


def session_coordination_key(family_id: str) -> str:
    canonical = require_family_id(family_id)
    digest = hashlib.sha256(_COORDINATION_DOMAIN + canonical.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True, eq=False)
class BearerFamilyAuthority:
    user_id: str = field(repr=False)
    subject: str = field(repr=False)
    family_id: str = field(repr=False)
    auth_epoch: int = field(repr=False)
    role: str
    absolute_expires_at: datetime = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "family_id", require_family_id(self.family_id))
        if isinstance(self.auth_epoch, bool) or self.auth_epoch < 1:
            raise ValueError("invalid authentication epoch")


@dataclass(frozen=True, slots=True, eq=False)
class IssuedTokenSession:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    user_id: str = field(repr=False)
    subject: str = field(repr=False)
    family_id: str = field(repr=False)
    auth_epoch: int = field(repr=False)
    refresh_generation: int
    role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "family_id", require_family_id(self.family_id))
        if (
            not self.access_token
            or not self.refresh_token
            or not self.user_id
            or not self.subject
        ):
            raise ValueError("invalid issued session")
        if isinstance(self.auth_epoch, bool) or self.auth_epoch < 1:
            raise ValueError("invalid authentication epoch")
        if isinstance(self.refresh_generation, bool) or self.refresh_generation < 0:
            raise ValueError("invalid refresh generation")

    @property
    def coordination_key(self) -> str:
        return session_coordination_key(self.family_id)


@dataclass(frozen=True, slots=True, eq=False)
class SessionIssueResult:
    status: SessionIssueStatus
    session: IssuedTokenSession | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class RefreshRotationResult:
    status: RefreshRotationStatus
    session: IssuedTokenSession | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class SessionRevocationResult:
    status: SessionRevocationStatus


__all__ = [
    "AccessTokenFactory",
    "BearerFamilyAuthority",
    "FAMILY_ABSOLUTE_LIFETIME_DAYS",
    "FAMILY_RETENTION_DAYS",
    "IssuedTokenSession",
    "RefreshFamilyState",
    "RefreshRevocationReason",
    "RefreshRotationResult",
    "RefreshRotationStatus",
    "RefreshTokenState",
    "SessionIssueResult",
    "SessionIssueStatus",
    "SessionRevocationResult",
    "SessionRevocationStatus",
    "generate_family_id",
    "generate_refresh_token",
    "hash_refresh_token",
    "is_canonical_family_id",
    "is_canonical_refresh_hash",
    "require_family_id",
    "session_coordination_key",
]
