"""Transport-neutral contracts for one-time WebSocket tickets."""
from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

WEBSOCKET_TICKET_TTL_SECONDS = 30
WEBSOCKET_TICKET_ENTROPY_BYTES = 32
WEBSOCKET_TICKET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

_VALID_PRINCIPAL_ROLES = frozenset(
    {"team_lead", "operator", "recon", "reporter"}
)


class WebSocketTicketCredentialKind(str, Enum):
    BEARER = "bearer"
    API_KEY = "api_key"


def _canonical_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty canonical string")
    return value


def normalize_utc_datetime(value: datetime) -> datetime:
    """Return an aware UTC datetime without accepting an ambiguous naive value."""
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("timestamp must have a UTC offset")
    return value.astimezone(timezone.utc)


def format_sqlite_utc(value: datetime) -> str:
    """Format a timestamp using the canonical millisecond UTC SQLite contract."""
    return (
        normalize_utc_datetime(value)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def parse_sqlite_utc(value: str) -> datetime:
    """Parse only the canonical UTC representation emitted by this module."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must use canonical UTC format")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    normalized = normalize_utc_datetime(parsed)
    if format_sqlite_utc(normalized) != value:
        raise ValueError("timestamp must use canonical UTC format")
    return normalized


def generate_websocket_ticket() -> str:
    raw_ticket = secrets.token_urlsafe(WEBSOCKET_TICKET_ENTROPY_BYTES)
    if WEBSOCKET_TICKET_PATTERN.fullmatch(raw_ticket) is None:
        raise RuntimeError("ticket generator returned a non-canonical value")
    return raw_ticket


def is_canonical_websocket_ticket(raw_ticket: object) -> bool:
    return (
        isinstance(raw_ticket, str)
        and WEBSOCKET_TICKET_PATTERN.fullmatch(raw_ticket) is not None
    )


def hash_websocket_ticket(raw_ticket: str) -> str:
    if not is_canonical_websocket_ticket(raw_ticket):
        raise ValueError("ticket must use canonical format")
    return hashlib.sha256(raw_ticket.encode("ascii")).hexdigest()


def normalize_api_key_scopes(raw_scopes: object) -> tuple[str, ...]:
    if not isinstance(raw_scopes, str):
        return ()
    return tuple(
        scope
        for scope in raw_scopes.replace(",", " ").split()
        if scope
    )


def is_valid_websocket_principal_role(role: object) -> bool:
    return isinstance(role, str) and role in _VALID_PRINCIPAL_ROLES


@dataclass(frozen=True, slots=True, eq=False)
class BearerTicketSource:
    user_id: str = field(repr=False)
    subject: str = field(repr=False)
    jti: str = field(repr=False)
    expires_at: datetime = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "user_id", _canonical_identifier(self.user_id, "user_id")
        )
        object.__setattr__(
            self, "subject", _canonical_identifier(self.subject, "subject")
        )
        object.__setattr__(self, "jti", _canonical_identifier(self.jti, "jti"))
        object.__setattr__(
            self, "expires_at", normalize_utc_datetime(self.expires_at)
        )

    @property
    def credential_kind(self) -> WebSocketTicketCredentialKind:
        return WebSocketTicketCredentialKind.BEARER


@dataclass(frozen=True, slots=True, eq=False)
class ApiKeyTicketSource:
    user_id: str = field(repr=False)
    api_key_id: str = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "user_id", _canonical_identifier(self.user_id, "user_id")
        )
        object.__setattr__(
            self,
            "api_key_id",
            _canonical_identifier(self.api_key_id, "api_key_id"),
        )

    @property
    def credential_kind(self) -> WebSocketTicketCredentialKind:
        return WebSocketTicketCredentialKind.API_KEY

    @property
    def required_scope(self) -> str:
        return "read"


@dataclass(frozen=True, slots=True, eq=False)
class ConsumedWebSocketTicket:
    campaign_id: str = field(repr=False)
    user_id: str = field(repr=False)
    credential_kind: WebSocketTicketCredentialKind
    bearer_subject: str | None = field(default=None, repr=False)
    bearer_jti: str | None = field(default=None, repr=False)
    bearer_expires_at: datetime | None = field(default=None, repr=False)
    api_key_id: str | None = field(default=None, repr=False)
    required_scope: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "campaign_id",
            _canonical_identifier(self.campaign_id, "campaign_id"),
        )
        object.__setattr__(
            self, "user_id", _canonical_identifier(self.user_id, "user_id")
        )
        if self.credential_kind is WebSocketTicketCredentialKind.BEARER:
            if (
                self.bearer_subject is None
                or self.bearer_jti is None
                or self.bearer_expires_at is None
                or self.api_key_id is not None
                or self.required_scope is not None
            ):
                raise ValueError("invalid bearer ticket handle")
            object.__setattr__(
                self,
                "bearer_subject",
                _canonical_identifier(self.bearer_subject, "bearer_subject"),
            )
            object.__setattr__(
                self,
                "bearer_jti",
                _canonical_identifier(self.bearer_jti, "bearer_jti"),
            )
            object.__setattr__(
                self,
                "bearer_expires_at",
                normalize_utc_datetime(self.bearer_expires_at),
            )
        elif self.credential_kind is WebSocketTicketCredentialKind.API_KEY:
            if (
                self.api_key_id is None
                or self.required_scope != "read"
                or self.bearer_subject is not None
                or self.bearer_jti is not None
                or self.bearer_expires_at is not None
            ):
                raise ValueError("invalid API-key ticket handle")
            object.__setattr__(
                self,
                "api_key_id",
                _canonical_identifier(self.api_key_id, "api_key_id"),
            )
        else:
            raise ValueError("invalid ticket credential kind")


@dataclass(frozen=True, slots=True, eq=False)
class WebSocketTicketPrincipal:
    user_id: str = field(repr=False)
    username: str = field(repr=False)
    role: str
    credential_kind: WebSocketTicketCredentialKind
    api_key_id: str | None = field(default=None, repr=False)
    api_key_scopes: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "user_id", _canonical_identifier(self.user_id, "user_id")
        )
        object.__setattr__(
            self, "username", _canonical_identifier(self.username, "username")
        )
        if not is_valid_websocket_principal_role(self.role):
            raise ValueError("invalid principal role")
        if self.credential_kind is WebSocketTicketCredentialKind.BEARER:
            if self.api_key_id is not None or self.api_key_scopes:
                raise ValueError("bearer principal cannot contain API-key state")
        elif self.credential_kind is WebSocketTicketCredentialKind.API_KEY:
            if self.api_key_id is None:
                raise ValueError("API-key principal requires a key identifier")
            object.__setattr__(
                self,
                "api_key_id",
                _canonical_identifier(self.api_key_id, "api_key_id"),
            )
            object.__setattr__(
                self, "api_key_scopes", tuple(self.api_key_scopes)
            )
        else:
            raise ValueError("invalid principal credential kind")
