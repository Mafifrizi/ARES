"""
ARES Database — async SQLite via aiosqlite.
All credential/token content encrypted at rest via Fernet.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, TypeVar
from urllib.parse import unquote

import aiosqlite

from ares.core.logger import get_logger
from ares.core.token_sessions import (
    FAMILY_ABSOLUTE_LIFETIME_DAYS,
    FAMILY_RETENTION_DAYS,
    AccessTokenFactory,
    IssuedTokenSession,
    RefreshRotationResult,
    RefreshRotationStatus,
    SessionIssueResult,
    SessionIssueStatus,
    SessionRevocationResult,
    SessionRevocationStatus,
    generate_family_id,
    generate_refresh_token,
    hash_refresh_token,
)
from ares.db.execution_lifecycle import (
    SYSTEM_PRINCIPAL_SUBJECT_REF,
    ExecutionLifecycleStore,
    FixedResult,
    OperationResult,
    valid_uuid,
    validate_sqlite_admission_authority_catalog_async,
)
from ares.db.websocket_tickets import (
    WEBSOCKET_TICKET_TTL_SECONDS,
    ApiKeyTicketSource,
    BearerTicketSource,
    ConsumedWebSocketTicket,
    WebSocketTicketCredentialKind,
    WebSocketTicketPrincipal,
    format_sqlite_utc,
    generate_websocket_ticket,
    hash_websocket_ticket,
    is_canonical_websocket_ticket,
    is_valid_websocket_principal_role,
    normalize_api_key_scopes,
    parse_sqlite_utc,
)

logger = get_logger("ares.db")

_CAMPAIGN_DELETE_OPERATION_DOMAIN = b"ares.campaign-delete.compat-operation.v1\x00"


def _campaign_delete_operation_id(campaign_id: str) -> str:
    """Derive the stable UUIDv4-shaped identity for an implicit delete operation."""
    digest = bytearray(
        hashlib.sha256(_CAMPAIGN_DELETE_OPERATION_DOMAIN + campaign_id.encode("utf-8")).digest()[
            :16
        ]
    )
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


from ares.core.campaign import Campaign, Finding
from ares.core.security import DataEncryptor, hash_password, verify_password
from ares.db.schema import CREATE_TABLES, SCHEMA_VERSION

_TicketResultT = TypeVar("_TicketResultT")
_FamilyResultT = TypeVar("_FamilyResultT")

_WEBSOCKET_TICKET_COLUMNS = (
    (0, "ticket_hash", "TEXT", 1, None, 1, 0),
    (1, "campaign_id", "TEXT", 1, None, 0, 0),
    (2, "user_id", "TEXT", 1, None, 0, 0),
    (3, "credential_kind", "TEXT", 1, None, 0, 0),
    (4, "bearer_subject", "TEXT", 0, None, 0, 0),
    (5, "bearer_jti", "TEXT", 0, None, 0, 0),
    (6, "bearer_expires_at", "TEXT", 0, None, 0, 0),
    (7, "api_key_id", "TEXT", 0, None, 0, 0),
    (8, "required_scope", "TEXT", 0, None, 0, 0),
    (9, "created_at", "TEXT", 1, None, 0, 0),
    (10, "expires_at", "TEXT", 1, None, 0, 0),
    (11, "consumed_at", "TEXT", 0, None, 0, 0),
    (12, "bearer_family_id", "TEXT", 0, None, 0, 0),
    (13, "bearer_auth_epoch", "INTEGER", 0, None, 0, 0),
)
_WEBSOCKET_TICKET_FOREIGN_KEYS = (
    (0, "api_key_id", "api_keys", "id", "NO ACTION", "CASCADE", "NONE"),
    (
        0,
        "bearer_family_id",
        "refresh_token_families",
        "id",
        "NO ACTION",
        "CASCADE",
        "NONE",
    ),
    (0, "campaign_id", "campaigns", "id", "NO ACTION", "CASCADE", "NONE"),
    (0, "user_id", "users", "id", "NO ACTION", "CASCADE", "NONE"),
    (
        1,
        "user_id",
        "refresh_token_families",
        "user_id",
        "NO ACTION",
        "CASCADE",
        "NONE",
    ),
)
_WEBSOCKET_TICKET_CHECKS = {
    "ck_ws_ticket_hash": """
        length(ticket_hash)=64
        AND ticket_hash NOT GLOB '*[^0-9a-f]*'
    """,
    "ck_ws_ticket_kind": """
        credential_kind IN ('bearer', 'api_key')
    """,
    "ck_ws_ticket_created_at": """
        strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at)=created_at
    """,
    "ck_ws_ticket_expires_at": """
        strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) IS NOT NULL
        AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at)=expires_at
    """,
    "ck_ws_ticket_consumed_at": """
        consumed_at IS NULL OR (
            strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) IS NOT NULL
            AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at)=consumed_at
        )
    """,
    "ck_ws_ticket_time_order": """
        julianday(expires_at) > julianday(created_at)
        AND (
            consumed_at IS NULL
            OR julianday(consumed_at) < julianday(expires_at)
        )
    """,
    "ck_ws_ticket_source_shape": """
        (
            credential_kind='bearer'
            AND bearer_subject IS NOT NULL
            AND length(trim(bearer_subject)) > 0
            AND bearer_subject=trim(bearer_subject)
            AND bearer_jti IS NOT NULL
            AND length(trim(bearer_jti)) > 0
            AND bearer_jti=trim(bearer_jti)
            AND bearer_expires_at IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            ) IS NOT NULL
            AND strftime(
                '%Y-%m-%dT%H:%M:%fZ', bearer_expires_at
            )=bearer_expires_at
            AND bearer_family_id IS NOT NULL
            AND length(bearer_family_id)=43
            AND bearer_family_id NOT GLOB '*[^A-Za-z0-9_-]*'
            AND bearer_auth_epoch IS NOT NULL
            AND typeof(bearer_auth_epoch)='integer'
            AND bearer_auth_epoch >= 1
            AND api_key_id IS NULL
            AND required_scope IS NULL
        )
        OR
        (
            credential_kind='api_key'
            AND bearer_subject IS NULL
            AND bearer_jti IS NULL
            AND bearer_expires_at IS NULL
            AND bearer_family_id IS NULL
            AND bearer_auth_epoch IS NULL
            AND api_key_id IS NOT NULL
            AND length(trim(api_key_id)) > 0
            AND api_key_id=trim(api_key_id)
            AND required_scope='read'
        )
    """,
}
_WEBSOCKET_TICKET_FOREIGN_KEY_NAMES = {
    "fk_ws_ticket_campaign",
    "fk_ws_ticket_user",
    "fk_ws_ticket_api_key",
    "fk_ws_ticket_bearer_family",
}
_WEBSOCKET_TICKET_NAMED_FOREIGN_KEYS = {
    "fk_ws_ticket_campaign": (
        "campaign_id",
        "campaigns",
        "id",
        "NO ACTION",
        "CASCADE",
    ),
    "fk_ws_ticket_user": (
        "user_id",
        "users",
        "id",
        "NO ACTION",
        "CASCADE",
    ),
    "fk_ws_ticket_api_key": (
        "api_key_id",
        "api_keys",
        "id",
        "NO ACTION",
        "CASCADE",
    ),
    "fk_ws_ticket_bearer_family": (
        "bearer_family_id,user_id",
        "refresh_token_families",
        "id,user_id",
        "NO ACTION",
        "CASCADE",
    ),
}


def _normalize_sql_fragment(fragment: str) -> str:
    """Normalize formatting while preserving quoted SQL literal contents."""
    normalized: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(fragment):
        character = fragment[index]
        if quote is not None:
            normalized.append(character)
            if character == quote:
                if index + 1 < len(fragment) and fragment[index + 1] == quote:
                    normalized.append(fragment[index + 1])
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"', "`"):
            quote = character
            normalized.append(character)
        elif character == "[":
            quote = "]"
            normalized.append(character)
        elif not character.isspace():
            normalized.append(character.lower())
        index += 1
    return "".join(normalized)


def _extract_named_checks(table_sql: str) -> tuple[dict[str, str], int]:
    pattern = re.compile(
        r"""\bconstraint\s+
            (?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_]*))
            \s+check\s*\(
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    checks: dict[str, str] = {}
    check_count = len(re.findall(r"\bcheck\s*\(", table_sql, re.IGNORECASE))
    for match in pattern.finditer(table_sql):
        name = next(group for group in match.groups() if group is not None)
        depth = 1
        quote: str | None = None
        index = match.end()
        expression_start = index
        while index < len(table_sql):
            character = table_sql[index]
            if quote is not None:
                if character == quote:
                    if index + 1 < len(table_sql) and table_sql[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif character in ("'", '"', "`"):
                quote = character
            elif character == "[":
                quote = "]"
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth != 0 or name in checks:
            return {}, check_count
        checks[name] = _normalize_sql_fragment(table_sql[expression_start:index])
    return checks, check_count


def _extract_named_constraints(table_sql: str) -> tuple[str, ...]:
    pattern = re.compile(
        r"""\bconstraint\s+
            (?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_]*))
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    return tuple(
        next(group for group in match.groups() if group is not None)
        for match in pattern.finditer(table_sql)
    )


def _split_sql_list(body: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(body):
        character = body[index]
        if quote is not None:
            if character == quote:
                if index + 1 < len(body) and body[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif character in ("'", '"', "`"):
            quote = character
        elif character == "[":
            quote = "]"
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(body[start:index])
            start = index + 1
        index += 1
    parts.append(body[start:])
    return tuple(parts)


def _foreign_key_action(fragment: str, action: str) -> str:
    match = re.search(
        rf"on{action}(noaction|restrict|cascade|setnull|setdefault)",
        fragment,
    )
    if match is None:
        return "NO ACTION"
    return {
        "noaction": "NO ACTION",
        "restrict": "RESTRICT",
        "cascade": "CASCADE",
        "setnull": "SET NULL",
        "setdefault": "SET DEFAULT",
    }[match.group(1)]


def _extract_named_foreign_keys(
    table_sql: str,
) -> dict[str, tuple[str, str, str, str, str]]:
    opening = table_sql.find("(")
    closing = table_sql.rfind(")")
    if opening < 0 or closing <= opening:
        return {}
    foreign_keys: dict[str, tuple[str, str, str, str, str]] = {}
    for raw_fragment in _split_sql_list(table_sql[opening + 1 : closing]):
        fragment = _normalize_sql_fragment(raw_fragment)
        fragment = fragment.replace('"', "").replace("`", "").replace("[", "").replace("]", "")
        name_match = re.search(
            r"""\bconstraint\s+
                (?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|
                ([A-Za-z_][A-Za-z0-9_]*))
            """,
            raw_fragment,
            re.IGNORECASE | re.VERBOSE,
        )
        if name_match is None:
            continue
        name = next(group for group in name_match.groups() if group is not None).lower()
        if name not in _WEBSOCKET_TICKET_FOREIGN_KEY_NAMES:
            continue
        table_level = re.search(
            r"foreignkey\(([a-z_][a-z0-9_]*(?:,[a-z_][a-z0-9_]*)*)\)"
            r"references([a-z_][a-z0-9_]*)"
            r"\(([a-z_][a-z0-9_]*(?:,[a-z_][a-z0-9_]*)*)\)",
            fragment,
        )
        if table_level is not None:
            local_column, target_table, target_column = table_level.groups()
        else:
            local_match = re.match(
                r"""\s*
                    (?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|
                    ([A-Za-z_][A-Za-z0-9_]*))
                """,
                raw_fragment,
                re.VERBOSE,
            )
            reference_match = re.search(
                r"references([a-z_][a-z0-9_]*)"
                r"\(([a-z_][a-z0-9_]*)\)",
                fragment,
            )
            if local_match is None or reference_match is None:
                return {}
            local_column = next(
                group for group in local_match.groups() if group is not None
            ).lower()
            target_table, target_column = reference_match.groups()
        if name in foreign_keys:
            return {}
        foreign_keys[name] = (
            local_column,
            target_table,
            target_column,
            _foreign_key_action(fragment, "update"),
            _foreign_key_action(fragment, "delete"),
        )
    return foreign_keys


async def _await_task_completion(
    task: asyncio.Future[Any],
    *,
    cancellation_baseline: int,
    caught_cancellations: list[int],
) -> Any:
    """Wait for one owned SQLite operation and account for caller cancellation."""
    caller = asyncio.current_task()
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            if caller is not None:
                caught_cancellations[0] = max(
                    caught_cancellations[0],
                    caller.cancelling() - cancellation_baseline,
                )
            if task.done():
                return task.result()


def _cancel_count() -> int:
    task = asyncio.current_task()
    return task.cancelling() if task is not None else 0


def _remove_suppressed_cancellations(
    *,
    cancellation_baseline: int,
    caught_cancellations: int,
) -> int:
    """Remove only cancellation requests suppressed after a committed rotation."""
    task = asyncio.current_task()
    if task is None:
        return 0
    removed = 0
    while removed < caught_cancellations and task.cancelling() > cancellation_baseline:
        task.uncancel()
        removed += 1
    return removed


def _sqlite_uri_query_value(query: str, name: str) -> str | None:
    for item in query.split("&"):
        key, separator, value = item.partition("=")
        if unquote(key).lower() == name.lower():
            return unquote(value) if separator else ""
    return None


def _windows_drive_uri_path(uri_path: str) -> str | None:
    """Return the drive-absolute path from a standard Windows file URI."""
    leading_slashes = len(uri_path) - len(uri_path.lstrip("/"))
    if leading_slashes not in (0, 1, 3):
        return None
    candidate = uri_path[leading_slashes:]
    if (
        len(candidate) >= 3
        and candidate[0].isalpha()
        and candidate[1] == ":"
        and candidate[2] in ("/", "\\")
    ):
        return candidate
    return None


def _normalize_sqlite_target(db_path: str) -> tuple[str, bool, str]:
    """Bind a SQLite target to one stable identity without rewriting URI data."""
    if db_path == ":memory:":
        return (
            f"file:ares-memory-{uuid.uuid4().hex}?mode=memory&cache=shared",
            True,
            "sqlite-memory",
        )
    if not db_path.startswith("file:"):
        return str(Path(db_path).expanduser().resolve()), False, "sqlite-file"

    uri_body = db_path[5:]
    uri_path, separator, query = uri_body.partition("?")
    if "\x00" in uri_path:
        raise ValueError("Unsupported SQLite file URI")
    if "%2f" in uri_path.lower() or "%5c" in uri_path.lower():
        raise ValueError("Unsupported SQLite file URI path")
    if _sqlite_uri_query_value(query, "vfs") is not None:
        raise ValueError("Unsupported SQLite file URI")

    mode = _sqlite_uri_query_value(query, "mode")
    if uri_path == ":memory:" or (mode is not None and mode.lower() == "memory"):
        return db_path, True, "sqlite-memory"
    if not uri_path:
        raise ValueError("Unsupported SQLite file URI")

    if uri_path.startswith("//") and not uri_path.startswith("///"):
        authority = uri_path[2:].replace("\\", "/").split("/", 1)[0]
        if authority.lower() != "localhost":
            raise ValueError("Unsupported SQLite file URI authority")

    windows_drive_path = _windows_drive_uri_path(uri_path)
    if windows_drive_path is not None:
        uri_path = windows_drive_path
        path_is_absolute = True
    else:
        path_is_absolute = Path(uri_path).is_absolute()
    if not path_is_absolute and not uri_path.startswith("//localhost/"):
        uri_path = Path(uri_path).expanduser().resolve().as_posix()

    normalized = f"file:{uri_path}"
    if separator:
        normalized = f"{normalized}?{query}"
    return normalized, True, "sqlite-file"


# ── Domain models ─────────────────────────────────────────────────────────────


@dataclass
class Host:
    """Domain model for a discovered host. Consistent with Campaign/Finding (Pydantic)."""

    campaign_id: str
    ip_address: str
    hostname: str | None = None
    fqdn: str | None = None
    os: str | None = None
    os_version: str | None = None
    domain: str | None = None
    is_dc: bool = False
    open_ports: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class DBCredential:
    """Domain model for a stored credential. Consistent with vault Credential model."""

    campaign_id: str
    username: str
    cred_type: str
    secret: str | None = None
    domain: str | None = None
    host_id: str | None = None
    source_module: str | None = None
    notes: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Loot:
    """Domain model for collected loot (files, tokens, keys)."""

    campaign_id: str
    loot_type: str
    name: str
    description: str = ""
    content: str | bytes | None = None
    host_id: str | None = None
    path_on_target: str | None = None
    source_module: str | None = None
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ── Database ──────────────────────────────────────────────────────────────────


class AresDatabase:
    """Async SQLite database wrapper with encryption support."""

    def __init__(
        self,
        db_path: str | Path = "ares.db",
        encryption_key: str | bytes | "DataEncryptor | None" = None,
    ) -> None:
        (
            self._db_path,
            self._is_sqlite_uri,
            self._database_label,
        ) = _normalize_sqlite_target(
            str(db_path),
        )
        if isinstance(encryption_key, DataEncryptor):
            self._enc: DataEncryptor | None = encryption_key
        elif encryption_key:
            self._enc = DataEncryptor(encryption_key)
        else:
            self._enc = None
        self._conn: aiosqlite.Connection | None = None
        self._connected = False
        self._lifecycle_lock = asyncio.Lock()

    def _require_connected(self) -> aiosqlite.Connection:
        if not self._connected or self._conn is None:
            raise RuntimeError("Database not connected — call await db.connect() first")
        return self._conn

    @property
    def conn(self) -> aiosqlite.Connection:
        return self._require_connected()

    async def _open_primary_connection(self) -> aiosqlite.Connection:
        return await aiosqlite.connect(
            self._db_path,
            uri=self._is_sqlite_uri,
        )

    async def _close_primary_connection(
        self,
        connection: aiosqlite.Connection,
    ) -> None:
        await connection.close()

    @staticmethod
    def _name_owned_task(task: asyncio.Future[Any], name: str) -> None:
        if isinstance(task, asyncio.Task):
            task.set_name(name)

    async def _finish_connection_cleanup(
        self,
        operation: Awaitable[Any],
        *,
        action: str,
        cancellation_baseline: int,
        caught_cancellations: list[int],
    ) -> None:
        cleanup_task = asyncio.ensure_future(operation)
        self._name_owned_task(cleanup_task, f"ares-sqlite-{action}")
        try:
            await _await_task_completion(
                cleanup_task,
                cancellation_baseline=cancellation_baseline,
                caught_cancellations=caught_cancellations,
            )
        except asyncio.CancelledError:
            raise
        except Exception as cleanup_error:
            logger.warning(
                "sqlite_connection_cleanup_failed",
                action=action,
                error_type=type(cleanup_error).__name__,
            )

    async def connect(self) -> "AresDatabase":
        async with self._lifecycle_lock:
            return await self._connect_locked()

    async def _connect_locked(self) -> "AresDatabase":
        if self._connected and self._conn is not None:
            return self

        cancellation_baseline = _cancel_count()
        caught_cancellations = [0]
        open_task = asyncio.ensure_future(self._open_primary_connection())
        self._name_owned_task(open_task, "ares-sqlite-primary-connect")
        connection = await _await_task_completion(
            open_task,
            cancellation_baseline=cancellation_baseline,
            caught_cancellations=caught_cancellations,
        )
        if caught_cancellations[0]:
            await self._finish_connection_cleanup(
                connection.close(),
                action="cancelled-primary-connect-close",
                cancellation_baseline=cancellation_baseline,
                caught_cancellations=caught_cancellations,
            )
            raise asyncio.CancelledError

        self._conn = connection
        try:
            connection.row_factory = aiosqlite.Row
            if not self._is_sqlite_uri:
                await connection.execute("PRAGMA journal_mode = WAL")
            await connection.execute("PRAGMA foreign_keys = ON")
            await self._init_schema()
        except BaseException:
            self._conn = None
            self._connected = False
            cleanup_baseline = _cancel_count()
            cleanup_cancellations = [0]
            await self._finish_connection_cleanup(
                connection.close(),
                action="failed-primary-connect-close",
                cancellation_baseline=cleanup_baseline,
                caught_cancellations=cleanup_cancellations,
            )
            raise
        self._connected = True
        return self

    async def __aenter__(self) -> "AresDatabase":
        return await self.connect()

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @classmethod
    async def create(
        cls,
        db_path: "str | Path" = "ares.db",
        encryption_key: str | None = None,
    ) -> "AresDatabase | PostgresDatabase":  # type: ignore[return]
        """
        Factory that returns the correct backend based on db_path / DATABASE_URL.

        SQLite  (default):
            db_path = "ares.db"  OR  "sqlite:///./ares.db"
        PostgreSQL (optional, requires asyncpg):
            db_path = "postgresql+asyncpg://user:pass@host/db"
            OR set ARES_DATABASE_URL=postgresql+asyncpg://...
        """
        # Resolve database URL: explicit arg wins, then env var
        import os as _os

        url = str(db_path)
        if not url or url == "ares.db":
            url = _os.environ.get("ARES_DATABASE_URL", url)

        if url.startswith(("postgresql", "postgres")):
            from ares.db.postgres import PostgresDatabase

            return await PostgresDatabase.create(dsn=url, encryption_key=encryption_key)

        # SQLite path — strip dialect prefix if present
        for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
            if url.startswith(prefix):
                url = url[len(prefix) :]

        db = cls(url, encryption_key)
        return await db.connect()

    async def _init_schema(self) -> None:
        if not self._is_sqlite_uri:
            from ares.db.migrations.adoption import (
                AdoptionExit,
                AdoptionFailure,
                inspect_sqlite_database,
            )

            try:
                ownership = await asyncio.to_thread(
                    inspect_sqlite_database,
                    self._db_path,
                )
            except AdoptionFailure as exc:
                if exc.exit_code == AdoptionExit.MANAGED_METADATA:
                    raise RuntimeError("Invalid managed SQLite database metadata") from None
                raise RuntimeError("Incompatible SQLite database catalog") from None

            if ownership.diagnostic.startswith("ARES-M2B-ADOPTION-READY:"):
                raise RuntimeError("SQLite database adoption is required")
            if ownership.diagnostic == "ARES-M2B-ALREADY-MANAGED:0011":
                await validate_sqlite_admission_authority_catalog_async(self._conn)
                return
            if ownership.exit_code == AdoptionExit.MIGRATION_REQUIRED:
                raise RuntimeError("SQLite schema migration is required")
            elif ownership.diagnostic != "ARES-M2B-EMPTY-DATABASE":
                raise RuntimeError("Incompatible SQLite database catalog")

            if await self._run_alembic_migrations():
                try:
                    managed = await asyncio.to_thread(
                        inspect_sqlite_database,
                        self._db_path,
                    )
                except AdoptionFailure:
                    raise RuntimeError("SQLite managed initialization failed") from None
                if managed.diagnostic != "ARES-M2B-ALREADY-MANAGED:0011":
                    raise RuntimeError("SQLite managed initialization failed")
                await validate_sqlite_admission_authority_catalog_async(self._conn)
                return

        async with self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='websocket_tickets'"
        ) as cursor:
            ticket_table_exists = await cursor.fetchone() is not None
        runtime_catalog_exists = False
        if ticket_table_exists:
            await self._validate_websocket_ticket_schema()
            await validate_sqlite_admission_authority_catalog_async(self._conn)
            runtime_catalog_exists = True

        alembic_applied = await self._run_alembic_migrations()
        if not alembic_applied and not runtime_catalog_exists:
            schema_body_marker = "PRAGMA foreign_keys = ON;"
            if CREATE_TABLES.count(schema_body_marker) != 1:
                raise RuntimeError("SQLite schema bootstrap is unavailable")
            schema_body = CREATE_TABLES.split(
                schema_body_marker,
                maxsplit=1,
            )[1]
            try:
                await self._conn.executescript(f"BEGIN IMMEDIATE;\n{schema_body}")
                await self._validate_websocket_ticket_schema()
                await validate_sqlite_admission_authority_catalog_async(self._conn)
                await self._conn.commit()
            except BaseException:
                await self._conn.rollback()
                raise
        await self._reconcile_sqlite_schema()
        await self._validate_websocket_ticket_schema()
        await validate_sqlite_admission_authority_catalog_async(self._conn)
        logger.info(
            "db_ready",
            database=self._database_label,
            schema_version=SCHEMA_VERSION,
        )

    async def _reconcile_sqlite_schema(self) -> None:
        """Ensure critical columns exist after idempotent/fallback migrations."""

        async def _columns(table: str) -> set[str]:
            async with self._conn.execute(f"PRAGMA table_info({table})") as cur:
                rows = await cur.fetchall()
            return {row["name"] for row in rows}

        findings_columns = await _columns("findings")
        missing_findings_columns = [
            ("cvss_score", "cvss_score REAL NOT NULL DEFAULT 0.0"),
            ("cvss_vector", "cvss_vector TEXT NOT NULL DEFAULT ''"),
            ("trace_id", "trace_id TEXT NOT NULL DEFAULT ''"),
        ]
        for name, ddl in missing_findings_columns:
            if name not in findings_columns:
                await self._conn.execute(f"ALTER TABLE findings ADD COLUMN {ddl}")
                findings_columns.add(name)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(cvss_score)"
        )
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS module_runs (
                id           TEXT PRIMARY KEY,
                campaign_id  TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                module_id    TEXT NOT NULL,
                outcome      TEXT NOT NULL,
                success      INTEGER NOT NULL DEFAULT 0,
                duration_ms  REAL NOT NULL DEFAULT 0.0,
                completed_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_module_runs_campaign ON module_runs(campaign_id)"
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_module_runs_completed ON module_runs(completed_at)"
        )
        await self._conn.commit()

    async def _validate_websocket_ticket_schema(self) -> None:
        """Reject a partially present ticket table instead of using it silently."""
        connection = self._conn
        if connection is None:
            raise RuntimeError("Database not connected")

        async with connection.execute("PRAGMA index_list(websocket_tickets)") as cursor:
            index_rows = await cursor.fetchall()
        primary_index_rows = tuple(row for row in index_rows if str(row["origin"]).lower() == "pk")
        if len(primary_index_rows) != 1:
            raise RuntimeError("Incompatible WebSocket ticket schema")
        primary_index_row = primary_index_rows[0]
        if int(primary_index_row["unique"]) != 1 or int(primary_index_row["partial"]) != 0:
            raise RuntimeError("Incompatible WebSocket ticket schema")
        primary_index_name = str(primary_index_row["name"])
        if not primary_index_name:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        async with connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE tbl_name='websocket_tickets'
            ORDER BY type, name
            """
        ) as cursor:
            attached_objects = await cursor.fetchall()
        expected_index_definitions = {
            "idx_ws_tickets_api_key": frozenset(
                {
                    "createindexidx_ws_tickets_api_keyonwebsocket_tickets(api_key_id)",
                    "createindexifnotexistsidx_ws_tickets_api_keyonwebsocket_tickets(api_key_id)",
                }
            ),
            "idx_ws_tickets_campaign": frozenset(
                {
                    "createindexidx_ws_tickets_campaignonwebsocket_tickets(campaign_id)",
                    "createindexifnotexistsidx_ws_tickets_campaignonwebsocket_tickets(campaign_id)",
                }
            ),
            "idx_ws_tickets_expires": frozenset(
                {
                    "createindexidx_ws_tickets_expiresonwebsocket_tickets(expires_at)",
                    "createindexifnotexistsidx_ws_tickets_expiresonwebsocket_tickets(expires_at)",
                }
            ),
            "idx_ws_tickets_user": frozenset(
                {
                    "createindexidx_ws_tickets_useronwebsocket_tickets(user_id)",
                    "createindexifnotexistsidx_ws_tickets_useronwebsocket_tickets(user_id)",
                }
            ),
            "idx_ws_tickets_bearer_family": frozenset(
                {
                    "createindexidx_ws_tickets_bearer_familyonwebsocket_tickets(bearer_family_id)",
                    "createindexifnotexistsidx_ws_tickets_bearer_family"
                    "onwebsocket_tickets(bearer_family_id)",
                }
            ),
        }
        if primary_index_name in expected_index_definitions:
            raise RuntimeError("Incompatible WebSocket ticket schema")
        if len(attached_objects) != len(expected_index_definitions) + 2:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        table_count = 0
        primary_index_count = 0
        explicit_index_names: set[str] = set()
        for row in attached_objects:
            object_type = str(row["type"])
            object_name = str(row["name"])
            table_name = str(row["tbl_name"])
            definition = row["sql"]
            if (
                object_type == "table"
                and object_name == "websocket_tickets"
                and table_name == "websocket_tickets"
                and definition is not None
            ):
                table_count += 1
            elif (
                object_type == "index"
                and object_name == primary_index_name
                and table_name == "websocket_tickets"
                and definition is None
            ):
                primary_index_count += 1
            elif (
                object_type == "index"
                and object_name in expected_index_definitions
                and table_name == "websocket_tickets"
                and definition is not None
                and _normalize_sql_fragment(str(definition))
                in expected_index_definitions[object_name]
            ):
                explicit_index_names.add(object_name)
            else:
                raise RuntimeError("Incompatible WebSocket ticket schema")
        if (
            table_count != 1
            or primary_index_count != 1
            or explicit_index_names != set(expected_index_definitions)
        ):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        async with connection.execute("PRAGMA table_xinfo(websocket_tickets)") as cursor:
            columns = await cursor.fetchall()
        actual_columns = tuple(
            (
                int(row["cid"]),
                str(row["name"]),
                str(row["type"]).upper(),
                int(row["notnull"]),
                row["dflt_value"],
                int(row["pk"]),
                int(row["hidden"]),
            )
            for row in columns
        )
        if actual_columns != _WEBSOCKET_TICKET_COLUMNS:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        async with connection.execute("PRAGMA foreign_key_list(websocket_tickets)") as cursor:
            foreign_keys = tuple(
                sorted(
                    (
                        int(row["seq"]),
                        str(row["from"]),
                        str(row["table"]),
                        str(row["to"]),
                        str(row["on_update"]).upper(),
                        str(row["on_delete"]).upper(),
                        str(row["match"]).upper(),
                    )
                    for row in await cursor.fetchall()
                )
            )
        if foreign_keys != _WEBSOCKET_TICKET_FOREIGN_KEYS:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        actual_indexes: dict[
            str,
            tuple[int, str, int, tuple[tuple[Any, ...], ...]],
        ] = {}
        for row in index_rows:
            index_name = str(row["name"])
            quoted_name = index_name.replace('"', '""')
            async with connection.execute(f'PRAGMA index_xinfo("{quoted_name}")') as cursor:
                index_columns = tuple(
                    (
                        int(index_row["seqno"]),
                        int(index_row["cid"]),
                        index_row["name"],
                        int(index_row["desc"]),
                        str(index_row["coll"]).upper(),
                        int(index_row["key"]),
                    )
                    for index_row in await cursor.fetchall()
                )
            actual_indexes[index_name] = (
                int(row["unique"]),
                str(row["origin"]).lower(),
                int(row["partial"]),
                index_columns,
            )
        if len(actual_indexes) != len(index_rows):
            raise RuntimeError("Incompatible WebSocket ticket schema")
        primary_index = actual_indexes.pop(primary_index_name, None)
        expected_primary_index = (
            1,
            "pk",
            0,
            (
                (0, 0, "ticket_hash", 0, "BINARY", 1),
                (1, -1, None, 0, "BINARY", 0),
            ),
        )
        expected_indexes = {
            "idx_ws_tickets_expires": (
                0,
                "c",
                0,
                (
                    (0, 10, "expires_at", 0, "BINARY", 1),
                    (1, -1, None, 0, "BINARY", 0),
                ),
            ),
            "idx_ws_tickets_user": (
                0,
                "c",
                0,
                (
                    (0, 2, "user_id", 0, "BINARY", 1),
                    (1, -1, None, 0, "BINARY", 0),
                ),
            ),
            "idx_ws_tickets_campaign": (
                0,
                "c",
                0,
                (
                    (0, 1, "campaign_id", 0, "BINARY", 1),
                    (1, -1, None, 0, "BINARY", 0),
                ),
            ),
            "idx_ws_tickets_api_key": (
                0,
                "c",
                0,
                (
                    (0, 7, "api_key_id", 0, "BINARY", 1),
                    (1, -1, None, 0, "BINARY", 0),
                ),
            ),
            "idx_ws_tickets_bearer_family": (
                0,
                "c",
                0,
                (
                    (0, 12, "bearer_family_id", 0, "BINARY", 1),
                    (1, -1, None, 0, "BINARY", 0),
                ),
            ),
        }
        if primary_index != expected_primary_index or actual_indexes != expected_indexes:
            raise RuntimeError("Incompatible WebSocket ticket schema")

        async with connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='websocket_tickets'"
        ) as cursor:
            table_row = await cursor.fetchone()
        table_sql = str(table_row["sql"] if table_row else "")
        normalized_table_sql = _normalize_sql_fragment(table_sql)
        if not normalized_table_sql.startswith(
            "createtablewebsocket_tickets("
        ) and not normalized_table_sql.startswith("createtableifnotexistswebsocket_tickets("):
            raise RuntimeError("Incompatible WebSocket ticket schema")
        if (
            "withoutrowid" in normalized_table_sql
            or "strict" in normalized_table_sql
            or "collate" in normalized_table_sql
            or "onconflict" in normalized_table_sql
            or "deferrable" in normalized_table_sql
            or "initiallydeferred" in normalized_table_sql
            or "initiallyimmediate" in normalized_table_sql
        ):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        named_checks, check_count = _extract_named_checks(table_sql)
        expected_checks = {
            name: _normalize_sql_fragment(expression)
            for name, expression in _WEBSOCKET_TICKET_CHECKS.items()
        }
        if named_checks != expected_checks or check_count != len(expected_checks):
            raise RuntimeError("Incompatible WebSocket ticket schema")

        expected_constraint_names = tuple(
            sorted(set(expected_checks) | _WEBSOCKET_TICKET_FOREIGN_KEY_NAMES)
        )
        if tuple(sorted(_extract_named_constraints(table_sql))) != (expected_constraint_names):
            raise RuntimeError("Incompatible WebSocket ticket schema")
        if _extract_named_foreign_keys(table_sql) != _WEBSOCKET_TICKET_NAMED_FOREIGN_KEYS:
            raise RuntimeError("Incompatible WebSocket ticket schema")

    async def _run_alembic_migrations(self) -> bool:
        if self._is_sqlite_uri:
            logger.debug(
                "alembic_skipped_for_sqlite_uri",
            )
            return False

        try:
            from types import SimpleNamespace

            from alembic import command as alembic_command
            from alembic.config import Config as AlembicConfig

            from ares.db.migrations.adoption import migration_config

            db_url = f"sqlite:///{self._db_path}"

            loop = asyncio.get_running_loop()

            def _upgrade() -> None:
                with migration_config() as configured:
                    alembic_cfg: AlembicConfig = configured
                    alembic_cfg.cmd_opts = SimpleNamespace(x=[f"db_url={db_url}"])
                    alembic_command.upgrade(alembic_cfg, "head")

            await loop.run_in_executor(
                None,
                _upgrade,
            )
            logger.info(
                "alembic_migrations_applied",
                database=self._database_label,
            )
            return True

        except ImportError:
            raise RuntimeError("SQLite managed initialization failed") from None
        except Exception as exc:
            raise RuntimeError(
                f"SQLite managed initialization failed [{type(exc).__name__}]"
            ) from None

    # ── Backup / export ───────────────────────────────────────────────────────

    async def checkpoint_wal(self) -> None:
        """Force a WAL checkpoint — consolidates WAL into main DB file.
        Call periodically (e.g. hourly) or before taking a file-system backup."""
        await self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await self._conn.commit()

    async def export_json(self, output_path: str | None = None) -> str:
        """
        Export all campaigns + findings to JSON.
        Safe to call during engagement — read-only snapshot.

        Returns the output file path written.
        Default path: ~/.ares/backups/ares_export_<timestamp>.json
        """
        import json
        from datetime import datetime, timezone
        from pathlib import Path

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not output_path:
            backup_dir = Path.home() / ".ares" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(backup_dir / f"ares_export_{ts}.json")

        async with self._conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC") as cur:
            campaigns = [dict(r) for r in await cur.fetchall()]

        for campaign in campaigns:
            cid = campaign["id"]
            async with self._conn.execute(
                "SELECT * FROM findings WHERE campaign_id=? ORDER BY discovered_at DESC",
                (cid,),
            ) as cur:
                campaign["_findings"] = [dict(r) for r in await cur.fetchall()]
            async with self._conn.execute(
                "SELECT * FROM hosts WHERE campaign_id=? ORDER BY first_seen",
                (cid,),
            ) as cur:
                campaign["_hosts"] = [dict(r) for r in await cur.fetchall()]

        export = {
            "export_version": "1.0",
            "exported_at": ts,
            "schema_version": SCHEMA_VERSION,
            "campaigns": campaigns,
        }
        with open(output_path, "w") as fh:
            json.dump(export, fh, indent=2, default=str)

        logger.info("db_export_complete", path=output_path, campaigns=len(campaigns))
        return output_path

    async def close(self) -> None:
        async with self._lifecycle_lock:
            await self._close_locked()

    async def _close_locked(self) -> None:
        connection = self._conn
        self._connected = False
        self._conn = None
        if connection is None:
            return
        cancellation_baseline = _cancel_count()
        caught_cancellations = [0]
        close_task = asyncio.ensure_future(self._close_primary_connection(connection))
        self._name_owned_task(close_task, "ares-sqlite-primary-close")
        try:
            await _await_task_completion(
                close_task,
                cancellation_baseline=cancellation_baseline,
                caught_cancellations=caught_cancellations,
            )
        finally:
            self._connected = False
            self._conn = None
        if caught_cancellations[0]:
            raise asyncio.CancelledError

    def _enc_val(self, v: str | None) -> str | None:
        return self._enc.encrypt(v) if self._enc and v else v

    def _dec_val(self, v: str | None) -> str | None:
        return self._enc.decrypt(v) if self._enc and v else v

    # ── Campaigns ─────────────────────────────────────────────────────────────

    async def save_campaign(self, c: Campaign) -> None:
        await self._conn.execute(
            """
            INSERT INTO campaigns(id,name,client,operator,noise_profile,status,scope_json,targets_json,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name, client=excluded.client, operator=excluded.operator,
              noise_profile=excluded.noise_profile, status=excluded.status,
              scope_json=excluded.scope_json, targets_json=excluded.targets_json,
              notes=excluded.notes,
              updated_at=datetime('now')
        """,
            (
                c.id,
                c.name,
                c.client,
                c.operator,
                c.noise_profile.value,
                c.status.value if hasattr(c.status, "value") else str(c.status),
                json.dumps([s.model_dump() for s in c.scope]),
                json.dumps(c.targets),
                c.notes,
            ),
        )
        await self._conn.commit()

    async def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        async with self._conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def list_campaigns(
        self, page: int = 1, per_page: int = 50, operator: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        offset = (page - 1) * per_page
        conditions: list[str] = []
        params_list: list[Any] = []
        if operator:
            conditions.append("operator=?")
            params_list.append(operator)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        async with self._conn.execute(
            f"SELECT COUNT(*) as n FROM campaigns {where}", params_list
        ) as cur:
            total = (await cur.fetchone())["n"]

        async with self._conn.execute(
            f"SELECT * FROM campaigns {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params_list + [per_page, offset],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        return rows, total

    async def delete_campaign(self, campaign_id: str) -> bool:
        """Delete once through the stable compatibility receipt authority."""
        result = await self.delete_campaign_lifecycle(campaign_id)
        return result.result is FixedResult.APPLIED

    async def delete_campaign_lifecycle(
        self,
        campaign_id: str,
        *,
        operation_id: str | None = None,
        lifecycle_operation_id: str | None = None,
        principal_kind: str = "system",
        principal_subject_ref: str | None = None,
        principal_user_id: str | None = None,
        principal_authority_revision: int | None = None,
    ) -> OperationResult:
        """Delete a campaign with explicit immutable operation/principal binding."""
        if (
            operation_id is not None
            and lifecycle_operation_id is not None
            and operation_id != lifecycle_operation_id
        ):
            return OperationResult(FixedResult.INVALID_CONTRACT, None)
        resolved_operation_id = operation_id if operation_id is not None else lifecycle_operation_id
        if resolved_operation_id is None:
            if not valid_uuid(campaign_id):
                return OperationResult(FixedResult.INVALID_CONTRACT, None)
            resolved_operation_id = _campaign_delete_operation_id(campaign_id)
        if principal_subject_ref is None:
            if principal_kind != "system":
                return OperationResult(FixedResult.INVALID_CONTRACT, None)
            principal_subject_ref = SYSTEM_PRINCIPAL_SUBJECT_REF

        store = ExecutionLifecycleStore(self._conn, "sqlite")
        try:
            receipt_spec = store._receipt_spec(
                operation_id=resolved_operation_id,
                operation_code="campaign_delete",
                campaign_id=campaign_id,
                primary_target_id=campaign_id,
                principal_kind=principal_kind,
                principal_subject_ref=principal_subject_ref,
                principal_user_id=principal_user_id,
                principal_authority_revision=principal_authority_revision,
            )
        except ValueError:
            return OperationResult(FixedResult.INVALID_CONTRACT, None)

        async with store._transaction() as connection:
            await store._acquire_transaction_key(connection, resolved_operation_id)
            replay = await store._classify_receipt(connection, receipt_spec, current_revision=None)
            if replay is not None:
                return replay
            await store._acquire_transaction_key(connection, campaign_id)
            async with connection.execute(
                "SELECT singleton_id FROM execution_gateway_state WHERE singleton_id=1"
            ) as cursor:
                await cursor.fetchone()
            async with connection.execute(
                "SELECT id FROM campaigns WHERE id=?", (campaign_id,)
            ) as cursor:
                if await cursor.fetchone() is None:
                    return OperationResult(FixedResult.NOT_FOUND_OR_PURGED, None)
            for statement in (
                "SELECT campaign_id FROM campaign_execution_authority_revisions "
                "WHERE campaign_id=?",
                "SELECT actor_user_id FROM campaign_execution_actor_grants "
                "WHERE campaign_id=? ORDER BY actor_user_id",
                "SELECT campaign_id FROM campaign_execution_destination_authorities "
                "WHERE campaign_id=?",
                "SELECT id FROM execution_approval_authorities WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM logical_executions WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM execution_attempts WHERE campaign_id=? ORDER BY ordinal,id",
                "SELECT attempt_id || ':' || CAST(ordinal AS TEXT) "
                "FROM execution_attempt_destination_observations "
                "WHERE campaign_id=? ORDER BY attempt_id,ordinal",
                "SELECT attempt_id || ':' || CAST(ordinal AS TEXT) "
                "FROM execution_attempt_credential_observations "
                "WHERE campaign_id=? ORDER BY attempt_id,ordinal",
                "SELECT id FROM campaign_execution_budgets WHERE campaign_id=? "
                "ORDER BY budget_kind,id",
                "SELECT id FROM campaign_execution_budget_ledger WHERE campaign_id=? "
                "ORDER BY budget_kind,id",
                "SELECT id FROM hosts WHERE campaign_id=? ORDER BY ip_address,id",
                "SELECT id FROM findings WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM credentials WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM loot WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM execution_output_links WHERE campaign_id=? ORDER BY id",
                "SELECT id FROM execution_publication_outbox WHERE campaign_id=? ORDER BY id",
            ):
                async with connection.execute(statement, (campaign_id,)) as cursor:
                    await cursor.fetchall()
            async with connection.execute(
                "SELECT 1 FROM execution_attempts WHERE campaign_id=? "
                "AND state IN ('accepted','queued','dispatching','running','cancelling',"
                "'settlement_pending') LIMIT 1",
                (campaign_id,),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    raise RuntimeError("Campaign lifecycle deletion is blocked")
            async with connection.execute(
                "SELECT 1 FROM logical_executions WHERE campaign_id=? "
                "AND closed_at IS NULL LIMIT 1",
                (campaign_id,),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    raise RuntimeError("Campaign lifecycle deletion is blocked")
            async with connection.execute(
                "SELECT 1 FROM execution_publication_outbox WHERE campaign_id=? "
                "AND publication_state='claimed' LIMIT 1",
                (campaign_id,),
            ) as cursor:
                if await cursor.fetchone() is not None:
                    raise RuntimeError("Campaign lifecycle deletion is blocked")
            async with connection.execute(
                "SELECT id FROM execution_attempts WHERE campaign_id=? ORDER BY ordinal DESC",
                (campaign_id,),
            ) as cursor:
                attempt_ids = tuple(str(row[0]) for row in await cursor.fetchall())

            async def delete_exact(statement: str, expected: tuple[str, ...]) -> None:
                async with connection.execute(statement, (campaign_id,)) as cursor:
                    observed = tuple(sorted(str(row[0]) for row in await cursor.fetchall()))
                if observed != tuple(sorted(expected)):
                    raise RuntimeError("Campaign lifecycle deletion invariant failed")

            identities: dict[str, tuple[str, ...]] = {}
            for key, statement in (
                ("links", "SELECT id FROM execution_output_links WHERE campaign_id=?"),
                ("outbox", "SELECT id FROM execution_publication_outbox WHERE campaign_id=?"),
                ("approvals", "SELECT id FROM execution_attempt_approvals WHERE campaign_id=?"),
                (
                    "approval_authorities",
                    "SELECT id FROM execution_approval_authorities WHERE campaign_id=?",
                ),
                (
                    "destination_observations",
                    "SELECT attempt_id || ':' || CAST(ordinal AS TEXT) "
                    "FROM execution_attempt_destination_observations WHERE campaign_id=?",
                ),
                (
                    "credential_observations",
                    "SELECT attempt_id || ':' || CAST(ordinal AS TEXT) "
                    "FROM execution_attempt_credential_observations WHERE campaign_id=?",
                ),
                ("ledgers", "SELECT id FROM campaign_execution_budget_ledger WHERE campaign_id=?"),
                ("logical", "SELECT id FROM logical_executions WHERE campaign_id=?"),
                ("budgets", "SELECT id FROM campaign_execution_budgets WHERE campaign_id=?"),
                (
                    "actor_grants",
                    "SELECT actor_user_id FROM campaign_execution_actor_grants WHERE campaign_id=?",
                ),
                (
                    "destination_authorities",
                    "SELECT campaign_id FROM campaign_execution_destination_authorities "
                    "WHERE campaign_id=?",
                ),
            ):
                async with connection.execute(statement, (campaign_id,)) as cursor:
                    identities[key] = tuple(str(row[0]) for row in await cursor.fetchall())
            await delete_exact(
                "DELETE FROM execution_output_links WHERE campaign_id=? RETURNING id",
                identities["links"],
            )
            await delete_exact(
                "DELETE FROM execution_publication_outbox WHERE campaign_id=? RETURNING id",
                identities["outbox"],
            )
            await delete_exact(
                "DELETE FROM execution_attempt_approvals WHERE campaign_id=? RETURNING id",
                identities["approvals"],
            )
            await delete_exact(
                "DELETE FROM execution_approval_authorities WHERE campaign_id=? RETURNING id",
                identities["approval_authorities"],
            )
            await delete_exact(
                "DELETE FROM execution_attempt_destination_observations WHERE campaign_id=? "
                "RETURNING attempt_id || ':' || CAST(ordinal AS TEXT)",
                identities["destination_observations"],
            )
            await delete_exact(
                "DELETE FROM execution_attempt_credential_observations WHERE campaign_id=? "
                "RETURNING attempt_id || ':' || CAST(ordinal AS TEXT)",
                identities["credential_observations"],
            )
            await delete_exact(
                "DELETE FROM campaign_execution_budget_ledger WHERE campaign_id=? RETURNING id",
                identities["ledgers"],
            )
            for attempt_id in attempt_ids:
                async with connection.execute(
                    "DELETE FROM execution_attempts WHERE id=? RETURNING id", (attempt_id,)
                ) as cursor:
                    row = await cursor.fetchone()
                if row is None or str(row[0]) != attempt_id:
                    raise RuntimeError("Campaign lifecycle deletion invariant failed")
            await delete_exact(
                "DELETE FROM logical_executions WHERE campaign_id=? RETURNING id",
                identities["logical"],
            )
            await delete_exact(
                "DELETE FROM campaign_execution_budgets WHERE campaign_id=? RETURNING id",
                identities["budgets"],
            )
            await delete_exact(
                "DELETE FROM campaign_execution_actor_grants WHERE campaign_id=? "
                "RETURNING actor_user_id",
                identities["actor_grants"],
            )
            await delete_exact(
                "DELETE FROM campaign_execution_destination_authorities WHERE campaign_id=? "
                "RETURNING campaign_id",
                identities["destination_authorities"],
            )
            async with connection.execute(
                "DELETE FROM campaign_execution_authority_revisions WHERE campaign_id=? "
                "RETURNING campaign_id",
                (campaign_id,),
            ) as cursor:
                authority_rows = await cursor.fetchall()
            if len(authority_rows) > 1:
                raise RuntimeError("Campaign lifecycle deletion invariant failed")
            for statement in (
                "DELETE FROM loot WHERE campaign_id=? RETURNING id",
                "DELETE FROM credentials WHERE campaign_id=? RETURNING id",
                "DELETE FROM hosts WHERE campaign_id=? RETURNING id",
                "DELETE FROM findings WHERE campaign_id=? RETURNING id",
            ):
                async with connection.execute(statement, (campaign_id,)) as cursor:
                    await cursor.fetchall()
            await store._insert_receipt(
                connection,
                receipt_spec,
                result=FixedResult.APPLIED,
                exact_replay_code=FixedResult.REPLAYED,
                result_identity=campaign_id,
                result_revision=None,
                result_fields=(("deleted", True),),
            )
            async with connection.execute(
                "DELETE FROM campaigns WHERE id=? RETURNING id", (campaign_id,)
            ) as cur:
                deleted_campaign = await cur.fetchall()
            if len(deleted_campaign) != 1 or str(deleted_campaign[0][0]) != campaign_id:
                raise RuntimeError("Campaign lifecycle deletion invariant failed")
            return OperationResult(FixedResult.APPLIED, None)

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(self, campaign_id: str, f: Finding, module_id: str = "") -> None:
        """FIX: module_id sekarang opsional (default '')."""
        await self._conn.execute(
            """
            INSERT INTO findings
            (id,campaign_id,module_id,title,description,severity,cvss_score,cvss_vector,
             confidence,mitre_technique,mitre_tactic,evidence_json,remediation,host,trace_id,
             validated,false_positive)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              module_id=excluded.module_id,title=excluded.title,
              description=excluded.description,severity=excluded.severity,
              cvss_score=excluded.cvss_score,cvss_vector=excluded.cvss_vector,
              confidence=excluded.confidence,mitre_technique=excluded.mitre_technique,
              mitre_tactic=excluded.mitre_tactic,evidence_json=excluded.evidence_json,
              remediation=excluded.remediation,host=excluded.host,
              trace_id=excluded.trace_id,validated=excluded.validated,
              false_positive=excluded.false_positive
        """,
            (
                f.id,
                campaign_id,
                module_id or getattr(f, "module_id", ""),
                f.title,
                f.description,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                getattr(f, "cvss_score", 0.0),
                getattr(f, "cvss_vector", ""),
                f.confidence,
                f.mitre_technique,
                f.mitre_tactic,
                json.dumps(f.evidence),
                f.remediation,
                f.host,
                getattr(f, "trace_id", ""),
                int(bool(getattr(f, "validated", False))),
                int(bool(getattr(f, "false_positive", False))),
            ),
        )
        await self._conn.commit()

    async def list_findings(
        self,
        campaign_id: str,
        page: int = 1,
        per_page: int = 50,
        severity: str | None = None,
        false_positive: bool | None = None,
        validated: bool | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        conditions = ["campaign_id=?"]
        params_list: list[Any] = [campaign_id]
        if severity:
            conditions.append("severity=?")
            params_list.append(severity)
        if false_positive is not None:
            conditions.append("false_positive=?")
            params_list.append(int(false_positive))
        if validated is not None:
            conditions.append("validated=?")
            params_list.append(int(validated))

        where = " AND ".join(conditions)
        offset = (page - 1) * per_page

        async with self._conn.execute(
            f"SELECT COUNT(*) as n FROM findings WHERE {where}", params_list
        ) as cur:
            total = (await cur.fetchone())["n"]

        async with self._conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC LIMIT ? OFFSET ?",
            params_list + [per_page, offset],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        return rows, total

    async def get_findings(
        self,
        campaign_id: str,
        confirmed_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return flat list of all findings for a campaign (no pagination)."""
        conditions = ["campaign_id=?"]
        params_list: list[Any] = [campaign_id]
        if confirmed_only:
            conditions.append("validated=1")
            conditions.append("false_positive=0")
        where = " AND ".join(conditions)
        async with self._conn.execute(
            f"SELECT * FROM findings WHERE {where} ORDER BY discovered_at DESC",
            params_list,
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_finding_stats(self, campaign_id: str) -> dict[str, Any]:
        """Return count breakdown by severity for a campaign."""
        async with self._conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings WHERE campaign_id=? GROUP BY severity",
            (campaign_id,),
        ) as cur:
            rows = await cur.fetchall()
        stats: dict[str, Any] = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for r in rows:
            sev = r["severity"]
            stats[sev] = r["n"]
            stats["total"] += r["n"]
        return stats

    async def get_monthly_confirmed_finding_stats(self) -> dict[str, Any]:
        """Return confirmed findings grouped by day in the current UTC month."""
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        async with self._conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM findings
            WHERE validated=1
              AND false_positive=0
            """
        ) as cur:
            confirmed_findings = int((await cur.fetchone())["n"])
        async with self._conn.execute(
            """
            SELECT substr(discovered_at, 1, 10) AS finding_date, COUNT(*) AS n
            FROM findings
            WHERE validated=1
              AND false_positive=0
              AND substr(discovered_at, 1, 7)=?
            GROUP BY substr(discovered_at, 1, 10)
            ORDER BY finding_date
            """,
            (period,),
        ) as cur:
            rows = await cur.fetchall()
        series = [{"date": str(row["finding_date"]), "count": int(row["n"])} for row in rows]
        return {
            "period": period,
            "label": "Security signals this cycle",
            "total": sum(item["count"] for item in series),
            "confirmed_findings": confirmed_findings,
            "series": series,
        }

    async def record_module_run(
        self,
        campaign_id: str,
        module_id: str,
        outcome: str,
        success: bool,
        duration_ms: float,
    ) -> None:
        """Persist non-sensitive execution metadata for restart-safe telemetry."""
        await self._conn.execute(
            """
            INSERT INTO module_runs
                (id, campaign_id, module_id, outcome, success, duration_ms, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                campaign_id,
                module_id,
                outcome,
                int(bool(success)),
                max(0.0, float(duration_ms or 0.0)),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await self._conn.commit()

    async def get_telemetry_stats(self) -> dict[str, Any]:
        """Aggregate persisted execution, finding, and discovered-host telemetry."""
        async with self._conn.execute(
            "SELECT success, duration_ms, completed_at FROM module_runs ORDER BY completed_at"
        ) as cur:
            run_rows = await cur.fetchall()

        total = len(run_rows)
        success = sum(int(row["success"]) for row in run_rows)
        failed = total - success
        durations = sorted(float(row["duration_ms"] or 0.0) for row in run_rows)

        def percentile(fraction: float) -> float | None:
            if not durations:
                return None
            index = max(0, min(len(durations) - 1, int(len(durations) * fraction + 0.999999) - 1))
            return round(durations[index], 1)

        recent_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        recent_runs = sum(1 for row in run_rows if str(row["completed_at"]) >= recent_cutoff)

        async with self._conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM findings
            WHERE validated=1 AND false_positive=0
            """
        ) as cur:
            confirmed_findings = int((await cur.fetchone())["n"])
        async with self._conn.execute("SELECT COUNT(*) AS n FROM hosts") as cur:
            discovered_hosts = int((await cur.fetchone())["n"])

        return {
            "modules": {
                "total": total,
                "success": success,
                "failed": failed,
                "error_rate": failed / total if total else 0.0,
            },
            "findings": confirmed_findings,
            "latency_ms": {
                "p50": percentile(0.50),
                "p95": percentile(0.95),
                "p99": percentile(0.99),
            },
            "throughput": {
                "tasks_per_min": float(recent_runs) if recent_runs else None,
            },
            "hosts": {
                "available": False,
                "discovered": discovered_hosts,
                "owned": None,
            },
        }

    async def campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        """High-level stats for a campaign."""
        findings = await self.get_findings(campaign_id)
        hosts = await self.get_hosts(campaign_id)
        creds = await self.get_credentials(campaign_id)
        loot = await self.get_loot(campaign_id)
        return {
            "campaign_id": campaign_id,
            "findings": findings,
            "finding_count": len(findings),
            "host_count": len(hosts),
            "credential_count": len(creds),
            "loot_count": len(loot),
        }

    # ── Hosts ─────────────────────────────────────────────────────────────────

    async def upsert_host(self, h: Host) -> str:
        await self._conn.execute(
            """
            INSERT INTO hosts(id,campaign_id,ip_address,hostname,fqdn,os,os_version,
                domain,is_dc,open_ports_json,tags_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(campaign_id,ip_address) DO UPDATE SET
              hostname=excluded.hostname, fqdn=excluded.fqdn, os=excluded.os,
              is_dc=excluded.is_dc, open_ports_json=excluded.open_ports_json,
              tags_json=excluded.tags_json, last_seen=datetime('now')
        """,
            (
                h.id,
                h.campaign_id,
                h.ip_address,
                h.hostname,
                h.fqdn,
                h.os,
                h.os_version,
                h.domain,
                int(h.is_dc),
                json.dumps(h.open_ports),
                json.dumps(h.tags),
            ),
        )
        async with self._conn.execute(
            "SELECT id FROM hosts WHERE campaign_id=? AND ip_address=?",
            (h.campaign_id, h.ip_address),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            await self._conn.rollback()
            raise RuntimeError("Canonical host persistence failed")
        await self._conn.commit()
        return str(row["id"])

    async def get_hosts(self, campaign_id: str) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM hosts WHERE campaign_id=? ORDER BY first_seen", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ── Credentials ───────────────────────────────────────────────────────────

    async def save_credential(self, c: DBCredential) -> None:
        await self._conn.execute(
            """
            INSERT INTO credentials
            (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              host_id=excluded.host_id,username=excluded.username,
              secret_enc=excluded.secret_enc,cred_type=excluded.cred_type,
              domain=excluded.domain,source_module=excluded.source_module,
              notes=excluded.notes
        """,
            (
                c.id,
                c.campaign_id,
                c.host_id,
                c.username,
                self._enc_val(c.secret),
                c.cred_type,
                c.domain,
                c.source_module,
                c.notes,
            ),
        )
        await self._conn.commit()

    async def save_credential_preencrypted(self, c: DBCredential) -> None:
        """
        Persist a credential whose secret is ALREADY Fernet-encrypted by
        CredentialVault. Skips _enc_val() to prevent double-encryption.
        Uses INSERT OR IGNORE so re-running after a crash doesn't overwrite
        existing secrets with the same ID.
        """
        await self._conn.execute(
            """
            INSERT INTO credentials
                (id,campaign_id,host_id,username,secret_enc,cred_type,domain,source_module,notes)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                secret_enc    = excluded.secret_enc,
                source_module = excluded.source_module,
                notes         = excluded.notes
        """,
            (
                c.id,
                c.campaign_id,
                c.host_id,
                c.username,
                c.secret,  # already vault-encrypted — store verbatim
                c.cred_type,
                c.domain,
                c.source_module,
                c.notes,
            ),
        )
        await self._conn.commit()

    async def load_credentials_raw(self, campaign_id: str) -> list[dict]:
        """
        Load all credentials for a campaign from DB as raw dicts.
        Secrets are returned as-is (Fernet-encrypted by CredentialVault) —
        use CredentialVault.restore_from_db_records() to re-hydrate.
        """
        async with self._conn.execute(
            "SELECT * FROM credentials WHERE campaign_id=? ORDER BY captured_at DESC",
            (campaign_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def get_credentials(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM credentials WHERE campaign_id=? ORDER BY captured_at", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if decrypt and d.get("secret_enc"):
                d["secret"] = self._dec_val(d["secret_enc"])
            else:
                d["secret"] = None
            result.append(d)
        return result

    # ── Loot ──────────────────────────────────────────────────────────────────

    async def save_loot(self, l: Loot) -> None:
        content_str = json.dumps(l.content) if isinstance(l.content, (dict, list)) else l.content
        await self._conn.execute(
            """
            INSERT INTO loot
            (id,campaign_id,host_id,loot_type,name,description,content_enc,
             path_on_target,source_module,tags_json)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              host_id=excluded.host_id,loot_type=excluded.loot_type,
              name=excluded.name,description=excluded.description,
              content_enc=excluded.content_enc,path_on_target=excluded.path_on_target,
              source_module=excluded.source_module,tags_json=excluded.tags_json
        """,
            (
                l.id,
                l.campaign_id,
                l.host_id,
                l.loot_type,
                l.name,
                l.description,
                self._enc_val(content_str),
                l.path_on_target,
                l.source_module,
                json.dumps(l.tags),
            ),
        )
        await self._conn.commit()

    def execution_lifecycle_store(self) -> ExecutionLifecycleStore:
        """Return the additive internal lifecycle persistence primitive."""
        return ExecutionLifecycleStore(self._conn, "sqlite")

    async def get_loot(self, campaign_id: str, decrypt: bool = False) -> list[dict]:
        """FIX: method getter yang sebelumnya tidak ada."""
        async with self._conn.execute(
            "SELECT * FROM loot WHERE campaign_id=? ORDER BY captured_at", (campaign_id,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if decrypt and d.get("content_enc"):
                d["content"] = self._dec_val(d["content_enc"])
            else:
                d["content"] = None
            result.append(d)
        return result

    async def save_campaign_graph(self, campaign_id: str, graph: dict[str, Any]) -> None:
        """Persist a sanitized graph snapshot without adding a new schema dependency."""
        graph_id = f"campaign_graph:{campaign_id}"
        payload = json.dumps(graph, separators=(",", ":"))
        await self._conn.execute(
            """
            INSERT INTO loot
                (id,campaign_id,loot_type,name,description,content_enc,source_module,tags_json)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              description=excluded.description,
              content_enc=excluded.content_enc,
              source_module=excluded.source_module,
              tags_json=excluded.tags_json,
              captured_at=datetime('now')
            """,
            (
                graph_id,
                campaign_id,
                "campaign_graph",
                "durable_attack_graph",
                "Sanitized artifact and BloodHound graph snapshot",
                self._enc_val(payload),
                "core.graph",
                json.dumps(["runtime", "safe-metadata"]),
            ),
        )
        await self._conn.commit()

    async def get_campaign_graph(self, campaign_id: str) -> dict[str, Any] | None:
        """Load the latest safe graph snapshot, returning no decrypted loot to callers."""
        async with self._conn.execute(
            """
            SELECT content_enc FROM loot
            WHERE id=? AND campaign_id=? AND loot_type='campaign_graph'
            """,
            (f"campaign_graph:{campaign_id}", campaign_id),
        ) as cur:
            row = await cur.fetchone()
        if not row or not row["content_enc"]:
            return None
        try:
            decoded = self._dec_val(row["content_enc"])
            parsed = json.loads(decoded) if decoded else None
            return parsed if isinstance(parsed, dict) else None
        except (TypeError, ValueError):
            logger.warning("campaign_graph_snapshot_invalid", campaign_id=campaign_id[:8])
            return None

    # ── Audit log ─────────────────────────────────────────────────────────────

    async def audit(
        self,
        actor: str,
        action: str,
        detail: str = "",
        campaign_id: str | None = None,
        module_id: str | None = None,
    ) -> None:
        await self._conn.execute(
            "INSERT INTO audit_log(campaign_id,actor,action,detail,module_id) VALUES(?,?,?,?,?)",
            (campaign_id, actor, action, detail, module_id),
        )
        await self._conn.commit()

    # ── Users (v5) ────────────────────────────────────────────────────────────

    async def create_user(
        self, username: str, password: str, role: str, created_by: str = "system"
    ) -> str:
        user_id = str(uuid.uuid4())
        await self._conn.execute(
            "INSERT INTO users(id,username,hashed_password,role,created_by) VALUES(?,?,?,?,?)",
            (user_id, username, hash_password(password), role, created_by),
        )
        await self._conn.commit()
        logger.info("user_created", username=username, role=role, by=created_by)
        return user_id

    async def get_user(self, username: str) -> dict[str, Any] | None:
        async with self._conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        async with self._conn.execute(
            "SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def resolve_access_token_principal(
        self,
        subject: str,
        jti: str,
        family_id: str,
        auth_epoch: int,
    ) -> dict[str, Any] | None:
        """Resolve bearer, family, epoch, and JTI authority read-only."""
        connection = self._require_connected()
        async with connection.execute(
            """SELECT u.id, u.username, u.role, u.auth_epoch
               FROM users AS u
               JOIN refresh_token_families AS f
                 ON f.user_id=u.id
                AND f.id=?
               WHERE u.username=?
                 AND u.is_active=1
                 AND u.auth_epoch=?
                 AND f.auth_epoch=u.auth_epoch
                 AND f.state='active'
                 AND f.revoked_at IS NULL
                 AND julianday(f.absolute_expires_at) > julianday('now')
                 AND NOT EXISTS (
                     SELECT 1
                     FROM revoked_access_tokens AS rat
                     WHERE rat.jti=?
                 )""",
            (family_id, subject, auth_epoch, jti),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def verify_user(self, username: str, password: str) -> dict[str, Any] | None:
        user = await self.get_user(username)
        # Always run bcrypt comparison to prevent username enumeration via timing attack.
        # If user not found, compare against a dummy hash so response time is constant.
        _DUMMY_HASH = "$2b$12$notarealthashXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        candidate_hash = user["hashed_password"] if user else _DUMMY_HASH
        password_ok = verify_password(password, candidate_hash)
        if not user or not password_ok:
            return None
        await self._conn.execute(
            "UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],)
        )
        await self._conn.commit()
        return user

    async def user_exists(self, username: str) -> bool:
        async with self._conn.execute("SELECT 1 FROM users WHERE username=?", (username,)) as cur:
            return (await cur.fetchone()) is not None

    async def update_password(self, user_id: str, new_hash: str) -> None:
        """Update a user's hashed password. Called from change-password endpoint."""
        await self._conn.execute(
            "UPDATE users SET hashed_password=? WHERE id=?",
            (new_hash, user_id),
        )
        await self._conn.commit()

    async def list_users(self) -> list[dict[str, Any]]:
        async with self._conn.execute(
            "SELECT id,username,role,is_active,created_at,last_login FROM users ORDER BY created_at"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def ensure_default_admin(self, admin_password: str) -> bool:
        async with self._conn.execute("SELECT COUNT(*) as n FROM users") as cur:
            n = (await cur.fetchone())["n"]
        if n == 0:
            await self.create_user("admin", admin_password, "team_lead", "bootstrap")
            logger.warning(
                "default_admin_created",
                msg="CHANGE admin password immediately: POST /auth/change-password",
            )
            return True
        return False

    # ── API Keys (v5) ─────────────────────────────────────────────────────────

    async def create_api_key(
        self,
        user_id: str,
        name: str,
        scopes: str = "read",
        expires_days: int | None = None,
    ) -> tuple[str, str]:
        raw_key = "ares_" + secrets.token_urlsafe(40)
        key_prefix = raw_key[:12]
        key_id = str(uuid.uuid4())
        expires_at = None
        if expires_days:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        await self._conn.execute(
            "INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,scopes,expires_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (key_id, user_id, name, hash_password(raw_key), key_prefix, scopes, expires_at),
        )
        await self._conn.commit()
        logger.info("api_key_created", user_id=user_id, name=name, prefix=key_prefix)
        return key_id, raw_key

    async def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        if not raw_key.startswith("ares_"):
            return None
        prefix = raw_key[:12]
        async with self._conn.execute(
            """SELECT ak.*, u.username, u.role
               FROM api_keys ak JOIN users u ON ak.user_id=u.id
               WHERE ak.key_prefix=? AND ak.is_active=1
               AND u.is_active=1
               AND (
                   ak.expires_at IS NULL
                   OR (
                       julianday(ak.expires_at) IS NOT NULL
                       AND julianday(ak.expires_at) > julianday('now')
                   )
               )""",
            (prefix,),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        for row in rows:
            if verify_password(raw_key, row["key_hash"]):
                async with self._conn.execute(
                    """UPDATE api_keys
                       SET last_used=datetime('now')
                       WHERE id=? AND is_active=1
                       AND (
                           expires_at IS NULL
                           OR (
                               julianday(expires_at) IS NOT NULL
                               AND julianday(expires_at) > julianday('now')
                           )
                       )
                       AND EXISTS (
                           SELECT 1 FROM users u
                           WHERE u.id=api_keys.user_id AND u.is_active=1
                       )""",
                    (row["id"],),
                ) as cur:
                    changed = cur.rowcount
                await self._conn.commit()
                if changed != 1:
                    return None
                return {
                    "username": row["username"],
                    "role": row["role"],
                    "auth_type": "api_key",
                    "key_id": row["id"],
                    "scopes": [row["scopes"]] if row["scopes"] else [],
                }
        return None

    async def list_api_keys(self, user_id: str) -> list[dict[str, Any]]:
        async with self._conn.execute(
            "SELECT id,name,key_prefix,scopes,is_active,last_used,expires_at,created_at "
            "FROM api_keys WHERE user_id=? AND is_active=1 ORDER BY created_at DESC",
            (user_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        async with self._conn.execute(
            "UPDATE api_keys SET is_active=0 WHERE id=? AND user_id=? AND is_active=1",
            (key_id, user_id),
        ) as cur:
            changed = cur.rowcount
        await self._conn.commit()
        return changed > 0

    async def _open_websocket_ticket_connection(self) -> aiosqlite.Connection:
        return await aiosqlite.connect(
            self._db_path,
            uri=self._is_sqlite_uri,
            timeout=30.0,
        )

    async def _commit_websocket_ticket_operation(
        self,
        connection: aiosqlite.Connection,
    ) -> None:
        await connection.commit()

    async def _finish_websocket_ticket_cleanup(
        self,
        operation: Awaitable[Any],
        action: str,
        *,
        cancellation_baseline: int,
        caught_cancellations: list[int],
    ) -> None:
        cleanup_task = asyncio.ensure_future(operation)
        self._name_owned_task(
            cleanup_task,
            f"ares-sqlite-websocket-ticket-{action}",
        )
        try:
            await _await_task_completion(
                cleanup_task,
                cancellation_baseline=cancellation_baseline,
                caught_cancellations=caught_cancellations,
            )
        except asyncio.CancelledError:
            raise
        except Exception as cleanup_error:
            logger.warning(
                "websocket_ticket_cleanup_failed",
                action=action,
                error_type=type(cleanup_error).__name__,
            )

    async def _run_websocket_ticket_transaction(
        self,
        operation: Callable[
            [aiosqlite.Connection],
            Awaitable[_TicketResultT],
        ],
    ) -> _TicketResultT:
        async with self._lifecycle_lock:
            self._require_connected()
            connection: aiosqlite.Connection | None = None
            transaction_started = False
            commit_started = False
            committed = False
            commit_cancellation_baseline = 0
            commit_cancellations = [0]
            noncommit_close_cancellations = [0]
            try:
                open_cancellation_baseline = _cancel_count()
                open_cancellations = [0]
                open_task = asyncio.ensure_future(self._open_websocket_ticket_connection())
                self._name_owned_task(
                    open_task,
                    "ares-sqlite-websocket-ticket-connect",
                )
                connection = await _await_task_completion(
                    open_task,
                    cancellation_baseline=open_cancellation_baseline,
                    caught_cancellations=open_cancellations,
                )
                if open_cancellations[0]:
                    await self._finish_websocket_ticket_cleanup(
                        connection.close(),
                        "cancelled-connect-close",
                        cancellation_baseline=open_cancellation_baseline,
                        caught_cancellations=open_cancellations,
                    )
                    connection = None
                    raise asyncio.CancelledError

                connection.row_factory = aiosqlite.Row
                await connection.execute("PRAGMA foreign_keys = ON")
                await connection.execute("BEGIN IMMEDIATE")
                transaction_started = True
                result = await operation(connection)

                commit_started = True
                commit_cancellation_baseline = _cancel_count()
                commit_task = asyncio.create_task(
                    self._commit_websocket_ticket_operation(connection),
                    name="ares-sqlite-websocket-ticket-commit",
                )
                await _await_task_completion(
                    commit_task,
                    cancellation_baseline=commit_cancellation_baseline,
                    caught_cancellations=commit_cancellations,
                )
                committed = True
                transaction_started = False
            except BaseException:
                if connection is not None and transaction_started and not committed:
                    cleanup_cancellation_baseline = _cancel_count()
                    cleanup_cancellations = [0]
                    cleanup_action = (
                        "rollback-after-commit-failure"
                        if commit_started
                        else "rollback-before-commit"
                    )
                    await self._finish_websocket_ticket_cleanup(
                        connection.rollback(),
                        cleanup_action,
                        cancellation_baseline=cleanup_cancellation_baseline,
                        caught_cancellations=cleanup_cancellations,
                    )
                raise
            finally:
                if connection is not None:
                    close_cancellation_baseline = (
                        commit_cancellation_baseline if committed else _cancel_count()
                    )
                    close_cancellations = (
                        commit_cancellations if committed else noncommit_close_cancellations
                    )
                    await self._finish_websocket_ticket_cleanup(
                        connection.close(),
                        "close",
                        cancellation_baseline=close_cancellation_baseline,
                        caught_cancellations=close_cancellations,
                    )

            if committed:
                _remove_suppressed_cancellations(
                    cancellation_baseline=commit_cancellation_baseline,
                    caught_cancellations=commit_cancellations[0],
                )
            elif noncommit_close_cancellations[0]:
                raise asyncio.CancelledError
            return result

    @staticmethod
    async def _purge_websocket_ticket_rows(
        connection: aiosqlite.Connection,
    ) -> int:
        async with connection.execute(
            "DELETE FROM websocket_tickets "
            "WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
        ) as cursor:
            canonical_count = max(0, cursor.rowcount)
        async with connection.execute(
            """DELETE FROM websocket_tickets
               WHERE strftime(
                   '%Y-%m-%dT%H:%M:%fZ', expires_at
               ) IS NULL
                  OR strftime(
                      '%Y-%m-%dT%H:%M:%fZ', expires_at
                  ) != expires_at"""
        ) as cursor:
            malformed_count = max(0, cursor.rowcount)
        return canonical_count + malformed_count

    async def issue_websocket_ticket(
        self,
        campaign_id: str,
        source: BearerTicketSource | ApiKeyTicketSource,
    ) -> tuple[str, int] | None:
        raw_ticket = generate_websocket_ticket()
        ticket_hash = hash_websocket_ticket(raw_ticket)

        async def _issue(
            connection: aiosqlite.Connection,
        ) -> tuple[str, int] | None:
            await self._purge_websocket_ticket_rows(connection)
            if isinstance(source, BearerTicketSource):
                source_expiry = format_sqlite_utc(source.expires_at)
                async with connection.execute(
                    """
                    INSERT INTO websocket_tickets (
                        ticket_hash, campaign_id, user_id, credential_kind,
                        bearer_subject, bearer_jti, bearer_expires_at,
                        bearer_family_id, bearer_auth_epoch,
                        api_key_id, required_scope, created_at, expires_at,
                        consumed_at
                    )
                    SELECT ?, c.id, u.id, 'bearer', u.username, ?, ?, ?, ?,
                           NULL, NULL,
                           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                           strftime(
                               '%Y-%m-%dT%H:%M:%fZ',
                               'now',
                               '+30 seconds'
                           ),
                           NULL
                    FROM users AS u
                    JOIN refresh_token_families AS f
                      ON f.id=? AND f.user_id=u.id
                    JOIN campaigns AS c ON c.id=?
                    WHERE u.id=?
                      AND u.username=?
                      AND u.is_active=1
                      AND u.auth_epoch=?
                      AND f.auth_epoch=u.auth_epoch
                      AND f.state='active'
                      AND f.revoked_at IS NULL
                      AND julianday(f.absolute_expires_at) > julianday('now')
                      AND u.role IN (
                          'team_lead', 'operator', 'recon', 'reporter'
                      )
                      AND julianday(?) > julianday('now')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM revoked_access_tokens AS rat
                          WHERE rat.jti=?
                      )
                      AND (
                          u.role='team_lead'
                          OR c.operator=u.username
                      )
                    """,
                    (
                        ticket_hash,
                        source.jti,
                        source_expiry,
                        source.family_id,
                        source.auth_epoch,
                        source.family_id,
                        campaign_id,
                        source.user_id,
                        source.subject,
                        source.auth_epoch,
                        source_expiry,
                        source.jti,
                    ),
                ) as cursor:
                    changed = cursor.rowcount
            elif isinstance(source, ApiKeyTicketSource):
                async with connection.execute(
                    """
                    INSERT INTO websocket_tickets (
                        ticket_hash, campaign_id, user_id, credential_kind,
                        bearer_subject, bearer_jti, bearer_expires_at,
                        bearer_family_id, bearer_auth_epoch,
                        api_key_id, required_scope, created_at, expires_at,
                        consumed_at
                    )
                    SELECT ?, c.id, u.id, 'api_key', NULL, NULL, NULL,
                           NULL, NULL,
                           ak.id, 'read',
                           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                           strftime(
                               '%Y-%m-%dT%H:%M:%fZ',
                               'now',
                               '+30 seconds'
                           ),
                           NULL
                    FROM api_keys AS ak
                    JOIN users AS u ON u.id=ak.user_id
                    JOIN campaigns AS c ON c.id=?
                    WHERE ak.id=?
                      AND u.id=?
                      AND ak.is_active=1
                      AND u.is_active=1
                      AND u.role IN (
                          'team_lead', 'operator', 'recon', 'reporter'
                      )
                      AND (
                          ak.expires_at IS NULL
                          OR (
                              julianday(ak.expires_at) IS NOT NULL
                              AND julianday(ak.expires_at) > julianday('now')
                          )
                      )
                      AND (
                          (' ' || replace(ak.scopes, ',', ' ') || ' ')
                              LIKE '% read %'
                          OR (' ' || replace(ak.scopes, ',', ' ') || ' ')
                              LIKE '% write %'
                          OR (' ' || replace(ak.scopes, ',', ' ') || ' ')
                              LIKE '% admin %'
                      )
                      AND (
                          u.role='team_lead'
                          OR c.operator=u.username
                      )
                    """,
                    (
                        ticket_hash,
                        campaign_id,
                        source.api_key_id,
                        source.user_id,
                    ),
                ) as cursor:
                    changed = cursor.rowcount
            else:
                raise TypeError("Unsupported WebSocket ticket source")
            if changed != 1:
                return None
            return raw_ticket, WEBSOCKET_TICKET_TTL_SECONDS

        return await self._run_websocket_ticket_transaction(_issue)

    async def consume_websocket_ticket(
        self,
        raw_ticket: str,
        campaign_id: str,
    ) -> ConsumedWebSocketTicket | None:
        if not is_canonical_websocket_ticket(raw_ticket):
            return None
        ticket_hash = hash_websocket_ticket(raw_ticket)

        async def _consume(
            connection: aiosqlite.Connection,
        ) -> ConsumedWebSocketTicket | None:
            async with connection.execute(
                """
                UPDATE websocket_tickets
                SET consumed_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE ticket_hash=?
                  AND campaign_id=?
                  AND consumed_at IS NULL
                  AND strftime(
                      '%Y-%m-%dT%H:%M:%fZ', expires_at
                  ) IS NOT NULL
                  AND strftime(
                      '%Y-%m-%dT%H:%M:%fZ', expires_at
                  )=expires_at
                  AND julianday(expires_at) > julianday('now')
                  AND (
                      credential_kind='api_key'
                      OR EXISTS (
                          SELECT 1
                          FROM users AS u
                          JOIN refresh_token_families AS f
                            ON f.id=websocket_tickets.bearer_family_id
                           AND f.user_id=u.id
                          WHERE u.id=websocket_tickets.user_id
                            AND u.username=websocket_tickets.bearer_subject
                            AND u.is_active=1
                            AND u.auth_epoch=
                                websocket_tickets.bearer_auth_epoch
                            AND f.auth_epoch=u.auth_epoch
                            AND f.state='active'
                            AND f.revoked_at IS NULL
                            AND julianday(f.absolute_expires_at) >
                                julianday('now')
                            AND julianday(
                                websocket_tickets.bearer_expires_at
                            ) > julianday('now')
                            AND NOT EXISTS (
                                SELECT 1
                                FROM revoked_access_tokens AS rat
                                WHERE rat.jti=
                                    websocket_tickets.bearer_jti
                            )
                      )
                  )
                """,
                (ticket_hash, campaign_id),
            ) as cursor:
                changed = cursor.rowcount
            if changed != 1:
                return None
            async with connection.execute(
                """
                SELECT campaign_id, user_id, credential_kind,
                       bearer_subject, bearer_jti, bearer_expires_at,
                       bearer_family_id, bearer_auth_epoch,
                       api_key_id, required_scope
                FROM websocket_tickets
                WHERE ticket_hash=?
                """,
                (ticket_hash,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                raise RuntimeError("Consumed WebSocket ticket row is missing")
            kind = WebSocketTicketCredentialKind(row["credential_kind"])
            bearer_expiry = (
                parse_sqlite_utc(row["bearer_expires_at"])
                if row["bearer_expires_at"] is not None
                else None
            )
            return ConsumedWebSocketTicket(
                campaign_id=row["campaign_id"],
                user_id=row["user_id"],
                credential_kind=kind,
                bearer_subject=row["bearer_subject"],
                bearer_jti=row["bearer_jti"],
                bearer_expires_at=bearer_expiry,
                bearer_family_id=row["bearer_family_id"],
                bearer_auth_epoch=row["bearer_auth_epoch"],
                api_key_id=row["api_key_id"],
                required_scope=row["required_scope"],
            )

        return await self._run_websocket_ticket_transaction(_consume)

    async def resolve_websocket_ticket_principal(
        self,
        handle: ConsumedWebSocketTicket,
    ) -> WebSocketTicketPrincipal | None:
        async with self._lifecycle_lock:
            connection = self._require_connected()
            if handle.credential_kind is WebSocketTicketCredentialKind.BEARER:
                if (
                    handle.bearer_subject is None
                    or handle.bearer_jti is None
                    or handle.bearer_expires_at is None
                    or handle.bearer_family_id is None
                    or handle.bearer_auth_epoch is None
                ):
                    return None
                source_expiry = format_sqlite_utc(handle.bearer_expires_at)
                async with connection.execute(
                    """
                    SELECT u.id, u.username, u.role
                    FROM users AS u
                    JOIN refresh_token_families AS f
                      ON f.id=? AND f.user_id=u.id
                    JOIN campaigns AS c ON c.id=?
                    WHERE u.id=?
                      AND u.username=?
                      AND u.is_active=1
                      AND u.auth_epoch=?
                      AND f.auth_epoch=u.auth_epoch
                      AND f.state='active'
                      AND f.revoked_at IS NULL
                      AND julianday(f.absolute_expires_at) > julianday('now')
                      AND u.role IN (
                          'team_lead', 'operator', 'recon', 'reporter'
                      )
                      AND julianday(?) > julianday('now')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM revoked_access_tokens AS rat
                          WHERE rat.jti=?
                      )
                      AND (
                          u.role='team_lead'
                          OR c.operator=u.username
                      )
                    """,
                    (
                        handle.bearer_family_id,
                        handle.campaign_id,
                        handle.user_id,
                        handle.bearer_subject,
                        handle.bearer_auth_epoch,
                        source_expiry,
                        handle.bearer_jti,
                    ),
                ) as cursor:
                    row = await cursor.fetchone()
                if row is None or not is_valid_websocket_principal_role(row["role"]):
                    return None
                return WebSocketTicketPrincipal(
                    user_id=row["id"],
                    username=row["username"],
                    role=row["role"],
                    credential_kind=WebSocketTicketCredentialKind.BEARER,
                )

            if (
                handle.credential_kind is not WebSocketTicketCredentialKind.API_KEY
                or handle.api_key_id is None
                or handle.required_scope != "read"
            ):
                return None
            async with connection.execute(
                """
                SELECT u.id, u.username, u.role, ak.id AS api_key_id,
                       ak.scopes
                FROM api_keys AS ak
                JOIN users AS u ON u.id=ak.user_id
                JOIN campaigns AS c ON c.id=?
                WHERE ak.id=?
                  AND u.id=?
                  AND ak.is_active=1
                  AND u.is_active=1
                  AND u.role IN (
                      'team_lead', 'operator', 'recon', 'reporter'
                  )
                  AND (
                      ak.expires_at IS NULL
                      OR (
                          julianday(ak.expires_at) IS NOT NULL
                          AND julianday(ak.expires_at) > julianday('now')
                      )
                  )
                  AND (
                      (' ' || replace(ak.scopes, ',', ' ') || ' ')
                          LIKE '% read %'
                      OR (' ' || replace(ak.scopes, ',', ' ') || ' ')
                          LIKE '% write %'
                      OR (' ' || replace(ak.scopes, ',', ' ') || ' ')
                          LIKE '% admin %'
                  )
                  AND (
                      u.role='team_lead'
                      OR c.operator=u.username
                  )
                """,
                (
                    handle.campaign_id,
                    handle.api_key_id,
                    handle.user_id,
                ),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None or not is_valid_websocket_principal_role(row["role"]):
                return None
            scopes = normalize_api_key_scopes(row["scopes"])
            if not set(scopes).intersection({"read", "write", "admin"}):
                return None
            return WebSocketTicketPrincipal(
                user_id=row["id"],
                username=row["username"],
                role=row["role"],
                credential_kind=WebSocketTicketCredentialKind.API_KEY,
                api_key_id=row["api_key_id"],
                api_key_scopes=scopes,
            )

    async def purge_expired_websocket_tickets(self) -> int:
        async def _purge(connection: aiosqlite.Connection) -> int:
            return await self._purge_websocket_ticket_rows(connection)

        return await self._run_websocket_ticket_transaction(_purge)

    # ── Refresh Tokens (v5) ───────────────────────────────────────────────────

    @staticmethod
    def _family_timestamps() -> tuple[str, str, str]:
        created = datetime.now(timezone.utc)
        expires = created + timedelta(days=FAMILY_ABSOLUTE_LIFETIME_DAYS)
        retain = expires + timedelta(days=FAMILY_RETENTION_DAYS)
        return (
            format_sqlite_utc(created),
            format_sqlite_utc(expires),
            format_sqlite_utc(retain),
        )

    async def _run_refresh_family_transaction(
        self,
        operation: Callable[[aiosqlite.Connection], Awaitable[_FamilyResultT]],
    ) -> _FamilyResultT:
        async with self._lifecycle_lock:
            self._require_connected()
            tx = await self._open_refresh_rotation_connection()
            tx.row_factory = aiosqlite.Row
            started = False
            committed = False
            cancellation_baseline = 0
            caught_cancellations = [0]
            try:
                await tx.execute("PRAGMA foreign_keys = ON")
                await tx.execute("BEGIN IMMEDIATE")
                started = True
                result = await operation(tx)
                cancellation_baseline = _cancel_count()
                commit_task = asyncio.create_task(
                    self._commit_refresh_rotation(tx),
                    name="ares-sqlite-family-commit",
                )
                await _await_task_completion(
                    commit_task,
                    cancellation_baseline=cancellation_baseline,
                    caught_cancellations=caught_cancellations,
                )
                committed = True
                started = False
            except BaseException:
                if started and not committed:
                    rollback_baseline = _cancel_count()
                    rollback_cancellations = [0]
                    await self._finish_refresh_rotation_cleanup(
                        tx.rollback(),
                        "family-rollback",
                        cancellation_baseline=rollback_baseline,
                        caught_cancellations=rollback_cancellations,
                    )
                raise
            finally:
                close_baseline = cancellation_baseline if committed else _cancel_count()
                close_cancellations = caught_cancellations if committed else [0]
                await self._finish_refresh_rotation_cleanup(
                    tx.close(),
                    "family-close",
                    cancellation_baseline=close_baseline,
                    caught_cancellations=close_cancellations,
                )
            if committed:
                _remove_suppressed_cancellations(
                    cancellation_baseline=cancellation_baseline,
                    caught_cancellations=caught_cancellations[0],
                )
            return result

    async def _insert_initial_family_token_with_expiry(
        self,
        tx: aiosqlite.Connection,
        *,
        user_id: str,
        auth_epoch: int,
    ) -> tuple[str, str, datetime]:
        family_id = generate_family_id()
        raw_token = generate_refresh_token()
        token_hash = hash_refresh_token(raw_token)
        created, expires, retain = self._family_timestamps()
        await tx.execute(
            "INSERT INTO refresh_token_families("
            "id,user_id,auth_epoch,state,created_at,absolute_expires_at,retain_until) "
            "VALUES(?,?,?,'active',?,?,?)",
            (family_id, user_id, auth_epoch, created, expires, retain),
        )
        await tx.execute(
            "INSERT INTO refresh_tokens("
            "id,user_id,is_revoked,expires_at,created_at,family_id,parent_id,"
            "generation,state,revoked_at) VALUES(?,?,0,?,?,?,NULL,0,'active',NULL)",
            (token_hash, user_id, expires, created, family_id),
        )
        return family_id, raw_token, parse_sqlite_utc(expires)

    async def _insert_initial_family_token(
        self,
        tx: aiosqlite.Connection,
        *,
        user_id: str,
        auth_epoch: int,
    ) -> tuple[str, str]:
        family_id, raw_token, _ = await self._insert_initial_family_token_with_expiry(
            tx,
            user_id=user_id,
            auth_epoch=auth_epoch,
        )
        return family_id, raw_token

    async def create_refresh_token(
        self, user_id: str, expires_days: int = FAMILY_ABSOLUTE_LIFETIME_DAYS
    ) -> str:
        if expires_days != FAMILY_ABSOLUTE_LIFETIME_DAYS:
            raise ValueError("refresh lifetime is fixed")

        async def _create(tx: aiosqlite.Connection) -> str:
            async with tx.execute(
                "SELECT auth_epoch FROM users WHERE id=? AND is_active=1",
                (user_id,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                raise ValueError("invalid refresh owner")
            _, raw_token = await self._insert_initial_family_token(
                tx, user_id=user_id, auth_epoch=int(row["auth_epoch"])
            )
            return raw_token

        return await self._run_refresh_family_transaction(_create)

    async def create_login_session(
        self,
        username: str,
        password: str,
        token_factory: AccessTokenFactory,
    ) -> SessionIssueResult:
        async def _login(tx: aiosqlite.Connection) -> SessionIssueResult:
            async with tx.execute(
                "SELECT id,username,hashed_password,role,is_active,auth_epoch "
                "FROM users WHERE username=?",
                (username,),
            ) as cursor:
                row = await cursor.fetchone()
            if (
                row is None
                or int(row["is_active"]) != 1
                or not verify_password(password, row["hashed_password"])
            ):
                return SessionIssueResult(SessionIssueStatus.INVALID)
            (
                family_id,
                raw_token,
                absolute_expiry,
            ) = await self._insert_initial_family_token_with_expiry(
                tx,
                user_id=row["id"],
                auth_epoch=int(row["auth_epoch"]),
            )
            access_token = token_factory(
                {
                    "sub": row["username"],
                    "sid": family_id,
                    "ver": int(row["auth_epoch"]),
                }
            )
            await tx.execute(
                "UPDATE users SET last_login=? WHERE id=?",
                (format_sqlite_utc(datetime.now(timezone.utc)), row["id"]),
            )
            await tx.execute(
                "INSERT INTO audit_log(actor,action,detail) VALUES("
                "'auth-system','login_family_created','')"
            )
            return SessionIssueResult(
                SessionIssueStatus.ISSUED,
                IssuedTokenSession(
                    access_token=access_token,
                    refresh_token=raw_token,
                    user_id=row["id"],
                    subject=row["username"],
                    family_id=family_id,
                    auth_epoch=int(row["auth_epoch"]),
                    absolute_expires_at=absolute_expiry,
                    refresh_generation=0,
                    role=row["role"],
                ),
            )

        return await self._run_refresh_family_transaction(_login)

    async def _legacy_create_refresh_token(self, user_id: str, expires_days: int = 30) -> str:
        import hashlib

        # Generate cryptographically strong random token
        raw_token = secrets.token_urlsafe(48)  # 384 bits — URL-safe, client sees this
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()  # stored in DB
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        await self._conn.execute(
            "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES(?,?,?)",
            (token_hash, user_id, expires_at),
        )
        await self._conn.commit()
        return raw_token  # client gets raw; DB stores only hash

    async def _open_refresh_rotation_connection(self) -> aiosqlite.Connection:
        return await aiosqlite.connect(
            self._db_path,
            uri=self._is_sqlite_uri,
            timeout=30.0,
        )

    async def _insert_refresh_successor(
        self,
        tx: aiosqlite.Connection,
        token_hash: str,
        user_id: str,
        expires_at: str,
    ) -> None:
        await tx.execute(
            "INSERT INTO refresh_tokens(id,user_id,expires_at) VALUES(?,?,?)",
            (token_hash, user_id, expires_at),
        )

    async def _insert_family_successor(
        self,
        tx: aiosqlite.Connection,
        *,
        token_hash: str,
        user_id: str,
        expires_at: str,
        created_at: str,
        family_id: str,
        parent_id: str,
        generation: int,
    ) -> None:
        await tx.execute(
            "INSERT INTO refresh_tokens("
            "id,user_id,is_revoked,expires_at,created_at,family_id,parent_id,"
            "generation,state,revoked_at) VALUES(?,?,0,?,?,?,?,?,'active',NULL)",
            (
                token_hash,
                user_id,
                expires_at,
                created_at,
                family_id,
                parent_id,
                generation,
            ),
        )

    async def _commit_refresh_rotation(
        self,
        tx: aiosqlite.Connection,
    ) -> None:
        await tx.commit()

    async def _finish_refresh_rotation_cleanup(
        self,
        operation: Awaitable[Any],
        action: str,
        *,
        cancellation_baseline: int,
        caught_cancellations: list[int],
    ) -> None:
        cleanup_task = asyncio.ensure_future(operation)
        self._name_owned_task(
            cleanup_task,
            f"ares-sqlite-refresh-{action}",
        )
        try:
            await _await_task_completion(
                cleanup_task,
                cancellation_baseline=cancellation_baseline,
                caught_cancellations=caught_cancellations,
            )
        except asyncio.CancelledError:
            raise
        except Exception as cleanup_error:
            logger.warning(
                "refresh_rotation_cleanup_failed",
                action=action,
                error_type=type(cleanup_error).__name__,
            )

    async def rotate_refresh_session(
        self,
        old_token: str,
        token_factory: AccessTokenFactory,
    ) -> RefreshRotationResult:
        old_hash = hash_refresh_token(old_token)

        async def _rotate(tx: aiosqlite.Connection) -> RefreshRotationResult:
            async with tx.execute(
                "SELECT rt.id,rt.user_id,rt.family_id,rt.generation,rt.state,"
                "rt.expires_at,f.state AS family_state,f.auth_epoch,"
                "f.absolute_expires_at,u.username,u.role,u.is_active,"
                "u.auth_epoch AS user_epoch FROM refresh_tokens AS rt "
                "JOIN refresh_token_families AS f "
                "ON f.id=rt.family_id AND f.user_id=rt.user_id "
                "JOIN users AS u ON u.id=rt.user_id WHERE rt.id=?",
                (old_hash,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return RefreshRotationResult(RefreshRotationStatus.INVALID)

            now_dt = datetime.now(timezone.utc)
            now = format_sqlite_utc(now_dt)
            if row["state"] != "active":
                if row["family_state"] == "active":
                    retain = format_sqlite_utc(
                        max(parse_sqlite_utc(row["absolute_expires_at"]), now_dt)
                        + timedelta(days=FAMILY_RETENTION_DAYS)
                    )
                    await tx.execute(
                        "UPDATE refresh_token_families SET state='revoked',"
                        "revoked_at=?,revoke_reason='replay',retain_until=? "
                        "WHERE id=? AND state='active'",
                        (now, retain, row["family_id"]),
                    )
                    await tx.execute(
                        "UPDATE refresh_tokens SET state='retired',is_revoked=1,"
                        "revoked_at=? WHERE family_id=? AND state='active'",
                        (now, row["family_id"]),
                    )
                    await tx.execute(
                        "INSERT INTO audit_log(actor,action,detail) VALUES("
                        "'auth-system','refresh_replay_family_revoked','')"
                    )
                return RefreshRotationResult(RefreshRotationStatus.REPLAYED)

            if (
                row["family_state"] != "active"
                or int(row["is_active"]) != 1
                or int(row["auth_epoch"]) != int(row["user_epoch"])
                or row["expires_at"] <= now
                or row["absolute_expires_at"] <= now
            ):
                return RefreshRotationResult(RefreshRotationStatus.INVALID)

            async with tx.execute(
                "UPDATE refresh_tokens SET state='consumed',is_revoked=1,used_at=? "
                "WHERE id=? AND state='active' AND is_revoked=0",
                (now, old_hash),
            ) as cursor:
                if cursor.rowcount != 1:
                    return RefreshRotationResult(RefreshRotationStatus.REPLAYED)

            raw_child = generate_refresh_token()
            child_hash = hash_refresh_token(raw_child)
            generation = int(row["generation"]) + 1
            await self._insert_family_successor(
                tx,
                token_hash=child_hash,
                user_id=row["user_id"],
                expires_at=row["absolute_expires_at"],
                created_at=now,
                family_id=row["family_id"],
                parent_id=old_hash,
                generation=generation,
            )
            access_token = token_factory(
                {
                    "sub": row["username"],
                    "sid": row["family_id"],
                    "ver": int(row["auth_epoch"]),
                }
            )
            await tx.execute(
                "INSERT INTO audit_log(actor,action,detail) VALUES("
                "'auth-system','refresh_rotated','')"
            )
            return RefreshRotationResult(
                RefreshRotationStatus.ROTATED,
                IssuedTokenSession(
                    access_token=access_token,
                    refresh_token=raw_child,
                    user_id=row["user_id"],
                    subject=row["username"],
                    family_id=row["family_id"],
                    auth_epoch=int(row["auth_epoch"]),
                    absolute_expires_at=parse_sqlite_utc(row["absolute_expires_at"]),
                    refresh_generation=generation,
                    role=row["role"],
                ),
            )

        return await self._run_refresh_family_transaction(_rotate)

    async def rotate_refresh_token(
        self, old_token: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        result = await self.rotate_refresh_session(old_token, lambda _: "compat-access")
        if result.status is not RefreshRotationStatus.ROTATED or result.session is None:
            return None, None
        return (
            {
                "id": result.session.user_id,
                "username": result.session.subject,
                "role": result.session.role,
                "family_id": result.session.family_id,
                "auth_epoch": result.session.auth_epoch,
            },
            result.session.refresh_token,
        )

    async def _legacy_rotate_refresh_token(
        self, old_token: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        async with self._lifecycle_lock:
            return await self._rotate_refresh_token_locked(old_token)

    async def _rotate_refresh_token_locked(
        self, old_token: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Rotate a token while lifecycle ownership keeps DB identity stable.

        Cancellation propagates before COMMIT. Once the protected COMMIT starts,
        cancellation may be delayed and suppressed so the committed successor can
        be returned after its dedicated connection is closed.
        """
        import hashlib

        self._require_connected()
        old_hash = hashlib.sha256(old_token.encode()).hexdigest()
        tx: aiosqlite.Connection | None = None
        transaction_started = False
        commit_started = False
        committed = False
        result: tuple[dict[str, Any] | None, str | None] = (None, None)
        commit_cancellation_baseline = 0
        commit_cancellations = [0]
        noncommit_close_cancellations = [0]
        try:
            open_cancellation_baseline = _cancel_count()
            open_cancellations = [0]
            open_task = asyncio.ensure_future(self._open_refresh_rotation_connection())
            self._name_owned_task(
                open_task,
                "ares-sqlite-refresh-connect",
            )
            tx = await _await_task_completion(
                open_task,
                cancellation_baseline=open_cancellation_baseline,
                caught_cancellations=open_cancellations,
            )
            if open_cancellations[0]:
                await self._finish_refresh_rotation_cleanup(
                    tx.close(),
                    "cancelled-connect-close",
                    cancellation_baseline=open_cancellation_baseline,
                    caught_cancellations=open_cancellations,
                )
                tx = None
                raise asyncio.CancelledError

            tx.row_factory = aiosqlite.Row
            await tx.execute("PRAGMA foreign_keys = ON")
            await tx.execute("BEGIN IMMEDIATE")
            transaction_started = True
            async with tx.execute(
                """SELECT rt.*, u.username, u.role, u.id as uid
                   FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id
                   WHERE rt.id=? AND rt.is_revoked=0
                   AND u.is_active=1
                   AND julianday(rt.expires_at) IS NOT NULL
                   AND julianday(rt.expires_at) > julianday('now')""",
                (old_hash,),
            ) as cur:
                row = await cur.fetchone()

            if not row:
                await tx.rollback()
                transaction_started = False
            else:
                async with tx.execute(
                    """UPDATE refresh_tokens
                       SET is_revoked=1, used_at=datetime('now')
                       WHERE id=? AND is_revoked=0
                       AND julianday(expires_at) IS NOT NULL
                       AND julianday(expires_at) > julianday('now')
                       AND EXISTS (
                           SELECT 1 FROM users u
                           WHERE u.id=refresh_tokens.user_id AND u.is_active=1
                       )""",
                    (old_hash,),
                ) as cur:
                    changed = cur.rowcount
                if changed != 1:
                    await tx.rollback()
                    transaction_started = False
                else:
                    row = dict(row)
                    new_raw = secrets.token_urlsafe(48)
                    new_hash = hashlib.sha256(new_raw.encode()).hexdigest()
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
                    await self._insert_refresh_successor(
                        tx,
                        new_hash,
                        row["uid"],
                        expires_at,
                    )
                    commit_started = True
                    commit_cancellation_baseline = _cancel_count()
                    commit_task = asyncio.create_task(
                        self._commit_refresh_rotation(tx),
                        name="ares-sqlite-refresh-commit",
                    )
                    await _await_task_completion(
                        commit_task,
                        cancellation_baseline=commit_cancellation_baseline,
                        caught_cancellations=commit_cancellations,
                    )
                    committed = True
                    transaction_started = False
                    user = {
                        "id": row["uid"],
                        "username": row["username"],
                        "role": row["role"],
                    }
                    result = (user, new_raw)
        except BaseException:
            if tx is not None and transaction_started and not committed:
                cleanup_cancellation_baseline = _cancel_count()
                cleanup_cancellations = [0]
                cleanup_action = (
                    "rollback_after_commit_failure" if commit_started else "rollback_before_commit"
                )
                await self._finish_refresh_rotation_cleanup(
                    tx.rollback(),
                    cleanup_action,
                    cancellation_baseline=cleanup_cancellation_baseline,
                    caught_cancellations=cleanup_cancellations,
                )
            raise
        finally:
            if tx is not None:
                close_cancellation_baseline = (
                    commit_cancellation_baseline if committed else _cancel_count()
                )
                close_cancellations = (
                    commit_cancellations if committed else noncommit_close_cancellations
                )
                await self._finish_refresh_rotation_cleanup(
                    tx.close(),
                    "close",
                    cancellation_baseline=close_cancellation_baseline,
                    caught_cancellations=close_cancellations,
                )

        if committed:
            _remove_suppressed_cancellations(
                cancellation_baseline=commit_cancellation_baseline,
                caught_cancellations=commit_cancellations[0],
            )
        elif noncommit_close_cancellations[0]:
            raise asyncio.CancelledError
        return result

    async def revoke_access_token(self, jti: str, user_id: str, expires_at: str) -> None:
        """Add access token jti to blacklist. Called on logout."""
        await self._conn.execute(
            "INSERT OR IGNORE INTO revoked_access_tokens (jti, user_id, expires_at) VALUES (?,?,?)",
            (jti, user_id, expires_at),
        )
        # Prune expired entries while we're here (low-cost housekeeping)
        await self._conn.execute(
            "DELETE FROM revoked_access_tokens WHERE expires_at < datetime('now')",
        )
        await self._conn.commit()

    async def is_access_token_revoked(self, jti: str) -> bool:
        """Return True if this jti has been explicitly revoked."""
        async with self._conn.execute(
            "SELECT 1 FROM revoked_access_tokens WHERE jti=?", (jti,)
        ) as cur:
            return await cur.fetchone() is not None

    @staticmethod
    async def _revoke_family_rows(
        tx: aiosqlite.Connection,
        *,
        user_id: str,
        reason: str,
        family_id: str | None = None,
    ) -> int:
        now_dt = datetime.now(timezone.utc)
        now = format_sqlite_utc(now_dt)
        if family_id is None:
            cursor = await tx.execute(
                "SELECT id,absolute_expires_at FROM refresh_token_families "
                "WHERE user_id=? AND state='active'",
                (user_id,),
            )
        else:
            cursor = await tx.execute(
                "SELECT id,absolute_expires_at FROM refresh_token_families "
                "WHERE user_id=? AND state='active' AND id=?",
                (user_id, family_id),
            )
        async with cursor:
            rows = await cursor.fetchall()
        for row in rows:
            retain = format_sqlite_utc(
                max(parse_sqlite_utc(row["absolute_expires_at"]), now_dt)
                + timedelta(days=FAMILY_RETENTION_DAYS)
            )
            await tx.execute(
                "UPDATE refresh_token_families SET state='revoked',revoked_at=?,"
                "revoke_reason=?,retain_until=? WHERE id=? AND state='active'",
                (now, reason, retain, row["id"]),
            )
            await tx.execute(
                "UPDATE refresh_tokens SET state='retired',is_revoked=1,revoked_at=? "
                "WHERE family_id=? AND state='active'",
                (now, row["id"]),
            )
        return len(rows)

    async def revoke_current_session(
        self,
        *,
        user_id: str,
        family_id: str,
        jti: str,
        expires_at: datetime,
    ) -> SessionRevocationResult:
        async def _revoke(tx: aiosqlite.Connection) -> SessionRevocationResult:
            async with tx.execute(
                "SELECT 1 FROM refresh_token_families WHERE id=? AND user_id=?",
                (family_id, user_id),
            ) as cursor:
                known = await cursor.fetchone() is not None
            if not known:
                return SessionRevocationResult(SessionRevocationStatus.INVALID)
            changed = await self._revoke_family_rows(
                tx,
                user_id=user_id,
                family_id=family_id,
                reason="logout_current",
            )
            await tx.execute(
                "INSERT OR IGNORE INTO revoked_access_tokens(jti,user_id,expires_at) VALUES(?,?,?)",
                (jti, user_id, format_sqlite_utc(expires_at)),
            )
            if changed:
                await tx.execute(
                    "INSERT INTO audit_log(actor,action,detail) VALUES("
                    "'auth-system','logout_current','')"
                )
                return SessionRevocationResult(SessionRevocationStatus.REVOKED)
            return SessionRevocationResult(SessionRevocationStatus.ALREADY_REVOKED)

        return await self._run_refresh_family_transaction(_revoke)

    async def revoke_refresh_cookie_session(
        self,
        raw_token: str,
    ) -> SessionRevocationResult:
        """Revoke the family identified only by a browser refresh cookie."""
        token_hash = hash_refresh_token(raw_token)

        async def _revoke(tx: aiosqlite.Connection) -> SessionRevocationResult:
            async with tx.execute(
                "SELECT rt.user_id,rt.family_id,rt.state,f.state AS family_state "
                "FROM refresh_tokens AS rt JOIN refresh_token_families AS f "
                "ON f.id=rt.family_id AND f.user_id=rt.user_id WHERE rt.id=?",
                (token_hash,),
            ) as cursor:
                row = await cursor.fetchone()
            if row is None:
                return SessionRevocationResult(SessionRevocationStatus.INVALID)
            if row["family_state"] != "active":
                return SessionRevocationResult(SessionRevocationStatus.ALREADY_REVOKED)
            reason = "logout_current" if row["state"] == "active" else "replay"
            changed = await self._revoke_family_rows(
                tx,
                user_id=row["user_id"],
                family_id=row["family_id"],
                reason=reason,
            )
            if changed:
                action = (
                    "logout_cookie_family_revoked"
                    if reason == "logout_current"
                    else "logout_cookie_replay_family_revoked"
                )
                await tx.execute(
                    "INSERT INTO audit_log(actor,action,detail) VALUES('auth-system',?,'')",
                    (action,),
                )
                return SessionRevocationResult(SessionRevocationStatus.REVOKED)
            return SessionRevocationResult(SessionRevocationStatus.ALREADY_REVOKED)

        return await self._run_refresh_family_transaction(_revoke)

    async def revoke_all_sessions(
        self,
        *,
        user_id: str,
        jti: str,
        expires_at: datetime,
    ) -> SessionRevocationResult:
        async def _revoke(tx: aiosqlite.Connection) -> SessionRevocationResult:
            async with tx.execute(
                "UPDATE users SET auth_epoch=auth_epoch+1 WHERE id=? AND is_active=1",
                (user_id,),
            ) as cursor:
                if cursor.rowcount != 1:
                    return SessionRevocationResult(SessionRevocationStatus.INVALID)
            await self._revoke_family_rows(tx, user_id=user_id, reason="logout_all")
            await tx.execute(
                "INSERT OR IGNORE INTO revoked_access_tokens(jti,user_id,expires_at) VALUES(?,?,?)",
                (jti, user_id, format_sqlite_utc(expires_at)),
            )
            await tx.execute(
                "INSERT INTO audit_log(actor,action,detail) VALUES('auth-system','logout_all','')"
            )
            return SessionRevocationResult(SessionRevocationStatus.REVOKED)

        return await self._run_refresh_family_transaction(_revoke)

    async def apply_user_security_event(
        self,
        *,
        user_id: str,
        reason: str,
        new_password_hash: str | None = None,
        new_role: str | None = None,
        is_active: bool | None = None,
    ) -> bool:
        if reason not in {"password_change", "password_reset", "role_change", "user_status_change"}:
            raise ValueError("invalid security event")

        async def _apply(tx: aiosqlite.Connection) -> bool:
            async with tx.execute(
                "UPDATE users SET auth_epoch=auth_epoch+1,"
                "hashed_password=COALESCE(?,hashed_password),"
                "role=COALESCE(?,role),is_active=COALESCE(?,is_active) "
                "WHERE id=?",
                (
                    new_password_hash,
                    new_role,
                    None if is_active is None else int(is_active),
                    user_id,
                ),
            ) as cursor:
                if cursor.rowcount != 1:
                    return False
            await self._revoke_family_rows(tx, user_id=user_id, reason=reason)
            await tx.execute(
                "INSERT INTO audit_log(actor,action,detail) VALUES('auth-system',?,'')",
                (reason,),
            )
            return True

        return await self._run_refresh_family_transaction(_apply)

    async def revoke_all_refresh_tokens(self, user_id: str) -> None:
        async def _revoke(tx: aiosqlite.Connection) -> None:
            await self._revoke_family_rows(tx, user_id=user_id, reason="operator_revoke")

        await self._run_refresh_family_transaction(_revoke)

    async def _legacy_revoke_all_refresh_tokens(self, user_id: str) -> None:
        await self._conn.execute(
            "UPDATE refresh_tokens SET is_revoked=1 WHERE user_id=?", (user_id,)
        )
        await self._conn.commit()

    async def save_bypass_outcome(
        self,
        technique_id: str,
        edr_vendor: str,
        edr_version: str,
        success: bool,
        campaign_id: str,
        notes: str = "",
    ) -> None:
        """Persist bypass technique outcome for cross-session learning."""
        import time as _time

        try:
            await self._conn.execute(
                """INSERT INTO bypass_outcomes
                   (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    technique_id,
                    edr_vendor,
                    edr_version,
                    int(success),
                    campaign_id,
                    notes[:500],
                    _time.time(),
                ),
            )
            await self._conn.commit()
        except Exception:
            # Table may not exist yet — create it
            await self._ensure_bypass_outcomes_table()
            await self._conn.execute(
                """INSERT INTO bypass_outcomes
                   (technique_id, edr_vendor, edr_version, success, campaign_id, notes, ts)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    technique_id,
                    edr_vendor,
                    edr_version,
                    int(success),
                    campaign_id,
                    notes[:500],
                    _time.time(),
                ),
            )
            await self._conn.commit()

    async def get_bypass_success_rate(
        self,
        technique_id: str,
        edr_vendor: str,
        min_samples: int = 3,
    ) -> float | None:
        """
        Return historical success rate for a bypass technique against an EDR vendor.
        Returns None if fewer than min_samples recorded.
        """
        import time as _time

        try:
            async with self._conn.execute(
                """SELECT COUNT(*) as total, COALESCE(SUM(success), 0) as successes
                   FROM bypass_outcomes
                   WHERE technique_id = ? AND edr_vendor = ?
                   AND ts > ?""",
                (technique_id, edr_vendor, _time.time() - 7_776_000),  # 90 days
            ) as cur:
                row = await cur.fetchone()
            if not row or row["total"] < min_samples:
                return None
            return round(row["successes"] / row["total"], 3)
        except Exception:
            return None

    async def _ensure_bypass_outcomes_table(self) -> None:
        """Create bypass_outcomes table if it doesn't exist."""
        await self._conn.execute(
            """CREATE TABLE IF NOT EXISTS bypass_outcomes (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               technique_id TEXT    NOT NULL,
               edr_vendor   TEXT    NOT NULL,
               edr_version  TEXT    DEFAULT '',
               success      INTEGER NOT NULL,
               campaign_id  TEXT    DEFAULT '',
               notes        TEXT    DEFAULT '',
               ts           REAL    NOT NULL
            )"""
        )
        await self._conn.commit()

    async def purge_expired_tokens(self) -> int:
        async with self._conn.execute(
            "DELETE FROM refresh_token_families WHERE julianday(retain_until) <= julianday('now')"
        ) as cur:
            n = cur.rowcount
        await self._conn.commit()
        await self.purge_expired_websocket_tickets()
        return n


# Backward-compat alias
Credential = DBCredential  # noqa
