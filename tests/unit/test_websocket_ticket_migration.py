"""Real SQLite migration and bootstrap proof for WebSocket ticket storage."""
from __future__ import annotations

import argparse
import asyncio
import importlib
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from alembic import command
from alembic.config import Config

from ares.db.database import AresDatabase
from ares.db.schema import SCHEMA_VERSION
from ares.db.websocket_tickets import ApiKeyTicketSource

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TICKET_TABLE = "websocket_tickets"
_TICKET_INDEX_NAMES = (
    "idx_ws_tickets_api_key",
    "idx_ws_tickets_campaign",
    "idx_ws_tickets_expires",
    "idx_ws_tickets_user",
)
_CHECK_NAMES = (
    "ck_ws_ticket_consumed_at",
    "ck_ws_ticket_created_at",
    "ck_ws_ticket_expires_at",
    "ck_ws_ticket_hash",
    "ck_ws_ticket_kind",
    "ck_ws_ticket_source_shape",
    "ck_ws_ticket_time_order",
)
_FOREIGN_KEY_NAMES = (
    "fk_ws_ticket_api_key",
    "fk_ws_ticket_campaign",
    "fk_ws_ticket_user",
)


@dataclass(frozen=True, slots=True)
class _ColumnContract:
    ordinal: int
    name: str
    logical_type: str
    nullable: bool
    default: str | None
    primary_key_position: int
    hidden: int


@dataclass(frozen=True, slots=True)
class _ForeignKeyContract:
    local_column: str
    target_table: str
    target_column: str
    on_update: str
    on_delete: str
    match: str


@dataclass(frozen=True, slots=True)
class _IndexContract:
    name: str
    unique: bool
    origin: str
    partial: bool
    columns: tuple[tuple[str, bool, str], ...]


@dataclass(frozen=True, slots=True)
class _ManagedPrimaryKeyIndexContract:
    unique: bool
    origin: str
    partial: bool
    structure: tuple[
        tuple[int, int, str | None, bool, str, bool],
        ...,
    ]
    schema_objects: tuple[tuple[str, str, bool], ...]


@dataclass(frozen=True, slots=True)
class _AttachedObjectContract:
    object_type: str
    name: str
    table_name: str
    definition: str | None


@dataclass(frozen=True, slots=True)
class _TicketContract:
    columns: tuple[_ColumnContract, ...]
    primary_key: tuple[str, ...]
    foreign_keys: tuple[_ForeignKeyContract, ...]
    checks: tuple[tuple[str, str], ...]
    indexes: tuple[_IndexContract, ...]
    managed_primary_key_indexes: tuple[
        _ManagedPrimaryKeyIndexContract,
        ...,
    ]
    attached_objects: tuple[_AttachedObjectContract, ...]
    named_constraints: tuple[str, ...]
    canonical_table: bool
    named_foreign_keys_bound: tuple[str, ...]


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


@contextmanager
def _temporary_database(label: str) -> Iterator[Path]:
    with TemporaryDirectory(prefix="ares-ws-ticket-migration-") as directory:
        yield Path(directory) / f"{label}.db"


def _alembic_config(path: Path) -> Config:
    url = f"sqlite:///{path.resolve().as_posix()}"
    config = Config(str(_REPO_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(_REPO_ROOT / "migrations"),
    )
    config.set_main_option("sqlalchemy.url", "sqlite:///unused.db")
    config.cmd_opts = argparse.Namespace(x=[f"db_url={url}"])
    return config


def _upgrade(path: Path, revision: str) -> None:
    try:
        command.upgrade(_alembic_config(path), revision)
    except Exception as exc:
        raise RuntimeError(
            "SQLite ticket migration failed "
            f"[upgrade: {type(exc).__name__}]"
        ) from None


def _downgrade(path: Path, revision: str) -> None:
    try:
        command.downgrade(_alembic_config(path), revision)
    except Exception as exc:
        raise RuntimeError(
            "SQLite ticket migration failed "
            f"[downgrade: {type(exc).__name__}]"
        ) from None


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _version(path: Path) -> str | None:
    connection = _connect(path)
    try:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='alembic_version'"
        ).fetchone()
        if exists is None:
            return None
        row = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        return str(row[0]) if row is not None else None
    finally:
        connection.close()


def _application_tables(path: Path) -> tuple[str, ...]:
    connection = _connect(path)
    try:
        return tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        )
    finally:
        connection.close()


def _compact_sql(value: str) -> str:
    compact: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            compact.append(character)
            if character == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    compact.append(value[index + 1])
                    index += 1
                else:
                    quote = None
        elif character in {"'", '"', "`"}:
            quote = character
            compact.append(character)
        elif character == "[":
            quote = "]"
            compact.append(character)
        elif not character.isspace():
            compact.append(character.lower())
        index += 1
    if quote is not None:
        raise RuntimeError("Malformed WebSocket ticket SQL")
    return "".join(compact)


def _parenthesized_sql(value: str, open_index: int) -> tuple[str, int]:
    depth = 0
    quote: str | None = None
    index = open_index
    while index < len(value):
        character = value[index]
        if quote is not None:
            if character == quote:
                if index + 1 < len(value) and value[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return value[open_index + 1:index], index
        index += 1
    raise RuntimeError("Malformed WebSocket ticket table definition")


def _named_checks(table_sql: str) -> tuple[tuple[str, str], ...]:
    checks: list[tuple[str, str]] = []
    pattern = re.compile(
        r"\bCONSTRAINT\s+[\"`\[]?([A-Za-z0-9_]+)[\"`\]]?"
        r"\s+CHECK\s*\(",
        re.IGNORECASE,
    )
    for match in pattern.finditer(table_sql):
        expression, _end = _parenthesized_sql(table_sql, match.end() - 1)
        checks.append((match.group(1), _compact_sql(expression)))
    return tuple(sorted(checks))


def _named_constraints(table_sql: str) -> tuple[str, ...]:
    names = re.findall(
        r"\bCONSTRAINT\s+[\"`\[]?([A-Za-z0-9_]+)[\"`\]]?",
        table_sql,
        flags=re.IGNORECASE,
    )
    return tuple(sorted(names))


def _named_foreign_keys_bound(table_sql: str) -> tuple[str, ...]:
    compact = _compact_sql(table_sql)
    expected = {
        "fk_ws_ticket_campaign": (
            "campaign_id",
            "campaigns",
            "id",
            True,
        ),
        "fk_ws_ticket_user": ("user_id", "users", "id", True),
        "fk_ws_ticket_api_key": (
            "api_key_id",
            "api_keys",
            "id",
            False,
        ),
    }
    bound: list[str] = []
    for name, (local, target, remote, required) in expected.items():
        update_action = "(?:onupdatenoaction)?"
        table_pattern = re.compile(
            f"constraint{name}foreignkey\\({local}\\)"
            f"references{target}\\({remote}\\)"
            f"{update_action}ondeletecascade"
        )
        nullable = "notnull" if required else "(?:notnull)?"
        inline_pattern = re.compile(
            f"{local}text{nullable}constraint{name}"
            f"references{target}\\({remote}\\)"
            f"{update_action}ondeletecascade"
        )
        if (
            table_pattern.search(compact) is not None
            or inline_pattern.search(compact) is not None
        ):
            bound.append(name)
    return tuple(sorted(bound))


def _ticket_contract(path: Path) -> _TicketContract | None:
    connection = _connect(path)
    try:
        table_row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name=?",
            (_TICKET_TABLE,),
        ).fetchone()
        if table_row is None:
            return None
        table_sql = str(table_row[0] or "")
        column_rows = connection.execute(
            f"PRAGMA table_xinfo({_TICKET_TABLE})"
        ).fetchall()
        columns = tuple(
            _ColumnContract(
                ordinal=int(row["cid"]),
                name=str(row["name"]),
                logical_type=str(row["type"]).upper(),
                nullable=not bool(row["notnull"]),
                default=(
                    None
                    if row["dflt_value"] is None
                    else _compact_sql(str(row["dflt_value"]))
                ),
                primary_key_position=int(row["pk"]),
                hidden=int(row["hidden"]),
            )
            for row in column_rows
        )
        primary_key = tuple(
            column.name
            for column in sorted(
                (item for item in columns if item.primary_key_position),
                key=lambda item: item.primary_key_position,
            )
        )
        foreign_keys = tuple(
            sorted(
                (
                    _ForeignKeyContract(
                        local_column=str(row["from"]),
                        target_table=str(row["table"]),
                        target_column=str(row["to"]),
                        on_update=str(row["on_update"]).upper(),
                        on_delete=str(row["on_delete"]).upper(),
                        match=str(row["match"]).upper(),
                    )
                    for row in connection.execute(
                        f"PRAGMA foreign_key_list({_TICKET_TABLE})"
                    )
                ),
                key=lambda item: item.local_column,
            )
        )
        indexes: list[_IndexContract] = []
        managed_primary_key_indexes: list[
            _ManagedPrimaryKeyIndexContract
        ] = []
        managed_primary_key_names: set[str] = set()
        for row in connection.execute(
            f"PRAGMA index_list({_TICKET_TABLE})"
        ):
            name = str(row["name"])
            index_details = tuple(
                (
                    int(detail["seqno"]),
                    int(detail["cid"]),
                    None
                    if detail["name"] is None
                    else str(detail["name"]),
                    bool(detail["desc"]),
                    str(detail["coll"]).upper(),
                    bool(detail["key"]),
                )
                for detail in connection.execute(
                    f"PRAGMA index_xinfo('{name}')"
                )
            )
            origin = str(row["origin"]).lower()
            if origin == "pk":
                managed_primary_key_names.add(name)
                schema_objects = tuple(
                    (
                        str(schema_row["type"]),
                        str(schema_row["tbl_name"]),
                        schema_row["sql"] is None,
                    )
                    for schema_row in connection.execute(
                        "SELECT type, tbl_name, sql "
                        "FROM sqlite_schema WHERE name=?",
                        (name,),
                    )
                )
                managed_primary_key_indexes.append(
                    _ManagedPrimaryKeyIndexContract(
                        unique=bool(row["unique"]),
                        origin=origin,
                        partial=bool(row["partial"]),
                        structure=index_details,
                        schema_objects=schema_objects,
                    )
                )
                continue
            indexes.append(
                _IndexContract(
                    name=name,
                    unique=bool(row["unique"]),
                    origin=origin,
                    partial=bool(row["partial"]),
                    columns=tuple(
                        (
                            str(detail[2]),
                            detail[3],
                            detail[4],
                        )
                        for detail in index_details
                        if detail[5]
                    ),
                )
            )
        compact_table = _compact_sql(table_sql)
        canonical_table = (
            (
                compact_table.startswith(
                    "createtablewebsocket_tickets("
                )
                or compact_table.startswith(
                    "createtableifnotexistswebsocket_tickets("
                )
            )
            and all(
                forbidden not in compact_table
                for forbidden in (
                    "withoutrowid",
                    "strict",
                    "collate",
                    "onconflict",
                    "deferrable",
                    "initiallydeferred",
                    "initiallyimmediate",
                )
            )
            and len(re.findall(r"\bCHECK\s*\(", table_sql, re.IGNORECASE))
            == len(_CHECK_NAMES)
        )
        attached_objects = tuple(
            _AttachedObjectContract(
                object_type=str(row["type"]),
                name=str(row["name"]),
                table_name=str(row["tbl_name"]),
                definition=(
                    None
                    if row["sql"] is None
                    else (
                        "ordinary-ticket-table"
                        if str(row["type"]) == "table"
                        and str(row["name"]) == _TICKET_TABLE
                        and str(row["tbl_name"]) == _TICKET_TABLE
                        else _compact_sql(str(row["sql"])).replace(
                            "createindexifnotexists",
                            "createindex",
                            1,
                        )
                    )
                ),
            )
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql "
                "FROM sqlite_schema WHERE tbl_name=? "
                "ORDER BY type, name",
                (_TICKET_TABLE,),
            )
            if not (
                str(row["type"]) == "index"
                and str(row["name"]) in managed_primary_key_names
            )
        )
        return _TicketContract(
            columns=columns,
            primary_key=primary_key,
            foreign_keys=foreign_keys,
            checks=_named_checks(table_sql),
            indexes=tuple(sorted(indexes, key=lambda item: item.name)),
            managed_primary_key_indexes=tuple(
                managed_primary_key_indexes
            ),
            attached_objects=attached_objects,
            named_constraints=_named_constraints(table_sql),
            canonical_table=canonical_table,
            named_foreign_keys_bound=_named_foreign_keys_bound(table_sql),
        )
    finally:
        connection.close()


def _expected_ticket_contract() -> _TicketContract:
    columns = (
        _ColumnContract(0, "ticket_hash", "TEXT", False, None, 1, 0),
        _ColumnContract(1, "campaign_id", "TEXT", False, None, 0, 0),
        _ColumnContract(2, "user_id", "TEXT", False, None, 0, 0),
        _ColumnContract(3, "credential_kind", "TEXT", False, None, 0, 0),
        _ColumnContract(4, "bearer_subject", "TEXT", True, None, 0, 0),
        _ColumnContract(5, "bearer_jti", "TEXT", True, None, 0, 0),
        _ColumnContract(6, "bearer_expires_at", "TEXT", True, None, 0, 0),
        _ColumnContract(7, "api_key_id", "TEXT", True, None, 0, 0),
        _ColumnContract(8, "required_scope", "TEXT", True, None, 0, 0),
        _ColumnContract(9, "created_at", "TEXT", False, None, 0, 0),
        _ColumnContract(10, "expires_at", "TEXT", False, None, 0, 0),
        _ColumnContract(11, "consumed_at", "TEXT", True, None, 0, 0),
    )
    checks = {
        "ck_ws_ticket_hash": (
            "length(ticket_hash)=64 "
            "AND ticket_hash NOT GLOB '*[^0-9a-f]*'"
        ),
        "ck_ws_ticket_kind": (
            "credential_kind IN ('bearer', 'api_key')"
        ),
        "ck_ws_ticket_created_at": (
            "strftime('%Y-%m-%dT%H:%M:%fZ', created_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at)=created_at"
        ),
        "ck_ws_ticket_expires_at": (
            "strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at)=expires_at"
        ),
        "ck_ws_ticket_consumed_at": (
            "consumed_at IS NULL OR ("
            "strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) IS NOT NULL "
            "AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at)=consumed_at)"
        ),
        "ck_ws_ticket_time_order": (
            "julianday(expires_at) > julianday(created_at) "
            "AND (consumed_at IS NULL "
            "OR julianday(consumed_at) < julianday(expires_at))"
        ),
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
                AND api_key_id IS NULL
                AND required_scope IS NULL
            )
            OR
            (
                credential_kind='api_key'
                AND bearer_subject IS NULL
                AND bearer_jti IS NULL
                AND bearer_expires_at IS NULL
                AND api_key_id IS NOT NULL
                AND length(trim(api_key_id)) > 0
                AND api_key_id=trim(api_key_id)
                AND required_scope='read'
            )
        """,
    }
    indexes = (
        _IndexContract(
            "idx_ws_tickets_api_key",
            False,
            "c",
            False,
            (("api_key_id", False, "BINARY"),),
        ),
        _IndexContract(
            "idx_ws_tickets_campaign",
            False,
            "c",
            False,
            (("campaign_id", False, "BINARY"),),
        ),
        _IndexContract(
            "idx_ws_tickets_expires",
            False,
            "c",
            False,
            (("expires_at", False, "BINARY"),),
        ),
        _IndexContract(
            "idx_ws_tickets_user",
            False,
            "c",
            False,
            (("user_id", False, "BINARY"),),
        ),
    )
    managed_primary_key_indexes = (
        _ManagedPrimaryKeyIndexContract(
            unique=True,
            origin="pk",
            partial=False,
            structure=(
                (0, 0, "ticket_hash", False, "BINARY", True),
                (1, -1, None, False, "BINARY", False),
            ),
            schema_objects=(("index", _TICKET_TABLE, True),),
        ),
    )
    attached_objects = (
        _AttachedObjectContract(
            "index",
            "idx_ws_tickets_api_key",
            _TICKET_TABLE,
            "createindexidx_ws_tickets_api_key"
            "onwebsocket_tickets(api_key_id)",
        ),
        _AttachedObjectContract(
            "index",
            "idx_ws_tickets_campaign",
            _TICKET_TABLE,
            "createindexidx_ws_tickets_campaign"
            "onwebsocket_tickets(campaign_id)",
        ),
        _AttachedObjectContract(
            "index",
            "idx_ws_tickets_expires",
            _TICKET_TABLE,
            "createindexidx_ws_tickets_expires"
            "onwebsocket_tickets(expires_at)",
        ),
        _AttachedObjectContract(
            "index",
            "idx_ws_tickets_user",
            _TICKET_TABLE,
            "createindexidx_ws_tickets_user"
            "onwebsocket_tickets(user_id)",
        ),
        _AttachedObjectContract(
            "table",
            _TICKET_TABLE,
            _TICKET_TABLE,
            "ordinary-ticket-table",
        ),
    )
    return _TicketContract(
        columns=columns,
        primary_key=("ticket_hash",),
        foreign_keys=(
            _ForeignKeyContract(
                "api_key_id",
                "api_keys",
                "id",
                "NO ACTION",
                "CASCADE",
                "NONE",
            ),
            _ForeignKeyContract(
                "campaign_id",
                "campaigns",
                "id",
                "NO ACTION",
                "CASCADE",
                "NONE",
            ),
            _ForeignKeyContract(
                "user_id",
                "users",
                "id",
                "NO ACTION",
                "CASCADE",
                "NONE",
            ),
        ),
        checks=tuple(
            sorted(
                (name, _compact_sql(expression))
                for name, expression in checks.items()
            )
        ),
        indexes=indexes,
        managed_primary_key_indexes=managed_primary_key_indexes,
        attached_objects=attached_objects,
        named_constraints=tuple(
            sorted(_CHECK_NAMES + _FOREIGN_KEY_NAMES)
        ),
        canonical_table=True,
        named_foreign_keys_bound=tuple(sorted(_FOREIGN_KEY_NAMES)),
    )


_EXPECTED_TICKET_CONTRACT = _expected_ticket_contract()


def _schema_snapshot(path: Path) -> tuple[tuple[str, str, str], ...]:
    connection = _connect(path)
    try:
        return tuple(
            (
                str(row["type"]),
                str(row["name"]),
                _compact_sql(str(row["sql"] or "")),
            )
            for row in connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' "
                "ORDER BY type, name"
            )
        )
    finally:
        connection.close()


def _complete_schema_snapshot(
    path: Path,
) -> tuple[tuple[str, str, str, str], ...]:
    connection = _connect(path)
    try:
        return tuple(
            (
                str(row["type"]),
                str(row["name"]),
                str(row["tbl_name"]),
                _compact_sql(str(row["sql"] or "")),
            )
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "ORDER BY type, name, tbl_name",
            )
        )
    finally:
        connection.close()


def _ticket_data_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    connection = _connect(path)
    try:
        return tuple(
            tuple(row)
            for row in connection.execute(
                """
                SELECT ticket_hash, campaign_id, user_id, credential_kind,
                       bearer_subject, bearer_jti, bearer_expires_at,
                       api_key_id, required_scope, created_at, expires_at,
                       consumed_at
                FROM websocket_tickets
                ORDER BY ticket_hash
                """
            )
        )
    finally:
        connection.close()


def _non_ticket_snapshot(path: Path) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        item
        for item in _schema_snapshot(path)
        if item[1] != _TICKET_TABLE
        and item[1] not in _TICKET_INDEX_NAMES
        and item[1] != "alembic_version"
    )


def _seed_parent_rows(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO users(
            id, username, hashed_password, role, is_active, created_by
        ) VALUES(?, ?, ?, ?, 1, ?)
        """,
        (
            "ticket-user",
            "ticket-user-name",
            "synthetic-password-hash",
            "operator",
            "system",
        ),
    )
    connection.execute(
        "INSERT INTO campaigns(id, name, operator) VALUES(?, ?, ?)",
        ("ticket-campaign", "Ticket campaign", "ticket-user-name"),
    )
    connection.execute(
        """
        INSERT INTO api_keys(
            id, user_id, name, key_hash, key_prefix, scopes, is_active
        ) VALUES(?, ?, ?, ?, ?, ?, 1)
        """,
        (
            "ticket-api-key",
            "ticket-user",
            "Ticket key",
            "0" * 64,
            "synthetic",
            "read",
        ),
    )
    connection.commit()


def _parent_row_count(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM users)
            + (SELECT COUNT(*) FROM campaigns)
            + (SELECT COUNT(*) FROM api_keys)
        """
    ).fetchone()
    return int(row[0]) if row is not None else -1


def _insert_bearer_ticket(
    connection: sqlite3.Connection,
    *,
    digest_character: str = "a",
    campaign_id: str = "ticket-campaign",
    credential_kind: str = "bearer",
    subject: str | None = "ticket-user-name",
    created_at: str = "2026-01-01T00:00:00.000Z",
    expires_at: str = "2026-01-01T00:00:30.000Z",
    consumed_at: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO websocket_tickets(
            ticket_hash, campaign_id, user_id, credential_kind,
            bearer_subject, bearer_jti, bearer_expires_at,
            api_key_id, required_scope, created_at, expires_at, consumed_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)
        """,
        (
            digest_character * 64,
            campaign_id,
            "ticket-user",
            credential_kind,
            subject,
            "synthetic-jti",
            "2026-01-01T00:05:00.000Z",
            created_at,
            expires_at,
            consumed_at,
        ),
    )


def _insert_api_key_ticket(
    connection: sqlite3.Connection,
    *,
    digest_character: str = "b",
    required_scope: str = "read",
) -> None:
    connection.execute(
        """
        INSERT INTO websocket_tickets(
            ticket_hash, campaign_id, user_id, credential_kind,
            bearer_subject, bearer_jti, bearer_expires_at,
            api_key_id, required_scope, created_at, expires_at, consumed_at
        ) VALUES(?, ?, ?, 'api_key', NULL, NULL, NULL, ?, ?, ?, ?, NULL)
        """,
        (
            digest_character * 64,
            "ticket-campaign",
            "ticket-user",
            "ticket-api-key",
            required_scope,
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:30.000Z",
        ),
    )


def _sqlite_rejects(
    connection: sqlite3.Connection,
    operation: Callable[[], None],
) -> bool:
    rejected = False
    try:
        operation()
    except sqlite3.IntegrityError:
        rejected = True
    connection.rollback()
    reusable_row = connection.execute("SELECT 1").fetchone()
    reusable = reusable_row is not None and int(reusable_row[0]) == 1
    return rejected and reusable


def _exercise_ticket_enforcement(path: Path) -> bool:
    connection = _connect(path)
    try:
        _seed_parent_rows(connection)
        _insert_bearer_ticket(connection)
        _insert_api_key_ticket(connection)
        connection.commit()
        valid_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM websocket_tickets"
            ).fetchone()[0]
        )
        cases = (
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="x",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="c",
                credential_kind="unknown",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="d",
                subject="",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="e",
                campaign_id="missing-campaign",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="f",
                created_at="2026-01-01 00:00:00",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="1",
                expires_at="2025-12-31T23:59:59.000Z",
            ),
            lambda: _insert_bearer_ticket(
                connection,
                digest_character="2",
                consumed_at="2026-01-01T00:00:30.000Z",
            ),
            lambda: _insert_api_key_ticket(
                connection,
                digest_character="3",
                required_scope="write",
            ),
        )
        rejected = tuple(_sqlite_rejects(connection, case) for case in cases)
        unchanged_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM websocket_tickets"
            ).fetchone()[0]
        )
        connection.execute(
            "DELETE FROM api_keys WHERE id=?",
            ("ticket-api-key",),
        )
        connection.commit()
        api_key_ticket_removed = (
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM websocket_tickets "
                    "WHERE credential_kind='api_key'"
                ).fetchone()[0]
            )
            == 0
        )
        return (
            valid_count == 2
            and all(rejected)
            and unchanged_count == 2
            and api_key_ticket_removed
        )
    finally:
        connection.close()


def _replace_named_check(
    table_sql: str,
    name: str,
    replacement: str | None,
) -> str:
    match = re.search(
        rf"\bCONSTRAINT\s+{re.escape(name)}\s+CHECK\s*\(",
        table_sql,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise RuntimeError("Ticket mutation target was absent")
    _expression, close_index = _parenthesized_sql(
        table_sql,
        match.end() - 1,
    )
    if replacement is None:
        return table_sql[:match.start()] + table_sql[close_index + 1:]
    return (
        table_sql[:match.start()]
        + f"CONSTRAINT {name} CHECK ({replacement})"
        + table_sql[close_index + 1:]
    )


def _replace_required(
    value: str,
    pattern: str,
    replacement: str,
) -> str:
    updated, count = re.subn(
        pattern,
        replacement,
        value,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if count != 1:
        raise RuntimeError("Ticket mutation target was absent")
    return updated


def _remove_required_scope_column(table_sql: str) -> str:
    updated = _replace_required(
        table_sql,
        r"\brequired_scope\s+TEXT\s*,",
        "",
    )
    match = re.search(
        r"\bCONSTRAINT\s+ck_ws_ticket_source_shape\s+CHECK\s*\(",
        updated,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise RuntimeError("Ticket mutation target was absent")
    expression, _close_index = _parenthesized_sql(
        updated,
        match.end() - 1,
    )
    expression = re.sub(
        r"\s+AND\s+required_scope\s+IS\s+NULL",
        "",
        expression,
        flags=re.IGNORECASE,
    )
    expression = re.sub(
        r"\s+AND\s+required_scope\s*=\s*'read'",
        "",
        expression,
        flags=re.IGNORECASE,
    )
    return _replace_named_check(
        updated,
        "ck_ws_ticket_source_shape",
        expression,
    )


def _rebuild_ticket_table(
    path: Path,
    transform: Callable[[str], str],
) -> None:
    connection = _connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        table_row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name=?",
            (_TICKET_TABLE,),
        ).fetchone()
        if table_row is None:
            raise RuntimeError("Ticket mutation table was absent")
        table_sql = str(table_row[0])
        index_sql = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type='index' AND tbl_name=? AND sql IS NOT NULL "
                "ORDER BY name",
                (_TICKET_TABLE,),
            )
        )
        mutated_sql = transform(table_sql)
        if mutated_sql == table_sql:
            raise RuntimeError("Ticket mutation did not change the catalog")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "ALTER TABLE websocket_tickets "
            "RENAME TO websocket_tickets_original"
        )
        connection.execute(mutated_sql)
        connection.execute("DROP TABLE websocket_tickets_original")
        for statement in index_sql:
            connection.execute(statement)
        connection.commit()
        connection.execute("PRAGMA foreign_keys=ON")
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _mutate_ticket_schema(path: Path, variant: str) -> None:
    if variant == "hash-glob-class":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_named_check(
                sql,
                "ck_ws_ticket_hash",
                "length(ticket_hash)=64 "
                "AND ticket_hash NOT GLOB '*[^0-9a-e]*'",
            ),
        )
        return
    if variant == "check-body":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_named_check(
                sql,
                "ck_ws_ticket_kind",
                "credential_kind IN ('bearer', 'api_key', 'unknown')",
            ),
        )
        return
    if variant == "missing-check":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_named_check(
                sql,
                "ck_ws_ticket_kind",
                None,
            ),
        )
        return
    if variant == "extra-check":
        _rebuild_ticket_table(
            path,
            lambda sql: sql.rstrip()[:-1]
            + ", CONSTRAINT ck_ws_ticket_extra CHECK (1=1))",
        )
        return
    if variant == "missing-column":
        _rebuild_ticket_table(path, _remove_required_scope_column)
        return
    if variant == "extra-column":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(consumed_at\s+TEXT\s*,)",
                r"\1 unexpected_state TEXT,",
            ),
        )
        return
    if variant == "hidden-column":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(consumed_at\s+TEXT\s*,)",
                (
                    r"\1 unexpected_generated TEXT "
                    "GENERATED ALWAYS AS (credential_kind) VIRTUAL,"
                ),
            ),
        )
        return
    if variant == "quoted-table":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"^CREATE\s+TABLE\s+websocket_tickets",
                'CREATE TABLE "websocket_tickets"',
            ),
        )
        return
    if variant == "quoted-check-identifier":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_named_check(
                sql,
                "ck_ws_ticket_kind",
                '"credential_kind" IN (\'bearer\', \'api_key\')',
            ),
        )
        return
    if variant == "wrong-pk":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(ticket_hash\s+TEXT\s+NOT\s+NULL)\s+PRIMARY\s+KEY",
                r"\1",
            ),
        )
        return
    if variant == "wrong-fk-target":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+)campaigns(\s*\(\s*id\s*\))",
                r"\1users\2",
            ),
        )
        return
    if variant == "wrong-fk-action":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+campaigns\s*\(\s*id\s*\)\s+"
                r"ON\s+DELETE\s+)CASCADE",
                r"\1RESTRICT",
            ),
        )
        return
    if variant == "wrong-fk-update":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+campaigns\s*\(\s*id\s*\)\s+)"
                r"ON\s+DELETE\s+CASCADE",
                r"\1ON UPDATE CASCADE ON DELETE CASCADE",
            ),
        )
        return
    if variant == "wrong-type":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(bearer_expires_at\s+)TEXT",
                r"\1BLOB",
            ),
        )
        return
    if variant == "wrong-default":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(created_at\s+TEXT\s+NOT\s+NULL)",
                r"\1 DEFAULT '2026-01-01T00:00:00.000Z'",
            ),
        )
        return
    if variant == "wrong-nullability":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(created_at\s+TEXT)\s+NOT\s+NULL",
                r"\1",
            ),
        )
        return
    if variant == "collation":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(bearer_subject\s+TEXT)",
                r"\1 COLLATE NOCASE",
            ),
        )
        return
    if variant == "conflict-policy":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(ticket_hash\s+TEXT\s+NOT\s+NULL\s+PRIMARY\s+KEY)",
                r"\1 ON CONFLICT REPLACE",
            ),
        )
        return
    if variant == "deferred-fk":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+campaigns\s*\(\s*id\s*\)\s+"
                r"ON\s+DELETE\s+CASCADE)",
                r"\1 DEFERRABLE INITIALLY DEFERRED",
            ),
        )
        return
    if variant == "immediate-fk":
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+campaigns\s*\(\s*id\s*\)\s+"
                r"ON\s+DELETE\s+CASCADE)",
                r"\1 DEFERRABLE INITIALLY IMMEDIATE",
            ),
        )
        return

    connection = _connect(path)
    try:
        if variant == "missing-index":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
        elif variant == "wrong-index-column":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(user_id)"
            )
        elif variant == "wrong-index-order":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(user_id, expires_at)"
            )
        elif variant == "wrong-index-uniqueness":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE UNIQUE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(expires_at)"
            )
        elif variant == "duplicate-index":
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires_duplicate "
                "ON websocket_tickets(expires_at)"
            )
        elif variant == "extra-index":
            connection.execute(
                "CREATE INDEX idx_ws_tickets_extra "
                "ON websocket_tickets(credential_kind)"
            )
        elif variant == "partial-index":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(expires_at) "
                "WHERE consumed_at IS NULL"
            )
        elif variant == "expression-index":
            connection.execute("DROP INDEX idx_ws_tickets_user")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_user "
                "ON websocket_tickets(lower(user_id))"
            )
        elif variant == "consumption-reset-trigger":
            connection.execute(
                """
                CREATE TRIGGER ws_ticket_restore_consumed
                AFTER UPDATE OF consumed_at ON websocket_tickets
                WHEN NEW.consumed_at IS NOT NULL
                BEGIN
                    UPDATE websocket_tickets
                    SET consumed_at=NULL
                    WHERE ticket_hash=NEW.ticket_hash;
                END
                """
            )
        elif variant == "unexpected-insert-trigger":
            connection.execute(
                """
                CREATE TRIGGER ws_ticket_unexpected_insert
                AFTER INSERT ON websocket_tickets
                BEGIN
                    SELECT 1;
                END
                """
            )
        else:
            raise RuntimeError("Unknown ticket schema mutation")
        connection.commit()
    finally:
        connection.close()


async def _runtime_bootstrap(path: Path) -> bool:
    uri = f"file:{path.resolve().as_posix()}?mode=rwc"
    database = AresDatabase(uri)
    await database.connect()
    try:
        repeated = await database.connect()
        return repeated is database
    finally:
        await database.close()


def test_migration_head_is_real_empty_base_to_0007() -> None:
    with _temporary_database("empty-head") as path:
        initially_empty = _application_tables(path) == ()
        initial_revision_absent = _version(path) is None
        _upgrade(path, "0007")
        revision_is_current = _version(path) == "0007"
        exact_contract = _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
        enforcement_holds = _exercise_ticket_enforcement(path)

        _require_fixed(
            initially_empty and initial_revision_absent,
            "fresh migration database was not empty",
        )
        _require_fixed(SCHEMA_VERSION == 7, "SQLite schema version is not seven")
        _require_fixed(revision_is_current, "Alembic head is not revision 0007")
        _require_fixed(
            exact_contract,
            "fresh revision 0007 ticket fingerprint diverged",
        )
        _require_fixed(
            enforcement_holds,
            "fresh revision 0007 enforcement diverged",
        )


def test_sqlite_0006_to_0007_to_0006_to_0007_preserves_parent_data() -> None:
    with _temporary_database("round-trip") as path:
        _upgrade(path, "0006")
        parent_before = _non_ticket_snapshot(path)
        connection = _connect(path)
        try:
            _seed_parent_rows(connection)
            parent_count_before = _parent_row_count(connection)
        finally:
            connection.close()

        _upgrade(path, "0007")
        upgraded_exact = _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
        connection = _connect(path)
        try:
            _insert_bearer_ticket(connection)
            connection.commit()
        finally:
            connection.close()

        _downgrade(path, "0006")
        parent_after = _non_ticket_snapshot(path)
        connection = _connect(path)
        try:
            parent_count_after = _parent_row_count(connection)
            ticket_objects_absent = (
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master "
                    "WHERE name=? OR name IN (?, ?, ?, ?)",
                    (_TICKET_TABLE, *_TICKET_INDEX_NAMES),
                ).fetchone()[0]
                == 0
            )
        finally:
            connection.close()
        downgraded_exact = (
            _version(path) == "0006"
            and parent_after == parent_before
            and parent_count_after == parent_count_before
            and ticket_objects_absent
        )

        _upgrade(path, "0007")
        reupgraded_exact = (
            _version(path) == "0007"
            and _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
        )
        connection = _connect(path)
        try:
            final_parent_count = _parent_row_count(connection)
        finally:
            connection.close()

        _require_fixed(upgraded_exact, "revision 0007 upgrade was incomplete")
        _require_fixed(
            downgraded_exact,
            "revision 0007 downgrade changed parent-owned state",
        )
        _require_fixed(
            reupgraded_exact and final_parent_count == parent_count_before,
            "revision 0007 re-upgrade did not converge",
        )


def test_runtime_bootstrap_and_alembic_have_exact_ticket_parity() -> None:
    with _temporary_database("migration") as migration_path:
        with _temporary_database("runtime") as runtime_path:
            _upgrade(migration_path, "0007")
            repeated_is_stable = asyncio.run(
                _runtime_bootstrap(runtime_path)
            )
            migration_contract = _ticket_contract(migration_path)
            runtime_contract = _ticket_contract(runtime_path)
            both_exact = (
                migration_contract == _EXPECTED_TICKET_CONTRACT
                and runtime_contract == _EXPECTED_TICKET_CONTRACT
                and migration_contract == runtime_contract
            )

            _require_fixed(
                both_exact,
                "runtime and migration ticket fingerprints diverged",
            )
            _require_fixed(
                repeated_is_stable,
                "repeated runtime initialization was not stable",
            )


@pytest.mark.asyncio
async def test_runtime_rejects_consumption_reset_trigger_and_recovers() -> None:
    with _temporary_database("consumption-reset-trigger") as path:
        await _runtime_bootstrap(path)
        connection = _connect(path)
        try:
            _seed_parent_rows(connection)
            _insert_bearer_ticket(
                connection,
                digest_character="c",
                expires_at="2099-01-01T00:00:30.000Z",
            )
            connection.commit()
        finally:
            connection.close()
        _mutate_ticket_schema(path, "consumption-reset-trigger")

        connection = _connect(path)
        try:
            first_cursor = connection.execute(
                """
                UPDATE websocket_tickets
                SET consumed_at=strftime(
                    '%Y-%m-%dT%H:%M:%fZ', 'now'
                )
                WHERE ticket_hash=?
                  AND consumed_at IS NULL
                  AND julianday(expires_at) > julianday('now')
                """,
                ("c" * 64,),
            )
            first_changed = first_cursor.rowcount
            second_cursor = connection.execute(
                """
                UPDATE websocket_tickets
                SET consumed_at=strftime(
                    '%Y-%m-%dT%H:%M:%fZ', 'now'
                )
                WHERE ticket_hash=?
                  AND consumed_at IS NULL
                  AND julianday(expires_at) > julianday('now')
                """,
                ("c" * 64,),
            )
            second_changed = second_cursor.rowcount
            consumed_row = connection.execute(
                "SELECT consumed_at IS NULL FROM websocket_tickets "
                "WHERE ticket_hash=?",
                ("c" * 64,),
            ).fetchone()
            connection.commit()
        finally:
            connection.close()
        trigger_permits_replay = (
            first_changed == 1
            and second_changed == 1
            and consumed_row is not None
            and bool(consumed_row[0])
        )
        independent_oracle_rejects = (
            _ticket_contract(path) != _EXPECTED_TICKET_CONTRACT
        )
        catalog_before = _complete_schema_snapshot(path)
        data_before = _ticket_data_snapshot(path)

        database = AresDatabase(
            f"file:{path.resolve().as_posix()}?mode=rwc"
        )
        failure_type: type[BaseException] | None = None
        failure_message_fixed = False
        try:
            await database.connect()
        except Exception as exc:
            failure_type = type(exc)
            failure_message_fixed = (
                str(exc) == "Incompatible WebSocket ticket schema"
            )
        finally:
            await database.close()

        catalog_after = _complete_schema_snapshot(path)
        data_after = _ticket_data_snapshot(path)
        connection = _connect(path)
        try:
            trigger_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema "
                    "WHERE type='trigger' AND tbl_name=?",
                    (_TICKET_TABLE,),
                ).fetchone()[0]
            )
            connection.execute(
                "DROP TRIGGER ws_ticket_restore_consumed"
            )
            connection.commit()
        finally:
            connection.close()
        contract_recovers = (
            _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
        )

        recovered = AresDatabase(
            f"file:{path.resolve().as_posix()}?mode=rwc"
        )
        await recovered.connect()
        try:
            issued = await recovered.issue_websocket_ticket(
                "ticket-campaign",
                ApiKeyTicketSource(
                    user_id="ticket-user",
                    api_key_id="ticket-api-key",
                ),
            )
            if issued is None:
                pytest.fail(
                    "ticket issue failed after trigger removal",
                    pytrace=False,
                )
            raw_ticket, _ttl = issued
            first_handle = await recovered.consume_websocket_ticket(
                raw_ticket,
                "ticket-campaign",
            )
            second_handle = await recovered.consume_websocket_ticket(
                raw_ticket,
                "ticket-campaign",
            )
            ordinary_single_use = (
                first_handle is not None and second_handle is None
            )
        finally:
            await recovered.close()

        _require_fixed(
            trigger_permits_replay and independent_oracle_rejects,
            "consumption reset trigger was not security-authentic",
        )
        _require_fixed(
            failure_type is RuntimeError and failure_message_fixed,
            "consumption reset trigger was not rejected safely",
        )
        _require_fixed(
            catalog_before == catalog_after
            and data_before == data_after
            and trigger_count == 1,
            "trigger rejection changed ticket catalog or data",
        )
        _require_fixed(
            contract_recovers and ordinary_single_use,
            "trigger removal did not restore one-time consumption",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    [
        "hash-glob-class",
        "check-body",
        "missing-check",
        "extra-check",
        "missing-column",
        "extra-column",
        "hidden-column",
        "quoted-table",
        "quoted-check-identifier",
        "wrong-pk",
        "wrong-fk-target",
        "wrong-fk-action",
        "wrong-fk-update",
        "wrong-type",
        "wrong-default",
        "wrong-nullability",
        "collation",
        "conflict-policy",
        "deferred-fk",
        "immediate-fk",
        "missing-index",
        "wrong-index-column",
        "wrong-index-order",
        "wrong-index-uniqueness",
        "duplicate-index",
        "extra-index",
        "partial-index",
        "expression-index",
        "consumption-reset-trigger",
        "unexpected-insert-trigger",
    ],
)
async def test_near_compatible_runtime_schema_is_rejected_without_mutation(
    variant: str,
) -> None:
    with _temporary_database(f"mutation-{variant}") as path:
        await _runtime_bootstrap(path)
        _mutate_ticket_schema(path, variant)
        before = _schema_snapshot(path)
        database = AresDatabase(
            f"file:{path.resolve().as_posix()}?mode=rwc"
        )
        failure_type: type[BaseException] | None = None
        failure_message_fixed = False
        try:
            await database.connect()
        except Exception as exc:
            failure_type = type(exc)
            failure_message_fixed = (
                str(exc) == "Incompatible WebSocket ticket schema"
            )
        finally:
            await database.close()
        after = _schema_snapshot(path)

        _require_fixed(
            failure_type is RuntimeError and failure_message_fixed,
            "incompatible ticket schema was not rejected safely",
        )
        _require_fixed(
            before == after,
            "failed ticket schema validation mutated the catalog",
        )


@pytest.mark.asyncio
async def test_partial_runtime_schema_is_rejected_without_mutation() -> None:
    with _temporary_database("partial") as path:
        connection = _connect(path)
        try:
            connection.execute(
                "CREATE TABLE websocket_tickets("
                "ticket_hash TEXT PRIMARY KEY)"
            )
            connection.commit()
        finally:
            connection.close()
        before = _schema_snapshot(path)
        database = AresDatabase(
            f"file:{path.resolve().as_posix()}?mode=rwc"
        )
        failure_type: type[BaseException] | None = None
        failure_message_fixed = False
        try:
            await database.connect()
        except Exception as exc:
            failure_type = type(exc)
            failure_message_fixed = (
                str(exc) == "Incompatible WebSocket ticket schema"
            )
        finally:
            await database.close()
        after = _schema_snapshot(path)

        _require_fixed(
            failure_type is RuntimeError and failure_message_fixed,
            "partial ticket schema was not rejected safely",
        )
        _require_fixed(
            before == after,
            "partial ticket rejection mutated the catalog",
        )


@pytest.mark.asyncio
async def test_explicit_no_action_fk_remains_semantically_equivalent() -> None:
    with _temporary_database("explicit-no-action") as path:
        await _runtime_bootstrap(path)
        _rebuild_ticket_table(
            path,
            lambda sql: _replace_required(
                sql,
                r"(CONSTRAINT\s+fk_ws_ticket_campaign\s+"
                r"REFERENCES\s+campaigns\s*\(\s*id\s*\)\s+)"
                r"ON\s+DELETE\s+CASCADE",
                r"\1ON UPDATE NO ACTION ON DELETE CASCADE",
            ),
        )
        before_is_exact = (
            _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
        )
        database = AresDatabase(
            f"file:{path.resolve().as_posix()}?mode=rwc"
        )
        await database.connect()
        try:
            after_is_exact = (
                _ticket_contract(path) == _EXPECTED_TICKET_CONTRACT
            )
        finally:
            await database.close()

        _require_fixed(
            before_is_exact and after_is_exact,
            "explicit NO ACTION changed the logical ticket contract",
        )


def test_revision_0007_rejects_an_unsupported_dialect() -> None:
    migration = importlib.import_module(
        "migrations.versions.0007_add_websocket_tickets"
    )
    failure_type: type[BaseException] | None = None
    failure_message_fixed = False
    try:
        migration._timestamp_type("unsupported")
    except Exception as exc:
        failure_type = type(exc)
        failure_message_fixed = (
            str(exc) == "Unsupported WebSocket ticket migration dialect"
        )
    _require_fixed(
        failure_type is RuntimeError and failure_message_fixed,
        "revision 0007 accepted an unsupported dialect",
    )
