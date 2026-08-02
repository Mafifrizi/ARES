"""SQLite and pure-contract coverage for one-time WebSocket tickets."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import sqlite3
import threading
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import aiosqlite
import pytest

import ares.db.database as database_module
from ares.db.database import AresDatabase
from ares.db.websocket_tickets import (
    WEBSOCKET_TICKET_TTL_SECONDS,
    ApiKeyTicketSource,
    BearerTicketSource,
    ConsumedWebSocketTicket,
    WebSocketTicketCredentialKind,
    WebSocketTicketPrincipal,
    generate_websocket_ticket,
    hash_websocket_ticket,
    is_canonical_websocket_ticket,
)


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


async def _connected_database(path: Path | str) -> AresDatabase:
    database = AresDatabase(str(path))
    await database.connect()
    return database


async def _connected_raw_database(path: Path | str) -> AresDatabase:
    database = AresDatabase(str(path))

    async def migrations_unavailable() -> bool:
        return False

    database._run_alembic_migrations = migrations_unavailable  # type: ignore[method-assign]
    await database.connect()
    return database


async def _seed_identity(
    database: AresDatabase,
    *,
    role: str = "operator",
    scopes: str = "read",
) -> tuple[str, str, str, str, str]:
    username = f"ticket_user_{uuid4().hex}"
    original_info = database_module.logger.info

    def suppress_user_created(
        event: str,
        *args: object,
        **values: object,
    ) -> Any:
        if event == "user_created":
            return None
        return original_info(event, *args, **values)

    with patch.object(
        database_module.logger,
        "info",
        suppress_user_created,
    ):
        user_id = await database.create_user(
            username,
            "synthetic-test-password",
            role,
        )
    campaign_id = f"campaign-{uuid4().hex}"
    other_campaign_id = f"campaign-{uuid4().hex}"
    connection = database._require_connected()
    await connection.executemany(
        """
        INSERT INTO campaigns(id, name, operator)
        VALUES(?, ?, ?)
        """,
        (
            (campaign_id, "Ticket campaign", username),
            (other_campaign_id, "Other campaign", username),
        ),
    )
    await connection.commit()
    api_key_id = f"api-key-{uuid4().hex}"
    await connection.execute(
        """
        INSERT INTO api_keys(
            id, user_id, name, key_hash, key_prefix, scopes
        )
        VALUES(?, ?, 'ticket-key', 'synthetic-test-only', 'test', ?)
        """,
        (api_key_id, user_id, scopes),
    )
    await connection.commit()
    now = datetime.now(timezone.utc)
    family_id = _test_family_id(user_id)
    await connection.execute(
        "INSERT INTO refresh_token_families("
        "id,user_id,auth_epoch,state,created_at,absolute_expires_at,retain_until) "
        "VALUES(?,?,1,'active',?,?,?)",
        (
            family_id,
            user_id,
            now.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{now.microsecond // 1000:03d}Z",
            (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{(now + timedelta(days=30)).microsecond // 1000:03d}Z",
            (now + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{(now + timedelta(days=60)).microsecond // 1000:03d}Z",
        ),
    )
    await connection.commit()
    return user_id, username, campaign_id, other_campaign_id, api_key_id


def _test_family_id(user_id: str) -> str:
    digest = hashlib.sha256(b"ARES-WS-TEST-FAMILY\0" + user_id.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _bearer_source(
    user_id: str,
    username: str,
    *,
    family_id: str | None = None,
    auth_epoch: int = 1,
) -> BearerTicketSource:
    return BearerTicketSource(
        user_id=user_id,
        subject=username,
        jti=f"ticket-jti-{uuid4().hex}",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        family_id=family_id or _test_family_id(user_id),
        auth_epoch=auth_epoch,
    )


def _identity_dataclass_contract(
    first: object,
    second: object,
    *,
    sensitive_values: tuple[object, ...],
    frozen_field: str,
) -> tuple[bool, bool, bool, bool, bool, bool]:
    first_representation = repr(first)
    second_representation = repr(second)
    sensitive_markers = tuple(
        marker
        for value in sensitive_values
        for marker in (str(value), repr(value))
        if marker
    )
    representation_is_safe = all(
        marker not in first_representation
        and marker not in second_representation
        for marker in sensitive_markers
    )
    identity_equality_is_preserved = (
        first is not second
        and first != second
        and first == first
        and second == second
    )
    identity_methods_are_preserved = (
        type(first) is type(second)
        and type(first).__eq__ is object.__eq__
        and type(first).__ne__ is object.__ne__
        and type(first).__hash__ is object.__hash__
        and type(first).__lt__ is object.__lt__
        and type(first).__le__ is object.__le__
        and type(first).__gt__ is object.__gt__
        and type(first).__ge__ is object.__ge__
    )

    hashing_is_usable = False
    collections_preserve_identity = False
    try:
        hash(first)
        hash(second)
        instance_set = {first, second}
        instance_dictionary = {first: "first", second: "second"}
        hashing_is_usable = True
        collections_preserve_identity = (
            len(instance_set) == 2
            and len(instance_dictionary) == 2
            and instance_dictionary.get(first) == "first"
            and instance_dictionary.get(second) == "second"
        )
    except TypeError:
        pass

    existing_field_rejected = False
    try:
        setattr(first, frozen_field, "synthetic-mutated-value")
    except FrozenInstanceError:
        existing_field_rejected = True

    unexpected_field_rejected = False
    unexpected_field = "synthetic_unexpected_field"
    try:
        setattr(first, unexpected_field, "synthetic-value")
    except (AttributeError, TypeError):
        unexpected_field_rejected = True
    frozen_slots_are_preserved = (
        existing_field_rejected
        and unexpected_field_rejected
        and not hasattr(first, "__dict__")
    )

    rejected_ordering_count = 0
    ordering_operations = (
        lambda: first < second,
        lambda: first <= second,
        lambda: first > second,
        lambda: first >= second,
    )
    for operation in ordering_operations:
        try:
            operation()
        except TypeError:
            rejected_ordering_count += 1
    ordering_is_not_generated = rejected_ordering_count == len(
        ordering_operations
    )

    return (
        representation_is_safe,
        identity_equality_is_preserved,
        identity_methods_are_preserved,
        hashing_is_usable and collections_preserve_identity,
        frozen_slots_are_preserved,
        ordering_is_not_generated,
    )


def _require_identity_dataclass_contract(
    checks: tuple[bool, bool, bool, bool, bool, bool],
) -> None:
    (
        representation_is_safe,
        identity_equality_is_preserved,
        identity_methods_are_preserved,
        identity_collections_are_preserved,
        frozen_slots_are_preserved,
        ordering_is_not_generated,
    ) = checks
    _require_fixed(
        representation_is_safe,
        "ticket contract representation exposed a sensitive field",
    )
    _require_fixed(
        identity_equality_is_preserved,
        "ticket contract gained value equality",
    )
    _require_fixed(
        identity_methods_are_preserved,
        "ticket contract generated comparison or hashing methods",
    )
    _require_fixed(
        identity_collections_are_preserved,
        "ticket contract lost identity-based collection behavior",
    )
    _require_fixed(
        frozen_slots_are_preserved,
        "ticket contract lost frozen or slotted behavior",
    )
    _require_fixed(
        ordering_is_not_generated,
        "ticket contract gained field-based ordering",
    )


def _owned_ticket_tasks() -> list[asyncio.Task[Any]]:
    current = asyncio.current_task()
    return [
        task
        for task in asyncio.all_tasks()
        if task is not current
        and not task.done()
        and task.get_name().startswith("ares-sqlite-websocket-ticket-")
    ]


class _PostExecuteBarrier:
    def __init__(
        self,
        result: Any,
        entered: asyncio.Event,
        release: asyncio.Event,
    ) -> None:
        self._result = result
        self._entered = entered
        self._release = release
        self._cursor: Any = None

    async def __aenter__(self) -> Any:
        self._cursor = await self._result
        if self._cursor.rowcount == 1:
            self._entered.set()
            await asyncio.wait_for(self._release.wait(), timeout=5)
        return self._cursor

    async def __aexit__(self, *_args: object) -> None:
        if self._cursor is not None:
            await self._cursor.close()


class _BeginProbe:
    def __init__(
        self,
        result: Any,
        acquired: asyncio.Event,
    ) -> None:
        self._result = result
        self._acquired = acquired

    async def _wait(self) -> Any:
        result = await self._result
        self._acquired.set()
        return result

    def __await__(self) -> Any:
        return self._wait().__await__()


class _TicketConnectionProxy:
    def __init__(
        self,
        connection: aiosqlite.Connection,
        *,
        cas_entered: asyncio.Event | None = None,
        cas_release: asyncio.Event | None = None,
        begin_acquired: asyncio.Event | None = None,
    ) -> None:
        self._connection = connection
        self._cas_entered = cas_entered
        self._cas_release = cas_release
        self._begin_acquired = begin_acquired
        self.statement_order: list[str] = []

    @property
    def row_factory(self) -> Any:
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value: Any) -> None:
        self._connection.row_factory = value

    def execute(self, statement: str, *parameters: object) -> Any:
        normalized = " ".join(statement.upper().split())
        result = self._connection.execute(statement, *parameters)
        if normalized == "BEGIN IMMEDIATE":
            self.statement_order.append("BEGIN IMMEDIATE")
            if self._begin_acquired is not None:
                return _BeginProbe(
                    result,
                    self._begin_acquired,
                )
        elif normalized.startswith("UPDATE WEBSOCKET_TICKETS"):
            self.statement_order.append("CAS UPDATE")
            if (
                self._cas_entered is not None
                and self._cas_release is not None
            ):
                return _PostExecuteBarrier(
                    result,
                    self._cas_entered,
                    self._cas_release,
                )
        elif (
            normalized.startswith("SELECT ")
            and "FROM WEBSOCKET_TICKETS" in normalized
        ):
            self.statement_order.append("HANDLE SELECT")
        return result

    async def commit(self) -> None:
        self.statement_order.append("COMMIT")
        await self._connection.commit()

    async def rollback(self) -> None:
        self.statement_order.append("ROLLBACK")
        await self._connection.rollback()

    async def close(self) -> None:
        await self._connection.close()


def _sqlite_schema_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(path)
    try:
        return tuple(
            connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
        )
    finally:
        connection.close()


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("ticket schema mutation setup failed")
    return source.replace(old, new, 1)


def _regex_replace_once(source: str, pattern: str, replacement: str) -> str:
    mutated, count = re.subn(
        pattern,
        replacement,
        source,
        count=1,
        flags=re.IGNORECASE,
    )
    if count != 1:
        raise RuntimeError("ticket schema mutation setup failed")
    return mutated


def _mutate_ticket_schema(path: Path, mutation: str) -> None:
    connection = sqlite3.connect(path)
    try:
        table_row = connection.execute(
            "SELECT sql FROM sqlite_schema "
            "WHERE type='table' AND name='websocket_tickets'"
        ).fetchone()
        index_rows = connection.execute(
            "SELECT name, sql FROM sqlite_schema "
            "WHERE type='index' AND tbl_name='websocket_tickets' "
            "AND sql IS NOT NULL ORDER BY name"
        ).fetchall()
        if table_row is None:
            raise RuntimeError("ticket schema mutation setup failed")
        table_sql = str(table_row[0])

        if mutation == "wrong_check":
            table_sql = _replace_once(
                table_sql,
                "length(ticket_hash)=64",
                "length(ticket_hash)=63",
            )
        elif mutation == "wrong_fk_action":
            table_sql = _regex_replace_once(
                table_sql,
                r"ON\s+DELETE\s+CASCADE",
                "ON DELETE SET NULL",
            )
        elif mutation == "wrong_pk":
            table_sql = _regex_replace_once(
                table_sql,
                r"NOT\s+NULL\s+PRIMARY\s+KEY",
                "NOT NULL UNIQUE",
            )
        elif mutation == "wrong_nullability":
            table_sql = _regex_replace_once(
                table_sql,
                r"\bcreated_at\s+TEXT\s+NOT\s+NULL",
                "created_at TEXT",
            )
        elif mutation == "wrong_default":
            table_sql = _regex_replace_once(
                table_sql,
                r"\bcreated_at\s+TEXT\s+NOT\s+NULL",
                "created_at TEXT NOT NULL DEFAULT ''",
            )
        elif mutation == "extra_check":
            closing = table_sql.rfind(")")
            if closing < 0:
                raise RuntimeError("ticket schema mutation setup failed")
            table_sql = (
                table_sql[:closing]
                + ", CONSTRAINT ck_ws_ticket_extra CHECK (1)"
                + table_sql[closing:]
            )
        elif mutation == "on_conflict":
            table_sql = _replace_once(
                table_sql,
                "PRIMARY KEY",
                "PRIMARY KEY ON CONFLICT REPLACE",
            )
        elif mutation == "deferrable":
            table_sql = _regex_replace_once(
                table_sql,
                r"ON\s+DELETE\s+CASCADE",
                "ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED",
            )
        elif mutation == "swapped_fk_names":
            table_sql = _replace_once(
                table_sql,
                "fk_ws_ticket_campaign",
                "fk_ws_ticket_name_swap",
            )
            table_sql = _replace_once(
                table_sql,
                "fk_ws_ticket_user",
                "fk_ws_ticket_campaign",
            )
            table_sql = _replace_once(
                table_sql,
                "fk_ws_ticket_name_swap",
                "fk_ws_ticket_user",
            )

        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN")
        if mutation in {
            "wrong_check",
            "wrong_fk_action",
            "wrong_pk",
            "wrong_nullability",
            "wrong_default",
            "extra_check",
            "on_conflict",
            "deferrable",
            "swapped_fk_names",
        }:
            connection.execute("DROP TABLE websocket_tickets")
            connection.execute(table_sql)
            for _name, index_sql in index_rows:
                connection.execute(str(index_sql))
        elif mutation == "missing_index":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
        elif mutation == "wrong_index":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(consumed_at)"
            )
        elif mutation == "wrong_index_order":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(expires_at, user_id)"
            )
        elif mutation == "wrong_uniqueness":
            connection.execute("DROP INDEX idx_ws_tickets_expires")
            connection.execute(
                "CREATE UNIQUE INDEX idx_ws_tickets_expires "
                "ON websocket_tickets(expires_at)"
            )
        elif mutation == "duplicate_index":
            connection.execute(
                "CREATE INDEX idx_ws_tickets_duplicate "
                "ON websocket_tickets(expires_at)"
            )
        else:
            raise RuntimeError("unknown ticket schema mutation")
        connection.commit()
    finally:
        connection.close()


async def _ticket_count(database: AresDatabase) -> int:
    async with database.conn.execute(
        "SELECT COUNT(*) AS count FROM websocket_tickets"
    ) as cursor:
        return int((await cursor.fetchone())["count"])


async def _consumed_ticket_count(database: AresDatabase) -> int:
    async with database.conn.execute(
        "SELECT COUNT(*) AS count FROM websocket_tickets "
        "WHERE consumed_at IS NOT NULL"
    ) as cursor:
        return int((await cursor.fetchone())["count"])


def test_ticket_contract_is_canonical_and_sensitive_fields_are_not_represented() -> None:
    raw_ticket = generate_websocket_ticket()
    raw_is_canonical = is_canonical_websocket_ticket(raw_ticket)
    digest = hash_websocket_ticket(raw_ticket)
    digest_is_canonical = (
        len(digest) == 64
        and digest == digest.lower()
        and all(character in "0123456789abcdef" for character in digest)
    )
    source = _bearer_source("user-contract", "contract-subject")
    source_repr_is_safe = (
        source.user_id not in repr(source)
        and source.subject not in repr(source)
        and source.jti not in repr(source)
    )

    _require_fixed(raw_is_canonical, "generated ticket was not canonical")
    _require_fixed(digest_is_canonical, "ticket digest was not canonical")
    _require_fixed(source_repr_is_safe, "source representation exposed an identifier")
    _require_fixed(
        WEBSOCKET_TICKET_TTL_SECONDS == 30,
        "ticket lifetime contract changed",
    )


def test_bearer_ticket_source_preserves_identity_and_confidentiality() -> None:
    expires_at = datetime(2035, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    values = {
        "user_id": "synthetic-bearer-user",
        "subject": "synthetic-bearer-subject",
        "jti": "synthetic-bearer-jti",
        "expires_at": expires_at,
        "family_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "auth_epoch": 7,
    }
    first = BearerTicketSource(**values)
    second = BearerTicketSource(**values)
    checks = _identity_dataclass_contract(
        first,
        second,
        sensitive_values=tuple(values.values()),
        frozen_field="subject",
    )

    _require_identity_dataclass_contract(checks)


def test_api_key_ticket_source_preserves_identity_and_confidentiality() -> None:
    values = {
        "user_id": "synthetic-api-user",
        "api_key_id": "synthetic-api-key",
    }
    first = ApiKeyTicketSource(**values)
    second = ApiKeyTicketSource(**values)
    checks = _identity_dataclass_contract(
        first,
        second,
        sensitive_values=tuple(values.values()),
        frozen_field="api_key_id",
    )

    _require_identity_dataclass_contract(checks)


def test_consumed_ticket_preserves_identity_and_confidentiality() -> None:
    bearer_expiry = datetime(2035, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
    bearer_values = {
        "campaign_id": "synthetic-bearer-campaign",
        "user_id": "synthetic-consumed-bearer-user",
        "credential_kind": WebSocketTicketCredentialKind.BEARER,
        "bearer_subject": "synthetic-consumed-subject",
        "bearer_jti": "synthetic-consumed-jti",
        "bearer_expires_at": bearer_expiry,
        "bearer_family_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "bearer_auth_epoch": 9,
    }
    first_bearer = ConsumedWebSocketTicket(**bearer_values)
    second_bearer = ConsumedWebSocketTicket(**bearer_values)
    bearer_checks = _identity_dataclass_contract(
        first_bearer,
        second_bearer,
        sensitive_values=(
            bearer_values["campaign_id"],
            bearer_values["user_id"],
            bearer_values["bearer_subject"],
            bearer_values["bearer_jti"],
            bearer_values["bearer_expires_at"],
            bearer_values["bearer_family_id"],
            bearer_values["bearer_auth_epoch"],
        ),
        frozen_field="bearer_jti",
    )

    api_key_values = {
        "campaign_id": "synthetic-api-campaign",
        "user_id": "synthetic-consumed-api-user",
        "credential_kind": WebSocketTicketCredentialKind.API_KEY,
        "api_key_id": "synthetic-consumed-api-key",
        "required_scope": "read",
    }
    first_api_key = ConsumedWebSocketTicket(**api_key_values)
    second_api_key = ConsumedWebSocketTicket(**api_key_values)
    api_key_checks = _identity_dataclass_contract(
        first_api_key,
        second_api_key,
        sensitive_values=(
            api_key_values["campaign_id"],
            api_key_values["user_id"],
            api_key_values["api_key_id"],
            api_key_values["required_scope"],
        ),
        frozen_field="api_key_id",
    )

    _require_identity_dataclass_contract(bearer_checks)
    _require_identity_dataclass_contract(api_key_checks)


def test_ticket_principal_preserves_identity_and_confidentiality() -> None:
    values = {
        "user_id": "synthetic-principal-user",
        "username": "synthetic-principal-name",
        "role": "operator",
        "credential_kind": WebSocketTicketCredentialKind.API_KEY,
        "api_key_id": "synthetic-principal-api-key",
        "api_key_scopes": ("synthetic-scope",),
    }
    first = WebSocketTicketPrincipal(**values)
    second = WebSocketTicketPrincipal(**values)
    checks = _identity_dataclass_contract(
        first,
        second,
        sensitive_values=(
            values["user_id"],
            values["username"],
            values["api_key_id"],
            values["api_key_scopes"],
        ),
        frozen_field="username",
    )

    _require_identity_dataclass_contract(checks)


def test_ticket_contract_rejects_invalid_and_mixed_shapes() -> None:
    invalid_values = ("", "short", " " * 43, "!" * 43, "a" * 44)
    invalid_results = [
        is_canonical_websocket_ticket(candidate)
        for candidate in invalid_values
    ]
    mixed_rejected = False
    try:
        ConsumedWebSocketTicket(
            campaign_id="campaign-contract",
            user_id="user-contract",
            credential_kind=WebSocketTicketCredentialKind.API_KEY,
            api_key_id="key-contract",
            required_scope="read",
            bearer_subject="unexpected",
        )
    except ValueError:
        mixed_rejected = True

    _require_fixed(
        not any(invalid_results),
        "invalid ticket syntax was accepted",
    )
    _require_fixed(mixed_rejected, "mixed credential state was accepted")


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_check",
        "wrong_fk_action",
        "wrong_pk",
        "wrong_nullability",
        "wrong_default",
        "extra_check",
        "on_conflict",
        "deferrable",
        "swapped_fk_names",
        "missing_index",
        "wrong_index",
        "wrong_index_order",
        "wrong_uniqueness",
        "duplicate_index",
    ],
)
@pytest.mark.asyncio
async def test_sqlite_existing_ticket_schema_rejects_exact_mutations_without_change(
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / f"ticket-schema-{mutation}.db"
    setup = await _connected_raw_database(path)
    await setup.close()
    _mutate_ticket_schema(path, mutation)
    before = _sqlite_schema_snapshot(path)

    candidate = AresDatabase(path)
    rejected = False
    try:
        await candidate.connect()
    except RuntimeError:
        rejected = True
    finally:
        if candidate._conn is not None:
            await candidate.close()
    after = _sqlite_schema_snapshot(path)

    _require_fixed(rejected, "incompatible ticket schema was accepted")
    _require_fixed(
        before == after,
        "failed ticket schema validation mutated the database",
    )


@pytest.mark.asyncio
async def test_sqlite_raw_bootstrap_validates_before_commit_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ticket-bootstrap-rollback.db"
    database = AresDatabase(path)

    async def migrations_unavailable() -> bool:
        return False

    class ValidationError(RuntimeError):
        pass

    async def reject_created_schema() -> None:
        raise ValidationError("fixed validation failure")

    monkeypatch.setattr(
        database,
        "_run_alembic_migrations",
        migrations_unavailable,
    )
    monkeypatch.setattr(
        database,
        "_validate_websocket_ticket_schema",
        reject_created_schema,
    )
    failure_is_primary = False
    try:
        await database.connect()
    except ValidationError:
        failure_is_primary = True

    connection = sqlite3.connect(path)
    try:
        application_table_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
        )
    finally:
        connection.close()

    recovered = await _connected_raw_database(path)
    try:
        schema_is_present = await _ticket_count(recovered) == 0
    finally:
        await recovered.close()

    _require_fixed(
        failure_is_primary,
        "bootstrap validation failure was not propagated",
    )
    _require_fixed(
        application_table_count == 0,
        "failed bootstrap committed partial schema",
    )
    _require_fixed(
        schema_is_present,
        "bootstrap failure prevented clean recovery",
    )


@pytest.mark.asyncio
async def test_sqlite_issue_consume_replay_and_raw_not_stored(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-lifecycle.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "valid bearer ticket was not issued")
        raw_ticket, ttl = issued or ("", 0)

        connection = database._require_connected()
        async with connection.execute(
            """
            SELECT ticket_hash, bearer_subject, bearer_jti, api_key_id,
                   required_scope, consumed_at
            FROM websocket_tickets
            """
        ) as cursor:
            stored = await cursor.fetchone()
        raw_absent = stored is not None and all(
            raw_ticket != value for value in tuple(stored)
        )
        digest_matches = (
            stored is not None
            and stored["ticket_hash"] == hash_websocket_ticket(raw_ticket)
        )

        consumed = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        replay = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        principal = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        resolved = (
            principal is not None
            and principal.user_id == user_id
            and principal.username == username
            and principal.role == "operator"
        )

        _require_fixed(ttl == 30, "issued ticket lifetime changed")
        _require_fixed(raw_absent, "raw ticket was persisted")
        _require_fixed(digest_matches, "stored digest did not match the ticket")
        _require_fixed(consumed is not None, "valid ticket was not consumed")
        _require_fixed(replay is None, "consumed ticket was accepted twice")
        _require_fixed(resolved, "bearer principal was not resolved")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_wrong_campaign_and_malformed_input_do_not_consume(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-campaign.db")
    try:
        user_id, username, campaign_id, other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]

        malformed = await database.consume_websocket_ticket(
            "not-a-ticket",
            campaign_id,
        )
        wrong = await database.consume_websocket_ticket(raw_ticket, other_id)
        correct = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(malformed is None, "malformed ticket reached storage")
        _require_fixed(wrong is None, "wrong campaign consumed a ticket")
        _require_fixed(
            correct is not None,
            "wrong-campaign attempt mutated the ticket",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_exact_now_expiry_and_purge_boundaries(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-expiry.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        digest = hash_websocket_ticket(raw_ticket)
        connection = database._require_connected()
        await connection.execute(
            """
            UPDATE websocket_tickets
            SET expires_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE ticket_hash=?
            """,
            (digest,),
        )
        await connection.commit()

        expired = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        deleted = await database.purge_expired_websocket_tickets()
        async with connection.execute(
            "SELECT COUNT(*) AS count FROM websocket_tickets"
        ) as cursor:
            remaining = int((await cursor.fetchone())["count"])

        _require_fixed(expired is None, "exact-now ticket was accepted")
        _require_fixed(deleted == 1, "expired ticket purge count was incorrect")
        _require_fixed(remaining == 0, "expired ticket remained stored")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_api_key_revalidation_does_not_update_last_used(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-api-key.db")
    try:
        user_id, _username, campaign_id, _other_id, key_id = (
            await _seed_identity(database, scopes="read,write")
        )
        connection = database._require_connected()
        async with connection.execute(
            "SELECT last_used FROM api_keys WHERE id=?",
            (key_id,),
        ) as cursor:
            before = (await cursor.fetchone())["last_used"]

        issued = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        _require_fixed(issued is not None, "valid API-key ticket was not issued")
        raw_ticket = (issued or ("", 0))[0]
        handle = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with connection.execute(
            "SELECT last_used FROM api_keys WHERE id=?",
            (key_id,),
        ) as cursor:
            after = (await cursor.fetchone())["last_used"]
        unchanged = before == after
        resolved = (
            principal is not None
            and principal.credential_kind
            is WebSocketTicketCredentialKind.API_KEY
            and "read" in principal.api_key_scopes
        )

        _require_fixed(resolved, "API-key principal was not resolved")
        _require_fixed(
            unchanged,
            "ticket resolution mutated API-key usage state",
        )

        await connection.execute(
            "UPDATE api_keys SET is_active=0 WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        denied = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        _require_fixed(denied is None, "revoked API key remained authorized")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_source_and_campaign_revalidation_is_authoritative(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-revalidation.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        source = _bearer_source(user_id, username)
        issued = await database.issue_websocket_ticket(campaign_id, source)
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        handle = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(handle is not None, "ticket handle setup failed")

        connection = database._require_connected()
        await connection.execute(
            "INSERT INTO revoked_access_tokens(jti,user_id,expires_at) "
            "VALUES(?,?,?)",
            (
                source.jti,
                user_id,
                (
                    datetime.now(timezone.utc) + timedelta(minutes=5)
                ).isoformat(),
            ),
        )
        await connection.commit()
        revoked = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        _require_fixed(revoked is None, "revoked source remained authorized")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_issue_revalidates_source_role_and_campaign_access(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-issue-auth.db")
    try:
        user_id, username, campaign_id, _other_id, key_id = (
            await _seed_identity(database, scopes="telemetry")
        )
        source = _bearer_source(user_id, username)
        connection = database._require_connected()
        await connection.execute(
            "INSERT INTO revoked_access_tokens(jti,user_id,expires_at) "
            "VALUES(?,?,?)",
            (
                source.jti,
                user_id,
                (
                    datetime.now(timezone.utc) + timedelta(minutes=5)
                ).isoformat(),
            ),
        )
        await connection.commit()
        revoked = await database.issue_websocket_ticket(campaign_id, source)

        await connection.execute(
            "DELETE FROM revoked_access_tokens WHERE jti=?",
            (source.jti,),
        )
        await connection.execute(
            "UPDATE users SET role='unknown-role' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        unknown_role = await database.issue_websocket_ticket(
            campaign_id,
            source,
        )

        await connection.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await connection.execute(
            "UPDATE campaigns SET operator='different-operator' WHERE id=?",
            (campaign_id,),
        )
        await connection.commit()
        inaccessible = await database.issue_websocket_ticket(
            campaign_id,
            source,
        )
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (username, campaign_id),
        )
        await connection.commit()
        invalid_scope = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        await connection.execute(
            "UPDATE users SET is_active=0 WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        inactive = await database.issue_websocket_ticket(
            campaign_id,
            source,
        )

        _require_fixed(revoked is None, "revoked bearer source issued a ticket")
        _require_fixed(unknown_role is None, "unknown role issued a ticket")
        _require_fixed(
            inaccessible is None,
            "campaign access loss still issued a ticket",
        )
        _require_fixed(
            invalid_scope is None,
            "API key without an accepted scope issued a ticket",
        )
        _require_fixed(inactive is None, "inactive user issued a ticket")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_bearer_resolver_complete_authority_mutations(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-bearer-matrix.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        source = _bearer_source(user_id, username)
        issued = await database.issue_websocket_ticket(campaign_id, source)
        _require_fixed(issued is not None, "bearer ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        handle = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(handle is not None, "bearer handle setup failed")
        if handle is None:
            return

        connection = database.conn
        changes_before = connection.total_changes
        active = await database.resolve_websocket_ticket_principal(handle)
        active_again = await database.resolve_websocket_ticket_principal(handle)
        read_only = connection.total_changes == changes_before

        await connection.execute(
            "UPDATE users SET is_active=0 WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        inactive = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET is_active=1 WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        reactivated = await database.resolve_websocket_ticket_principal(handle)

        await connection.execute(
            "UPDATE users SET role='team_lead' WHERE id=?",
            (user_id,),
        )
        await connection.execute(
            "UPDATE campaigns SET operator='different-operator' WHERE id=?",
            (campaign_id,),
        )
        await connection.commit()
        promoted = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        demoted = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (username, campaign_id),
        )
        await connection.execute(
            "UPDATE users SET role='unknown-role' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        invalid_role = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='reporter' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        current_role = await database.resolve_websocket_ticket_principal(handle)

        await connection.execute(
            "INSERT INTO revoked_access_tokens(jti,user_id,expires_at) "
            "VALUES(?,?,?)",
            (
                source.jti,
                user_id,
                (
                    datetime.now(timezone.utc) + timedelta(minutes=5)
                ).isoformat(),
            ),
        )
        await connection.commit()
        revoked = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "DELETE FROM revoked_access_tokens WHERE jti=?",
            (source.jti,),
        )
        await connection.commit()
        unrevoked = await database.resolve_websocket_ticket_principal(handle)

        expired_handle = replace(
            handle,
            bearer_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        expired_source = await database.resolve_websocket_ticket_principal(
            expired_handle
        )

        renamed_username = f"renamed_{uuid4().hex}"
        await connection.execute(
            "UPDATE users SET username=? WHERE id=?",
            (renamed_username, user_id),
        )
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (renamed_username, campaign_id),
        )
        await connection.commit()
        renamed = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET username=? WHERE id=?",
            (username, user_id),
        )
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (username, campaign_id),
        )
        await connection.commit()

        digest = hash_websocket_ticket(raw_ticket)
        await connection.execute(
            """
            UPDATE websocket_tickets
            SET created_at='2000-01-01T00:00:00.000Z',
                consumed_at='2000-01-01T00:00:00.001Z',
                expires_at='2000-01-01T00:00:00.002Z'
            WHERE ticket_hash=?
            """,
            (digest,),
        )
        await connection.commit()
        purged = await database.purge_expired_websocket_tickets()
        after_row_purge = await database.resolve_websocket_ticket_principal(
            handle
        )
        replay = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )

        await connection.execute("DELETE FROM users WHERE id=?", (user_id,))
        await connection.commit()
        deleted = await database.resolve_websocket_ticket_principal(handle)

        active_valid = (
            active is not None
            and active_again is not None
            and active.user_id == user_id
            and active.role == "operator"
        )
        reactivation_valid = (
            inactive is None
            and reactivated is not None
            and reactivated.user_id == user_id
        )
        role_matrix_valid = (
            promoted is not None
            and promoted.role == "team_lead"
            and demoted is None
            and invalid_role is None
            and current_role is not None
            and current_role.role == "reporter"
        )
        revocation_valid = revoked is None and unrevoked is not None
        lifetime_valid = (
            expired_source is None
            and renamed is None
            and purged == 1
            and after_row_purge is not None
            and replay is None
            and deleted is None
        )

        _require_fixed(active_valid, "active bearer authority was incorrect")
        _require_fixed(
            reactivation_valid,
            "bearer reactivation did not use the same authority",
        )
        _require_fixed(role_matrix_valid, "bearer role authority was incorrect")
        _require_fixed(revocation_valid, "bearer revocation authority was incorrect")
        _require_fixed(lifetime_valid, "bearer handle lifetime rules changed")
        _require_fixed(read_only, "bearer resolution mutated database state")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_api_key_resolver_complete_authority_mutations(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-api-matrix.db")
    try:
        user_id, username, campaign_id, _other_id, key_id = (
            await _seed_identity(database, scopes="read")
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        _require_fixed(issued is not None, "API-key ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        handle = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(handle is not None, "API-key handle setup failed")
        if handle is None:
            return

        connection = database.conn
        async with connection.execute(
            "SELECT last_used FROM api_keys WHERE id=?",
            (key_id,),
        ) as cursor:
            last_used_before = (await cursor.fetchone())["last_used"]

        read_principal = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET scopes='write' WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        write_principal = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET scopes='admin' WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        admin_principal = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET scopes='telemetry' WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        insufficient = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET scopes='read', is_active=0 WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        revoked = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET is_active=1 WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        reactivated = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET expires_at='2000-01-01T00:00:00.000Z' "
            "WHERE id=?",
            (key_id,),
        )
        await connection.commit()
        expired = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE api_keys SET expires_at=NULL WHERE id=?",
            (key_id,),
        )
        await connection.execute(
            "UPDATE users SET is_active=0 WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        owner_inactive = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET is_active=1 WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        owner_reactivated = (
            await database.resolve_websocket_ticket_principal(handle)
        )

        renamed_username = f"renamed_{uuid4().hex}"
        await connection.execute(
            "UPDATE users SET username=? WHERE id=?",
            (renamed_username, user_id),
        )
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (renamed_username, campaign_id),
        )
        await connection.commit()
        renamed = await database.resolve_websocket_ticket_principal(handle)

        await connection.execute(
            "UPDATE users SET role='reporter' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        current_role = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='unknown-role' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        invalid_role = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await connection.execute(
            "UPDATE campaigns SET operator='different-operator' WHERE id=?",
            (campaign_id,),
        )
        await connection.commit()
        reassigned = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='team_lead' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        promoted = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE users SET role='operator' WHERE id=?",
            (user_id,),
        )
        await connection.commit()
        demoted = await database.resolve_websocket_ticket_principal(handle)
        await connection.execute(
            "UPDATE campaigns SET operator=? WHERE id=?",
            (renamed_username, campaign_id),
        )
        await connection.commit()

        wrong_key = await database.resolve_websocket_ticket_principal(
            replace(handle, api_key_id=f"replacement-{uuid4().hex}")
        )
        wrong_owner = await database.resolve_websocket_ticket_principal(
            replace(handle, user_id=f"replacement-{uuid4().hex}")
        )

        digest = hash_websocket_ticket(raw_ticket)
        await connection.execute(
            """
            UPDATE websocket_tickets
            SET created_at='2000-01-01T00:00:00.000Z',
                consumed_at='2000-01-01T00:00:00.001Z',
                expires_at='2000-01-01T00:00:00.002Z'
            WHERE ticket_hash=?
            """,
            (digest,),
        )
        await connection.commit()
        purged = await database.purge_expired_websocket_tickets()
        after_row_purge = await database.resolve_websocket_ticket_principal(
            handle
        )
        replay = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        async with connection.execute(
            "SELECT last_used FROM api_keys WHERE id=?",
            (key_id,),
        ) as cursor:
            last_used_after = (await cursor.fetchone())["last_used"]

        await connection.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        replacement_key_id = f"replacement-{uuid4().hex}"
        await connection.execute(
            """
            INSERT INTO api_keys(
                id, user_id, name, key_hash, key_prefix, scopes
            )
            VALUES(?, ?, 'replacement', 'synthetic', 'test', 'read')
            """,
            (replacement_key_id, user_id),
        )
        await connection.commit()
        replacement_does_not_match = (
            await database.resolve_websocket_ticket_principal(handle)
        )
        await connection.execute("DELETE FROM users WHERE id=?", (user_id,))
        await connection.commit()
        owner_deleted = await database.resolve_websocket_ticket_principal(handle)

        scopes_valid = (
            read_principal is not None
            and "read" in read_principal.api_key_scopes
            and write_principal is not None
            and "write" in write_principal.api_key_scopes
            and admin_principal is not None
            and "admin" in admin_principal.api_key_scopes
            and insufficient is None
        )
        lifecycle_valid = (
            revoked is None
            and reactivated is not None
            and expired is None
            and owner_inactive is None
            and owner_reactivated is not None
        )
        identity_valid = (
            renamed is not None
            and renamed.username == renamed_username
            and current_role is not None
            and current_role.role == "reporter"
            and invalid_role is None
        )
        campaign_valid = (
            reassigned is None
            and promoted is not None
            and promoted.role == "team_lead"
            and demoted is None
        )
        stable_binding_valid = (
            wrong_key is None
            and wrong_owner is None
            and replacement_does_not_match is None
            and owner_deleted is None
        )
        lifetime_valid = (
            purged == 1
            and after_row_purge is not None
            and replay is None
        )
        read_only = last_used_before == last_used_after

        _require_fixed(scopes_valid, "API-key scope authority was incorrect")
        _require_fixed(
            lifecycle_valid,
            "API-key lifecycle authority was incorrect",
        )
        _require_fixed(
            identity_valid,
            "API-key canonical identity was incorrect",
        )
        _require_fixed(
            campaign_valid,
            "API-key campaign authority was incorrect",
        )
        _require_fixed(
            stable_binding_valid,
            "API-key stable ownership was not enforced",
        )
        _require_fixed(lifetime_valid, "API-key handle lifetime rules changed")
        _require_fixed(read_only, "ticket operations updated API-key usage")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_purge_removes_malformed_expiry_defensively(
    tmp_path: Path,
) -> None:
    database = await _connected_database(tmp_path / "ticket-malformed.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        connection = database._require_connected()
        digest = hash_websocket_ticket(generate_websocket_ticket())
        canonical_now = (
            datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        canonical_source_expiry = (
            (datetime.now(timezone.utc) + timedelta(minutes=5))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        await connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            await connection.execute(
                """
                INSERT INTO websocket_tickets(
                    ticket_hash, campaign_id, user_id, credential_kind,
                    bearer_subject, bearer_jti, bearer_expires_at,
                    created_at, expires_at
                )
                VALUES(?, ?, ?, 'bearer', ?, ?, ?, ?, ?)
                """,
                (
                    digest,
                    campaign_id,
                    user_id,
                    username,
                    f"malformed-jti-{uuid4().hex}",
                    canonical_source_expiry,
                    canonical_now,
                    "not-a-timestamp",
                ),
            )
            await connection.commit()
        finally:
            await connection.execute("PRAGMA ignore_check_constraints=OFF")

        deleted = await database.purge_expired_websocket_tickets()
        async with connection.execute(
            "SELECT COUNT(*) AS count FROM websocket_tickets"
        ) as cursor:
            remaining = int((await cursor.fetchone())["count"])
        _require_fixed(deleted == 1, "malformed expiry purge count was wrong")
        _require_fixed(remaining == 0, "malformed expiry row was retained")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_collision_rolls_back_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-collision.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        fixed_ticket = generate_websocket_ticket()
        with monkeypatch.context() as patcher:
            patcher.setattr(
                "ares.db.database.generate_websocket_ticket",
                lambda: fixed_ticket,
            )
            first = await database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
            _require_fixed(first is not None, "collision setup failed")
            collision_rejected = False
            try:
                await database.issue_websocket_ticket(
                    campaign_id,
                    _bearer_source(user_id, username),
                )
            except aiosqlite.IntegrityError:
                collision_rejected = True

        consumed = await database.consume_websocket_ticket(
            fixed_ticket,
            campaign_id,
        )
        recovered = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(
            consumed is not None,
            "collision damaged the existing ticket",
        )
        _require_fixed(collision_rejected, "ticket collision was not rejected")
        _require_fixed(recovered is not None, "database did not recover")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_commit_failure_rolls_back_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-commit-failure.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_commit = database._commit_websocket_ticket_operation

        async def failed_commit(connection: Any) -> None:
            raise RuntimeError("synthetic commit failure")

        monkeypatch.setattr(
            database,
            "_commit_websocket_ticket_operation",
            failed_commit,
        )
        failure_type: type[BaseException] | None = None
        try:
            await database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
        except Exception as exc:
            failure_type = type(exc)
        monkeypatch.setattr(
            database,
            "_commit_websocket_ticket_operation",
            original_commit,
        )

        connection = database._require_connected()
        async with connection.execute(
            "SELECT COUNT(*) AS count FROM websocket_tickets"
        ) as cursor:
            count = int((await cursor.fetchone())["count"])
        recovered = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(
            failure_type is RuntimeError,
            "commit failure did not propagate",
        )
        _require_fixed(count == 0, "commit failure persisted a ticket")
        _require_fixed(recovered is not None, "commit failure prevented recovery")
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_two_instances_have_one_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ticket-concurrency.db"
    first = await _connected_database(path)
    second = await _connected_database(path)
    first_cas_won = asyncio.Event()
    release_first = asyncio.Event()
    second_begin_submitted = asyncio.Event()
    second_begin_acquired = asyncio.Event()
    first_task: asyncio.Task[ConsumedWebSocketTicket | None] | None = None
    second_task: asyncio.Task[ConsumedWebSocketTicket | None] | None = None
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(first)
        )
        issued = await first.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]

        original_first_open = first._open_websocket_ticket_connection
        original_second_open = second._open_websocket_ticket_connection
        first_proxy: _TicketConnectionProxy | None = None
        second_proxy: _TicketConnectionProxy | None = None

        async def open_first() -> Any:
            nonlocal first_proxy
            first_proxy = _TicketConnectionProxy(
                await original_first_open(),
                cas_entered=first_cas_won,
                cas_release=release_first,
            )
            return first_proxy

        async def open_second() -> Any:
            nonlocal second_proxy
            connection = await original_second_open()
            loop = asyncio.get_running_loop()

            def trace(statement: str) -> None:
                if " ".join(statement.upper().split()) == "BEGIN IMMEDIATE":
                    loop.call_soon_threadsafe(second_begin_submitted.set)

            await connection.set_trace_callback(trace)
            second_proxy = _TicketConnectionProxy(
                connection,
                begin_acquired=second_begin_acquired,
            )
            return second_proxy

        monkeypatch.setattr(
            first,
            "_open_websocket_ticket_connection",
            open_first,
        )
        monkeypatch.setattr(
            second,
            "_open_websocket_ticket_connection",
            open_second,
        )

        first_task = asyncio.create_task(
            first.consume_websocket_ticket(raw_ticket, campaign_id)
        )
        await asyncio.wait_for(first_cas_won.wait(), timeout=5)

        lock_probe = sqlite3.connect(path, timeout=0)
        writer_lock_observed = False
        try:
            try:
                lock_probe.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                writer_lock_observed = True
            else:
                lock_probe.rollback()
        finally:
            lock_probe.close()

        second_task = asyncio.create_task(
            second.consume_websocket_ticket(raw_ticket, campaign_id)
        )
        await asyncio.wait_for(second_begin_submitted.wait(), timeout=5)
        second_waiting = (
            not second_begin_acquired.is_set()
            and not second_task.done()
        )

        release_first.set()
        results = await asyncio.wait_for(
            asyncio.gather(first_task, second_task),
            timeout=10,
        )
        winner_count = sum(result is not None for result in results)
        durable_count = await _consumed_ticket_count(first)
        first_reusable = await first.conn.execute_fetchall("SELECT 1")
        second_reusable = await second.conn.execute_fetchall("SELECT 1")
        first_order = (
            tuple(first_proxy.statement_order)
            if first_proxy is not None
            else ()
        )
        second_order = (
            tuple(second_proxy.statement_order)
            if second_proxy is not None
            else ()
        )

        _require_fixed(
            writer_lock_observed,
            "first consumer did not hold the physical writer lock",
        )
        _require_fixed(
            second_waiting,
            "second consumer did not wait on the writer lock",
        )
        _require_fixed(winner_count == 1, "ticket did not have one consumer")
        _require_fixed(
            durable_count == 1,
            "ticket consumption was not durable exactly once",
        )
        _require_fixed(
            first_order
            == (
                "BEGIN IMMEDIATE",
                "CAS UPDATE",
                "HANDLE SELECT",
                "COMMIT",
            ),
            "winning ticket statement order changed",
        )
        _require_fixed(
            second_order
            == ("BEGIN IMMEDIATE", "CAS UPDATE", "COMMIT"),
            "losing ticket statement order changed",
        )
        _require_fixed(
            bool(first_reusable) and bool(second_reusable),
            "ticket contention left a connection unusable",
        )
        _require_fixed(
            not _owned_ticket_tasks(),
            "ticket operation left an owned task",
        )
    finally:
        release_first.set()
        pending = [
            task
            for task in (first_task, second_task)
            if task is not None and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await second.close()
        await first.close()


@pytest.mark.asyncio
async def test_sqlite_lifecycle_and_relative_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_cwd = Path.cwd()
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_directory.mkdir()
    second_directory.mkdir()
    database: AresDatabase | None = None
    try:
        monkeypatch.chdir(first_directory)
        database = AresDatabase("relative-ticket.db")
        with pytest.raises(RuntimeError):
            await database.issue_websocket_ticket(
                "campaign-before-connect",
                _bearer_source("user-before-connect", "before-connect"),
            )
        await database.connect()
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        monkeypatch.chdir(second_directory)
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "relative database identity changed")
        alternate_absent = not (second_directory / "relative-ticket.db").exists()
        _require_fixed(
            alternate_absent,
            "CWD change created an alternate database",
        )
        await database.close()
        with pytest.raises(RuntimeError):
            await database.consume_websocket_ticket(
                (issued or ("", 0))[0],
                campaign_id,
            )
    finally:
        if database is not None and database._conn is not None:
            await database.close()
        os.chdir(original_cwd)


@pytest.mark.asyncio
async def test_sqlite_transaction_order_contains_required_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-order.db")
    statements: list[str] = []
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        original_open = database._open_websocket_ticket_connection

        async def traced_open() -> Any:
            connection = await original_open()

            def trace(statement: str) -> None:
                normalized = " ".join(statement.upper().split())
                if normalized == "BEGIN IMMEDIATE":
                    statements.append("BEGIN IMMEDIATE")
                elif normalized.startswith("UPDATE WEBSOCKET_TICKETS"):
                    statements.append("CAS UPDATE")
                elif (
                    normalized.startswith("SELECT ")
                    and "FROM WEBSOCKET_TICKETS" in normalized
                ):
                    statements.append("HANDLE SELECT")
                elif normalized == "COMMIT":
                    statements.append("COMMIT")

            await connection.set_trace_callback(trace)
            return connection

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            traced_open,
        )
        consumed = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(consumed is not None, "traced consume failed")
        _require_fixed(
            tuple(statements)
            == ("BEGIN IMMEDIATE", "CAS UPDATE", "HANDLE SELECT", "COMMIT"),
            "ticket transaction statement order changed",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_cancellation_before_commit_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-cancel-before.db")
    entered = asyncio.Event()
    release = asyncio.Event()
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_purge = database._purge_websocket_ticket_rows

        async def paused_purge(connection: Any) -> int:
            count = await original_purge(connection)
            entered.set()
            await asyncio.wait_for(release.wait(), timeout=5)
            return count

        monkeypatch.setattr(
            database,
            "_purge_websocket_ticket_rows",
            paused_purge,
        )
        task = asyncio.create_task(
            database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=5)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)

        connection = database._require_connected()
        async with connection.execute(
            "SELECT COUNT(*) AS count FROM websocket_tickets"
        ) as cursor:
            count = int((await cursor.fetchone())["count"])
        _require_fixed(count == 0, "pre-commit cancellation persisted a ticket")
        _require_fixed(
            not _owned_ticket_tasks(),
            "pre-commit cancellation left an owned task",
        )
    finally:
        release.set()
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_cancellation_after_real_commit_returns_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-cancel-commit.db")
    commit_started = asyncio.Event()
    release_commit = threading.Event()
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_open = database._open_websocket_ticket_connection
        loop = asyncio.get_running_loop()

        async def traced_open() -> Any:
            connection = await original_open()

            def trace(statement: str) -> None:
                if " ".join(statement.upper().split()) == "COMMIT":
                    loop.call_soon_threadsafe(commit_started.set)
                    release_commit.wait(timeout=5)

            await connection.set_trace_callback(trace)
            return connection

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            traced_open,
        )
        task = asyncio.create_task(
            database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
        )
        await asyncio.wait_for(commit_started.wait(), timeout=5)
        baseline = task.cancelling()
        task.cancel()
        release_commit.set()
        result = await asyncio.wait_for(task, timeout=5)
        normalized = (
            result is not None
            and not task.cancelled()
            and task.cancelling() == baseline
        )
        _require_fixed(
            normalized,
            "post-commit cancellation was not normalized",
        )
        _require_fixed(
            not _owned_ticket_tasks(),
            "post-commit cancellation left an owned task",
        )
    finally:
        release_commit.set()
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_consume_cancellation_after_real_cas_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-cancel-cas.db")
    cas_won = asyncio.Event()
    release = asyncio.Event()
    consume_task: asyncio.Task[ConsumedWebSocketTicket | None] | None = None
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        original_open = database._open_websocket_ticket_connection

        async def open_paused() -> Any:
            return _TicketConnectionProxy(
                await original_open(),
                cas_entered=cas_won,
                cas_release=release,
            )

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            open_paused,
        )
        consume_task = asyncio.create_task(
            database.consume_websocket_ticket(raw_ticket, campaign_id)
        )
        await asyncio.wait_for(cas_won.wait(), timeout=5)
        consume_task.cancel()
        release.set()
        cancelled = False
        try:
            await asyncio.wait_for(consume_task, timeout=5)
        except asyncio.CancelledError:
            cancelled = True

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            original_open,
        )
        durable_before_retry = await _consumed_ticket_count(database)
        retry = await database.consume_websocket_ticket(
            raw_ticket,
            campaign_id,
        )
        _require_fixed(cancelled, "consume cancellation did not propagate")
        _require_fixed(
            durable_before_retry == 0,
            "cancelled consume committed the CAS",
        )
        _require_fixed(retry is not None, "cancelled consume did not recover")
        _require_fixed(
            not _owned_ticket_tasks(),
            "cancelled consume left an owned task",
        )
    finally:
        release.set()
        if consume_task is not None and not consume_task.done():
            consume_task.cancel()
            await asyncio.gather(consume_task, return_exceptions=True)
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_repeated_commit_cancellation_preserves_existing_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-cancel-debt.db")
    commit_started = asyncio.Event()
    release_commit = threading.Event()
    task: asyncio.Task[Any] | None = None
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_open = database._open_websocket_ticket_connection
        loop = asyncio.get_running_loop()

        async def traced_open() -> Any:
            connection = await original_open()

            def trace(statement: str) -> None:
                if " ".join(statement.upper().split()) == "COMMIT":
                    loop.call_soon_threadsafe(commit_started.set)
                    release_commit.wait(timeout=5)

            await connection.set_trace_callback(trace)
            return connection

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            traced_open,
        )

        async def issue_with_existing_debt() -> tuple[Any, int, int]:
            current = asyncio.current_task()
            if current is None:
                raise RuntimeError("ticket cancellation task is unavailable")
            current.cancel()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass
            entry_debt = current.cancelling()
            try:
                result = await database.issue_websocket_ticket(
                    campaign_id,
                    _bearer_source(user_id, username),
                )
                return result, entry_debt, current.cancelling()
            finally:
                while current.cancelling():
                    current.uncancel()

        task = asyncio.create_task(issue_with_existing_debt())
        await asyncio.wait_for(commit_started.wait(), timeout=5)
        before_new_cancellations = task.cancelling()
        task.cancel()
        task.cancel()
        release_commit.set()
        result, entry_debt, final_debt = await asyncio.wait_for(
            task,
            timeout=5,
        )

        _require_fixed(result is not None, "committed ticket result was lost")
        _require_fixed(
            before_new_cancellations == entry_debt == final_debt == 1,
            "commit normalization changed pre-existing cancellation debt",
        )
        _require_fixed(
            task.cancelling() == 0,
            "test cancellation debt was not settled",
        )
        _require_fixed(
            not _owned_ticket_tasks(),
            "repeated cancellation left an owned task",
        )
    finally:
        release_commit.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_rollback_cleanup_failure_preserves_primary_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-rollback-error.db")
    warnings: list[tuple[object, object]] = []

    class PrimaryTicketError(RuntimeError):
        pass

    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_open = database._open_websocket_ticket_connection

        async def open_with_failing_rollback() -> Any:
            connection = await original_open()
            original_rollback = connection.rollback

            async def rollback_then_fail() -> None:
                await original_rollback()
                raise RuntimeError("synthetic cleanup failure")

            monkeypatch.setattr(connection, "rollback", rollback_then_fail)
            return connection

        async def fail_operation(_connection: Any) -> int:
            raise PrimaryTicketError("synthetic primary failure")

        def record_warning(_event: str, **values: object) -> None:
            warnings.append(
                (values.get("action"), values.get("error_type"))
            )

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            open_with_failing_rollback,
        )
        monkeypatch.setattr(
            database,
            "_purge_websocket_ticket_rows",
            fail_operation,
        )
        with patch.object(
            database_module.logger,
            "warning",
            record_warning,
        ):
            caught_type: type[BaseException] | None = None
            try:
                await database.issue_websocket_ticket(
                    campaign_id,
                    _bearer_source(user_id, username),
                )
            except BaseException as exc:
                caught_type = type(exc)

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            original_open,
        )
        monkeypatch.undo()
        recovered = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        cleanup_recorded = (
            ("rollback-before-commit", "RuntimeError") in warnings
        )

        _require_fixed(
            caught_type is PrimaryTicketError,
            "cleanup failure replaced the primary ticket failure",
        )
        _require_fixed(
            cleanup_recorded,
            "rollback cleanup failure was not sanitized",
        )
        _require_fixed(recovered is not None, "rollback failure blocked recovery")
        _require_fixed(
            not _owned_ticket_tasks(),
            "rollback failure left an owned task",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_close_cleanup_failure_keeps_committed_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-close-error.db")
    warnings: list[tuple[object, object]] = []
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_open = database._open_websocket_ticket_connection

        async def open_with_failing_close() -> Any:
            connection = await original_open()
            original_close = connection.close

            async def close_then_fail() -> None:
                await original_close()
                raise RuntimeError("synthetic cleanup failure")

            monkeypatch.setattr(connection, "close", close_then_fail)
            return connection

        def record_warning(_event: str, **values: object) -> None:
            warnings.append(
                (values.get("action"), values.get("error_type"))
            )

        monkeypatch.setattr(
            database,
            "_open_websocket_ticket_connection",
            open_with_failing_close,
        )
        with patch.object(
            database_module.logger,
            "warning",
            record_warning,
        ):
            issued = await database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
        close_recorded = ("close", "RuntimeError") in warnings

        _require_fixed(issued is not None, "close failure lost committed result")
        _require_fixed(
            await _ticket_count(database) == 1,
            "close failure changed committed ticket state",
        )
        _require_fixed(
            close_recorded,
            "close cleanup failure was not sanitized",
        )
        _require_fixed(
            not _owned_ticket_tasks(),
            "close failure left an owned task",
        )
    finally:
        await database.close()


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.asyncio
async def test_sqlite_ticket_control_flow_exceptions_propagate_and_recover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[BaseException],
) -> None:
    database = await _connected_database(
        tmp_path / f"ticket-control-{error_type.__name__}.db"
    )
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_purge = database._purge_websocket_ticket_rows

        async def raise_control_flow(_connection: Any) -> int:
            raise error_type()

        monkeypatch.setattr(
            database,
            "_purge_websocket_ticket_rows",
            raise_control_flow,
        )
        caught_type: type[BaseException] | None = None
        try:
            await database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
        except BaseException as exc:
            caught_type = type(exc)
        monkeypatch.setattr(
            database,
            "_purge_websocket_ticket_rows",
            original_purge,
        )
        recovered = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )

        _require_fixed(
            caught_type is error_type,
            "control-flow exception was converted or replaced",
        )
        _require_fixed(recovered is not None, "control-flow failure blocked recovery")
        _require_fixed(
            not _owned_ticket_tasks(),
            "control-flow failure left an owned task",
        )
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_sqlite_purge_uses_protected_transaction_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = await _connected_database(tmp_path / "ticket-purge-tx.db")
    try:
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        digest = hash_websocket_ticket((issued or ("", 0))[0])
        await database.conn.execute(
            "UPDATE websocket_tickets "
            "SET expires_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now') "
            "WHERE ticket_hash=?",
            (digest,),
        )
        await database.conn.commit()
        original_commit = database._commit_websocket_ticket_operation

        async def fail_commit(_connection: Any) -> None:
            raise RuntimeError("synthetic commit failure")

        monkeypatch.setattr(
            database,
            "_commit_websocket_ticket_operation",
            fail_commit,
        )
        failed = False
        try:
            await database.purge_expired_websocket_tickets()
        except RuntimeError:
            failed = True
        retained = await _ticket_count(database)
        monkeypatch.setattr(
            database,
            "_commit_websocket_ticket_operation",
            original_commit,
        )
        purged = await database.purge_expired_websocket_tickets()
        remaining = await _ticket_count(database)

        _require_fixed(failed, "purge commit failure did not propagate")
        _require_fixed(retained == 1, "failed purge committed a deletion")
        _require_fixed(purged == 1, "recovered purge count changed")
        _require_fixed(remaining == 0, "recovered purge left an expired row")
    finally:
        await database.close()
