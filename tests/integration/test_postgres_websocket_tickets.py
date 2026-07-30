"""Real PostgreSQL integration coverage for one-time WebSocket tickets."""
from __future__ import annotations

import asyncio
import contextlib
import multiprocessing
import os
import re
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import quote
from uuid import uuid4

import pytest

from ares.db import postgres as postgres_module
from ares.db.postgres import PostgresDatabase
from ares.db.websocket_tickets import (
    ApiKeyTicketSource,
    BearerTicketSource,
    WebSocketTicketCredentialKind,
    generate_websocket_ticket,
    hash_websocket_ticket,
)

_POSTGRES_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_SAFE_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]+$")
_SAFE_EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POSTGRES_OPERATION_TIMEOUT_SECONDS = 15.0
_MIGRATION_PROCESS_TIMEOUT_SECONDS = 45.0
_MIGRATION_ACTIONS = frozenset({"upgrade", "downgrade"})
_MIGRATION_REVISIONS = frozenset({"0006", "0007"})
_OWNED_MIGRATION_PROCESSES: set[Any] = set()


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class _PostgresHarness:
    database: PostgresDatabase = field(repr=False)
    database_name: str = field(repr=False)


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _postgres_test_config() -> dict[str, str | int]:
    present = {name for name in _POSTGRES_ENV if name in os.environ}
    if not present:
        pytest.skip("real PostgreSQL test environment is not configured")
    if present != set(_POSTGRES_ENV):
        pytest.fail(
            "Incomplete PostgreSQL test environment",
            pytrace=False,
        )
    values = {name: os.environ[name] for name in _POSTGRES_ENV}
    if any(not value or value != value.strip() for value in values.values()):
        pytest.fail("Invalid PostgreSQL test environment", pytrace=False)
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if re.fullmatch(r"[1-9][0-9]{0,4}", raw_port) is None:
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    port = int(raw_port)
    if not 1 <= port <= 65535:
        pytest.fail("PostgreSQL test port is outside its valid range", pytrace=False)
    return {
        "host": values["ARES_TEST_POSTGRES_HOST"],
        "port": port,
        "user": values["ARES_TEST_POSTGRES_USER"],
        "database": values["ARES_TEST_POSTGRES_DB"],
    }


def _runtime_dsn(config: dict[str, str | int], database: str) -> str:
    host = str(config["host"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return (
        "postgresql://"
        f"{quote(str(config['user']), safe='')}@"
        f"{host}:{config['port']}/"
        f"{quote(database, safe='')}"
    )


def _database_for_target(
    database_name: str,
    *,
    pool_min: int = 1,
    pool_max: int = 2,
) -> PostgresDatabase:
    return PostgresDatabase(
        _runtime_dsn(_postgres_test_config(), database_name),
        pool_min=pool_min,
        pool_max=pool_max,
    )


def _set_complete_postgres_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARES_TEST_POSTGRES_HOST", "127.0.0.1")
    monkeypatch.setenv("ARES_TEST_POSTGRES_PORT", "5432")
    monkeypatch.setenv("ARES_TEST_POSTGRES_USER", "synthetic_runner")
    monkeypatch.setenv("ARES_TEST_POSTGRES_DB", "synthetic_control")


def test_ticket_postgres_config_skips_only_when_canonical_names_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _POSTGRES_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARES_TEST_POSTGRES_DATABASE", "ignored_alias")
    monkeypatch.setenv("ARES_DATABASE_URL", "ignored_fallback")
    skipped = False
    try:
        _postgres_test_config()
    except pytest.skip.Exception:
        skipped = True
    _require_fixed(
        skipped,
        "noncanonical PostgreSQL configuration prevented the intentional skip",
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("ARES_TEST_POSTGRES_HOST", "", id="empty-host"),
        pytest.param("ARES_TEST_POSTGRES_HOST", " ", id="blank-host"),
        pytest.param("ARES_TEST_POSTGRES_HOST", " host", id="padded-host"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "not-a-port", id="invalid-port"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "+5432", id="signed-port"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "05432", id="leading-zero-port"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "５４３２", id="unicode-port"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "0", id="low-port"),
        pytest.param("ARES_TEST_POSTGRES_PORT", "65536", id="high-port"),
        pytest.param("ARES_TEST_POSTGRES_USER", "", id="empty-user"),
        pytest.param("ARES_TEST_POSTGRES_DB", " ", id="blank-database"),
    ],
)
def test_ticket_postgres_config_rejects_present_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    _set_complete_postgres_config(monkeypatch)
    monkeypatch.setenv(name, value)
    failed = False
    try:
        _postgres_test_config()
    except pytest.fail.Exception:
        failed = True
    _require_fixed(failed, "invalid PostgreSQL configuration was accepted")


def test_ticket_postgres_config_rejects_partial_presence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _POSTGRES_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARES_TEST_POSTGRES_HOST", "127.0.0.1")
    failed = False
    try:
        _postgres_test_config()
    except pytest.fail.Exception:
        failed = True
    _require_fixed(failed, "partial PostgreSQL configuration was accepted")


def test_ticket_postgres_config_accepts_complete_canonical_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_complete_postgres_config(monkeypatch)
    config = _postgres_test_config()
    reduced = (
        set(config) == {"host", "port", "user", "database"}
        and config["port"] == 5432
        and all(config[name] for name in ("host", "user", "database"))
    )
    _require_fixed(reduced, "complete canonical PostgreSQL configuration was rejected")


def test_ticket_harness_representation_is_secret_safe() -> None:
    marker = "synthetic-confidential-marker"
    harness = _PostgresHarness(
        database=PostgresDatabase(marker),
        database_name=f"ares_ws_ticket_{uuid4().hex}",
    )
    marker_absent = marker not in repr(harness)
    _require_fixed(marker_absent, "PostgreSQL harness representation exposed state")


class _StartupPool:
    def __init__(self) -> None:
        self.close_count = 0

    async def close(self) -> None:
        self.close_count += 1


@pytest.mark.asyncio
async def test_postgres_connect_closes_failed_pool_and_can_recover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pools = (_StartupPool(), _StartupPool())
    pool_index = 0

    async def _create_pool(*_args: object, **_kwargs: object) -> _StartupPool:
        nonlocal pool_index
        selected = pools[pool_index]
        pool_index += 1
        return selected

    primary = RuntimeError()
    initialization_count = 0

    async def _initialize() -> None:
        nonlocal initialization_count
        initialization_count += 1
        if initialization_count == 1:
            raise primary

    monkeypatch.setitem(
        sys.modules,
        "asyncpg",
        SimpleNamespace(create_pool=_create_pool),
    )
    database = PostgresDatabase("synthetic")
    database._init_schema = _initialize
    observed: BaseException | None = None
    with patch.object(postgres_module.logger, "info", return_value=None):
        try:
            await database.connect()
        except Exception as exc:
            observed = exc
        first_state = (
            observed is primary
            and pools[0].close_count == 1
            and database._pool is None
        )
        recovered = await database.connect()
        await database.close()
    recovered_state = (
        recovered is database
        and database._pool is pools[1]
        and pools[1].close_count == 1
        and initialization_count == 2
    )
    _require_fixed(
        first_state and recovered_state,
        "PostgreSQL startup pool cleanup/recovery contract failed",
    )


@pytest.mark.parametrize(
    ("first", "terminal", "exit_code", "eof"),
    [
        pytest.param(("OK",), ("OK",), 0, True, id="ok-before-ready"),
        pytest.param(("READY",), ("READY",), 0, True, id="duplicate-ready"),
        pytest.param(("READY",), ("ERROR", "RuntimeError"), 0, True, id="error"),
        pytest.param(("READY",), ("OK",), 1, True, id="success-then-crash"),
        pytest.param(("READY",), ("OK",), 0, False, id="trailing-frame"),
        pytest.param(("READY", "extra"), ("OK",), 0, True, id="malformed-ready"),
        pytest.param(("READY",), ("OK", "extra"), 0, True, id="malformed-terminal"),
    ],
)
def test_ticket_migration_protocol_rejects_invalid_sequences(
    first: object,
    terminal: object,
    exit_code: object,
    eof: bool,
) -> None:
    accepted = _migration_protocol_succeeded(first, terminal, exit_code, eof)
    _require_fixed(not accepted, "invalid migration child protocol was accepted")


def test_ticket_migration_protocol_accepts_one_complete_sequence() -> None:
    accepted = _migration_protocol_succeeded(
        ("READY",),
        ("OK",),
        0,
        True,
    )
    _require_fixed(accepted, "valid migration child protocol was rejected")


def _sanitized_exception_type(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if _SAFE_EXCEPTION_TYPE.fullmatch(name) else "Exception"


def test_ticket_migration_exception_type_is_reduced_to_a_safe_frame() -> None:
    unsafe_exception = type("unsafe exception", (Exception,), {})
    reduced = _sanitized_exception_type(unsafe_exception())
    _require_fixed(
        reduced == "Exception",
        "migration child exception type was not sanitized",
    )


class _SettlementProcess:
    def __init__(self, states: tuple[bool, ...]) -> None:
        self._states = list(states)
        self._last_state = states[-1]
        self.actions: list[str] = []

    def is_alive(self) -> bool:
        if self._states:
            self._last_state = self._states.pop(0)
        return self._last_state

    def terminate(self) -> None:
        self.actions.append("terminate")

    def kill(self) -> None:
        self.actions.append("kill")

    def join(self, *, timeout: int) -> None:
        self.actions.append(f"join-{timeout}")


def test_ticket_migration_settlement_escalates_to_kill() -> None:
    process = _SettlementProcess((True, True, False))
    settled = _settle_migration_process(process)
    _require_fixed(
        settled
        and tuple(process.actions)
        == ("terminate", "join-2", "kill", "join-2"),
        "migration child settlement did not use the bounded escalation order",
    )


def test_ticket_migration_settlement_refuses_unproved_death() -> None:
    process = _SettlementProcess((True, True, True))
    settled = _settle_migration_process(process)
    _require_fixed(
        not settled,
        "migration child settlement accepted a live process",
    )


def _sanitized_setup_failure(action: str, exc: Exception) -> RuntimeError:
    return RuntimeError(
        f"PostgreSQL ticket setup failed [{action}: {type(exc).__name__}]"
    )


async def _bounded_operation(
    action: str,
    operation: Awaitable[Any],
) -> Any:
    try:
        return await asyncio.wait_for(
            operation,
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise _sanitized_setup_failure(action, exc) from None


async def _attempt_cleanup(
    action: str,
    cleanup: Callable[[], Awaitable[object]],
    failures: list[str],
) -> None:
    try:
        await asyncio.wait_for(
            cleanup(),
            timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        failures.append(f"{action}: {type(exc).__name__}")


def _migration_child_config() -> dict[str, str | int]:
    if any(name not in os.environ for name in _POSTGRES_ENV):
        raise RuntimeError()
    values = {name: os.environ[name] for name in _POSTGRES_ENV}
    if any(not value or value != value.strip() for value in values.values()):
        raise RuntimeError()
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if re.fullmatch(r"[1-9][0-9]{0,4}", raw_port) is None:
        raise RuntimeError()
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise RuntimeError()
    return {
        "host": values["ARES_TEST_POSTGRES_HOST"],
        "port": port,
        "user": values["ARES_TEST_POSTGRES_USER"],
        "database": values["ARES_TEST_POSTGRES_DB"],
    }


def _ticket_migration_child(
    database_name: str,
    action: str,
    revision: str,
    control: Any,
) -> None:
    terminal_sent = False
    ready_sent = False
    devnull = -1
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)

        from alembic import command
        from alembic.config import Config

        if (
            _SAFE_DATABASE_NAME.fullmatch(database_name) is None
            or not database_name.startswith("ares_ws_ticket_")
            or action not in _MIGRATION_ACTIONS
            or revision not in _MIGRATION_REVISIONS
        ):
            raise RuntimeError()
        config_values = _migration_child_config()
        migration_url = _runtime_dsn(
            config_values,
            database_name,
        ).replace("postgresql://", "postgresql+asyncpg://", 1)
        alembic_config = Config("alembic.ini")
        alembic_config.cmd_opts = SimpleNamespace(
            x=[f"db_url={migration_url}"],
        )
        migration_action = getattr(command, action)
        control.send(("READY",))
        ready_sent = True
        if control.recv() != ("GO",):
            raise RuntimeError()
        migration_action(alembic_config, revision)
        control.send(("OK",))
        terminal_sent = True
    except Exception as exc:
        if not terminal_sent:
            frame = "ERROR" if ready_sent else "SETUP_ERROR"
            with contextlib.suppress(Exception):
                control.send((frame, _sanitized_exception_type(exc)))
    finally:
        if devnull >= 0:
            with contextlib.suppress(OSError):
                os.close(devnull)
        with contextlib.suppress(Exception):
            control.close()


def _process_is_alive(process: Any) -> bool | None:
    try:
        return bool(process.is_alive())
    except (AssertionError, ValueError):
        return None


def _settle_migration_process(process: Any) -> bool:
    alive = _process_is_alive(process)
    if alive is None:
        return getattr(process, "pid", None) is None
    if alive:
        process.terminate()
        process.join(timeout=2)
        alive = _process_is_alive(process)
    if alive:
        process.kill()
        process.join(timeout=2)
        alive = _process_is_alive(process)
    return alive is False


def _migration_protocol_succeeded(
    first: object,
    terminal: object,
    exit_code: object,
    eof: bool,
) -> bool:
    return (
        first == ("READY",)
        and terminal == ("OK",)
        and exit_code == 0
        and eof
    )


def _run_ticket_migration(
    database_name: str,
    action: str,
    revision: str,
) -> None:
    context = multiprocessing.get_context("spawn")
    parent = None
    child = None
    process = None
    start_attempted = False
    completed = False
    try:
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_ticket_migration_child,
            args=(database_name, action, revision, child),
        )
        _OWNED_MIGRATION_PROCESSES.add(process)
        start_attempted = True
        process.start()
        child.close()
        if not parent.poll(_MIGRATION_PROCESS_TIMEOUT_SECONDS):
            raise RuntimeError("PostgreSQL ticket migration process timed out")
        first = parent.recv()
        if first != ("READY",):
            raise RuntimeError("PostgreSQL ticket migration setup failed")
        parent.send(("GO",))
        if not parent.poll(_MIGRATION_PROCESS_TIMEOUT_SECONDS):
            raise RuntimeError("PostgreSQL ticket migration process timed out")
        terminal = parent.recv()
        process.join(timeout=2)
        if process.is_alive():
            raise RuntimeError("PostgreSQL ticket migration process did not exit")
        eof = False
        if parent.poll(1):
            try:
                parent.recv()
            except EOFError:
                eof = True
        completed = _migration_protocol_succeeded(
            first,
            terminal,
            process.exitcode,
            eof,
        )
        if not completed:
            raise RuntimeError("PostgreSQL ticket migration action failed")
    finally:
        settled = process is None
        if process is not None:
            if completed:
                settled = _process_is_alive(process) is False
            elif start_attempted:
                settled = _settle_migration_process(process)
            if not settled:
                raise RuntimeError(
                    "PostgreSQL ticket migration process could not be settled"
                ) from None
        if parent is not None:
            with contextlib.suppress(Exception):
                parent.close()
        if child is not None:
            with contextlib.suppress(Exception):
                child.close()
        if process is not None and settled:
            with contextlib.suppress(Exception):
                process.close()
            _OWNED_MIGRATION_PROCESSES.discard(process)


@asynccontextmanager
async def _postgres_harness(
    *,
    initialize_runtime: bool = True,
) -> AsyncIterator[_PostgresHarness]:
    config = _postgres_test_config()
    try:
        import asyncpg
    except ImportError:
        pytest.fail(
            "asyncpg is required for configured PostgreSQL tests",
            pytrace=False,
        )

    test_database = f"ares_ws_ticket_{uuid4().hex}"
    _require_fixed(
        _SAFE_DATABASE_NAME.fullmatch(test_database) is not None,
        "generated PostgreSQL database identifier was unsafe",
    )
    _require_fixed(
        test_database != config["database"],
        "generated PostgreSQL database identifier collided",
    )

    admin = None
    database = None
    creation_attempted = False
    cleanup_failures: list[str] = []
    try:
        try:
            admin = await _bounded_operation(
                "admin-connect",
                asyncpg.connect(
                    host=config["host"],
                    port=config["port"],
                    user=config["user"],
                    database=config["database"],
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                ),
            )
        except Exception as exc:
            raise _sanitized_setup_failure("admin-connect", exc) from None

        creation_attempted = True
        try:
            await _bounded_operation(
                "database-create",
                admin.execute(f'CREATE DATABASE "{test_database}"'),
            )
        except Exception as exc:
            raise _sanitized_setup_failure("database-create", exc) from None

        dsn = _runtime_dsn(config, test_database)
        database = PostgresDatabase(dsn, pool_min=1, pool_max=8)
        if initialize_runtime:
            try:
                await _bounded_operation(
                    "runtime-initialize",
                    database.connect(),
                )
            except Exception as exc:
                raise _sanitized_setup_failure("runtime-initialize", exc) from None
        yield _PostgresHarness(
            database=database,
            database_name=test_database,
        )
    finally:
        primary_failure = sys.exception()
        workers_unsettled = bool(_OWNED_MIGRATION_PROCESSES)
        if workers_unsettled:
            cleanup_failures.append("migration-worker: UnsettledProcess")
        if database is not None:
            await _attempt_cleanup(
                "close-runtime-pool",
                database.close,
                cleanup_failures,
            )
        if creation_attempted and admin is not None and not workers_unsettled:

            async def _drop_database() -> None:
                await admin.execute(
                    f'DROP DATABASE IF EXISTS "{test_database}" WITH (FORCE)'
                )

            await _attempt_cleanup(
                "drop-test-database",
                _drop_database,
                cleanup_failures,
            )
        if admin is not None:
            await _attempt_cleanup(
                "close-admin-connection",
                admin.close,
                cleanup_failures,
            )
        if cleanup_failures:
            if primary_failure is not None:
                for failure in cleanup_failures:
                    primary_failure.add_note(
                        f"PostgreSQL ticket cleanup failure [{failure}]"
                    )
            else:
                raise RuntimeError(
                    "PostgreSQL ticket cleanup failed: "
                    + "; ".join(cleanup_failures)
                ) from None


async def _seed_identity(
    database: PostgresDatabase,
    *,
    scopes: str = "read",
) -> tuple[str, str, str, str, str]:
    username = f"ws_ticket_{uuid4().hex}"
    original_info = postgres_module.logger.info

    def _suppress_identity_log(event: str, **values: object) -> Any:
        if event == "user_created":
            return None
        return original_info(event, **values)

    with patch.object(
        postgres_module.logger,
        "info",
        new=_suppress_identity_log,
    ):
        user_id = await database.create_user(
            username,
            "synthetic-test-password",
            "operator",
        )
    campaign_id = f"campaign-{uuid4().hex}"
    other_campaign_id = f"campaign-{uuid4().hex}"
    async with database._pool.acquire() as connection:
        await connection.executemany(
            """
            INSERT INTO campaigns(id, name, operator)
            VALUES($1, $2, $3)
            """,
            (
                (campaign_id, "Ticket campaign", username),
                (other_campaign_id, "Other campaign", username),
            ),
        )
    api_key_id = (
        await database.create_api_key(
            user_id,
            "ticket-key",
            scopes=scopes,
        )
    )[0]
    return user_id, username, campaign_id, other_campaign_id, api_key_id


def _bearer_source(user_id: str, username: str) -> BearerTicketSource:
    return BearerTicketSource(
        user_id=user_id,
        subject=username,
        jti=f"ticket-jti-{uuid4().hex}",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


_EXPECTED_TICKET_COLUMNS = (
    ("ticket_hash", "text", True, "", "", True, None),
    ("campaign_id", "text", True, "", "", True, None),
    ("user_id", "text", True, "", "", True, None),
    ("credential_kind", "text", True, "", "", True, None),
    ("bearer_subject", "text", False, "", "", True, None),
    ("bearer_jti", "text", False, "", "", True, None),
    (
        "bearer_expires_at",
        "timestamp with time zone",
        False,
        "",
        "",
        True,
        None,
    ),
    ("api_key_id", "text", False, "", "", True, None),
    ("required_scope", "text", False, "", "", True, None),
    (
        "created_at",
        "timestamp with time zone",
        True,
        "",
        "",
        True,
        None,
    ),
    (
        "expires_at",
        "timestamp with time zone",
        True,
        "",
        "",
        True,
        None,
    ),
    (
        "consumed_at",
        "timestamp with time zone",
        False,
        "",
        "",
        True,
        None,
    ),
)

_EXPECTED_TICKET_CHECKS = (
    (
        "ck_ws_ticket_bearer_expires_finite",
        "CHECK (bearer_expires_at IS NULL OR isfinite(bearer_expires_at))",
    ),
    (
        "ck_ws_ticket_consumed_at",
        "CHECK (consumed_at IS NULL OR consumed_at < expires_at)",
    ),
    (
        "ck_ws_ticket_consumed_finite",
        "CHECK (consumed_at IS NULL OR isfinite(consumed_at))",
    ),
    ("ck_ws_ticket_created_at", "CHECK (created_at < expires_at)"),
    ("ck_ws_ticket_created_finite", "CHECK (isfinite(created_at))"),
    ("ck_ws_ticket_expires_at", "CHECK (expires_at > created_at)"),
    ("ck_ws_ticket_expires_finite", "CHECK (isfinite(expires_at))"),
    (
        "ck_ws_ticket_hash",
        "CHECK (ticket_hash ~ '^[0-9a-f]{64}$'::text)",
    ),
    (
        "ck_ws_ticket_kind",
        "CHECK (credential_kind = ANY "
        "(ARRAY['bearer'::text, 'api_key'::text]))",
    ),
    (
        "ck_ws_ticket_source_shape",
        "CHECK (credential_kind = 'bearer'::text "
        "AND bearer_subject IS NOT NULL "
        "AND length(btrim(bearer_subject)) > 0 "
        "AND bearer_subject = btrim(bearer_subject) "
        "AND bearer_jti IS NOT NULL "
        "AND length(btrim(bearer_jti)) > 0 "
        "AND bearer_jti = btrim(bearer_jti) "
        "AND bearer_expires_at IS NOT NULL "
        "AND api_key_id IS NULL "
        "AND required_scope IS NULL "
        "OR credential_kind = 'api_key'::text "
        "AND bearer_subject IS NULL "
        "AND bearer_jti IS NULL "
        "AND bearer_expires_at IS NULL "
        "AND api_key_id IS NOT NULL "
        "AND length(btrim(api_key_id)) > 0 "
        "AND api_key_id = btrim(api_key_id) "
        "AND required_scope = 'read'::text)",
    ),
    (
        "ck_ws_ticket_time_order",
        "CHECK (expires_at > created_at AND "
        "(consumed_at IS NULL OR consumed_at < expires_at))",
    ),
)

_EXPECTED_TICKET_FOREIGN_KEYS = (
    (
        "fk_ws_ticket_api_key",
        ("api_key_id",),
        "api_keys",
        ("id",),
        "a",
        "c",
    ),
    (
        "fk_ws_ticket_campaign",
        ("campaign_id",),
        "campaigns",
        ("id",),
        "a",
        "c",
    ),
    (
        "fk_ws_ticket_user",
        ("user_id",),
        "users",
        ("id",),
        "a",
        "c",
    ),
)

_EXPECTED_TICKET_INDEXES = (
    (
        "idx_ws_tickets_api_key",
        "btree",
        False,
        False,
        True,
        True,
        True,
        1,
        1,
        ("api_key_id",),
        (0,),
        ("text_ops",),
        (True,),
        None,
        None,
    ),
    (
        "idx_ws_tickets_campaign",
        "btree",
        False,
        False,
        True,
        True,
        True,
        1,
        1,
        ("campaign_id",),
        (0,),
        ("text_ops",),
        (True,),
        None,
        None,
    ),
    (
        "idx_ws_tickets_expires",
        "btree",
        False,
        False,
        True,
        True,
        True,
        1,
        1,
        ("expires_at",),
        (0,),
        ("timestamptz_ops",),
        (True,),
        None,
        None,
    ),
    (
        "idx_ws_tickets_user",
        "btree",
        False,
        False,
        True,
        True,
        True,
        1,
        1,
        ("user_id",),
        (0,),
        ("text_ops",),
        (True,),
        None,
        None,
    ),
    (
        "websocket_tickets_pkey",
        "btree",
        True,
        True,
        True,
        True,
        True,
        1,
        1,
        ("ticket_hash",),
        (0,),
        ("text_ops",),
        (True,),
        None,
        None,
    ),
)

_EXPECTED_TICKET_INDEX_IDENTITIES = (
    (
        "idx_ws_tickets_api_key",
        "i",
        "p",
        False,
        ("text_ops",),
        ("pg_catalog",),
    ),
    (
        "idx_ws_tickets_campaign",
        "i",
        "p",
        False,
        ("text_ops",),
        ("pg_catalog",),
    ),
    (
        "idx_ws_tickets_expires",
        "i",
        "p",
        False,
        ("timestamptz_ops",),
        ("pg_catalog",),
    ),
    (
        "idx_ws_tickets_user",
        "i",
        "p",
        False,
        ("text_ops",),
        ("pg_catalog",),
    ),
    (
        "websocket_tickets_pkey",
        "i",
        "p",
        False,
        ("text_ops",),
        ("pg_catalog",),
    ),
)


async def _ticket_catalog_fingerprint(connection: Any) -> dict[str, object]:
    relation = await connection.fetchrow(
        """
        SELECT rel.oid::bigint AS table_oid,
               nsp.oid::bigint AS schema_oid,
               nsp.nspname AS schema_name,
               rel.relkind,
               rel.relpersistence,
               rel.relispartition,
               rel.relrowsecurity,
               rel.relforcerowsecurity,
               (
                   SELECT COUNT(*) FROM pg_inherits AS inherited
                   WHERE inherited.inhrelid=rel.oid
               ) AS parent_count,
               (
                   SELECT COUNT(*) FROM pg_inherits AS inherited
                   WHERE inherited.inhparent=rel.oid
               ) AS child_count,
               (
                   SELECT COUNT(*) FROM pg_policy AS policy
                   WHERE policy.polrelid=rel.oid
               ) AS policy_count,
               (
                   SELECT COUNT(*) FROM pg_trigger AS trg
                   WHERE trg.tgrelid=rel.oid
                     AND NOT trg.tgisinternal
               ) AS user_trigger_count,
               (
                   SELECT COUNT(*) FROM pg_rewrite AS rewrite
                   WHERE rewrite.ev_class=rel.oid
               ) AS user_rule_count
        FROM pg_class AS rel
        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
        WHERE nsp.nspname=current_schema()
          AND rel.relname='websocket_tickets'
        """
    )
    if relation is None:
        return {"relation": None}
    table_oid = int(relation["table_oid"])
    schema_oid = int(relation["schema_oid"])
    column_rows = await connection.fetch(
        """
        SELECT att.attname AS name,
               pg_catalog.format_type(att.atttypid, att.atttypmod) AS type,
               att.attnotnull,
               att.attidentity,
               att.attgenerated,
               att.attcollation=typ.typcollation AS collation_is_default,
               pg_get_expr(def.adbin, def.adrelid) AS default_value
        FROM pg_attribute AS att
        JOIN pg_type AS typ ON typ.oid=att.atttypid
        LEFT JOIN pg_attrdef AS def
          ON def.adrelid=att.attrelid AND def.adnum=att.attnum
        WHERE att.attrelid=$1::oid
          AND att.attnum > 0
          AND NOT att.attisdropped
        ORDER BY att.attnum
        """,
        table_oid,
    )
    constraint_rows = await connection.fetch(
        """
        SELECT con.conname, con.contype,
               con.conrelid::bigint AS table_oid,
               con.confrelid::bigint AS referenced_oid,
               con.conindid::bigint AS constraint_index_oid,
               con.convalidated,
               con.condeferrable, con.condeferred,
               pg_get_constraintdef(con.oid, true) AS definition,
               ref_nsp.oid::bigint AS referenced_schema_oid,
               ref_nsp.nspname=current_schema() AS reference_is_local,
               ref_rel.relname AS referenced_table,
               ARRAY(
                   SELECT local_att.attname
                   FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum, ordinality)
                   JOIN pg_attribute AS local_att
                     ON local_att.attrelid=con.conrelid
                    AND local_att.attnum=key.attnum
                   ORDER BY key.ordinality
               ) AS local_columns,
               ARRAY(
                   SELECT remote_att.attname
                   FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum, ordinality)
                   JOIN pg_attribute AS remote_att
                     ON remote_att.attrelid=con.confrelid
                    AND remote_att.attnum=key.attnum
                   ORDER BY key.ordinality
               ) AS remote_columns,
               con.confupdtype, con.confdeltype
        FROM pg_constraint AS con
        LEFT JOIN pg_class AS ref_rel ON ref_rel.oid=con.confrelid
        LEFT JOIN pg_namespace AS ref_nsp ON ref_nsp.oid=ref_rel.relnamespace
        WHERE con.conrelid=$1::oid
        ORDER BY con.conname
        """,
        table_oid,
    )
    index_rows = await connection.fetch(
        """
        SELECT ind.indrelid::bigint AS table_oid,
               ind.indexrelid::bigint AS index_oid,
               idx.relnamespace::bigint AS index_schema_oid,
               idx_nsp.nspname=current_schema() AS index_schema_is_local,
               idx.relname AS name,
               idx.relkind,
               idx.relpersistence,
               idx.relispartition,
               am.amname,
               ind.indisunique, ind.indisprimary,
               ind.indisvalid, ind.indisready, ind.indislive,
               ind.indnkeyatts, ind.indnatts,
               ARRAY(
                   SELECT CASE WHEN key.attnum=0 THEN NULL ELSE att.attname END
                   FROM unnest(ind.indkey) WITH ORDINALITY AS key(attnum, ordinality)
                   LEFT JOIN pg_attribute AS att
                     ON att.attrelid=ind.indrelid AND att.attnum=key.attnum
                   ORDER BY key.ordinality
               ) AS columns,
               ARRAY(
                   SELECT option
                   FROM unnest(ind.indoption) WITH ORDINALITY AS item(option, ordinality)
                   ORDER BY item.ordinality
               ) AS options,
               ARRAY(
                   SELECT opc.opcname
                   FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                   JOIN pg_opclass AS opc ON opc.oid=item.opclass
                   ORDER BY item.ordinality
               ) AS opclasses,
               ARRAY(
                   SELECT opc.oid::bigint
                   FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                   JOIN pg_opclass AS opc ON opc.oid=item.opclass
                   ORDER BY item.ordinality
               ) AS opclass_oids,
               ARRAY(
                   SELECT opc_nsp.nspname
                   FROM unnest(ind.indclass) WITH ORDINALITY AS item(opclass, ordinality)
                   JOIN pg_opclass AS opc ON opc.oid=item.opclass
                   JOIN pg_namespace AS opc_nsp
                     ON opc_nsp.oid=opc.opcnamespace
                   ORDER BY item.ordinality
               ) AS opclass_namespaces,
               ARRAY(
                   SELECT item.collation=att.attcollation
                   FROM unnest(ind.indcollation) WITH ORDINALITY
                        AS item(collation, ordinality)
                   JOIN unnest(ind.indkey) WITH ORDINALITY
                        AS key(attnum, ordinality)
                     ON key.ordinality=item.ordinality
                   LEFT JOIN pg_attribute AS att
                     ON att.attrelid=ind.indrelid AND att.attnum=key.attnum
                   ORDER BY item.ordinality
               ) AS collations_match,
               pg_get_expr(ind.indexprs, ind.indrelid) AS expressions,
               pg_get_expr(ind.indpred, ind.indrelid) AS predicate
        FROM pg_index AS ind
        JOIN pg_class AS idx ON idx.oid=ind.indexrelid
        JOIN pg_namespace AS idx_nsp ON idx_nsp.oid=idx.relnamespace
        JOIN pg_am AS am ON am.oid=idx.relam
        WHERE ind.indrelid=$1::oid
        ORDER BY idx.relname
        """,
        table_oid,
    )
    canonical_opclass_rows = await connection.fetch(
        """
        SELECT opc.opcname, opc.oid::bigint AS opclass_oid
        FROM pg_opclass AS opc
        JOIN pg_namespace AS nsp ON nsp.oid=opc.opcnamespace
        JOIN pg_am AS am ON am.oid=opc.opcmethod
        WHERE nsp.nspname='pg_catalog'
          AND am.amname='btree'
          AND opc.opcname=ANY($1::text[])
        """,
        ["text_ops", "timestamptz_ops"],
    )
    canonical_opclasses = {
        str(row["opcname"]): int(row["opclass_oid"])
        for row in canonical_opclass_rows
    }
    checks = tuple(
        (
            str(row["conname"]),
            " ".join(str(row["definition"]).split()),
        )
        for row in constraint_rows
        if str(row["contype"]) == "c"
        and bool(row["convalidated"])
        and not bool(row["condeferrable"])
        and not bool(row["condeferred"])
    )
    foreign_keys = tuple(
        (
            str(row["conname"]),
            tuple(str(value) for value in row["local_columns"]),
            str(row["referenced_table"]),
            tuple(str(value) for value in row["remote_columns"]),
            str(row["confupdtype"]),
            str(row["confdeltype"]),
        )
        for row in constraint_rows
        if str(row["contype"]) == "f"
        and bool(row["convalidated"])
        and not bool(row["condeferrable"])
        and not bool(row["condeferred"])
        and bool(row["reference_is_local"])
    )
    primary = tuple(
        (
            str(row["conname"]),
            tuple(str(value) for value in row["local_columns"]),
            bool(row["convalidated"]),
            bool(row["condeferrable"]),
            bool(row["condeferred"]),
        )
        for row in constraint_rows
        if str(row["contype"]) == "p"
    )
    return {
        "relation": (
            str(relation["relkind"]),
            str(relation["relpersistence"]),
            bool(relation["relispartition"]),
            bool(relation["relrowsecurity"]),
            bool(relation["relforcerowsecurity"]),
            int(relation["parent_count"]),
            int(relation["child_count"]),
            int(relation["policy_count"]),
            int(relation["user_trigger_count"]),
            int(relation["user_rule_count"]),
        ),
        "relation_oid": table_oid,
        "schema_oid": schema_oid,
        "columns": tuple(
            (
                str(row["name"]),
                str(row["type"]),
                bool(row["attnotnull"]),
                str(row["attidentity"]),
                str(row["attgenerated"]),
                bool(row["collation_is_default"]),
                None
                if row["default_value"] is None
                else str(row["default_value"]),
            )
            for row in column_rows
        ),
        "checks": checks,
        "foreign_keys": foreign_keys,
        "primary": primary,
        "indexes": tuple(
            (
                str(row["name"]),
                str(row["amname"]),
                bool(row["indisunique"]),
                bool(row["indisprimary"]),
                bool(row["indisvalid"]),
                bool(row["indisready"]),
                bool(row["indislive"]),
                int(row["indnkeyatts"]),
                int(row["indnatts"]),
                tuple(
                    None if value is None else str(value)
                    for value in row["columns"]
                ),
                tuple(int(value) for value in row["options"]),
                tuple(str(value) for value in row["opclasses"]),
                tuple(bool(value) for value in row["collations_match"]),
                None if row["expressions"] is None else str(row["expressions"]),
                None if row["predicate"] is None else str(row["predicate"]),
            )
            for row in index_rows
        ),
        "index_identities": tuple(
            (
                str(row["name"]),
                str(row["relkind"]),
                str(row["relpersistence"]),
                bool(row["relispartition"]),
                tuple(str(value) for value in row["opclasses"]),
                tuple(str(value) for value in row["opclass_namespaces"]),
            )
            for row in index_rows
        ),
        "index_bindings": tuple(
            (
                int(row["table_oid"]) == table_oid,
                int(row["index_schema_oid"]) == schema_oid,
                bool(row["index_schema_is_local"]),
                int(row["index_oid"]),
                tuple(int(value) for value in row["opclass_oids"]),
                tuple(
                    canonical_opclasses.get(str(name), -1)
                    for name in row["opclasses"]
                ),
            )
            for row in index_rows
        ),
        "constraint_bindings": tuple(
            (
                str(row["conname"]),
                int(row["table_oid"]),
                int(row["referenced_oid"]),
                None
                if row["referenced_schema_oid"] is None
                else int(row["referenced_schema_oid"]),
                int(row["constraint_index_oid"]),
            )
            for row in constraint_rows
        ),
        "constraint_count": len(constraint_rows),
    }


def _ticket_catalog_matches_fixed_contract(
    fingerprint: dict[str, object],
) -> bool:
    return (
        fingerprint.get("relation")
        == ("r", "p", False, False, False, 0, 0, 0, 0, 0)
        and isinstance(fingerprint.get("relation_oid"), int)
        and isinstance(fingerprint.get("schema_oid"), int)
        and fingerprint.get("columns") == _EXPECTED_TICKET_COLUMNS
        and fingerprint.get("checks") == _EXPECTED_TICKET_CHECKS
        and fingerprint.get("foreign_keys") == _EXPECTED_TICKET_FOREIGN_KEYS
        and fingerprint.get("primary")
        == (("websocket_tickets_pkey", ("ticket_hash",), True, False, False),)
        and fingerprint.get("indexes") == _EXPECTED_TICKET_INDEXES
        and fingerprint.get("index_identities")
        == _EXPECTED_TICKET_INDEX_IDENTITIES
        and all(
            table_is_exact
            and schema_oid_is_exact
            and schema_name_is_exact
            and index_oid > 0
            and opclass_oids == canonical_oids
            for (
                table_is_exact,
                schema_oid_is_exact,
                schema_name_is_exact,
                index_oid,
                opclass_oids,
                canonical_oids,
            ) in fingerprint.get("index_bindings", ())
        )
        and len(
            {
                binding[3]
                for binding in fingerprint.get("index_bindings", ())
            }
        )
        == 5
        and all(
            binding[1] == fingerprint.get("relation_oid")
            for binding in fingerprint.get("constraint_bindings", ())
        )
        and fingerprint.get("constraint_count") == 15
    )


@pytest.mark.asyncio
async def test_postgres_catalog_issue_consume_replay_and_revalidation() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, other_id, _key_id = (
            await _seed_identity(database)
        )
        source = _bearer_source(user_id, username)
        issued = await database.issue_websocket_ticket(campaign_id, source)
        _require_fixed(issued is not None, "valid bearer ticket was not issued")
        raw_ticket, ttl = issued or ("", 0)

        async with database._pool.acquire() as connection:
            await database._validate_websocket_ticket_schema(connection)
            catalog = await _ticket_catalog_fingerprint(connection)
            row = await connection.fetchrow(
                """
                SELECT ticket_hash, bearer_subject, bearer_jti, api_key_id
                FROM websocket_tickets
                """
            )
        catalog_is_exact = _ticket_catalog_matches_fixed_contract(catalog)
        raw_absent = row is not None and all(
            raw_ticket != value for value in tuple(row)
        )
        digest_matches = (
            row is not None
            and row["ticket_hash"] == hash_websocket_ticket(raw_ticket)
        )

        wrong = await database.consume_websocket_ticket(raw_ticket, other_id)
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
            and principal.role == "operator"
        )

        _require_fixed(ttl == 30, "ticket lifetime contract changed")
        _require_fixed(catalog_is_exact, "ticket catalog contract changed")
        _require_fixed(raw_absent, "raw ticket was persisted")
        _require_fixed(digest_matches, "stored digest did not match ticket")
        _require_fixed(wrong is None, "wrong campaign consumed a ticket")
        _require_fixed(consumed is not None, "valid ticket was not consumed")
        _require_fixed(replay is None, "ticket replay was accepted")
        _require_fixed(resolved, "bearer principal was not resolved")

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='reporter' WHERE id=$1",
                user_id,
            )
        current_role = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        current_role_applied = (
            current_role is not None and current_role.role == "reporter"
        )
        _require_fixed(
            current_role_applied,
            "bearer resolver did not use the current role",
        )

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='unknown-role' WHERE id=$1",
                user_id,
            )
        invalid_role = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        _require_fixed(invalid_role is None, "unknown role remained authorized")

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='operator' WHERE id=$1",
                user_id,
            )
            await connection.execute(
                "UPDATE campaigns SET operator='different-operator' WHERE id=$1",
                campaign_id,
            )
        inaccessible = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        _require_fixed(
            inaccessible is None,
            "campaign access loss remained authorized",
        )

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='team_lead' WHERE id=$1",
                user_id,
            )
        promoted = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='reporter' WHERE id=$1",
                user_id,
            )
        demoted = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        _require_fixed(
            promoted is not None
            and promoted.role == "team_lead"
            and demoted is None,
            "bearer role/campaign revalidation matrix failed",
        )

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='operator' WHERE id=$1",
                user_id,
            )
            await connection.execute(
                "UPDATE campaigns SET operator=$1 WHERE id=$2",
                username,
                campaign_id,
            )
            await connection.execute(
                """
                INSERT INTO revoked_access_tokens(jti, user_id, expires_at)
                VALUES($1, $2, $3)
                """,
                source.jti,
                user_id,
                datetime.now(timezone.utc) + timedelta(minutes=5),
            )
        revoked = (
            await database.resolve_websocket_ticket_principal(consumed)
            if consumed is not None
            else None
        )
        _require_fixed(revoked is None, "revoked bearer remained authorized")


@pytest.mark.asyncio
async def test_postgres_bearer_resolver_mutation_matrix_and_pool_recovery() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "bearer mutation setup failed")
        consumed = await database.consume_websocket_ticket(
            (issued or ("", 0))[0],
            campaign_id,
        )
        _require_fixed(consumed is not None, "bearer mutation consume failed")
        if consumed is None:
            return

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET username='renamed-user' WHERE id=$1",
                user_id,
            )
        renamed = await database.resolve_websocket_ticket_principal(consumed)
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET username=$1 WHERE id=$2",
                username,
                user_id,
            )
            await connection.execute(
                "UPDATE users SET is_active=0 WHERE id=$1",
                user_id,
            )
        inactive = await database.resolve_websocket_ticket_principal(consumed)
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET is_active=1 WHERE id=$1",
                user_id,
            )
        expired = await database.resolve_websocket_ticket_principal(
            replace(
                consumed,
                bearer_expires_at=datetime.now(timezone.utc)
                - timedelta(seconds=1),
            )
        )
        recovered = await database.resolve_websocket_ticket_principal(consumed)
        async with database._pool.acquire() as connection:
            reusable = await connection.fetchval("SELECT 1")
            await connection.execute("DELETE FROM users WHERE id=$1", user_id)
        deleted = await database.resolve_websocket_ticket_principal(consumed)
        _require_fixed(
            renamed is None
            and inactive is None
            and expired is None
            and recovered is not None
            and deleted is None
            and reusable == 1,
            "bearer resolver mutation matrix failed",
        )


@pytest.mark.asyncio
async def test_postgres_ticket_timestamps_reject_both_infinities() -> None:
    async with _postgres_harness() as harness:
        import asyncpg

        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "finite timestamp setup failed")
        raw_ticket = (issued or ("", 0))[0]
        digest = hash_websocket_ticket(raw_ticket)
        rejected = 0
        async with database._pool.acquire() as connection:
            await connection.execute(
                """
                UPDATE websocket_tickets
                SET bearer_expires_at=now() + interval '5 minutes',
                    expires_at=now() + interval '2 minutes',
                    created_at=now(),
                    consumed_at=now()
                WHERE ticket_hash=$1
                """,
                digest,
            )
            finite_values = await connection.fetchrow(
                """
                SELECT bearer_expires_at, created_at, expires_at, consumed_at
                FROM websocket_tickets
                WHERE ticket_hash=$1
                """,
                digest,
            )
            finite_values_are_aware = finite_values is not None and all(
                value is not None and value.utcoffset() is not None
                for value in tuple(finite_values)
            )
            for statement in (
                """
                UPDATE websocket_tickets
                SET bearer_expires_at=$2::timestamptz
                WHERE ticket_hash=$1
                """,
                """
                UPDATE websocket_tickets
                SET created_at=$2::timestamptz
                WHERE ticket_hash=$1
                """,
                """
                UPDATE websocket_tickets
                SET expires_at=$2::timestamptz
                WHERE ticket_hash=$1
                """,
                """
                UPDATE websocket_tickets
                SET consumed_at=$2::timestamptz
                WHERE ticket_hash=$1
                """,
            ):
                for literal in ("infinity", "-infinity"):
                    before = await connection.fetchrow(
                        """
                        SELECT bearer_expires_at, created_at,
                               expires_at, consumed_at
                        FROM websocket_tickets
                        WHERE ticket_hash=$1
                        """,
                        digest,
                    )
                    failed = False
                    try:
                        await connection.execute(
                            statement,
                            digest,
                            literal,
                        )
                    except asyncpg.CheckViolationError:
                        failed = True
                    after = await connection.fetchrow(
                        """
                        SELECT bearer_expires_at, created_at,
                               expires_at, consumed_at
                        FROM websocket_tickets
                        WHERE ticket_hash=$1
                        """,
                        digest,
                    )
                    unchanged = (
                        before is not None
                        and after is not None
                        and tuple(before) == tuple(after)
                    )
                    rejected += int(failed)
                    reusable = await connection.fetchval("SELECT 1")
                    _require_fixed(
                        failed and unchanged and reusable == 1,
                        "non-finite ticket timestamp was accepted",
                    )
            null_rejected = 0
            for statement in (
                """
                UPDATE websocket_tickets
                SET created_at=NULL
                WHERE ticket_hash=$1
                """,
                """
                UPDATE websocket_tickets
                SET expires_at=NULL
                WHERE ticket_hash=$1
                """,
            ):
                before = await connection.fetchrow(
                    """
                    SELECT bearer_expires_at, created_at,
                           expires_at, consumed_at
                    FROM websocket_tickets
                    WHERE ticket_hash=$1
                    """,
                    digest,
                )
                failed = False
                try:
                    await connection.execute(
                        statement,
                        digest,
                    )
                except asyncpg.NotNullViolationError:
                    failed = True
                after = await connection.fetchrow(
                    """
                    SELECT bearer_expires_at, created_at,
                           expires_at, consumed_at
                    FROM websocket_tickets
                    WHERE ticket_hash=$1
                    """,
                    digest,
                )
                unchanged = (
                    before is not None
                    and after is not None
                    and tuple(before) == tuple(after)
                )
                reusable = await connection.fetchval("SELECT 1")
                null_rejected += int(failed)
                _require_fixed(
                    failed and unchanged and reusable == 1,
                    "required ticket timestamp accepted NULL",
                )

            api_issued = await database.issue_websocket_ticket(
                campaign_id,
                ApiKeyTicketSource(user_id=user_id, api_key_id=_key_id),
            )
            _require_fixed(
                api_issued is not None,
                "API-key timestamp setup failed",
            )
            api_digest = hash_websocket_ticket((api_issued or ("", 0))[0])
            await connection.execute(
                """
                UPDATE websocket_tickets
                SET bearer_expires_at=NULL, consumed_at=NULL
                WHERE ticket_hash=$1
                """,
                api_digest,
            )
            nullable_values = await connection.fetchrow(
                """
                SELECT bearer_expires_at IS NULL AS bearer_is_null,
                       consumed_at IS NULL AS consumed_is_null
                FROM websocket_tickets
                WHERE ticket_hash=$1
                """,
                api_digest,
            )
            nullable_accepted = (
                nullable_values is not None
                and bool(nullable_values["bearer_is_null"])
                and bool(nullable_values["consumed_is_null"])
            )
            insert_hash = "f" * 64
            insert_failed = False
            try:
                await connection.execute(
                    """
                    INSERT INTO websocket_tickets(
                        ticket_hash, campaign_id, user_id,
                        credential_kind, bearer_subject, bearer_jti,
                        bearer_expires_at, created_at, expires_at
                    )
                    VALUES(
                        $1, $2, $3, 'bearer', $4, $5,
                        now() + interval '5 minutes',
                        'infinity'::timestamptz,
                        now() + interval '30 seconds'
                    )
                    """,
                    insert_hash,
                    campaign_id,
                    user_id,
                    username,
                    f"finite-insert-{uuid4().hex}",
                )
            except asyncpg.CheckViolationError:
                insert_failed = True
            inserted_rows = await connection.fetchval(
                """
                SELECT COUNT(*) FROM websocket_tickets
                WHERE ticket_hash=$1
                """,
                insert_hash,
            )
            insert_reusable = await connection.fetchval("SELECT 1")
            rejected_insert_is_clean = (
                insert_failed and inserted_rows == 0 and insert_reusable == 1
            )
        _require_fixed(rejected == 8, "finite timestamp rejection count changed")
        _require_fixed(
            null_rejected == 2,
            "required timestamp NULL rejection count changed",
        )
        _require_fixed(
            finite_values_are_aware
            and nullable_accepted
            and rejected_insert_is_clean,
            "ticket timestamp finite/nullable contract changed",
        )


@pytest.mark.asyncio
async def test_postgres_api_key_resolution_and_expiry_cleanup() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, key_id = (
            await _seed_identity(database, scopes="read,write")
        )
        async with database._pool.acquire() as connection:
            before = await connection.fetchval(
                "SELECT last_used FROM api_keys WHERE id=$1",
                key_id,
            )
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
        repeated_principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            after = await connection.fetchval(
                "SELECT last_used FROM api_keys WHERE id=$1",
                key_id,
            )
            await connection.execute(
                "UPDATE api_keys SET scopes='write' WHERE id=$1",
                key_id,
            )
        write_principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET scopes='admin' WHERE id=$1",
                key_id,
            )
        admin_principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        renamed_username = f"renamed-{uuid4().hex}"
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET username=$1 WHERE id=$2",
                renamed_username,
                user_id,
            )
            await connection.execute(
                "UPDATE campaigns SET operator=$1 WHERE id=$2",
                renamed_username,
                campaign_id,
            )
        renamed_principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE campaigns SET operator='different-owner' WHERE id=$1",
                campaign_id,
            )
        reassigned = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='team_lead' WHERE id=$1",
                user_id,
            )
        promoted = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='reporter' WHERE id=$1",
                user_id,
            )
        demoted = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET role='unknown-role' WHERE id=$1",
                user_id,
            )
        invalid_role = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET username=$1, role='operator' WHERE id=$2",
                username,
                user_id,
            )
            await connection.execute(
                "UPDATE campaigns SET operator=$1 WHERE id=$2",
                username,
                campaign_id,
            )
            await connection.execute(
                "UPDATE api_keys SET scopes='read' WHERE id=$1",
                key_id,
            )
            await connection.execute(
                """
                UPDATE websocket_tickets
                SET expires_at=now(), consumed_at=NULL
                WHERE ticket_hash=$1
                """,
                hash_websocket_ticket(raw_ticket),
            )
        deleted = await database.purge_expired_websocket_tickets()
        async with database._pool.acquire() as connection:
            after_purge = await connection.fetchval(
                "SELECT last_used FROM api_keys WHERE id=$1",
                key_id,
            )
        resolved = (
            principal is not None
            and principal.credential_kind
            is WebSocketTicketCredentialKind.API_KEY
            and "read" in principal.api_key_scopes
        )
        _require_fixed(resolved, "API-key principal was not resolved")
        scope_and_identity_matrix = (
            repeated_principal is not None
            and write_principal is not None
            and write_principal.api_key_scopes == ("write",)
            and admin_principal is not None
            and admin_principal.api_key_scopes == ("admin",)
            and renamed_principal is not None
            and renamed_principal.username == renamed_username
            and renamed_principal.user_id == user_id
            and renamed_principal.api_key_id == key_id
            and reassigned is None
            and promoted is not None
            and promoted.role == "team_lead"
            and demoted is None
            and invalid_role is None
        )
        _require_fixed(
            scope_and_identity_matrix,
            "API-key scope/identity/role matrix failed",
        )
        _require_fixed(
            before == after == after_purge,
            "API-key last_used was mutated",
        )
        _require_fixed(deleted == 1, "exact-now purge boundary changed")

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET scopes='telemetry' WHERE id=$1",
                key_id,
            )
        invalid_scope = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        issue_denied = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        _require_fixed(
            invalid_scope is None,
            "API-key scope loss remained authorized",
        )
        _require_fixed(
            issue_denied is None,
            "API key without an accepted scope issued a ticket",
        )

        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET scopes='read' WHERE id=$1",
                key_id,
            )
            await connection.execute(
                "UPDATE api_keys SET is_active=0 WHERE id=$1",
                key_id,
            )
        inactive_key = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET is_active=1, expires_at=now() WHERE id=$1",
                key_id,
            )
        expired_key = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE api_keys SET expires_at=NULL WHERE id=$1",
                key_id,
            )
            await connection.execute(
                "UPDATE users SET is_active=0 WHERE id=$1",
                user_id,
            )
        inactive_user = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "UPDATE users SET is_active=1 WHERE id=$1",
                user_id,
            )
        recovered_principal = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        _require_fixed(
            inactive_key is None
            and expired_key is None
            and inactive_user is None
            and recovered_principal is not None,
            "API-key resolver mutation matrix failed",
        )

        expiring = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        _require_fixed(expiring is not None, "expiry setup ticket was not issued")
        expiring_raw = (expiring or ("", 0))[0]
        async with database._pool.acquire() as connection:
            await connection.execute(
                """
                UPDATE websocket_tickets SET expires_at=now()
                WHERE ticket_hash=$1
                """,
                hash_websocket_ticket(expiring_raw),
            )
        exact_now = await database.consume_websocket_ticket(
            expiring_raw,
            campaign_id,
        )
        _require_fixed(exact_now is None, "exact-now ticket was consumed")

        replacement_key_id = (
            await database.create_api_key(
                user_id,
                "replacement-ticket-key",
                scopes="read",
            )
        )[0]
        stable_binding = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute(
                "DELETE FROM api_keys WHERE id=$1",
                key_id,
            )
        deleted_key = (
            await database.resolve_websocket_ticket_principal(handle)
            if handle is not None
            else None
        )
        replacement_issued = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(
                user_id=user_id,
                api_key_id=replacement_key_id,
            ),
        )
        replacement_handle = (
            await database.consume_websocket_ticket(
                (replacement_issued or ("", 0))[0],
                campaign_id,
            )
            if replacement_issued is not None
            else None
        )
        async with database._pool.acquire() as connection:
            await connection.execute("DELETE FROM users WHERE id=$1", user_id)
        deleted_owner = (
            await database.resolve_websocket_ticket_principal(replacement_handle)
            if replacement_handle is not None
            else None
        )
        binding_and_deletion_matrix = (
            stable_binding is not None
            and stable_binding.user_id == user_id
            and stable_binding.api_key_id == key_id
            and replacement_key_id != key_id
            and deleted_key is None
            and replacement_handle is not None
            and deleted_owner is None
        )
        _require_fixed(
            binding_and_deletion_matrix,
            "API-key ownership/replacement/deletion matrix failed",
        )


@pytest.mark.asyncio
async def test_postgres_two_pools_have_one_consumer() -> None:
    async with _postgres_harness() as harness:
        first = harness.database
        second = _database_for_target(harness.database_name)
        first_task: asyncio.Task[Any] | None = None
        second_task: asyncio.Task[Any] | None = None
        release_exit = asyncio.Event()
        original_pool = first._pool
        second_original_pool = None
        first_backend_pids: list[int] = []
        second_backend_pids: list[int] = []
        second_update_started = asyncio.Event()
        try:
            await _bounded_operation("second-runtime-initialize", second.connect())
            second_original_pool = second._pool
            user_id, username, campaign_id, _other_id, _key_id = (
                await _seed_identity(first)
            )
            issued = await first.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
            _require_fixed(issued is not None, "ticket setup failed")
            raw_ticket = (issued or ("", 0))[0]
            digest = hash_websocket_ticket(raw_ticket)
            exit_reached = asyncio.Event()
            first._pool = _BarrierPool(
                original_pool,
                exit_reached,
                release_exit,
                first_backend_pids,
            )
            second._pool = _PoolProxy(
                second_original_pool,
                [],
                second_backend_pids,
                second_update_started,
            )
            first_task = asyncio.create_task(
                first.consume_websocket_ticket(raw_ticket, campaign_id)
            )
            await asyncio.wait_for(exit_reached.wait(), timeout=10)
            second_task = asyncio.create_task(
                second.consume_websocket_ticket(raw_ticket, campaign_id)
            )
            await asyncio.wait_for(second_update_started.wait(), timeout=10)

            async def _observe_blocked_consumer() -> bool:
                async with original_pool.acquire() as observer:
                    observer_pid = int(
                        await observer.fetchval("SELECT pg_backend_pid()")
                    )
                    for _ in range(200):
                        blocked = await observer.fetchval(
                            """
                            SELECT
                                EXISTS(
                                    SELECT 1 FROM pg_locks
                                    WHERE pid=$1 AND NOT granted
                                )
                                AND $2=ANY(pg_blocking_pids($1))
                            """,
                            second_backend_pids[0],
                            first_backend_pids[0],
                        )
                        if blocked:
                            hidden = await observer.fetchval(
                                """
                                SELECT consumed_at IS NULL
                                FROM websocket_tickets
                                WHERE ticket_hash=$1
                                """,
                                digest,
                            )
                            distinct = len(
                                {
                                    first_backend_pids[0],
                                    second_backend_pids[0],
                                    observer_pid,
                                }
                            ) == 3
                            return bool(hidden) and distinct
                        await asyncio.sleep(0.01)
                return False

            lock_and_visibility_proved = await asyncio.wait_for(
                _observe_blocked_consumer(),
                timeout=10,
            )
            second_waited = not second_task.done()
            release_exit.set()
            results = await asyncio.wait_for(
                asyncio.gather(first_task, second_task),
                timeout=10,
            )
            first._pool = original_pool
            second._pool = second_original_pool
            winner_count = sum(result is not None for result in results)
            async with original_pool.acquire() as observer:
                committed_visible = await observer.fetchval(
                    """
                    SELECT consumed_at IS NOT NULL
                    FROM websocket_tickets
                    WHERE ticket_hash=$1
                    """,
                    digest,
                )
            _require_fixed(
                lock_and_visibility_proved and second_waited,
                "cross-pool row-lock visibility was not proved",
            )
            _require_fixed(
                winner_count == 1 and bool(committed_visible),
                "ticket did not have exactly one PostgreSQL consumer",
            )
            async with second._pool.acquire() as connection:
                reusable = await connection.fetchval("SELECT 1")
            _require_fixed(reusable == 1, "second pool was not reusable")
        finally:
            primary_failure = sys.exception()
            release_exit.set()
            first._pool = original_pool
            if second_original_pool is not None:
                second._pool = second_original_pool
            for task in (first_task, second_task):
                if task is not None and not task.done():
                    task.cancel()
            tasks = tuple(
                task
                for task in (first_task, second_task)
                if task is not None
            )
            if tasks:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=10,
                )
            close_failures: list[str] = []
            if second._pool is not None:
                await _attempt_cleanup(
                    "second-runtime-close",
                    second.close,
                    close_failures,
                )
            if close_failures:
                if primary_failure is not None:
                    for failure in close_failures:
                        primary_failure.add_note(
                            f"PostgreSQL ticket cleanup failure [{failure}]"
                        )
                else:
                    raise RuntimeError(
                        "PostgreSQL ticket secondary cleanup failed"
                    ) from None


@pytest.mark.asyncio
async def test_postgres_collision_rolls_back_and_pool_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _postgres_harness() as harness:
        import asyncpg

        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        fixed_ticket = generate_websocket_ticket()
        with monkeypatch.context() as patcher:
            patcher.setattr(
                postgres_module,
                "generate_websocket_ticket",
                lambda: fixed_ticket,
            )
            first = await database.issue_websocket_ticket(
                campaign_id,
                _bearer_source(user_id, username),
            )
            _require_fixed(first is not None, "collision setup failed")
            collision_type: type[BaseException] | None = None
            try:
                await database.issue_websocket_ticket(
                    campaign_id,
                    _bearer_source(user_id, username),
                )
            except Exception as exc:
                collision_type = type(exc)
            _require_fixed(
                collision_type is asyncpg.UniqueViolationError,
                "ticket collision did not fail with the expected fixed type",
            )

        consumed = await database.consume_websocket_ticket(
            fixed_ticket,
            campaign_id,
        )
        recovered = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        async with database._pool.acquire() as connection:
            reusable = await connection.fetchval("SELECT 1")
        _require_fixed(consumed is not None, "collision damaged prior ticket")
        _require_fixed(recovered is not None, "issuance did not recover")
        _require_fixed(reusable == 1, "pool was not reusable after collision")


class _ConnectionProxy:
    def __init__(
        self,
        connection: Any,
        classes: list[str],
        backend_pids: list[int] | None = None,
        update_started: asyncio.Event | None = None,
    ) -> None:
        self._connection = connection
        self._classes = classes
        self._backend_pids = backend_pids
        self._update_started = update_started

    def transaction(self, *args: object, **kwargs: object) -> Any:
        return self._connection.transaction(*args, **kwargs)

    async def fetchrow(
        self,
        query: str,
        *args: object,
        **kwargs: object,
    ) -> Any:
        normalized = " ".join(query.upper().split())
        if (
            normalized.startswith("INSERT INTO WEBSOCKET_TICKETS")
            and "'API_KEY'" in normalized
        ):
            required = (
                "CREDENTIAL_KIND, API_KEY_ID, REQUIRED_SCOPE,"
                " CREATED_AT, EXPIRES_AT" in normalized
                and "SELECT $1, C.ID, U.ID, 'API_KEY', AK.ID, 'READ',"
                " NOW(), NOW() + INTERVAL '30 SECONDS'" in normalized
                and "AK.ID=$4" in normalized
                and "AK.USER_ID=$3" in normalized
            )
            self._classes.append(
                "API KEY INSERT WITH REQUIRED SCOPE"
                if required
                else "UNSAFE API KEY INSERT"
            )
        elif normalized.startswith("UPDATE WEBSOCKET_TICKETS"):
            if self._backend_pids is not None:
                self._backend_pids.append(
                    int(await self._connection.fetchval("SELECT pg_backend_pid()"))
                )
            if self._update_started is not None:
                self._update_started.set()
            required_predicates = (
                "TICKET_HASH=$1",
                "CAMPAIGN_ID=$2",
                "CONSUMED_AT IS NULL",
                "EXPIRES_AT > NOW()",
            )
            required_return_fields = (
                "CAMPAIGN_ID",
                "USER_ID",
                "CREDENTIAL_KIND",
                "BEARER_SUBJECT",
                "BEARER_JTI",
                "BEARER_EXPIRES_AT",
                "API_KEY_ID",
                "REQUIRED_SCOPE",
            )
            returning = normalized.partition(" RETURNING ")[2]
            returned_fields = tuple(
                field.strip() for field in returning.split(",")
            )
            required = (
                all(predicate in normalized for predicate in required_predicates)
                and returned_fields == required_return_fields
            )
            self._classes.append(
                "CONDITIONAL UPDATE RETURNING"
                if required
                else "UNSAFE UPDATE"
            )
        return await self._connection.fetchrow(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _AcquireProxy:
    def __init__(
        self,
        acquisition: Any,
        classes: list[str],
        backend_pids: list[int] | None = None,
        update_started: asyncio.Event | None = None,
    ) -> None:
        self._acquisition = acquisition
        self._classes = classes
        self._backend_pids = backend_pids
        self._update_started = update_started
        self._connection = None

    async def __aenter__(self) -> _ConnectionProxy:
        self._connection = await self._acquisition.__aenter__()
        return _ConnectionProxy(
            self._connection,
            self._classes,
            self._backend_pids,
            self._update_started,
        )

    async def __aexit__(self, *exc_info: object) -> object:
        return await self._acquisition.__aexit__(*exc_info)


class _PoolProxy:
    def __init__(
        self,
        pool: Any,
        classes: list[str],
        backend_pids: list[int] | None = None,
        update_started: asyncio.Event | None = None,
    ) -> None:
        self._pool = pool
        self._classes = classes
        self._backend_pids = backend_pids
        self._update_started = update_started

    def acquire(self) -> _AcquireProxy:
        return _AcquireProxy(
            self._pool.acquire(),
            self._classes,
            self._backend_pids,
            self._update_started,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool, name)


class _ResolverConnectionProxy:
    def __init__(
        self,
        connection: Any,
        started: asyncio.Event,
        release: asyncio.Event | None,
        failure: Exception | None,
    ) -> None:
        self._connection = connection
        self._started = started
        self._release = release
        self._failure = failure

    async def fetchrow(
        self,
        query: str,
        *args: object,
        **kwargs: object,
    ) -> Any:
        normalized = " ".join(query.upper().split())
        if normalized.startswith("SELECT U.ID"):
            self._started.set()
            if self._failure is not None:
                raise self._failure
            if self._release is not None:
                await asyncio.wait_for(self._release.wait(), timeout=10)
        return await self._connection.fetchrow(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _ResolverAcquireProxy:
    def __init__(
        self,
        acquisition: Any,
        started: asyncio.Event,
        release: asyncio.Event | None,
        failure: Exception | None,
    ) -> None:
        self._acquisition = acquisition
        self._started = started
        self._release = release
        self._failure = failure

    async def __aenter__(self) -> _ResolverConnectionProxy:
        connection = await self._acquisition.__aenter__()
        return _ResolverConnectionProxy(
            connection,
            self._started,
            self._release,
            self._failure,
        )

    async def __aexit__(self, *exc_info: object) -> object:
        return await self._acquisition.__aexit__(*exc_info)


class _ResolverPoolProxy:
    def __init__(
        self,
        pool: Any,
        started: asyncio.Event,
        release: asyncio.Event | None = None,
        failure: Exception | None = None,
    ) -> None:
        self._pool = pool
        self._started = started
        self._release = release
        self._failure = failure

    def acquire(self) -> _ResolverAcquireProxy:
        return _ResolverAcquireProxy(
            self._pool.acquire(),
            self._started,
            self._release,
            self._failure,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool, name)


class _PureAsyncContext:
    def __init__(self, value: Any = None) -> None:
        self._value = value

    async def __aenter__(self) -> Any:
        return self._value

    async def __aexit__(self, *exc_info: object) -> None:
        return None


class _PureTicketConnection:
    def transaction(self, *args: object, **kwargs: object) -> _PureAsyncContext:
        return _PureAsyncContext()

    async def execute(
        self,
        _query: str,
        *_args: object,
        **_kwargs: object,
    ) -> str:
        return "DELETE 0"

    async def fetchrow(
        self,
        _query: str,
        *_args: object,
        **_kwargs: object,
    ) -> dict[str, object]:
        return {
            "campaign_id": "synthetic-campaign",
            "user_id": "synthetic-user",
            "credential_kind": "bearer",
            "bearer_subject": "synthetic-subject",
            "bearer_jti": "synthetic-jti",
            "bearer_expires_at": datetime.now(timezone.utc)
            + timedelta(minutes=1),
            "api_key_id": None,
            "required_scope": None,
        }


class _PureTicketPool:
    def __init__(self) -> None:
        self._connection = _PureTicketConnection()

    def acquire(self) -> _PureAsyncContext:
        return _PureAsyncContext(self._connection)


class _TransactionExitBarrier:
    def __init__(
        self,
        transaction: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
    ) -> None:
        self._transaction = transaction
        self._exit_reached = exit_reached
        self._release_exit = release_exit

    async def __aenter__(self) -> Any:
        return await self._transaction.__aenter__()

    async def __aexit__(self, *exc_info: object) -> object:
        self._exit_reached.set()
        await asyncio.wait_for(self._release_exit.wait(), timeout=10)
        return await self._transaction.__aexit__(*exc_info)


class _BarrierConnection:
    def __init__(
        self,
        connection: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
        backend_pids: list[int],
    ) -> None:
        self._connection = connection
        self._exit_reached = exit_reached
        self._release_exit = release_exit
        self._backend_pids = backend_pids

    def transaction(self, *args: object, **kwargs: object) -> Any:
        return _TransactionExitBarrier(
            self._connection.transaction(*args, **kwargs),
            self._exit_reached,
            self._release_exit,
        )

    async def fetchrow(
        self,
        query: str,
        *args: object,
        **kwargs: object,
    ) -> Any:
        normalized = " ".join(query.upper().split())
        if normalized.startswith("UPDATE WEBSOCKET_TICKETS"):
            self._backend_pids.append(
                int(await self._connection.fetchval("SELECT pg_backend_pid()"))
            )
        return await self._connection.fetchrow(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _BarrierAcquire:
    def __init__(
        self,
        acquisition: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
        backend_pids: list[int],
    ) -> None:
        self._acquisition = acquisition
        self._exit_reached = exit_reached
        self._release_exit = release_exit
        self._backend_pids = backend_pids

    async def __aenter__(self) -> _BarrierConnection:
        connection = await self._acquisition.__aenter__()
        return _BarrierConnection(
            connection,
            self._exit_reached,
            self._release_exit,
            self._backend_pids,
        )

    async def __aexit__(self, *exc_info: object) -> object:
        return await self._acquisition.__aexit__(*exc_info)


class _BarrierPool:
    def __init__(
        self,
        pool: Any,
        exit_reached: asyncio.Event,
        release_exit: asyncio.Event,
        backend_pids: list[int],
    ) -> None:
        self._pool = pool
        self._exit_reached = exit_reached
        self._release_exit = release_exit
        self._backend_pids = backend_pids

    def acquire(self) -> _BarrierAcquire:
        return _BarrierAcquire(
            self._pool.acquire(),
            self._exit_reached,
            self._release_exit,
            self._backend_pids,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool, name)


@pytest.mark.asyncio
async def test_consume_sql_tripwire_exercises_production_without_postgres() -> None:
    statement_classes: list[str] = []
    database = PostgresDatabase("synthetic")
    database._pool = _PoolProxy(_PureTicketPool(), statement_classes)
    consumed = await database.consume_websocket_ticket(
        generate_websocket_ticket(),
        "synthetic-campaign",
    )
    _require_fixed(consumed is not None, "pure consume tripwire did not execute")
    _require_fixed(
        tuple(statement_classes) == ("CONDITIONAL UPDATE RETURNING",),
        "production consume SQL lost its exact CAS/return contract",
    )


@pytest.mark.asyncio
async def test_api_key_issue_sql_persists_required_scope_without_postgres() -> None:
    statement_classes: list[str] = []
    database = PostgresDatabase("synthetic")
    database._pool = _PoolProxy(_PureTicketPool(), statement_classes)
    issued = await database.issue_websocket_ticket(
        "synthetic-campaign",
        ApiKeyTicketSource(
            user_id="synthetic-user",
            api_key_id="synthetic-key",
        ),
    )
    _require_fixed(issued is not None, "pure API-key issue tripwire did not execute")
    _require_fixed(
        tuple(statement_classes) == ("API KEY INSERT WITH REQUIRED SCOPE",),
        "production API-key ticket SQL lost its required scope",
    )


@pytest.mark.asyncio
async def test_postgres_consume_uses_one_conditional_update_returning() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(issued is not None, "ticket setup failed")
        raw_ticket = (issued or ("", 0))[0]
        original_pool = database._pool
        statement_classes: list[str] = []
        database._pool = _PoolProxy(original_pool, statement_classes)
        try:
            consumed = await database.consume_websocket_ticket(
                raw_ticket,
                campaign_id,
            )
        finally:
            database._pool = original_pool

        _require_fixed(consumed is not None, "instrumented consume failed")
        _require_fixed(
            tuple(statement_classes) == ("CONDITIONAL UPDATE RETURNING",),
            "PostgreSQL consume lost its conditional UPDATE RETURNING",
        )


@pytest.mark.asyncio
async def test_postgres_resolver_errors_and_cancellation_release_pool() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, key_id = (
            await _seed_identity(database)
        )
        bearer_issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        api_issued = await database.issue_websocket_ticket(
            campaign_id,
            ApiKeyTicketSource(user_id=user_id, api_key_id=key_id),
        )
        _require_fixed(
            bearer_issued is not None and api_issued is not None,
            "resolver failure setup failed",
        )
        bearer = await database.consume_websocket_ticket(
            (bearer_issued or ("", 0))[0],
            campaign_id,
        )
        api_key = await database.consume_websocket_ticket(
            (api_issued or ("", 0))[0],
            campaign_id,
        )
        _require_fixed(
            bearer is not None and api_key is not None,
            "resolver failure handles were not created",
        )
        if bearer is None or api_key is None:
            return

        original_pool = database._pool
        for handle in (bearer, api_key):
            started = asyncio.Event()
            database._pool = _ResolverPoolProxy(
                original_pool,
                started,
                failure=RuntimeError(),
            )
            failure_type: type[BaseException] | None = None
            try:
                await database.resolve_websocket_ticket_principal(handle)
            except Exception as exc:
                failure_type = type(exc)
            finally:
                database._pool = original_pool
            _require_fixed(
                started.is_set() and failure_type is RuntimeError,
                "resolver database error did not propagate safely",
            )

            cancel_started = asyncio.Event()
            release = asyncio.Event()
            database._pool = _ResolverPoolProxy(
                original_pool,
                cancel_started,
                release=release,
            )
            task = asyncio.create_task(
                database.resolve_websocket_ticket_principal(handle)
            )
            cancelled = False
            try:
                await asyncio.wait_for(cancel_started.wait(), timeout=10)
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=10)
                except asyncio.CancelledError:
                    cancelled = True
            finally:
                release.set()
                database._pool = original_pool
                if not task.done():
                    task.cancel()
                await asyncio.wait_for(
                    asyncio.gather(task, return_exceptions=True),
                    timeout=10,
                )
            recovered = await database.resolve_websocket_ticket_principal(handle)
            async with original_pool.acquire() as connection:
                reusable = await connection.fetchval("SELECT 1")
            _require_fixed(
                cancelled and recovered is not None and reusable == 1,
                "resolver cancellation did not release and recover the pool",
            )


@pytest.mark.asyncio
async def test_postgres_issue_returns_only_after_transaction_exit() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        original_pool = database._pool
        exit_reached = asyncio.Event()
        release_exit = asyncio.Event()
        task: asyncio.Task[tuple[str, int] | None] | None = None
        database._pool = _BarrierPool(
            original_pool,
            exit_reached,
            release_exit,
            [],
        )
        try:
            task = asyncio.create_task(
                database.issue_websocket_ticket(
                    campaign_id,
                    _bearer_source(user_id, username),
                )
            )
            await asyncio.wait_for(exit_reached.wait(), timeout=10)
            returned_early = task.done()
            release_exit.set()
            issued = await asyncio.wait_for(task, timeout=10)
        finally:
            release_exit.set()
            database._pool = original_pool
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        _require_fixed(
            not returned_early,
            "ticket was returned before transaction exit",
        )
        _require_fixed(issued is not None, "barrier issuance did not complete")


@pytest.mark.asyncio
async def test_postgres_revision_0007_upgrade_and_downgrade(
) -> None:
    migration_catalog: dict[str, object] | None = None
    async with _postgres_harness(initialize_runtime=False) as harness:
        import asyncpg

        config = _postgres_test_config()

        async def _connect() -> Any:
            return await _bounded_operation(
                "migration-catalog-connect",
                asyncpg.connect(
                    host=config["host"],
                    port=config["port"],
                    user=config["user"],
                    database=harness.database_name,
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                ),
            )

        connection = await _connect()
        try:
            initial_counts = await _bounded_operation(
                "migration-empty-catalog",
                connection.fetchrow(
                    """
                    SELECT
                        (
                            SELECT COUNT(*)
                            FROM information_schema.tables
                            WHERE table_schema=current_schema()
                        ) AS tables,
                        (
                            SELECT to_regclass('alembic_version') IS NULL
                        ) AS version_absent
                    """
                ),
            )
        finally:
            await _attempt_cleanup(
                "migration-empty-close",
                connection.close,
                [],
            )
        initially_empty = (
            initial_counts is not None
            and int(initial_counts["tables"]) == 0
            and bool(initial_counts["version_absent"])
        )
        _require_fixed(
            initially_empty,
            "PostgreSQL migration target was not genuinely empty",
        )

        _run_ticket_migration(harness.database_name, "upgrade", "0006")
        connection = await _connect()
        try:
            parent_revision = await connection.fetchval(
                "SELECT version_num FROM alembic_version"
            )
            seed_user = f"migration-user-{uuid4().hex}"
            seed_campaign = f"migration-campaign-{uuid4().hex}"
            seed_key = f"migration-key-{uuid4().hex}"
            await connection.execute(
                """
                INSERT INTO users(id, username, hashed_password, role)
                VALUES($1, $2, $3, 'operator')
                """,
                seed_user,
                f"migration-name-{uuid4().hex}",
                "synthetic-hash",
            )
            await connection.execute(
                """
                INSERT INTO campaigns(id, name, operator)
                VALUES($1, $2, $3)
                """,
                seed_campaign,
                "Migration campaign",
                "migration-operator",
            )
            await connection.execute(
                """
                INSERT INTO api_keys(
                    id, user_id, name, key_hash, key_prefix, scopes
                )
                VALUES($1, $2, $3, $4, $5, 'read')
                """,
                seed_key,
                seed_user,
                "migration-key",
                "synthetic-key-hash",
                "synthetic-key",
            )
        finally:
            await _attempt_cleanup(
                "migration-parent-close",
                connection.close,
                [],
            )
        _require_fixed(
            parent_revision == "0006",
            "PostgreSQL migration did not reach revision 0006",
        )

        _run_ticket_migration(harness.database_name, "upgrade", "0007")
        connection = await _connect()
        try:
            await PostgresDatabase._validate_websocket_ticket_schema(connection)
            migration_catalog = await _ticket_catalog_fingerprint(connection)
            upgraded_state = await connection.fetchrow(
                """
                SELECT
                    (SELECT version_num FROM alembic_version) AS revision,
                    (SELECT COUNT(*) FROM users WHERE id=$1) AS users,
                    (SELECT COUNT(*) FROM campaigns WHERE id=$2) AS campaigns,
                    (SELECT COUNT(*) FROM api_keys WHERE id=$3) AS api_keys
                """,
                seed_user,
                seed_campaign,
                seed_key,
            )
        finally:
            await _attempt_cleanup(
                "migration-upgrade-close",
                connection.close,
                [],
            )
        upgraded = (
            upgraded_state is not None
            and upgraded_state["revision"] == "0007"
            and all(
                int(upgraded_state[name]) == 1
                for name in ("users", "campaigns", "api_keys")
            )
            and migration_catalog is not None
            and _ticket_catalog_matches_fixed_contract(migration_catalog)
        )
        _require_fixed(
            upgraded,
            "PostgreSQL ticket migration contract changed",
        )

        _run_ticket_migration(harness.database_name, "downgrade", "0006")
        connection = await _connect()
        try:
            downgraded_state = await connection.fetchrow(
                """
                SELECT
                    to_regclass('websocket_tickets') IS NULL AS ticket_absent,
                    (SELECT version_num FROM alembic_version) AS revision,
                    (SELECT COUNT(*) FROM users WHERE id=$1) AS users,
                    (SELECT COUNT(*) FROM campaigns WHERE id=$2) AS campaigns,
                    (SELECT COUNT(*) FROM api_keys WHERE id=$3) AS api_keys
                """,
                seed_user,
                seed_campaign,
                seed_key,
            )
        finally:
            await _attempt_cleanup(
                "migration-downgrade-close",
                connection.close,
                [],
            )
        downgraded = (
            downgraded_state is not None
            and bool(downgraded_state["ticket_absent"])
            and downgraded_state["revision"] == "0006"
            and all(
                int(downgraded_state[name]) == 1
                for name in ("users", "campaigns", "api_keys")
            )
        )
        _require_fixed(downgraded, "PostgreSQL ticket downgrade contract changed")

        _run_ticket_migration(harness.database_name, "upgrade", "0007")
        connection = await _connect()
        try:
            await PostgresDatabase._validate_websocket_ticket_schema(connection)
            reupgraded_catalog = await _ticket_catalog_fingerprint(connection)
            final_state = await connection.fetchrow(
                """
                SELECT
                    (SELECT version_num FROM alembic_version) AS revision,
                    (SELECT COUNT(*) FROM users WHERE id=$1) AS users,
                    (SELECT COUNT(*) FROM campaigns WHERE id=$2) AS campaigns,
                    (SELECT COUNT(*) FROM api_keys WHERE id=$3) AS api_keys
                """,
                seed_user,
                seed_campaign,
                seed_key,
            )
        finally:
            await _attempt_cleanup(
                "migration-reupgrade-close",
                connection.close,
                [],
            )
        final_state_is_exact = (
            final_state is not None
            and final_state["revision"] == "0007"
            and all(
                int(final_state[name]) == 1
                for name in ("users", "campaigns", "api_keys")
            )
            and _ticket_catalog_matches_fixed_contract(reupgraded_catalog)
            and reupgraded_catalog == migration_catalog
        )
        _require_fixed(
            final_state_is_exact,
            "PostgreSQL ticket re-upgrade contract changed",
        )

    async with _postgres_harness() as runtime_harness:
        async with runtime_harness.database._pool.acquire() as connection:
            runtime_catalog = await _ticket_catalog_fingerprint(connection)
    parity = (
        migration_catalog is not None
        and _ticket_catalog_matches_fixed_contract(runtime_catalog)
        and runtime_catalog == migration_catalog
    )
    _require_fixed(
        parity,
        "runtime and migration ticket catalogs diverged",
    )


@pytest.mark.asyncio
async def test_postgres_partial_ticket_schema_fails_clearly() -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        async with database._pool.acquire() as connection:
            await connection.execute("DROP TABLE websocket_tickets")
            await connection.execute(
                """
                CREATE TABLE websocket_tickets(
                    ticket_hash TEXT PRIMARY KEY
                )
                """
            )
            incompatible = await _ticket_catalog_fingerprint(connection)
        failure_type: type[BaseException] | None = None
        failure_message_is_fixed = False
        try:
            await database._init_schema()
        except Exception as exc:
            failure_type = type(exc)
            failure_message_is_fixed = (
                str(exc) == "Incompatible WebSocket ticket schema"
            )
        async with database._pool.acquire() as connection:
            after_failure = await _ticket_catalog_fingerprint(connection)
            reusable = await connection.fetchval("SELECT 1")
        _require_fixed(
            failure_type is RuntimeError
            and failure_message_is_fixed
            and incompatible == after_failure
            and reusable == 1,
            "partial PostgreSQL ticket schema did not fail clearly",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            """
            CREATE INDEX idx_ws_ticket_unexpected_expression
            ON websocket_tickets ((lower(ticket_hash)))
            """,
            id="expression-index",
        ),
        pytest.param(
            """
            DROP INDEX idx_ws_tickets_expires;
            CREATE INDEX idx_ws_tickets_expires
            ON websocket_tickets(expires_at DESC)
            """,
            id="index-order",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_created_finite;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_created_finite
            CHECK (isfinite(created_at)) NOT VALID
            """,
            id="not-valid-check",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT fk_ws_ticket_campaign;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT fk_ws_ticket_campaign
            FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
            ON UPDATE CASCADE ON DELETE CASCADE
            """,
            id="foreign-key-action",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ALTER COLUMN required_scope SET DEFAULT 'read'
            """,
            id="column-default",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ALTER COLUMN created_at SET DEFAULT now()
            """,
            id="timestamp-column-default",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_created_at;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_created_at
            CHECK (created_at <= expires_at)
            """,
            id="same-name-check-body",
        ),
        pytest.param(
            """
            DROP INDEX idx_ws_tickets_campaign;
            CREATE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(user_id)
            """,
            id="same-name-index-column",
        ),
        pytest.param(
            """
            DROP INDEX idx_ws_tickets_campaign;
            CREATE UNIQUE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(campaign_id)
            """,
            id="same-name-index-uniqueness",
        ),
        pytest.param(
            """
            CREATE INDEX idx_ws_ticket_duplicate_campaign
            ON websocket_tickets(campaign_id)
            """,
            id="duplicate-equivalent-index",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT websocket_tickets_pkey;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT websocket_tickets_pkey PRIMARY KEY(campaign_id)
            """,
            id="wrong-primary-key",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT fk_ws_ticket_campaign;
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT fk_ws_ticket_campaign
            FOREIGN KEY(campaign_id) REFERENCES users(id)
            ON DELETE CASCADE
            """,
            id="wrong-foreign-key-target",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            DROP CONSTRAINT ck_ws_ticket_created_finite
            """,
            id="missing-constraint",
        ),
        pytest.param(
            """
            DROP INDEX idx_ws_tickets_campaign
            """,
            id="missing-index",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ADD CONSTRAINT ck_ws_ticket_unexpected CHECK (true)
            """,
            id="extra-constraint",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ALTER COLUMN bearer_expires_at
            TYPE timestamp without time zone
            USING bearer_expires_at AT TIME ZONE 'UTC'
            """,
            id="timestamp-type",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ALTER COLUMN created_at DROP NOT NULL
            """,
            id="column-nullability",
        ),
        pytest.param(
            """
            ALTER TABLE websocket_tickets
            ALTER COLUMN bearer_subject TYPE text COLLATE "C"
            """,
            id="column-collation",
        ),
    ],
)
@pytest.mark.asyncio
async def test_postgres_validator_rejects_near_compatible_catalogs(
    mutation: str,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        async with database._pool.acquire() as connection:
            await connection.execute(mutation)
            incompatible = await _ticket_catalog_fingerprint(connection)
        failure_type: type[BaseException] | None = None
        fixed_message = False
        try:
            await database._init_schema()
        except Exception as exc:
            failure_type = type(exc)
            fixed_message = (
                str(exc) == "Incompatible WebSocket ticket schema"
            )
        async with database._pool.acquire() as connection:
            after_failure = await _ticket_catalog_fingerprint(connection)
            reusable = await connection.fetchval("SELECT 1")
        _require_fixed(
            failure_type is RuntimeError
            and fixed_message
            and incompatible == after_failure
            and reusable == 1,
            "near-compatible ticket startup prevalidation failed",
        )


_POSTGRES_RELATION_METADATA_MUTATIONS = (
    "unlogged",
    "wrong-kind",
    "partitioned",
    "inheritance-child",
    "inheritance-parent",
    "rls",
    "force-rls",
    "policy",
    "consumption-trigger",
    "rewrite-rule",
    "decoy-schema",
    "wrong-opclass",
    "wrong-relation-binding",
)


async def _apply_ticket_metadata_mutation(
    connection: Any,
    mutation: str,
) -> None:
    if mutation == "unlogged":
        await connection.execute(
            "ALTER TABLE websocket_tickets SET UNLOGGED"
        )
    elif mutation == "wrong-kind":
        await connection.execute(
            "ALTER TABLE websocket_tickets RENAME TO websocket_tickets_saved"
        )
        await connection.execute(
            """
            CREATE VIEW websocket_tickets AS
            SELECT * FROM websocket_tickets_saved
            """
        )
    elif mutation == "partitioned":
        await connection.execute(
            "ALTER TABLE websocket_tickets RENAME TO websocket_tickets_saved"
        )
        await connection.execute(
            """
            CREATE TABLE websocket_tickets(ticket_hash TEXT NOT NULL)
            PARTITION BY HASH(ticket_hash)
            """
        )
        await connection.execute(
            """
            CREATE TABLE websocket_tickets_partition
            PARTITION OF websocket_tickets
            FOR VALUES WITH (MODULUS 1, REMAINDER 0)
            """
        )
    elif mutation == "inheritance-child":
        await connection.execute(
            "CREATE TABLE ws_ticket_inheritance_parent()"
        )
        await connection.execute(
            """
            ALTER TABLE websocket_tickets
            INHERIT ws_ticket_inheritance_parent
            """
        )
    elif mutation == "inheritance-parent":
        await connection.execute(
            """
            CREATE TABLE ws_ticket_inheritance_child()
            INHERITS (websocket_tickets)
            """
        )
    elif mutation == "rls":
        await connection.execute(
            "ALTER TABLE websocket_tickets ENABLE ROW LEVEL SECURITY"
        )
    elif mutation == "force-rls":
        await connection.execute(
            "ALTER TABLE websocket_tickets ENABLE ROW LEVEL SECURITY"
        )
        await connection.execute(
            "ALTER TABLE websocket_tickets FORCE ROW LEVEL SECURITY"
        )
    elif mutation == "policy":
        await connection.execute(
            """
            CREATE POLICY ws_ticket_policy
            ON websocket_tickets
            USING (true)
            WITH CHECK (true)
            """
        )
    elif mutation == "consumption-trigger":
        await connection.execute(
            """
            CREATE FUNCTION ws_ticket_preserve_unconsumed()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $function$
            BEGIN
                NEW.consumed_at := NULL;
                RETURN NEW;
            END
            $function$
            """
        )
        await connection.execute(
            """
            CREATE TRIGGER ws_ticket_preserve_unconsumed
            BEFORE UPDATE OF consumed_at ON websocket_tickets
            FOR EACH ROW
            WHEN (NEW.consumed_at IS NOT NULL)
            EXECUTE FUNCTION ws_ticket_preserve_unconsumed()
            """
        )
    elif mutation == "rewrite-rule":
        await connection.execute(
            """
            CREATE RULE ws_ticket_update_rule AS
            ON UPDATE TO websocket_tickets
            DO ALSO NOTHING
            """
        )
    elif mutation == "decoy-schema":
        await connection.execute(
            "DROP INDEX idx_ws_tickets_campaign"
        )
        await connection.execute("CREATE SCHEMA ws_ticket_decoy")
        await connection.execute(
            """
            CREATE TABLE ws_ticket_decoy.websocket_tickets(
                campaign_id TEXT
            )
            """
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON ws_ticket_decoy.websocket_tickets(campaign_id)
            """
        )
    elif mutation == "wrong-opclass":
        await connection.execute(
            "DROP INDEX idx_ws_tickets_campaign"
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(campaign_id text_pattern_ops)
            """
        )
    elif mutation == "wrong-relation-binding":
        await connection.execute(
            "DROP INDEX idx_ws_tickets_campaign"
        )
        await connection.execute(
            "CREATE TABLE ws_ticket_index_decoy(campaign_id TEXT)"
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON ws_ticket_index_decoy(campaign_id)
            """
        )
    else:
        raise RuntimeError("Unknown PostgreSQL ticket metadata mutation")


async def _remove_ticket_metadata_mutation(
    connection: Any,
    mutation: str,
) -> None:
    if mutation == "unlogged":
        await connection.execute(
            "ALTER TABLE websocket_tickets SET LOGGED"
        )
    elif mutation == "wrong-kind":
        await connection.execute("DROP VIEW websocket_tickets")
        await connection.execute(
            "ALTER TABLE websocket_tickets_saved RENAME TO websocket_tickets"
        )
    elif mutation == "partitioned":
        await connection.execute(
            "DROP TABLE websocket_tickets CASCADE"
        )
        await connection.execute(
            "ALTER TABLE websocket_tickets_saved RENAME TO websocket_tickets"
        )
    elif mutation == "inheritance-child":
        await connection.execute(
            """
            ALTER TABLE websocket_tickets
            NO INHERIT ws_ticket_inheritance_parent
            """
        )
        await connection.execute(
            "DROP TABLE ws_ticket_inheritance_parent"
        )
    elif mutation == "inheritance-parent":
        await connection.execute(
            "DROP TABLE ws_ticket_inheritance_child"
        )
    elif mutation == "rls":
        await connection.execute(
            "ALTER TABLE websocket_tickets DISABLE ROW LEVEL SECURITY"
        )
    elif mutation == "force-rls":
        await connection.execute(
            "ALTER TABLE websocket_tickets NO FORCE ROW LEVEL SECURITY"
        )
        await connection.execute(
            "ALTER TABLE websocket_tickets DISABLE ROW LEVEL SECURITY"
        )
    elif mutation == "policy":
        await connection.execute(
            "DROP POLICY ws_ticket_policy ON websocket_tickets"
        )
    elif mutation == "consumption-trigger":
        await connection.execute(
            """
            DROP TRIGGER ws_ticket_preserve_unconsumed
            ON websocket_tickets
            """
        )
        await connection.execute(
            "DROP FUNCTION ws_ticket_preserve_unconsumed()"
        )
    elif mutation == "rewrite-rule":
        await connection.execute(
            "DROP RULE ws_ticket_update_rule ON websocket_tickets"
        )
    elif mutation == "decoy-schema":
        await connection.execute(
            "DROP SCHEMA ws_ticket_decoy CASCADE"
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(campaign_id)
            """
        )
    elif mutation == "wrong-opclass":
        await connection.execute(
            "DROP INDEX idx_ws_tickets_campaign"
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(campaign_id)
            """
        )
    elif mutation == "wrong-relation-binding":
        await connection.execute(
            "DROP TABLE ws_ticket_index_decoy"
        )
        await connection.execute(
            """
            CREATE INDEX idx_ws_tickets_campaign
            ON websocket_tickets(campaign_id)
            """
        )
    else:
        raise RuntimeError("Unknown PostgreSQL ticket metadata mutation")


async def _ticket_metadata_mutation_exists(
    connection: Any,
    mutation: str,
) -> bool:
    fingerprint = await _ticket_catalog_fingerprint(connection)
    relation = fingerprint.get("relation")
    if not isinstance(relation, tuple):
        return False
    if mutation == "unlogged":
        return relation[1] == "u"
    if mutation == "wrong-kind":
        return relation[0] == "v"
    if mutation == "partitioned":
        return relation[0] == "p" and relation[6] == 1
    if mutation == "inheritance-child":
        return relation[5] == 1
    if mutation == "inheritance-parent":
        return relation[6] == 1
    if mutation == "rls":
        return relation[3] is True and relation[4] is False
    if mutation == "force-rls":
        return relation[3] is True and relation[4] is True
    if mutation == "policy":
        return relation[7] == 1
    if mutation == "consumption-trigger":
        return relation[8] == 1
    if mutation == "rewrite-rule":
        return relation[9] == 1
    if mutation == "wrong-opclass":
        return any(
            identity[0] == "idx_ws_tickets_campaign"
            and identity[4] == ("text_pattern_ops",)
            and identity[5] == ("pg_catalog",)
            for identity in fingerprint.get("index_identities", ())
        )
    if mutation == "decoy-schema":
        return bool(
            await connection.fetchval(
                """
                SELECT
                    NOT EXISTS(
                        SELECT 1
                        FROM pg_index AS ind
                        JOIN pg_class AS rel ON rel.oid=ind.indrelid
                        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                        JOIN pg_class AS idx ON idx.oid=ind.indexrelid
                        WHERE nsp.nspname=current_schema()
                          AND rel.relname='websocket_tickets'
                          AND idx.relname='idx_ws_tickets_campaign'
                    )
                    AND EXISTS(
                        SELECT 1
                        FROM pg_index AS ind
                        JOIN pg_class AS rel ON rel.oid=ind.indrelid
                        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                        JOIN pg_class AS idx ON idx.oid=ind.indexrelid
                        WHERE nsp.nspname='ws_ticket_decoy'
                          AND rel.relname='websocket_tickets'
                          AND idx.relname='idx_ws_tickets_campaign'
                    )
                """
            )
        )
    if mutation == "wrong-relation-binding":
        return bool(
            await connection.fetchval(
                """
                SELECT
                    NOT EXISTS(
                        SELECT 1
                        FROM pg_index AS ind
                        JOIN pg_class AS rel ON rel.oid=ind.indrelid
                        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                        JOIN pg_class AS idx ON idx.oid=ind.indexrelid
                        WHERE nsp.nspname=current_schema()
                          AND rel.relname='websocket_tickets'
                          AND idx.relname='idx_ws_tickets_campaign'
                    )
                    AND EXISTS(
                        SELECT 1
                        FROM pg_index AS ind
                        JOIN pg_class AS rel ON rel.oid=ind.indrelid
                        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                        JOIN pg_class AS idx ON idx.oid=ind.indexrelid
                        WHERE nsp.nspname=current_schema()
                          AND rel.relname='ws_ticket_index_decoy'
                          AND idx.relname='idx_ws_tickets_campaign'
                    )
                """
            )
        )
    return False


async def _ticket_related_object_fingerprint(
    connection: Any,
) -> tuple[tuple[object, ...], ...]:
    rows = await connection.fetch(
        """
        SELECT nsp.nspname, rel.relname, rel.relkind,
               rel.relpersistence, rel.relispartition,
               rel.relrowsecurity, rel.relforcerowsecurity
        FROM pg_class AS rel
        JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
        WHERE (
                nsp.nspname=current_schema()
                AND (
                    rel.relname LIKE 'websocket_tickets%'
                    OR rel.relname LIKE 'idx_ws_tickets%'
                    OR rel.relname LIKE 'ws_ticket_%'
                )
              )
           OR nsp.nspname='ws_ticket_decoy'
        ORDER BY nsp.nspname, rel.relname
        """
    )
    return tuple(tuple(row) for row in rows)


async def _ticket_rows_for_metadata_mutation(
    connection: Any,
    mutation: str,
) -> tuple[tuple[object, ...], ...]:
    if mutation in {"wrong-kind", "partitioned"}:
        query = """
            SELECT ticket_hash, campaign_id, user_id, credential_kind,
                   bearer_subject, bearer_jti, bearer_expires_at,
                   api_key_id, required_scope, created_at, expires_at,
                   consumed_at
            FROM websocket_tickets_saved
            ORDER BY ticket_hash
        """
    else:
        query = """
            SELECT ticket_hash, campaign_id, user_id, credential_kind,
                   bearer_subject, bearer_jti, bearer_expires_at,
                   api_key_id, required_scope, created_at, expires_at,
                   consumed_at
            FROM websocket_tickets
            ORDER BY ticket_hash
        """
    rows = await connection.fetch(
        query
    )
    return tuple(tuple(row) for row in rows)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(value, id=value)
        for value in _POSTGRES_RELATION_METADATA_MUTATIONS
    ],
)
@pytest.mark.asyncio
async def test_postgres_rejects_security_altering_relation_metadata(
    mutation: str,
) -> None:
    async with _postgres_harness() as harness:
        database = harness.database
        user_id, username, campaign_id, _other_id, _key_id = (
            await _seed_identity(database)
        )
        issued = await database.issue_websocket_ticket(
            campaign_id,
            _bearer_source(user_id, username),
        )
        _require_fixed(
            issued is not None,
            "PostgreSQL metadata mutation ticket setup failed",
        )
        raw_ticket = (issued or ("", 0))[0]
        observer_pool = database._pool
        candidate = _database_for_target(harness.database_name)
        mutation_applied = False
        candidate_connected = False
        try:
            async with observer_pool.acquire() as connection:
                await asyncio.wait_for(
                    _apply_ticket_metadata_mutation(connection, mutation),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                mutation_applied = True
                mutation_exists = await asyncio.wait_for(
                    _ticket_metadata_mutation_exists(connection, mutation),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )

            trigger_would_enable_replay = True
            if mutation == "consumption-trigger":
                first = await asyncio.wait_for(
                    database.consume_websocket_ticket(
                        raw_ticket,
                        campaign_id,
                    ),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                second = await asyncio.wait_for(
                    database.consume_websocket_ticket(
                        raw_ticket,
                        campaign_id,
                    ),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                async with observer_pool.acquire() as connection:
                    remains_unconsumed = bool(
                        await connection.fetchval(
                            """
                            SELECT consumed_at IS NULL
                            FROM websocket_tickets
                            WHERE ticket_hash=$1
                            """,
                            hash_websocket_ticket(raw_ticket),
                        )
                    )
                trigger_would_enable_replay = (
                    first is not None
                    and second is not None
                    and remains_unconsumed
                )

            async with observer_pool.acquire() as connection:
                before_catalog = await asyncio.wait_for(
                    _ticket_catalog_fingerprint(connection),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                before_related = await asyncio.wait_for(
                    _ticket_related_object_fingerprint(connection),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                before_rows = await asyncio.wait_for(
                    _ticket_rows_for_metadata_mutation(connection, mutation),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )

            failure_type: type[BaseException] | None = None
            fixed_message = False
            try:
                await asyncio.wait_for(
                    candidate.connect(),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                candidate_connected = True
            except Exception as exc:
                failure_type = type(exc)
                fixed_message = (
                    str(exc) == "Incompatible WebSocket ticket schema"
                )
            pool_was_cleared = candidate._pool is None

            async with observer_pool.acquire() as connection:
                after_catalog = await asyncio.wait_for(
                    _ticket_catalog_fingerprint(connection),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                after_related = await asyncio.wait_for(
                    _ticket_related_object_fingerprint(connection),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                after_rows = await asyncio.wait_for(
                    _ticket_rows_for_metadata_mutation(connection, mutation),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                observer_reusable = (
                    await asyncio.wait_for(
                        connection.fetchval("SELECT 1"),
                        timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                    )
                    == 1
                )
            startup_preserved_state = (
                before_catalog == after_catalog
                and before_related == after_related
                and before_rows == after_rows
            )
            _require_fixed(
                mutation_exists
                and trigger_would_enable_replay
                and failure_type is RuntimeError
                and fixed_message
                and pool_was_cleared
                and startup_preserved_state
                and observer_reusable,
                "PostgreSQL relation metadata prevalidation failed",
            )
        finally:
            if candidate_connected or candidate._pool is not None:
                await _attempt_cleanup(
                    "metadata-candidate-close",
                    candidate.close,
                    [],
                )
            if mutation_applied:
                async with observer_pool.acquire() as connection:
                    await asyncio.wait_for(
                        _remove_ticket_metadata_mutation(connection, mutation),
                        timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                    )

        recovery = _database_for_target(harness.database_name)
        try:
            await asyncio.wait_for(
                recovery.connect(),
                timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
            )
            async with recovery._pool.acquire() as connection:
                recovered_catalog = await asyncio.wait_for(
                    _ticket_catalog_fingerprint(connection),
                    timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                )
                recovered_connection = (
                    await asyncio.wait_for(
                        connection.fetchval("SELECT 1"),
                        timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
                    )
                    == 1
                )
            consumed = await asyncio.wait_for(
                recovery.consume_websocket_ticket(
                    raw_ticket,
                    campaign_id,
                ),
                timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
            )
            replay = await asyncio.wait_for(
                recovery.consume_websocket_ticket(
                    raw_ticket,
                    campaign_id,
                ),
                timeout=_POSTGRES_OPERATION_TIMEOUT_SECONDS,
            )
            recovery_is_exact = (
                _ticket_catalog_matches_fixed_contract(recovered_catalog)
                and recovered_connection
                and consumed is not None
                and replay is None
            )
            _require_fixed(
                recovery_is_exact,
                "PostgreSQL metadata correction recovery failed",
            )
        finally:
            if recovery._pool is not None:
                await _attempt_cleanup(
                    "metadata-recovery-close",
                    recovery.close,
                    [],
                )
