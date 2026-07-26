"""SQLite API-key expiry and atomic refresh-token lifecycle regressions."""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable
from unittest.mock import Mock

import aiosqlite
import pytest

import ares.db.database as database_module
from ares.db.database import AresDatabase


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _owned_sqlite_tasks() -> list[asyncio.Task[object]]:
    current = asyncio.current_task()
    return [
        task
        for task in asyncio.all_tasks()
        if task is not current
        and not task.done()
        and task.get_name().startswith("ares-sqlite-")
    ]


def _install_real_commit_gate(
    db: AresDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[asyncio.Event, threading.Event, list[int]]:
    """Pause in SQLite's worker-thread COMMIT trace callback."""
    loop = asyncio.get_running_loop()
    commit_started = asyncio.Event()
    release_commit = threading.Event()
    commit_count = [0]
    original_open = db._open_refresh_rotation_connection

    async def open_with_commit_trace() -> aiosqlite.Connection:
        tx = await original_open()

        def trace(statement: str) -> None:
            if statement.strip().upper() == "COMMIT":
                commit_count[0] += 1
                loop.call_soon_threadsafe(commit_started.set)
                release_commit.wait()

        await tx.set_trace_callback(trace)
        return tx

    monkeypatch.setattr(
        db,
        "_open_refresh_rotation_connection",
        open_with_commit_trace,
    )
    return commit_started, release_commit, commit_count


async def _set_api_key_expiry(
    db: AresDatabase,
    key_id: str,
    expires_at: str | None,
) -> None:
    await db.conn.execute(
        "UPDATE api_keys SET expires_at=? WHERE id=?",
        (expires_at, key_id),
    )
    await db.conn.commit()


async def _refresh_rows(db: AresDatabase) -> list[dict[str, object]]:
    async with db.conn.execute(
        "SELECT id,user_id,is_revoked,expires_at,used_at FROM refresh_tokens"
    ) as cur:
        return [dict(row) for row in await cur.fetchall()]


async def _active_refresh_count(db: AresDatabase, user_id: str) -> int:
    async with db.conn.execute(
        "SELECT COUNT(*) AS n FROM refresh_tokens "
        "WHERE user_id=? AND is_revoked=0",
        (user_id,),
    ) as cur:
        return int((await cur.fetchone())["n"])


def _require_fixed(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


async def _api_key_last_used(db: AresDatabase, key_id: str) -> object:
    async with db.conn.execute(
        "SELECT last_used FROM api_keys WHERE id=?",
        (key_id,),
    ) as cur:
        row = await cur.fetchone()
    return None if row is None else row["last_used"]


async def _run_cleanup_helper(
    db: AresDatabase,
    helper_name: str,
    operation: Awaitable[Any],
    *,
    action: str = "test-cleanup",
) -> None:
    cancellation_baseline = (
        asyncio.current_task().cancelling()
        if asyncio.current_task() is not None
        else 0
    )
    caught_cancellations = [0]
    if helper_name == "connection":
        await db._finish_connection_cleanup(
            operation,
            action=action,
            cancellation_baseline=cancellation_baseline,
            caught_cancellations=caught_cancellations,
        )
    else:
        await db._finish_refresh_rotation_cleanup(
            operation,
            action,
            cancellation_baseline=cancellation_baseline,
            caught_cancellations=caught_cancellations,
        )


@pytest.fixture
async def db_and_user(tmp_path: Path) -> AsyncIterator[tuple[AresDatabase, str]]:
    db = await AresDatabase.create(str(tmp_path / "sqlite-auth.db"))
    try:
        user_id = await db.create_user(
            "sqlite-lifecycle-user",
            "SyntheticLifecyclePass1!",
            "operator",
        )
        yield db, user_id
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_rotation_before_connect_fails_without_creating_database(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "not-connected.db"
    db = AresDatabase(str(db_path))

    with pytest.raises(RuntimeError, match="Database not connected"):
        await db.rotate_refresh_token("unused-input")

    assert not db_path.exists()
    await db.close()


@pytest.mark.asyncio
async def test_close_is_authoritative_repeatable_and_reconnects(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "lifecycle.db"
    moved_path = tmp_path / "lifecycle-closed.db"
    db = await AresDatabase.create(str(db_path))
    try:
        user_id = await db.create_user(
            "lifecycle-state-user",
            "SyntheticLifecycleStatePass1!",
            "operator",
        )
        predecessor = await db.create_refresh_token(user_id)

        await db.close()
        await db.close()
        db_path.replace(moved_path)
        try:
            with pytest.raises(RuntimeError, match="Database not connected"):
                await db.rotate_refresh_token(predecessor)
            assert not db_path.exists()
        finally:
            moved_path.replace(db_path)

        await db.connect()
        user, successor = await db.rotate_refresh_token(predecessor)
        assert user is not None
        assert successor is not None
        assert await _active_refresh_count(db, user_id) == 1
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_concurrent_connect_owns_one_primary_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = AresDatabase(str(tmp_path / "concurrent-connect.db"))
    open_started = asyncio.Event()
    release_open = asyncio.Event()
    second_attempted = asyncio.Event()
    opened: list[aiosqlite.Connection] = []
    schema_connections: list[aiosqlite.Connection | None] = []
    original_open = db._open_primary_connection
    original_init_schema = db._init_schema

    async def gated_open() -> aiosqlite.Connection:
        connection = await original_open()
        opened.append(connection)
        open_started.set()
        await release_open.wait()
        return connection

    async def checked_schema() -> None:
        schema_connections.append(db._conn)
        await original_init_schema()

    async def second_connect() -> AresDatabase:
        second_attempted.set()
        return await db.connect()

    first_task: asyncio.Task[AresDatabase] | None = None
    second_task: asyncio.Task[AresDatabase] | None = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(db, "_open_primary_connection", gated_open)
            patcher.setattr(db, "_init_schema", checked_schema)
            first_task = asyncio.create_task(db.connect())
            await open_started.wait()
            second_task = asyncio.create_task(second_connect())
            await second_attempted.wait()

            assert len(opened) == 1
            assert second_task.done() is False
            release_open.set()
            first_result, second_result = await asyncio.gather(
                first_task,
                second_task,
            )

        assert first_result is db
        assert second_result is db
        assert len(opened) == 1
        assert schema_connections == [opened[0]]
        assert db.conn is opened[0]
    finally:
        release_open.set()
        for task in (first_task, second_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (first_task, second_task) if task is not None),
            return_exceptions=True,
        )
        await db.close()


@pytest.mark.asyncio
async def test_rotation_holds_lifecycle_ownership_until_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = await AresDatabase(":memory:").connect()
    rotation_opened = asyncio.Event()
    release_rotation = asyncio.Event()
    close_attempted = asyncio.Event()
    original_open = db._open_refresh_rotation_connection
    rotation_task: asyncio.Task[tuple[dict[str, object] | None, str | None]] | None = None
    close_task: asyncio.Task[None] | None = None
    try:
        user_id = await db.create_user(
            "memory-close-race-user",
            "SyntheticMemoryCloseRacePass1!",
            "operator",
        )
        predecessor = await db.create_refresh_token(user_id)

        async def gated_rotation_open() -> aiosqlite.Connection:
            connection = await original_open()
            rotation_opened.set()
            await release_rotation.wait()
            return connection

        async def close_after_attempt() -> None:
            close_attempted.set()
            await db.close()

        with monkeypatch.context() as patcher:
            patcher.setattr(
                db,
                "_open_refresh_rotation_connection",
                gated_rotation_open,
            )
            rotation_task = asyncio.create_task(
                db.rotate_refresh_token(predecessor)
            )
            await rotation_opened.wait()
            close_task = asyncio.create_task(close_after_attempt())
            await close_attempted.wait()

            assert close_task.done() is False
            assert db.conn is not None
            release_rotation.set()
            user, successor = await rotation_task
            await close_task

        assert user is not None
        assert successor is not None
        with pytest.raises(RuntimeError, match="Database not connected"):
            await db.rotate_refresh_token(successor)
    finally:
        release_rotation.set()
        for task in (rotation_task, close_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (rotation_task, close_task) if task is not None),
            return_exceptions=True,
        )
        await db.close()


@pytest.mark.asyncio
async def test_reconnect_waits_for_prior_close_and_keeps_new_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = await AresDatabase.create(str(tmp_path / "close-reconnect.db"))
    old_connection = db.conn
    close_started = asyncio.Event()
    release_close = asyncio.Event()
    reconnect_attempted = asyncio.Event()
    original_close = db._close_primary_connection
    close_calls = [0]

    async def gated_close(connection: aiosqlite.Connection) -> None:
        close_calls[0] += 1
        if close_calls[0] == 1:
            close_started.set()
            await release_close.wait()
        await original_close(connection)

    async def reconnect_after_attempt() -> AresDatabase:
        reconnect_attempted.set()
        return await db.connect()

    close_task: asyncio.Task[None] | None = None
    reconnect_task: asyncio.Task[AresDatabase] | None = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(db, "_close_primary_connection", gated_close)
            close_task = asyncio.create_task(db.close())
            await close_started.wait()
            reconnect_task = asyncio.create_task(reconnect_after_attempt())
            await reconnect_attempted.wait()

            assert reconnect_task.done() is False
            release_close.set()
            await close_task
            reconnected = await reconnect_task

        assert reconnected is db
        assert db.conn is not old_connection
        assert db._connected is True
    finally:
        release_close.set()
        for task in (close_task, reconnect_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (close_task, reconnect_task) if task is not None),
            return_exceptions=True,
        )
        await db.close()


@pytest.mark.asyncio
async def test_cancelled_lifecycle_lock_waiter_creates_no_database(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "cancelled-lock-waiter.db"
    db = AresDatabase(str(db_path))
    connect_attempted = asyncio.Event()

    async def waiting_connect() -> AresDatabase:
        connect_attempted.set()
        return await db.connect()

    async with db._lifecycle_lock:
        connect_task = asyncio.create_task(waiting_connect())
        await connect_attempted.wait()
        connect_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await connect_task

    assert db._conn is None
    assert db._connected is False
    assert not db_path.exists()
    await db.close()


@pytest.mark.asyncio
async def test_relative_database_identity_survives_cwd_change(
    tmp_path: Path,
) -> None:
    original_dir = Path.cwd()
    database_dir = tmp_path / "database-root"
    redirected_dir = tmp_path / "other-cwd"
    database_dir.mkdir()
    redirected_dir.mkdir()
    db: AresDatabase | None = None
    try:
        os.chdir(database_dir)
        db = await AresDatabase.create("relative-auth.db")
        user_id = await db.create_user(
            "relative-path-user",
            "SyntheticRelativePathPass1!",
            "operator",
        )
        predecessor = await db.create_refresh_token(user_id)

        os.chdir(redirected_dir)
        user, successor = await db.rotate_refresh_token(predecessor)

        assert user is not None
        assert successor is not None
        assert (database_dir / "relative-auth.db").exists()
        assert not (redirected_dir / "relative-auth.db").exists()
        assert await _active_refresh_count(db, user_id) == 1
    finally:
        try:
            if db is not None:
                await db.close()
        finally:
            os.chdir(original_dir)


@pytest.mark.asyncio
async def test_relative_file_uri_preserves_identity_and_query_after_cwd_change(
    tmp_path: Path,
) -> None:
    original_dir = Path.cwd()
    database_dir = tmp_path / "uri-database-root"
    redirected_dir = tmp_path / "uri-other-cwd"
    database_dir.mkdir()
    redirected_dir.mkdir()
    db: AresDatabase | None = None
    try:
        os.chdir(database_dir)
        db = AresDatabase(
            "file:relative%20uri.db?mode=rwc&cache=shared"
        )
        assert db._db_path.endswith(
            "/relative%20uri.db?mode=rwc&cache=shared"
        )
        await db.connect()
        user_id = await db.create_user(
            "relative-uri-user",
            "SyntheticRelativeUriPass1!",
            "operator",
        )
        predecessor = await db.create_refresh_token(user_id)

        os.chdir(redirected_dir)
        user, successor = await db.rotate_refresh_token(predecessor)

        assert user is not None
        assert successor is not None
        assert (database_dir / "relative uri.db").exists()
        assert not (redirected_dir / "relative uri.db").exists()
        assert await _active_refresh_count(db, user_id) == 1
    finally:
        try:
            if db is not None:
                await db.close()
        finally:
            os.chdir(original_dir)


@pytest.mark.asyncio
async def test_explicit_absolute_file_uri_remains_valid(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "absolute uri.db"
    db = AresDatabase(
        f"file:{db_path.as_posix()}?mode=rwc&cache=shared"
    )
    try:
        await db.connect()
        assert db_path.exists()
        assert db._db_path.endswith("?mode=rwc&cache=shared")
    finally:
        await db.close()


@pytest.mark.parametrize(
    "uri_path",
    [
        pytest.param("C:/ARES Data/\u30e6\u30cb\u30b3\u30fc\u30c9%20auth.db", id="drive"),
        pytest.param("/C:/ARES Data/\u30e6\u30cb\u30b3\u30fc\u30c9%20auth.db", id="slash-drive"),
        pytest.param("///C:/ARES Data/\u30e6\u30cb\u30b3\u30fc\u30c9%20auth.db", id="triple-slash-drive"),
    ],
)
def test_windows_drive_file_uri_forms_have_one_cwd_independent_identity(
    uri_path: str,
    tmp_path: Path,
) -> None:
    query = "mode=rwc&cache=shared&label=%20"
    original_dir = Path.cwd()
    first = database_module._normalize_sqlite_target(
        f"file:{uri_path}?{query}"
    )
    try:
        os.chdir(tmp_path)
        second = database_module._normalize_sqlite_target(
            f"file:{uri_path}?{query}"
        )
    finally:
        os.chdir(original_dir)

    expected = (
        "file:C:/ARES Data/\u30e6\u30cb\u30b3\u30fc\u30c9%20auth.db"
        f"?{query}"
    )
    assert first == (expected, True, "sqlite-file")
    assert second == first
    assert first[0].partition("?")[2] == query
    assert "%2520" not in first[0]
    assert first[0].startswith("file:C:/")


@pytest.mark.skipif(os.name != "nt", reason="Windows filesystem integration")
@pytest.mark.asyncio
async def test_windows_drive_uri_forms_share_primary_and_rotation_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_dir = tmp_path / "Windows URI \u8a8d\u8a3c"
    redirected_dir = tmp_path / "redirected-cwd"
    database_dir.mkdir()
    redirected_dir.mkdir()
    database_path = database_dir / "auth database.db"
    encoded_path = database_path.as_posix().replace(" ", "%20")
    query = "mode=rwc&cache=shared"
    uri_forms = [
        f"file:{encoded_path}?{query}",
        f"file:/{encoded_path}?{query}",
        f"file:///{encoded_path}?{query}",
    ]
    expected_target = f"file:{encoded_path}?{query}"
    original_connect = database_module.aiosqlite.connect
    opened_targets: list[tuple[str, bool]] = []
    databases: list[AresDatabase] = []
    original_dir = Path.cwd()

    def recording_connect(
        database: str,
        *args: object,
        **kwargs: object,
    ) -> aiosqlite.Connection:
        opened_targets.append((database, bool(kwargs.get("uri"))))
        return original_connect(database, *args, **kwargs)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(
                database_module.aiosqlite,
                "connect",
                recording_connect,
            )
            first = await AresDatabase(uri_forms[0]).connect()
            databases.append(first)
            user_id = await first.create_user(
                "windows-uri-user",
                "SyntheticWindowsUriPass1!",
                "operator",
            )
            predecessor = await first.create_refresh_token(user_id)
            await first.close()

            os.chdir(redirected_dir)
            second = await AresDatabase(uri_forms[1]).connect()
            databases.append(second)
            user, successor = await second.rotate_refresh_token(predecessor)
            assert user is not None
            assert successor is not None
            await second.close()

            third = await AresDatabase(uri_forms[2]).connect()
            databases.append(third)
            rotated_user, replacement = await third.rotate_refresh_token(successor)
            assert rotated_user is not None
            assert replacement is not None
            assert await _active_refresh_count(third, user_id) == 1
    finally:
        try:
            for db in reversed(databases):
                await db.close()
        finally:
            os.chdir(original_dir)

    assert database_path.exists()
    assert opened_targets
    assert set(opened_targets) == {(expected_target, True)}


@pytest.mark.asyncio
async def test_explicit_memory_uri_remains_memory_backed(
    tmp_path: Path,
) -> None:
    original_dir = Path.cwd()
    db = AresDatabase(
        "file:explicit-memory?mode=memory&cache=shared"
    )
    try:
        os.chdir(tmp_path)
        await db.connect()
        user_id = await db.create_user(
            "explicit-memory-user",
            "SyntheticExplicitMemoryPass1!",
            "operator",
        )
        predecessor = await db.create_refresh_token(user_id)
        user, successor = await db.rotate_refresh_token(predecessor)

        assert db._database_label == "sqlite-memory"
        assert user is not None
        assert successor is not None
        assert not (tmp_path / "explicit-memory").exists()
    finally:
        try:
            await db.close()
        finally:
            os.chdir(original_dir)


@pytest.mark.parametrize(
    "db_uri",
    [
        pytest.param("file://remote-host/share/database.db", id="authority"),
        pytest.param("file:relative.db?vfs=custom", id="vfs"),
        pytest.param("file:relative.db?%76fs=custom", id="encoded-vfs"),
        pytest.param("file:%2Funstable.db?mode=rwc", id="encoded-separator"),
    ],
)
def test_unsupported_file_uri_semantics_fail_early(db_uri: str) -> None:
    with pytest.raises(ValueError, match="Unsupported SQLite file URI"):
        AresDatabase(db_uri)


def test_encoded_memory_mode_retains_memory_semantics() -> None:
    db = AresDatabase(
        "file:encoded-memory?mode=%6Demory&cache=shared"
    )
    assert db._database_label == "sqlite-memory"
    assert db._db_path.endswith("?mode=%6Demory&cache=shared")


@pytest.mark.asyncio
async def test_database_logs_use_sanitized_labels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "sensitive-parent" / "logged.db"
    db_path.parent.mkdir()
    captured_logger = Mock()
    db = AresDatabase(str(db_path))
    uri_db = AresDatabase(
        f"file:{(tmp_path / 'uri.db').as_posix()}?mode=rwc&cache=shared"
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(database_module, "logger", captured_logger)
        try:
            await db.connect()
            await uri_db.connect()
        finally:
            await uri_db.close()
            await db.close()

    calls = repr(captured_logger.mock_calls)
    assert str(tmp_path) not in calls
    assert tmp_path.as_posix() not in calls
    assert Path.home().name not in calls
    assert "mode=rwc&cache=shared" not in calls
    assert "sqlite-file" in calls


@pytest.mark.parametrize("helper_name", ["connection", "refresh"])
@pytest.mark.asyncio
async def test_cleanup_helpers_sanitize_ordinary_exceptions(
    helper_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = AresDatabase(":memory:")
    captured_logger = Mock()
    cleanup = asyncio.get_running_loop().create_future()
    cleanup.set_exception(RuntimeError("private-cleanup-detail"))

    with monkeypatch.context() as patcher:
        patcher.setattr(database_module, "logger", captured_logger)
        await _run_cleanup_helper(db, helper_name, cleanup)

    calls = repr(captured_logger.mock_calls)
    assert "RuntimeError" in calls
    assert "test-cleanup" in calls
    assert "private-cleanup-detail" not in calls
    assert _owned_sqlite_tasks() == []


@pytest.mark.parametrize("helper_name", ["connection", "refresh"])
@pytest.mark.parametrize("error_type", [SystemExit, KeyboardInterrupt])
@pytest.mark.asyncio
async def test_cleanup_helpers_propagate_control_flow_baseexceptions(
    helper_name: str,
    error_type: type[BaseException],
) -> None:
    db = AresDatabase(":memory:")
    cleanup = asyncio.get_running_loop().create_future()
    cleanup.set_exception(error_type())

    with pytest.raises(error_type):
        await _run_cleanup_helper(db, helper_name, cleanup)

    assert _owned_sqlite_tasks() == []


@pytest.mark.parametrize("helper_name", ["connection", "refresh"])
@pytest.mark.asyncio
async def test_owned_cleanup_task_cancellation_propagates_and_terminates(
    helper_name: str,
) -> None:
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()

    async def blocked_cleanup() -> None:
        cleanup_started.set()
        await release_cleanup.wait()

    db = AresDatabase(":memory:")
    waiter = asyncio.create_task(
        _run_cleanup_helper(db, helper_name, blocked_cleanup())
    )
    try:
        await cleanup_started.wait()
        owned = _owned_sqlite_tasks()
        assert len(owned) == 1
        owned[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
    finally:
        release_cleanup.set()
        if not waiter.done():
            waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)

    assert _owned_sqlite_tasks() == []


@pytest.mark.asyncio
async def test_rollback_cleanup_error_preserves_primary_rotation_failure(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PrimaryRotationFailure(Exception):
        pass

    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    original_open = db._open_refresh_rotation_connection
    captured_logger = Mock()

    async def open_with_failing_rollback() -> aiosqlite.Connection:
        tx = await original_open()
        original_rollback = tx.rollback

        async def rollback_then_fail() -> None:
            await original_rollback()
            raise RuntimeError("private-rollback-detail")

        patcher.setattr(tx, "rollback", rollback_then_fail)
        return tx

    async def fail_successor_insert(
        _tx: aiosqlite.Connection,
        _token_hash_value: str,
        _user_id: str,
        _expires_at: str,
    ) -> None:
        raise PrimaryRotationFailure("primary-rotation-failure")

    with monkeypatch.context() as patcher:
        patcher.setattr(database_module, "logger", captured_logger)
        patcher.setattr(
            db,
            "_open_refresh_rotation_connection",
            open_with_failing_rollback,
        )
        patcher.setattr(db, "_insert_refresh_successor", fail_successor_insert)
        with pytest.raises(
            PrimaryRotationFailure,
            match="primary-rotation-failure",
        ):
            await db.rotate_refresh_token(predecessor)

    rows = await _refresh_rows(db)
    assert len(rows) == 1
    assert rows[0]["is_revoked"] == 0
    assert rows[0]["used_at"] is None
    calls = repr(captured_logger.mock_calls)
    assert "rollback_before_commit" in calls
    assert "RuntimeError" in calls
    assert "private-rollback-detail" not in calls
    assert db._db_path not in calls
    assert _owned_sqlite_tasks() == []


@pytest.mark.asyncio
async def test_close_cleanup_error_after_commit_keeps_committed_result(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    original_open = db._open_refresh_rotation_connection
    captured_logger = Mock()

    async def open_with_failing_close() -> aiosqlite.Connection:
        tx = await original_open()
        original_close = tx.close

        async def close_then_fail() -> None:
            await original_close()
            raise RuntimeError("private-close-detail")

        patcher.setattr(tx, "close", close_then_fail)
        return tx

    with monkeypatch.context() as patcher:
        patcher.setattr(database_module, "logger", captured_logger)
        patcher.setattr(
            db,
            "_open_refresh_rotation_connection",
            open_with_failing_close,
        )
        user, successor = await db.rotate_refresh_token(predecessor)

    assert user is not None
    assert successor is not None
    assert await _active_refresh_count(db, user_id) == 1
    assert len(await _refresh_rows(db)) == 2
    calls = repr(captured_logger.mock_calls)
    assert "close" in calls
    assert "RuntimeError" in calls
    assert "private-close-detail" not in calls
    assert db._db_path not in calls
    assert _owned_sqlite_tasks() == []


@pytest.mark.asyncio
async def test_plain_memory_instances_are_isolated_and_independently_anchored() -> None:
    first = await AresDatabase(":memory:").connect()
    second = await AresDatabase(":memory:").connect()
    try:
        first_user = await first.create_user(
            "first-memory-user",
            "SyntheticFirstMemoryPass1!",
            "operator",
        )
        second_user = await second.create_user(
            "second-memory-user",
            "SyntheticSecondMemoryPass1!",
            "operator",
        )
        first_token = await first.create_refresh_token(first_user)
        second_token = await second.create_refresh_token(second_user)

        assert first._db_path != second._db_path
        assert await second.rotate_refresh_token(first_token) == (None, None)
        assert await first.rotate_refresh_token(second_token) == (None, None)

        first_result = await first.rotate_refresh_token(first_token)
        second_result = await second.rotate_refresh_token(second_token)
        assert first_result[0] is not None
        assert first_result[1] is not None
        assert second_result[0] is not None
        assert second_result[1] is not None
        assert await _active_refresh_count(first, first_user) == 1
        assert await _active_refresh_count(second, second_user) == 1
    finally:
        try:
            await second.close()
        finally:
            await first.close()


@pytest.mark.asyncio
async def test_inactive_owner_api_key_is_denied_without_usage_and_reactivates(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "inactive-owner-key")

    active_verification = await db.verify_api_key(raw_key)
    _require_fixed(
        active_verification is not None,
        "expected active-owner API key verification to succeed",
    )

    usage_marker = "2000-01-01 00:00:00"
    await db.conn.execute(
        "UPDATE api_keys SET last_used=? WHERE id=?",
        (usage_marker, key_id),
    )
    await db.conn.execute(
        "UPDATE users SET is_active=0 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    usage_before = await _api_key_last_used(db, key_id)

    inactive_verification = await db.verify_api_key(raw_key)
    usage_after = await _api_key_last_used(db, key_id)
    _require_fixed(
        inactive_verification is None,
        "expected inactive-owner API key verification to be rejected",
    )
    _require_fixed(
        usage_before == usage_marker and usage_after == usage_before,
        "expected inactive-owner API key usage metadata to remain unchanged",
    )

    await db.conn.execute(
        "UPDATE users SET is_active=1 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    reactivated_verification = await db.verify_api_key(raw_key)
    _require_fixed(
        reactivated_verification is not None,
        "expected reactivated-owner API key verification to succeed",
    )

    await db.conn.execute(
        "UPDATE api_keys SET is_active=0 WHERE id=?",
        (key_id,),
    )
    await db.conn.commit()
    revoked_verification = await db.verify_api_key(raw_key)
    _require_fixed(
        revoked_verification is None,
        "expected revoked API key verification to remain rejected",
    )


@pytest.mark.asyncio
async def test_inactive_owner_refresh_is_immutable_and_reactivates(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    await db.conn.execute(
        "UPDATE users SET is_active=0 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()

    inactive_result = await db.rotate_refresh_token(predecessor)
    inactive_rows = await _refresh_rows(db)
    _require_fixed(
        inactive_result == (None, None),
        "expected inactive-owner refresh rotation to be rejected",
    )
    _require_fixed(
        len(inactive_rows) == 1
        and inactive_rows[0]["user_id"] == user_id
        and inactive_rows[0]["is_revoked"] == 0
        and inactive_rows[0]["used_at"] is None,
        "expected inactive-owner refresh predecessor to remain unchanged",
    )

    await db.conn.execute(
        "UPDATE users SET is_active=1 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    reactivated_user, successor = await db.rotate_refresh_token(predecessor)
    _require_fixed(
        reactivated_user is not None and successor is not None,
        "expected reactivated-owner refresh rotation to succeed",
    )
    reused_result = await db.rotate_refresh_token(predecessor)
    _require_fixed(
        reused_result == (None, None),
        "expected the reactivated predecessor to rotate only once",
    )
    _require_fixed(
        await _active_refresh_count(db, user_id) == 1,
        "expected exactly one active refresh successor after reactivation",
    )


@pytest.mark.asyncio
async def test_authoritative_principal_state_role_revocation_and_read_only(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    from ares.api.rbac import PrincipalDecisionStatus, resolve_bearer_principal
    from ares.core.security import create_access_token

    db, user_id = db_and_user
    subject = "sqlite-lifecycle-user"
    jti = "sqlite-principal-jti"

    changes_before = db.conn.total_changes
    active = await db.resolve_access_token_principal(subject, jti)
    changes_after = db.conn.total_changes
    _require_fixed(
        active is not None
        and active.get("id") == user_id
        and active.get("username") == subject
        and active.get("role") == "operator",
        "expected active SQLite bearer principal to resolve canonically",
    )
    _require_fixed(
        changes_after == changes_before,
        "expected authoritative SQLite principal lookup to remain read-only",
    )

    await db.conn.execute(
        "UPDATE users SET is_active=0 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    inactive = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        inactive is None,
        "expected inactive SQLite bearer principal to be rejected",
    )

    await db.conn.execute(
        "UPDATE users SET is_active=1, role='reporter' WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    demoted = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        demoted is not None and demoted.get("role") == "reporter",
        "expected SQLite principal lookup to return the current demoted role",
    )

    await db.conn.execute(
        "UPDATE users SET role='team_lead' WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    promoted = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        promoted is not None and promoted.get("role") == "team_lead",
        "expected SQLite principal lookup to return the current promoted role",
    )

    await db.conn.execute(
        "UPDATE users SET role='unsupported-role' WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    signing_key = "sqlite-principal-test-signing-key"
    token = create_access_token(
        {"sub": subject, "role": "team_lead"},
        signing_key,
    )
    invalid_role = await resolve_bearer_principal(
        token,
        db=db,
        secret_key=signing_key,
        algorithm="HS256",
    )
    _require_fixed(
        invalid_role.status is PrincipalDecisionStatus.INVALID,
        "expected an unknown database role to fail bearer authorization",
    )

    await db.conn.execute(
        "UPDATE users SET role='operator' WHERE id=?",
        (user_id,),
    )
    await db.conn.execute(
        """INSERT INTO revoked_access_tokens(jti,user_id,expires_at)
           VALUES(?,?,?)""",
        (jti, user_id, "2099-01-01 00:00:00"),
    )
    await db.conn.commit()
    revoked = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        revoked is None,
        "expected revoked SQLite bearer principal to be rejected",
    )

    await db.conn.execute(
        "DELETE FROM revoked_access_tokens WHERE jti=?",
        (jti,),
    )
    await db.conn.execute(
        "UPDATE users SET is_active=0 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    suspended = await db.resolve_access_token_principal(subject, jti)
    await db.conn.execute(
        "UPDATE users SET is_active=1 WHERE id=?",
        (user_id,),
    )
    await db.conn.commit()
    reactivated = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        suspended is None and reactivated is not None,
        "expected temporary SQLite suspension to be reversible",
    )

    await db.conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    await db.conn.commit()
    deleted = await db.resolve_access_token_principal(subject, jti)
    _require_fixed(
        deleted is None,
        "expected a deleted SQLite bearer principal to be rejected",
    )


@pytest.mark.asyncio
async def test_authoritative_principal_closed_database_propagates(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, _ = db_and_user
    await db.close()
    with pytest.raises(RuntimeError):
        await db.resolve_access_token_principal(
            "sqlite-lifecycle-user",
            "sqlite-closed-jti",
        )
    await db.connect()


@pytest.mark.asyncio
async def test_api_key_rejects_iso_expiry_earlier_on_current_utc_date(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "expired-current-day")
    now = datetime.now(timezone.utc)
    expired = now.replace(hour=0, minute=0, second=0, microsecond=0)
    assert expired.date() == now.date()
    assert expired <= now
    await _set_api_key_expiry(db, key_id, expired.isoformat())

    assert await db.verify_api_key(raw_key) is None


@pytest.mark.asyncio
async def test_api_key_accepts_future_iso_offset_expiry(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "future-iso")
    await _set_api_key_expiry(
        db,
        key_id,
        (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    )

    assert await db.verify_api_key(raw_key) is not None


@pytest.mark.asyncio
async def test_api_key_accepts_null_expiry(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    _key_id, raw_key = await db.create_api_key(user_id, "no-expiry")

    assert await db.verify_api_key(raw_key) is not None


@pytest.mark.asyncio
async def test_api_key_accepts_legacy_space_format_future_expiry(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "future-legacy")
    future = datetime.now(timezone.utc) + timedelta(days=1)
    await _set_api_key_expiry(db, key_id, future.strftime("%Y-%m-%d %H:%M:%S"))

    assert await db.verify_api_key(raw_key) is not None


@pytest.mark.asyncio
async def test_nonzero_offset_crossing_utc_date_uses_instant_ordering(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "future-offset")
    now_utc = datetime.now(timezone.utc)
    future_utc = (now_utc + timedelta(days=2)).replace(
        hour=0,
        minute=30,
        second=0,
        microsecond=0,
    )
    encoded = future_utc.astimezone(timezone(timedelta(hours=-5)))

    assert encoded.date() < future_utc.date()
    assert encoded.astimezone(timezone.utc) == future_utc
    assert future_utc > now_utc
    await _set_api_key_expiry(db, key_id, encoded.isoformat())

    assert await db.verify_api_key(raw_key) is not None


@pytest.mark.asyncio
async def test_database_generated_exact_now_is_rejected(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "exact-now")
    predecessor = await db.create_refresh_token(user_id)
    await db.conn.execute(
        "UPDATE api_keys SET expires_at=datetime('now') WHERE id=?",
        (key_id,),
    )
    await db.conn.execute(
        "UPDATE refresh_tokens SET expires_at=datetime('now') WHERE id=?",
        (_token_hash(predecessor),),
    )
    await db.conn.commit()

    assert await db.verify_api_key(raw_key) is None
    assert await db.rotate_refresh_token(predecessor) == (None, None)


@pytest.mark.asyncio
async def test_api_key_rejects_malformed_non_null_expiry(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    key_id, raw_key = await db.create_api_key(user_id, "malformed-expiry")
    await _set_api_key_expiry(db, key_id, "not-a-timestamp")

    assert await db.verify_api_key(raw_key) is None


@pytest.mark.parametrize(
    "expires_at",
    [
        pytest.param(
            lambda: (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            id="expired-iso-offset",
        ),
        pytest.param(lambda: "not-a-timestamp", id="malformed"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_refresh_expiry_cannot_rotate_or_create_successor(
    db_and_user: tuple[AresDatabase, str],
    expires_at,
) -> None:
    db, user_id = db_and_user
    old_token = await db.create_refresh_token(user_id)
    await db.conn.execute(
        "UPDATE refresh_tokens SET expires_at=? WHERE id=?",
        (expires_at(), _token_hash(old_token)),
    )
    await db.conn.commit()

    assert await db.rotate_refresh_token(old_token) == (None, None)
    rows = await _refresh_rows(db)
    assert len(rows) == 1
    assert rows[0]["is_revoked"] == 0


@pytest.mark.asyncio
async def test_future_refresh_rotates_with_hashed_successor_and_30_day_expiry(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    old_token = await db.create_refresh_token(user_id)

    user, successor = await db.rotate_refresh_token(old_token)

    assert user is not None
    assert successor is not None
    rows = await _refresh_rows(db)
    assert len(rows) == 2
    assert await _active_refresh_count(db, user_id) == 1
    active = next(row for row in rows if row["is_revoked"] == 0)
    assert active["id"] == _token_hash(successor)
    assert active["id"] != successor
    remaining = datetime.fromisoformat(str(active["expires_at"])) - datetime.now(
        timezone.utc
    )
    assert timedelta(days=29, hours=23) < remaining <= timedelta(days=30)


@pytest.mark.asyncio
async def test_cancellation_before_commit_rolls_back_and_propagates(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    inserted = asyncio.Event()
    release = asyncio.Event()
    original_insert = db._insert_refresh_successor

    async def insert_then_pause(
        tx: aiosqlite.Connection,
        token_hash: str,
        successor_user_id: str,
        expires_at: str,
    ) -> None:
        await original_insert(
            tx,
            token_hash,
            successor_user_id,
            expires_at,
        )
        inserted.set()
        await release.wait()

    with monkeypatch.context() as patcher:
        patcher.setattr(db, "_insert_refresh_successor", insert_then_pause)
        rotation = asyncio.create_task(db.rotate_refresh_token(predecessor))
        await inserted.wait()
        rotation.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await rotation
        finally:
            release.set()

    rows = await _refresh_rows(db)
    assert len(rows) == 1
    assert rows[0]["is_revoked"] == 0
    assert rows[0]["used_at"] is None
    assert await _active_refresh_count(db, user_id) == 1

    user, successor = await db.rotate_refresh_token(predecessor)
    assert user is not None
    assert successor is not None
    assert await _active_refresh_count(db, user_id) == 1


@pytest.mark.asyncio
async def test_cancellation_during_commit_returns_committed_successor(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    predecessor_hash = _token_hash(predecessor)
    rotation: asyncio.Task[tuple[dict[str, object] | None, str | None]] | None = None
    with monkeypatch.context() as patcher:
        commit_started, release_commit, commit_count = _install_real_commit_gate(
            db,
            patcher,
        )
        try:
            rotation = asyncio.create_task(
                db.rotate_refresh_token(predecessor)
            )
            await commit_started.wait()
            entry_cancellation_count = rotation.cancelling()
            rotation.cancel()
            release_commit.set()
            user, successor = await rotation
        finally:
            release_commit.set()

    assert commit_count == [1]
    assert rotation.cancelled() is False
    assert rotation.cancelling() == entry_cancellation_count
    assert _owned_sqlite_tasks() == []
    assert user is not None
    assert successor is not None
    rows = await _refresh_rows(db)
    assert len(rows) == 2
    predecessor_row = next(row for row in rows if row["id"] == predecessor_hash)
    active_row = next(row for row in rows if row["is_revoked"] == 0)
    assert predecessor_row["is_revoked"] == 1
    assert predecessor_row["used_at"] is not None
    assert active_row["id"] == _token_hash(successor)
    assert await _active_refresh_count(db, user_id) == 1

    rotated_user, replacement = await db.rotate_refresh_token(successor)
    assert rotated_user is not None
    assert replacement is not None
    assert await db.rotate_refresh_token(successor) == (None, None)
    assert await _active_refresh_count(db, user_id) == 1


@pytest.mark.asyncio
async def test_repeated_cancellation_during_real_commit_is_normalized(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)
    rotation: asyncio.Task[tuple[dict[str, object] | None, str | None]] | None = None

    with monkeypatch.context() as patcher:
        commit_started, release_commit, commit_count = _install_real_commit_gate(
            db,
            patcher,
        )
        try:
            rotation = asyncio.create_task(
                db.rotate_refresh_token(predecessor)
            )
            await commit_started.wait()
            entry_cancellation_count = rotation.cancelling()
            assert rotation.cancel() is True
            assert rotation.cancel() is True
            assert rotation.cancelling() == entry_cancellation_count + 2
            release_commit.set()
            user, successor = await rotation
        finally:
            release_commit.set()

    assert commit_count == [1]
    assert rotation.cancelled() is False
    assert rotation.cancelling() == entry_cancellation_count
    assert _owned_sqlite_tasks() == []
    assert user is not None
    assert successor is not None
    rows = await _refresh_rows(db)
    assert len(rows) == 2
    assert sum(row["is_revoked"] == 0 for row in rows) == 1
    assert await _active_refresh_count(db, user_id) == 1


@pytest.mark.asyncio
async def test_commit_normalization_preserves_preexisting_cancellation_debt(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, _user_id = db_and_user
    predecessor = await db.create_refresh_token(_user_id)

    with monkeypatch.context() as patcher:
        commit_started, release_commit, commit_count = _install_real_commit_gate(
            db,
            patcher,
        )

        async def rotate_with_existing_debt():
            current = asyncio.current_task()
            assert current is not None
            current.cancel()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass
            entry_cancellation_count = current.cancelling()
            try:
                result = await db.rotate_refresh_token(predecessor)
                final_cancellation_count = current.cancelling()
                return result, entry_cancellation_count, final_cancellation_count
            finally:
                while current.cancelling():
                    current.uncancel()

        rotation = asyncio.create_task(rotate_with_existing_debt())
        try:
            await commit_started.wait()
            rotation.cancel()
            release_commit.set()
            (
                (user, successor),
                entry_cancellation_count,
                final_cancellation_count,
            ) = await rotation
        finally:
            release_commit.set()

    assert commit_count == [1]
    assert entry_cancellation_count == 1
    assert final_cancellation_count == entry_cancellation_count
    assert rotation.cancelling() == 0
    assert user is not None
    assert successor is not None


@pytest.mark.asyncio
async def test_purge_preserves_grace_and_malformed_unrevoked_rows(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    now = datetime.now(timezone.utc)
    rows = [
        (_token_hash(secrets.token_urlsafe(32)), 1, (now + timedelta(days=1)).isoformat()),
        (_token_hash(secrets.token_urlsafe(32)), 0, (now - timedelta(days=8)).isoformat()),
        (
            _token_hash(secrets.token_urlsafe(32)),
            0,
            (now - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
        ),
        (_token_hash(secrets.token_urlsafe(32)), 0, "not-a-timestamp"),
        (_token_hash(secrets.token_urlsafe(32)), 0, (now + timedelta(days=1)).isoformat()),
    ]
    await db.conn.executemany(
        "INSERT INTO refresh_tokens(id,user_id,is_revoked,expires_at) "
        "VALUES(?,?,?,?)",
        [(token_id, user_id, revoked, expires_at) for token_id, revoked, expires_at in rows],
    )
    await db.conn.commit()

    assert await db.purge_expired_tokens() == 2
    remaining = await _refresh_rows(db)
    assert {row["id"] for row in remaining} == {
        rows[2][0],
        rows[3][0],
        rows[4][0],
    }


@pytest.mark.asyncio
async def test_many_concurrent_rotations_have_one_winner_and_reusable_successor(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    old_token = await db.create_refresh_token(user_id)
    start = asyncio.Event()

    async def rotate_once():
        await start.wait()
        return await db.rotate_refresh_token(old_token)

    tasks = [asyncio.create_task(rotate_once()) for _ in range(16)]
    start.set()
    results = await asyncio.gather(*tasks)
    winners = [result for result in results if result != (None, None)]

    assert len(winners) == 1
    assert sum(result == (None, None) for result in results) == 15
    assert await _active_refresh_count(db, user_id) == 1
    assert len(await _refresh_rows(db)) == 2
    assert await db.rotate_refresh_token(old_token) == (None, None)

    successor = winners[0][1]
    assert successor is not None
    rotated_user, replacement = await db.rotate_refresh_token(successor)
    assert rotated_user is not None
    assert replacement is not None
    assert await db.rotate_refresh_token(successor) == (None, None)
    assert await _active_refresh_count(db, user_id) == 1


@pytest.mark.asyncio
async def test_two_database_instances_have_exactly_one_rotation_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "shared-auth.db")
    first = await AresDatabase.create(db_path)
    second = await AresDatabase.create(db_path)
    first_holds_writer = asyncio.Event()
    release_first = asyncio.Event()
    second_transaction_statement_seen = asyncio.Event()
    statement_lock = threading.Lock()
    first_transaction_order: list[str] = []
    second_transaction_order: list[str] = []
    first_task: asyncio.Task[
        tuple[dict[str, object] | None, str | None]
    ] | None = None
    second_task: asyncio.Task[
        tuple[dict[str, object] | None, str | None]
    ] | None = None
    try:
        user_id = await first.create_user(
            "shared-lifecycle-user",
            "SyntheticSharedPass1!",
            "operator",
        )
        old_token = await first.create_refresh_token(user_id)
        old_hash = _token_hash(old_token)
        original_insert = first._insert_refresh_successor
        original_first_open = first._open_refresh_rotation_connection
        original_second_open = second._open_refresh_rotation_connection
        loop = asyncio.get_running_loop()

        def record_transaction_statement(
            statement: str,
            destination: list[str],
            signal: asyncio.Event | None = None,
        ) -> None:
            normalized = " ".join(statement.strip().upper().split())
            statement_class: str | None = None
            if normalized == "BEGIN IMMEDIATE":
                statement_class = "BEGIN IMMEDIATE"
            elif normalized.startswith("BEGIN"):
                statement_class = "OTHER BEGIN"
            elif (
                normalized.startswith("SELECT ")
                and "FROM REFRESH_TOKENS" in normalized
            ):
                statement_class = "PREDECESSOR SELECT"
            elif normalized.startswith("UPDATE REFRESH_TOKENS"):
                statement_class = "CAS UPDATE"
            elif normalized.startswith("INSERT INTO REFRESH_TOKENS"):
                statement_class = "SUCCESSOR INSERT"
            elif normalized == "COMMIT":
                statement_class = "COMMIT"
            if statement_class is None:
                return
            with statement_lock:
                destination.append(statement_class)
            if signal is not None:
                loop.call_soon_threadsafe(signal.set)

        async def pause_with_writer_lock(
            tx: aiosqlite.Connection,
            token_hash: str,
            successor_user_id: str,
            expires_at: str,
        ) -> None:
            first_holds_writer.set()
            await release_first.wait()
            await original_insert(
                tx,
                token_hash,
                successor_user_id,
                expires_at,
            )

        async def open_first_with_transaction_trace() -> aiosqlite.Connection:
            tx = await original_first_open()

            def trace(statement: str) -> None:
                record_transaction_statement(
                    statement,
                    first_transaction_order,
                )

            await tx.set_trace_callback(trace)
            return tx

        async def open_with_begin_trace() -> aiosqlite.Connection:
            tx = await original_second_open()

            def trace(statement: str) -> None:
                record_transaction_statement(
                    statement,
                    second_transaction_order,
                    second_transaction_statement_seen,
                )

            await tx.set_trace_callback(trace)
            return tx

        with monkeypatch.context() as patcher:
            patcher.setattr(
                first,
                "_open_refresh_rotation_connection",
                open_first_with_transaction_trace,
            )
            patcher.setattr(
                first,
                "_insert_refresh_successor",
                pause_with_writer_lock,
            )
            patcher.setattr(
                second,
                "_open_refresh_rotation_connection",
                open_with_begin_trace,
            )
            first_task = asyncio.create_task(
                first.rotate_refresh_token(old_token)
            )
            await first_holds_writer.wait()
            with statement_lock:
                first_prefix = tuple(first_transaction_order)
            assert first_prefix == (
                "BEGIN IMMEDIATE",
                "PREDECESSOR SELECT",
                "CAS UPDATE",
            )
            second_task = asyncio.create_task(
                second.rotate_refresh_token(old_token)
            )
            await second_transaction_statement_seen.wait()
            with statement_lock:
                second_prefix = tuple(second_transaction_order)

            assert first_task.done() is False
            assert second_task.done() is False
            assert second_prefix == ("BEGIN IMMEDIATE",)
            release_first.set()
            first_result, second_result = await asyncio.gather(
                first_task,
                second_task,
            )

        assert first_result != (None, None)
        assert second_result == (None, None)
        with statement_lock:
            completed_first_order = tuple(first_transaction_order)
            completed_second_order = tuple(second_transaction_order)
        assert completed_first_order == (
            "BEGIN IMMEDIATE",
            "PREDECESSOR SELECT",
            "CAS UPDATE",
            "SUCCESSOR INSERT",
            "COMMIT",
        )
        assert completed_first_order.count("BEGIN IMMEDIATE") == 1
        assert completed_second_order.count("BEGIN IMMEDIATE") == 1
        assert await _active_refresh_count(first, user_id) == 1
        rows = await _refresh_rows(first)
        assert len(rows) == 2
        predecessor = next(row for row in rows if row["id"] == old_hash)
        assert predecessor["is_revoked"] == 1
        assert predecessor["used_at"] is not None
        assert sum(row["is_revoked"] == 0 for row in rows) == 1
        assert _owned_sqlite_tasks() == []
    finally:
        release_first.set()
        for task in (first_task, second_task):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(
                task
                for task in (first_task, second_task)
                if task is not None
            ),
            return_exceptions=True,
        )
        try:
            await second.close()
        finally:
            await first.close()


@pytest.mark.asyncio
async def test_successor_insert_failure_rolls_back_old_token_consumption(
    db_and_user: tuple[AresDatabase, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db, user_id = db_and_user
    old_token = await db.create_refresh_token(user_id)
    old_hash = _token_hash(old_token)

    with monkeypatch.context() as patcher:
        patcher.setattr(database_module.secrets, "token_urlsafe", lambda _size: old_token)
        with pytest.raises(aiosqlite.IntegrityError):
            await db.rotate_refresh_token(old_token)

    rows = await _refresh_rows(db)
    assert len(rows) == 1
    assert rows[0]["id"] == old_hash
    assert rows[0]["is_revoked"] == 0
    assert rows[0]["used_at"] is None

    user, successor = await db.rotate_refresh_token(old_token)
    assert user is not None
    assert successor is not None
    assert await _active_refresh_count(db, user_id) == 1


@pytest.mark.asyncio
async def test_rotation_then_logout_revokes_committed_successor(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)

    user, successor = await db.rotate_refresh_token(predecessor)
    assert user is not None
    assert successor is not None
    await db.revoke_all_refresh_tokens(user_id)

    assert await _active_refresh_count(db, user_id) == 0
    assert await db.rotate_refresh_token(predecessor) == (None, None)
    assert await db.rotate_refresh_token(successor) == (None, None)


@pytest.mark.asyncio
async def test_logout_then_rotation_has_no_winner(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    predecessor = await db.create_refresh_token(user_id)

    await db.revoke_all_refresh_tokens(user_id)

    assert await db.rotate_refresh_token(predecessor) == (None, None)
    assert await _active_refresh_count(db, user_id) == 0
    rows = await _refresh_rows(db)
    assert len(rows) == 1
    assert rows[0]["is_revoked"] == 1


@pytest.mark.asyncio
async def test_rotation_racing_logout_leaves_no_usable_refresh_token(
    db_and_user: tuple[AresDatabase, str],
) -> None:
    db, user_id = db_and_user
    old_token = await db.create_refresh_token(user_id)
    start = asyncio.Event()

    async def rotate():
        await start.wait()
        return await db.rotate_refresh_token(old_token)

    async def logout():
        await start.wait()
        await db.revoke_all_refresh_tokens(user_id)

    rotation_task = asyncio.create_task(rotate())
    logout_task = asyncio.create_task(logout())
    start.set()
    rotation_result, _ = await asyncio.gather(rotation_task, logout_task)

    assert await _active_refresh_count(db, user_id) == 0
    assert await db.rotate_refresh_token(old_token) == (None, None)
    successor = rotation_result[1]
    if successor is not None:
        assert await db.rotate_refresh_token(successor) == (None, None)


@pytest.mark.asyncio
async def test_plain_memory_database_supports_atomic_refresh_lifecycle() -> None:
    db = await AresDatabase(":memory:").connect()
    try:
        user_id = await db.create_user(
            "memory-lifecycle-user",
            "SyntheticMemoryPass1!",
            "operator",
        )
        old_token = await db.create_refresh_token(user_id)

        user, successor = await db.rotate_refresh_token(old_token)

        assert db._is_sqlite_uri is True
        assert user is not None
        assert successor is not None
        assert await db.rotate_refresh_token(old_token) == (None, None)
        assert await _active_refresh_count(db, user_id) == 1
    finally:
        await db.close()
