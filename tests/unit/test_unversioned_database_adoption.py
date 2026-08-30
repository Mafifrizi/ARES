"""Authentic SQLite and packaging tests for explicit M2b adoption."""
from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command

import ares.db.migrations.adoption as adoption_module
from ares.db.database import AresDatabase
from ares.db.execution_lifecycle import sqlite_admission_authority_runtime_script
from ares.db.migrations.adoption import (
    SUPPORTED_GENERATIONS,
    AdoptionExit,
    AdoptionFailure,
    AdoptionResult,
    adopt_sqlite,
    inspect_sqlite_database,
    migration_config,
    restore_sqlite,
    sqlite_catalog_and_row_digest,
    verify_managed_connection_from_path,
)
from ares.db.schema import CREATE_TABLES


async def _create_runtime(path: Path, *, generation: int = 7) -> None:
    engine = sa.create_engine(f"sqlite:///{path.resolve().as_posix()}")
    with engine.connect() as connection:
        with migration_config(connection) as config:
            command.upgrade(config, "0008")
        connection.exec_driver_sql("DROP TABLE rate_limit_events")
        connection.exec_driver_sql("DROP TABLE alembic_version")
        if generation == 6:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            try:
                connection.exec_driver_sql("DROP TABLE websocket_tickets")
            finally:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()
    engine.dispose()


def _catalog_digest(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        return sqlite_catalog_and_row_digest(connection)
    finally:
        connection.close()


def test_supported_generation_contract_is_frozen() -> None:
    contract = tuple(
        (item.dialect, item.generation, item.predecessor, item.has_websocket_tickets)
        for item in SUPPORTED_GENERATIONS
    )
    assert contract == (
        ("sqlite", 6, "0006", False),
        ("sqlite", 7, "0007", True),
        ("postgresql", 6, "0006", False),
        ("postgresql", 7, "0007", True),
        ("sqlite", 10, "runtime-0010", True),
        ("sqlite", 11, "runtime-0011", True),
    )


def test_result_repr_and_equality_do_not_expose_fields() -> None:
    result = AdoptionResult(AdoptionExit.OK, "ARES-M2B-EMPTY-DATABASE")
    assert "ARES" not in repr(result)
    assert result != AdoptionResult(AdoptionExit.OK, "ARES-M2B-EMPTY-DATABASE")


def test_installed_resource_contract_and_linear_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(Path.cwd().anchor)
    with migration_config() as config:
        script_location = config.get_main_option("script_location")
        assert script_location
        assert "alembic.ini" not in script_location


def test_packaging_configuration_carries_one_canonical_tree() -> None:
    project = Path(__file__).resolve().parents[2]
    configuration = (project / "pyproject.toml").read_text(encoding="utf-8")
    reduced = (
        'include = ["ares*", "migrations"]' in configuration,
        'migrations = ["script.py.mako", "versions/*.py"]' in configuration,
        not (project / "ares" / "db" / "migrations" / "versions").exists(),
    )
    assert reduced == (True, True, True)


@pytest.mark.asyncio
@pytest.mark.parametrize(("generation", "predecessor"), [(6, "0006"), (7, "0007")])
async def test_sqlite_runtime_generation_is_classified(
    tmp_path: Path,
    generation: int,
    predecessor: str,
) -> None:
    path = tmp_path / "runtime.db"
    await _create_runtime(path, generation=generation)
    result = inspect_sqlite_database(path)
    assert result.predecessor == predecessor
    assert result.diagnostic.endswith(predecessor)
    connection = sqlite3.connect(path)
    try:
        version_count = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name='alembic_version'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert version_count == 0


@pytest.mark.asyncio
async def test_runtime_generation_ten_adopts_by_exact_catalog_then_removes_marker(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime-ten.db"
    backup = tmp_path / "runtime-ten.backup"
    connection = sqlite3.connect(path)
    try:
        generation_11_script = sqlite_admission_authority_runtime_script()
        assert CREATE_TABLES.endswith(generation_11_script)
        connection.executescript(CREATE_TABLES[: -len(generation_11_script)])
    finally:
        connection.close()
    classified = inspect_sqlite_database(path)
    adopted = await asyncio.to_thread(adopt_sqlite, path, backup)
    connection = sqlite3.connect(path)
    try:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        legacy_marker = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name='schema_version'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert (classified.predecessor, adopted.exit_code, revision, legacy_marker) == (
        "runtime-0010",
        AdoptionExit.OK,
        "0011",
        0,
    ), "runtime generation ten adoption changed"


@pytest.mark.asyncio
async def test_unknown_sqlite_catalog_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unknown.db"
    await _create_runtime(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE unexpected_object(value TEXT)")
        connection.commit()
    finally:
        connection.close()
    before = _catalog_digest(path)
    with pytest.raises(AdoptionFailure) as caught:
        inspect_sqlite_database(path)
    rejected = (
        caught.value.exit_code == AdoptionExit.UNRECOGNIZED,
        _catalog_digest(path) == before,
    )
    assert rejected == (True, True)


@pytest.mark.asyncio
@pytest.mark.parametrize("generation", [6, 7])
async def test_sqlite_adoption_uses_backup_and_normal_history(
    tmp_path: Path,
    generation: int,
) -> None:
    path = tmp_path / "source.db"
    backup = tmp_path / "source.backup"
    await _create_runtime(path, generation=generation)
    before = _catalog_digest(path)
    result = await asyncio.to_thread(adopt_sqlite, path, backup)
    assert result.exit_code == AdoptionExit.OK
    assert backup.is_file()
    assert _catalog_digest(backup) == before
    managed = verify_managed_connection_from_path(path)
    assert managed.diagnostic == "ARES-M2B-ALREADY-MANAGED:0011"
    connection = sqlite3.connect(path)
    try:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
    finally:
        connection.close()
    assert revision == "0011"


@pytest.mark.asyncio
async def test_sqlite_adoption_rerun_is_verified_noop(tmp_path: Path) -> None:
    path = tmp_path / "source.db"
    backup = tmp_path / "source.backup"
    second_backup = tmp_path / "second.backup"
    await _create_runtime(path)
    first = await asyncio.to_thread(adopt_sqlite, path, backup)
    before = _catalog_digest(path)
    second = await asyncio.to_thread(adopt_sqlite, path, second_backup)
    assert (
        first.exit_code,
        second.diagnostic,
        _catalog_digest(path) == before,
        second_backup.exists(),
    ) == (
        AdoptionExit.OK,
        "ARES-M2B-ALREADY-MANAGED:0011",
        True,
        False,
    )


@pytest.mark.asyncio
async def test_sqlite_post_upgrade_failure_rolls_back_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "source.db"
    backup = tmp_path / "source.backup"
    await _create_runtime(path)
    before = _catalog_digest(path)
    original = adoption_module._run_canonical_adoption

    def fail_after_upgrade(connection: sa.Connection, predecessor: str) -> None:
        original(connection, predecessor)
        raise RuntimeError("fixed-injected-failure")

    monkeypatch.setattr(
        adoption_module,
        "_run_canonical_adoption",
        fail_after_upgrade,
    )
    with pytest.raises(AdoptionFailure) as caught:
        await asyncio.to_thread(adopt_sqlite, path, backup)
    connection = sqlite3.connect(path)
    try:
        version_objects = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name='alembic_version'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert (
        caught.value.exit_code,
        _catalog_digest(path) == before,
        backup.exists(),
        version_objects,
    ) == (AdoptionExit.ROLLED_BACK, True, True, 0)


@pytest.mark.asyncio
async def test_sqlite_backup_is_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "source.db"
    backup = tmp_path / "source.backup"
    await _create_runtime(path)
    backup.write_bytes(b"occupied")
    before = _catalog_digest(path)
    with pytest.raises(AdoptionFailure) as caught:
        await asyncio.to_thread(adopt_sqlite, path, backup)
    fixed = (
        caught.value.exit_code == AdoptionExit.BACKUP,
        backup.read_bytes() == b"occupied",
        _catalog_digest(path) == before,
    )
    assert fixed == (True, True, True)


@pytest.mark.asyncio
async def test_sqlite_restore_retains_verified_backup(tmp_path: Path) -> None:
    path = tmp_path / "source.db"
    backup = tmp_path / "source.backup"
    await _create_runtime(path)
    original = _catalog_digest(path)
    source = sqlite3.connect(path)
    target = sqlite3.connect(backup)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE drift(value TEXT)")
        connection.commit()
    finally:
        connection.close()
    result = await asyncio.to_thread(restore_sqlite, path, backup)
    assert result.exit_code == AdoptionExit.OK
    assert backup.exists()
    assert _catalog_digest(path) == original


@pytest.mark.asyncio
async def test_startup_rejects_unversioned_without_alembic_side_effect(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime.db"
    await _create_runtime(path)
    before = _catalog_digest(path)
    database = AresDatabase(path)
    with pytest.raises(RuntimeError, match="adoption is required"):
        await database.connect()
    assert _catalog_digest(path) == before
    assert database._conn is None


@pytest.mark.asyncio
async def test_startup_requires_migration_for_managed_0009(tmp_path: Path) -> None:
    path = tmp_path / "runtime.db"
    await _create_runtime(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE alembic_version ("
            "version_num VARCHAR(32) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
        connection.execute("INSERT INTO alembic_version VALUES ('0009')")
        connection.commit()
    finally:
        connection.close()
    before = _catalog_digest(path)
    database = AresDatabase(path)
    with pytest.raises(RuntimeError, match="migration is required"):
        await database.connect()
    assert _catalog_digest(path) == before


def test_cli_help_has_no_repository_dependency(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment["PYTHONPYCACHEPREFIX"] = os.fspath(tmp_path / "pycache")
    environment["PYTHONPATH"] = os.fspath(Path(__file__).resolve().parents[2])
    completed = subprocess.run(
        [sys.executable, "-m", "ares.db.migrations", "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    reduced = (
        completed.returncode,
        "verify-adoption" in completed.stdout,
        "ARES-M2B-E02" not in completed.stdout,
    )
    assert reduced == (0, True, True)


def test_caller_owned_connection_remains_open(tmp_path: Path) -> None:
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    try:
        with engine.connect() as connection:
            with migration_config(connection) as config:
                assert config.attributes["connection"] is connection
            assert connection.scalar(sa.text("SELECT 1")) == 1
    finally:
        engine.dispose()
