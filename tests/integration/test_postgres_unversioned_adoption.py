"""Real PostgreSQL tests for explicit unversioned database adoption."""
from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import create_async_engine

from ares.db.migrations import adoption
from ares.db.migrations.adoption import AdoptionExit, AdoptionFailure

_ENV = (
    "ARES_TEST_POSTGRES_HOST",
    "ARES_TEST_POSTGRES_PORT",
    "ARES_TEST_POSTGRES_USER",
    "ARES_TEST_POSTGRES_DB",
)
_SAFE_NAME = re.compile(r"\Aares_m2b_[0-9a-f]{32}\Z")


@dataclass(frozen=True, repr=False, eq=False)
class _Config:
    host: str = field(repr=False)
    port: int = field(repr=False)
    user: str = field(repr=False)
    database: str = field(repr=False)


def _config() -> _Config:
    present = [name for name in _ENV if name in os.environ]
    if not present:
        pytest.skip("real PostgreSQL test environment is not configured")
    if len(present) != len(_ENV):
        pytest.fail("Incomplete PostgreSQL test environment", pytrace=False)
    values = {name: os.environ[name] for name in _ENV}
    if any(not value or value != value.strip() for value in values.values()):
        pytest.fail("Invalid PostgreSQL test environment", pytrace=False)
    raw_port = values["ARES_TEST_POSTGRES_PORT"]
    if not raw_port.isascii() or not raw_port.isdecimal():
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    port = int(raw_port)
    if str(port) != raw_port or not 1 <= port <= 65535:
        pytest.fail("PostgreSQL test port is invalid", pytrace=False)
    return _Config(
        values["ARES_TEST_POSTGRES_HOST"],
        port,
        values["ARES_TEST_POSTGRES_USER"],
        values["ARES_TEST_POSTGRES_DB"],
    )


def _url(config: _Config, database: str) -> str:
    return URL.create(
        "postgresql+asyncpg",
        username=config.user,
        host=config.host,
        port=config.port,
        database=database,
    ).render_as_string(hide_password=False)


@asynccontextmanager
async def _database() -> AsyncIterator[str]:
    config = _config()
    try:
        import asyncpg
    except ImportError:
        pytest.fail("PostgreSQL test driver is unavailable", pytrace=False)
    name = f"ares_m2b_{uuid4().hex}"
    if _SAFE_NAME.fullmatch(name) is None or name == config.database:
        pytest.fail("Unsafe disposable database identity", pytrace=False)
    admin = await asyncio.wait_for(
        asyncpg.connect(
            host=config.host,
            port=config.port,
            user=config.user,
            database=config.database,
        ),
        timeout=20,
    )
    created = False
    try:
        created = True
        await asyncio.wait_for(
            admin.execute(f'CREATE DATABASE "{name}"'),
            timeout=20,
        )
        yield _url(config, name)
    finally:
        if created:
            await asyncio.wait_for(
                admin.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname=$1 AND pid <> pg_backend_pid()",
                    name,
                ),
                timeout=20,
            )
            await asyncio.wait_for(
                admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'),
                timeout=20,
            )
        await asyncio.wait_for(admin.close(), timeout=20)


async def _runtime(url: str, generation: int) -> None:
    from ares.db.postgres import (
        _PG_CREATE_TABLES,
        _POSTGRES_FALLBACK_STATEMENT_SPANS,
    )

    engine = create_async_engine(url, poolclass=sa.pool.NullPool)
    try:
        async with engine.begin() as connection:
            for _code, start, end in _POSTGRES_FALLBACK_STATEMENT_SPANS:
                await connection.exec_driver_sql(_PG_CREATE_TABLES[start:end])
            if generation == 6:
                await connection.exec_driver_sql("DROP TABLE websocket_tickets")
    finally:
        await engine.dispose()


async def _revision(url: str) -> str | None:
    engine = create_async_engine(url, poolclass=sa.pool.NullPool)
    try:
        async with engine.connect() as connection:
            relation = await connection.scalar(
                sa.text(
                    "SELECT to_regclass(current_schema() || '.alembic_version')"
                )
            )
            if relation is None:
                return None
            return await connection.scalar(
                sa.text("SELECT version_num FROM alembic_version")
            )
    finally:
        await engine.dispose()


def test_postgres_adoption_config_absence_is_intentional_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(pytest.skip.Exception):
        _config()


def test_postgres_adoption_partial_config_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ARES_TEST_POSTGRES_HOST", "fixed-host")
    with pytest.raises(pytest.fail.Exception):
        _config()


def test_postgres_adoption_invalid_port_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "ARES_TEST_POSTGRES_HOST": "fixed-host",
        "ARES_TEST_POSTGRES_PORT": "not-a-port",
        "ARES_TEST_POSTGRES_USER": "fixed-user",
        "ARES_TEST_POSTGRES_DB": "fixed-db",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(pytest.fail.Exception):
        _config()


@pytest.mark.asyncio
@pytest.mark.parametrize(("generation", "predecessor"), [(6, "0006"), (7, "0007")])
async def test_real_postgres_generation_adopts_atomically(
    monkeypatch: pytest.MonkeyPatch,
    generation: int,
    predecessor: str,
) -> None:
    async with _database() as url:
        await _runtime(url, generation)
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        verified = await adoption.execute("verify-adoption")
        before = await _revision(url)
        adopted = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
        after = await _revision(url)
        managed = await adoption.execute("verify-managed")
    reduced = (
        verified.predecessor,
        before,
        adopted.exit_code,
        after,
        managed.diagnostic,
    )
    assert reduced == (
        predecessor,
        None,
        AdoptionExit.OK,
        "0011",
        "ARES-M2B-ALREADY-MANAGED:0011",
    )


@pytest.mark.asyncio
async def test_real_postgres_unknown_object_rejects_before_version_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _database() as url:
        await _runtime(url, 7)
        engine = create_async_engine(url, poolclass=sa.pool.NullPool)
        try:
            async with engine.begin() as connection:
                await connection.exec_driver_sql("CREATE TABLE unexpected_object(value text)")
        finally:
            await engine.dispose()
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        try:
            await adoption.execute(
                "adopt",
                external_backup_confirmed=True,
            )
        except AdoptionFailure as caught:
            result_code = caught.exit_code
        else:
            result_code = AdoptionExit.OK
        revision = await _revision(url)
    assert (result_code, revision) == (AdoptionExit.UNRECOGNIZED, None)


@pytest.mark.asyncio
async def test_real_postgres_advisory_lock_has_one_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _database() as url:
        await _runtime(url, 7)
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        engine = create_async_engine(url, poolclass=sa.pool.NullPool)
        try:
            async with engine.connect() as owner:
                transaction = await owner.begin()
                locked = await owner.scalar(
                    sa.text("SELECT pg_try_advisory_xact_lock(:key)"),
                    {"key": adoption._LOCK_KEY},
                )
                try:
                    await adoption.execute(
                        "adopt",
                        external_backup_confirmed=True,
                    )
                except AdoptionFailure as caught:
                    contender_code = caught.exit_code
                else:
                    contender_code = AdoptionExit.OK
                await transaction.rollback()
        finally:
            await engine.dispose()
        winner = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
    assert (bool(locked), contender_code, winner.exit_code) == (
        True,
        AdoptionExit.OWNERSHIP,
        AdoptionExit.OK,
    )


@pytest.mark.asyncio
async def test_real_postgres_failure_after_upgrade_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _database() as url:
        await _runtime(url, 7)
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        original = adoption._run_canonical_adoption

        def _fail_after_upgrade(connection: sa.Connection, predecessor: str) -> None:
            original(connection, predecessor)
            raise RuntimeError("fixed-injected-failure")

        monkeypatch.setattr(adoption, "_run_canonical_adoption", _fail_after_upgrade)
        with pytest.raises(RuntimeError, match="fixed-injected-failure"):
            await adoption.execute(
                "adopt",
                external_backup_confirmed=True,
            )
        rolled_back = await _revision(url)
        monkeypatch.setattr(adoption, "_run_canonical_adoption", original)
        retry = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
    assert (rolled_back, retry.exit_code) == (None, AdoptionExit.OK)


@pytest.mark.asyncio
async def test_real_postgres_unrelated_schema_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _database() as url:
        await _runtime(url, 7)
        engine = create_async_engine(url, poolclass=sa.pool.NullPool)
        try:
            async with engine.begin() as connection:
                await connection.exec_driver_sql("CREATE SCHEMA unrelated_owner_data")
                await connection.exec_driver_sql(
                    "CREATE TABLE unrelated_owner_data.marker(value integer)"
                )
                await connection.exec_driver_sql(
                    "INSERT INTO unrelated_owner_data.marker VALUES (7)"
                )
        finally:
            await engine.dispose()
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        result = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
        engine = create_async_engine(url, poolclass=sa.pool.NullPool)
        try:
            async with engine.connect() as connection:
                preserved = await connection.scalar(
                    sa.text("SELECT count(*) FROM unrelated_owner_data.marker")
                )
        finally:
            await engine.dispose()
    assert (result.exit_code, preserved) == (AdoptionExit.OK, 1)


@pytest.mark.asyncio
async def test_real_postgres_adoption_rerun_is_verified_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _database() as url:
        await _runtime(url, 7)
        monkeypatch.setenv("ARES_DATABASE_URL", url)
        first = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
        second = await adoption.execute(
            "adopt",
            external_backup_confirmed=True,
        )
        revision = await _revision(url)
    assert (first.exit_code, second.diagnostic, revision) == (
        AdoptionExit.OK,
        "ARES-M2B-ALREADY-MANAGED:0011",
        "0011",
    )
