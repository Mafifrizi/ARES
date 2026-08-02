"""Alembic migration environment for the persistent ARES schema history."""
from __future__ import annotations

import asyncio
import configparser
import os
import sqlite3
import sys
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import event, pool
from sqlalchemy.engine import URL, Connection, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

_OFFLINE_ERROR = (
    "Offline migration is not supported for the ARES historical chain"
)
_UNSUPPORTED_DIALECT_ERROR = "Unsupported Alembic database dialect"
_INVALID_URL_ERROR = "Invalid Alembic database URL"


class _AlembicSanitizedError(RuntimeError):
    """Fixed migration-environment failure safe for operator diagnostics."""


def _configure_logging() -> None:
    """Apply Alembic logging without exposing configuration details."""
    if config.config_file_name is None:
        return
    try:
        fileConfig(config.config_file_name)
    except (
        configparser.Error,
        ImportError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise _AlembicSanitizedError(
            "Alembic logging configuration failed "
            f"[{type(exc).__name__}]"
        ) from None


_configure_logging()


def _configured_url() -> str:
    """Select the CLI override, environment URL, or configured Alembic URL."""
    explicit_values: list[str] = []
    for argument in context.get_x_argument():
        key, separator, value = argument.partition("=")
        if key != "db_url":
            continue
        if separator != "=":
            raise _AlembicSanitizedError(_INVALID_URL_ERROR)
        explicit_values.append(value)

    if len(explicit_values) > 1:
        raise _AlembicSanitizedError(_INVALID_URL_ERROR)
    if explicit_values:
        candidate = explicit_values[0]
    elif "ARES_DATABASE_URL" in os.environ:
        candidate = os.environ["ARES_DATABASE_URL"]
    else:
        candidate = config.get_main_option("sqlalchemy.url")

    if (
        not isinstance(candidate, str)
        or not candidate
        or candidate != candidate.strip()
    ):
        raise _AlembicSanitizedError(_INVALID_URL_ERROR)
    return candidate


def _async_url(raw_url: str) -> URL:
    """Return a supported URL using an already-installed async driver."""
    try:
        url = make_url(raw_url)
    except (SQLAlchemyError, TypeError, ValueError):
        raise _AlembicSanitizedError(_INVALID_URL_ERROR) from None

    backend = url.get_backend_name()
    driver = url.drivername
    if backend == "sqlite":
        if driver not in {"sqlite", "sqlite+aiosqlite"}:
            raise _AlembicSanitizedError(_UNSUPPORTED_DIALECT_ERROR)
        return url.set(drivername="sqlite+aiosqlite")
    if backend == "postgresql":
        if driver not in {"postgresql", "postgresql+asyncpg"}:
            raise _AlembicSanitizedError(_UNSUPPORTED_DIALECT_ERROR)
        return url.set(drivername="postgresql+asyncpg")
    raise _AlembicSanitizedError(_UNSUPPORTED_DIALECT_ERROR)


def run_migrations_offline() -> None:
    """Reject SQL rendering because historical revisions inspect live catalogs."""
    raise RuntimeError(_OFFLINE_ERROR)


def do_run_migrations(connection: Any) -> None:
    """Run Alembic operations through one real synchronous facade."""
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


def _configure_sqlite_connection(
    dbapi_connection: Any,
    _connection_record: Any,
) -> None:
    """Apply SQLite policy before Alembic begins migration work."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA foreign_keys = ON")
    finally:
        cursor.close()


async def run_async_migrations() -> None:
    """Run online migrations using aiosqlite or asyncpg."""
    url = _async_url(_configured_url())
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = url.render_as_string(hide_password=False)
    try:
        connectable = async_engine_from_config(
            section,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
    except (
        ImportError,
        KeyError,
        OSError,
        SQLAlchemyError,
        TypeError,
        ValueError,
    ) as exc:
        raise _AlembicSanitizedError(
            "Alembic engine configuration failed "
            f"[{type(exc).__name__}]"
        ) from None
    if url.get_backend_name() == "sqlite":
        event.listen(
            connectable.sync_engine,
            "connect",
            _configure_sqlite_connection,
        )
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        primary_failure = sys.exception()
        try:
            await connectable.dispose()
        except Exception as exc:
            if primary_failure is not None:
                primary_failure.add_note(
                    "Alembic engine cleanup failed "
                    f"[{type(exc).__name__}]"
                )
            else:
                raise _AlembicSanitizedError(
                    "Alembic engine cleanup failed "
                    f"[{type(exc).__name__}]"
                ) from None


def run_migrations_online() -> None:
    """Run the online migration and sanitize operational diagnostics."""
    try:
        supplied_connection = config.attributes.get("connection")
        if supplied_connection is not None:
            if not isinstance(supplied_connection, Connection):
                raise _AlembicSanitizedError(
                    "Invalid caller-owned Alembic connection"
                )
            do_run_migrations(supplied_connection)
        else:
            asyncio.run(run_async_migrations())
    except (
        asyncio.CancelledError,
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ):
        raise
    except _AlembicSanitizedError:
        raise
    except (
        configparser.Error,
        ImportError,
        OSError,
        SQLAlchemyError,
        sqlite3.Error,
    ) as exc:
        raise RuntimeError(
            f"Alembic online migration failed [{type(exc).__name__}]"
        ) from None
    except Exception:
        # Revision-owned, non-operational failures must retain object identity
        # and traceback. Revisions are responsible for fixed public messages.
        raise


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
