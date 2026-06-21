"""
Alembic migration environment for ARES.

Supports both sync SQLite (for alembic CLI) and async aiosqlite (for runtime).
Run migrations:
    alembic upgrade head           # Apply all pending migrations
    alembic revision -m "add_X"   # Create new migration
    alembic history                # Show migration history
    alembic current                # Show current version
    alembic downgrade -1           # Roll back one step

ARES also runs migrations automatically at startup via AresDatabase.run_migrations().
"""
from __future__ import annotations

import asyncio
from logging.config import fileConfig
from pathlib import Path
from typing import Any

from alembic import context
from alembic.config import Config
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

# ── Alembic config ────────────────────────────────────────────────────────────

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Determine DB URL ──────────────────────────────────────────────────────────

def _get_db_url() -> str:
    """Resolve database URL from environment or alembic.ini."""
    import os
    url = os.environ.get("ARES_DATABASE_URL", "")
    if url:
        # alembic needs sqlite:/// not sqlite+aiosqlite:///
        return url.replace("sqlite+aiosqlite:///", "sqlite:///")
    # Fallback from alembic.ini
    return config.get_main_option("sqlalchemy.url", "sqlite:///ares.db")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generates SQL without connecting)."""
    url = _get_db_url()
    context.configure(url=url, literal_binds=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Any) -> None:
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in async mode (for aiosqlite/asyncpg)."""
    db_url = _get_db_url().replace("sqlite:///", "sqlite+aiosqlite:///")
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = db_url
    connectable = async_engine_from_config(
        cfg, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
