"""Verified, explicit adoption of supported unversioned ARES databases.

This module is intentionally independent of application startup.  It recognizes
only the frozen runtime generations below, creates no version metadata until a
complete read-only verification succeeds, and drives the canonical Alembic
history through one caller-owned connection.
"""
from __future__ import annotations

import asyncio
import contextlib
import ctypes
import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from importlib import import_module, resources
from pathlib import Path
from typing import Any, Final

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import URL, Connection, make_url
from sqlalchemy.ext.asyncio import create_async_engine


class AdoptionExit(IntEnum):
    OK = 0
    USAGE = 2
    CONFIGURATION = 3
    MIGRATION_REQUIRED = 4
    MANAGED_METADATA = 5
    UNRECOGNIZED = 6
    OWNERSHIP = 7
    BACKUP = 8
    ROLLED_BACK = 9
    RECOVERY_REQUIRED = 10
    POST_VERIFY = 11


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class RuntimeGeneration:
    dialect: str
    generation: int
    predecessor: str
    has_websocket_tickets: bool


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class AdoptionResult:
    exit_code: AdoptionExit
    diagnostic: str
    predecessor: str | None = None


SUPPORTED_GENERATIONS: Final[tuple[RuntimeGeneration, ...]] = (
    RuntimeGeneration("sqlite", 6, "0006", False),
    RuntimeGeneration("sqlite", 7, "0007", True),
    RuntimeGeneration("postgresql", 6, "0006", False),
    RuntimeGeneration("postgresql", 7, "0007", True),
    RuntimeGeneration("sqlite", 10, "runtime-0010", True),
    RuntimeGeneration("sqlite", 11, "runtime-0011", True),
)

_KNOWN_REVISIONS: Final[frozenset[str]] = frozenset(
    f"{value:04d}" for value in range(1, 12)
)
_REVISION_FILES: Final[tuple[str, ...]] = (
    "0001_initial_schema.py",
    "0002_add_cvss_to_findings.py",
    "0003_add_rate_limit_tracking.py",
    "0004_add_revoked_access_tokens.py",
    "0005_add_trace_id_to_findings.py",
    "0006_rename_cracked_value_to_enc.py",
    "0007_add_websocket_tickets.py",
    "0008_reconcile_schema_parity.py",
    "0009_refresh_token_families.py",
    "0010_execution_lifecycle.py",
    "0011_execution_admission_authority.py",
)
_LOCK_KEY: Final[int] = int.from_bytes(
    hashlib.sha256(b"ARES-M2B-ADOPTION-LOCK-V1").digest()[:8],
    byteorder="big",
    signed=True,
)
_FIXED_DIAGNOSTICS: Final[frozenset[str]] = frozenset(
    {
        "ARES-M2B-EMPTY-DATABASE",
        "ARES-M2B-ALREADY-MANAGED:0011",
        "ARES-M2B-MIGRATION-REQUIRED",
        "ARES-M2B-ADOPTED:SQLITE:0011",
        "ARES-M2B-ADOPTED:POSTGRESQL:0011",
        "ARES-M2B-RESTORED:SQLITE",
        "ARES-M2B-E02:USAGE",
        "ARES-M2B-E03:CONFIGURATION",
        "ARES-M2B-E04:MIGRATION-REQUIRED",
        "ARES-M2B-E05:MANAGED-METADATA",
        "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
        "ARES-M2B-E07:OWNERSHIP-BUSY",
        "ARES-M2B-E08:BACKUP-FAILED",
        "ARES-M2B-E09:ADOPTION-ROLLED-BACK",
        "ARES-M2B-E10:RECOVERY-REQUIRED",
        "ARES-M2B-E11:POST-VERIFY-FAILED",
    }
)


class AdoptionFailure(RuntimeError):  # noqa: N818 - public fixed-boundary contract
    """Fixed, sanitized failure raised only inside the adoption boundary."""

    def __init__(self, exit_code: AdoptionExit, diagnostic: str) -> None:
        if diagnostic not in _FIXED_DIAGNOSTICS and not diagnostic.startswith(
            "ARES-M2B-ADOPTION-READY:"
        ):
            raise ValueError("Invalid adoption diagnostic")
        super().__init__(diagnostic)
        self.exit_code = exit_code
        self.diagnostic = diagnostic


def _failure(exit_code: AdoptionExit, diagnostic: str) -> AdoptionFailure:
    return AdoptionFailure(exit_code, diagnostic)


def _revision_module() -> Any:
    return import_module("migrations.versions.0011_execution_admission_authority")


@contextlib.contextmanager
def migration_config(connection: Connection | None = None) -> Iterator[Config]:
    """Materialize and validate the one installed canonical migration tree."""
    root = resources.files("migrations")
    with resources.as_file(root) as migration_root:
        required = {
            "__init__.py",
            "env.py",
            "script.py.mako",
        }
        if any(not (migration_root / name).is_file() for name in required):
            raise _failure(
                AdoptionExit.CONFIGURATION,
                "ARES-M2B-E03:CONFIGURATION",
            )
        versions = migration_root / "versions"
        actual_revisions = tuple(
            sorted(path.name for path in versions.glob("*.py"))
        )
        if actual_revisions != _REVISION_FILES:
            raise _failure(
                AdoptionExit.CONFIGURATION,
                "ARES-M2B-E03:CONFIGURATION",
            )
        cfg = Config()
        cfg.set_main_option("script_location", os.fspath(migration_root))
        if connection is not None:
            cfg.attributes["connection"] = connection
        script = ScriptDirectory.from_config(cfg)
        if script.get_heads() != ["0011"]:
            raise _failure(
                AdoptionExit.CONFIGURATION,
                "ARES-M2B-E03:CONFIGURATION",
            )
        revisions = tuple(script.walk_revisions(base="base", head="heads"))
        if tuple(item.revision for item in reversed(revisions)) != tuple(
            f"{value:04d}" for value in range(1, 12)
        ):
            raise _failure(
                AdoptionExit.CONFIGURATION,
                "ARES-M2B-E03:CONFIGURATION",
            )
        yield cfg


def _version_revision(connection: Connection) -> str | None:
    revision_module = _revision_module()
    dialect = connection.dialect.name
    try:
        if dialect == "sqlite":
            objects = connection.exec_driver_sql(
                "SELECT type FROM sqlite_schema "
                "WHERE name='alembic_version' OR tbl_name='alembic_version'"
            ).fetchall()
            if not objects:
                return None
            rows = connection.exec_driver_sql(
                "SELECT version_num FROM main.alembic_version"
            ).fetchall()
        elif dialect == "postgresql":
            objects = connection.execute(
                sa.text(
                    """
                    SELECT relation.relkind::text
                    FROM pg_class AS relation
                    JOIN pg_namespace AS namespace
                      ON namespace.oid=relation.relnamespace
                    WHERE namespace.nspname=current_schema()
                      AND relation.relname='alembic_version'
                    """
                )
            ).fetchall()
            if not objects:
                return None
            rows = connection.exec_driver_sql(
                'SELECT version_num FROM "alembic_version"'
            ).fetchall()
        else:
            raise _failure(
                AdoptionExit.CONFIGURATION,
                "ARES-M2B-E03:CONFIGURATION",
            )
        if len(rows) != 1 or not isinstance(rows[0][0], str):
            raise ValueError
        revision = rows[0][0]
        if revision not in _KNOWN_REVISIONS:
            raise ValueError
        if dialect == "sqlite":
            revision_module._require_sqlite_alembic_version_relation(
                connection,
                revision,
            )
        else:
            revision_module._pg_validate_alembic_version_relation(
                connection,
                revision,
            )
        return revision
    except AdoptionFailure:
        raise
    except (LookupError, RuntimeError, sa.exc.SQLAlchemyError, TypeError, ValueError):
        raise _failure(
            AdoptionExit.MANAGED_METADATA,
            "ARES-M2B-E05:MANAGED-METADATA",
        ) from None


def _is_empty(connection: Connection) -> bool:
    if connection.dialect.name == "sqlite":
        return connection.exec_driver_sql(
            "SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
        ).first() is None
    return connection.execute(
        sa.text(
            """
            SELECT 1
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace
              ON namespace.oid=relation.relnamespace
            WHERE namespace.nspname=current_schema()
              AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
            LIMIT 1
            """
        )
    ).first() is None


def _sqlite_catalog_signature(connection: Connection) -> tuple[tuple[str, ...], ...]:
    rows = connection.exec_driver_sql(
        "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
    ).fetchall()
    return tuple(tuple(str(value) for value in row) for row in rows)


def _sqlite_reference_catalog_signature(script: str) -> tuple[tuple[str, ...], ...]:
    reference = sqlite3.connect(":memory:")
    try:
        reference.execute("PRAGMA foreign_keys=ON")
        reference.executescript(script)
        expected_rows = reference.execute(
            "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
        ).fetchall()
        expected = tuple(
            tuple(str(value) for value in row) for row in expected_rows
        )
    finally:
        reference.close()
    return expected


def _is_sqlite_runtime_generation_10(connection: Connection) -> bool:
    """Recognize the exact unstamped predecessor runtime catalog."""
    if connection.dialect.name != "sqlite":
        return False
    from ares.db.execution_lifecycle import sqlite_admission_authority_runtime_script
    from ares.db.schema import CREATE_TABLES

    generation_11_script = sqlite_admission_authority_runtime_script()
    if not generation_11_script or not CREATE_TABLES.endswith(generation_11_script):
        return False
    generation_10_script = CREATE_TABLES[: -len(generation_11_script)]
    return _sqlite_catalog_signature(connection) == _sqlite_reference_catalog_signature(
        generation_10_script
    )


def _is_sqlite_runtime_generation_11(connection: Connection) -> bool:
    """Recognize the exact unstamped current runtime catalog."""
    if connection.dialect.name != "sqlite":
        return False
    from ares.db.schema import CREATE_TABLES

    return _sqlite_catalog_signature(connection) == _sqlite_reference_catalog_signature(
        CREATE_TABLES
    )


def inspect_connection(connection: Connection) -> AdoptionResult:
    """Classify one catalog without mutation or external dynamic diagnostics."""
    revision = _version_revision(connection)
    if revision == "0011":
        try:
            _revision_module().verify_managed_catalog(connection)
        except (RuntimeError, sa.exc.SQLAlchemyError):
            raise _failure(
                AdoptionExit.MANAGED_METADATA,
                "ARES-M2B-E05:MANAGED-METADATA",
            ) from None
        return AdoptionResult(
            AdoptionExit.OK,
            "ARES-M2B-ALREADY-MANAGED:0011",
        )
    if revision is not None:
        return AdoptionResult(
            AdoptionExit.MIGRATION_REQUIRED,
            "ARES-M2B-MIGRATION-REQUIRED",
            revision,
        )
    if _is_empty(connection):
        return AdoptionResult(AdoptionExit.OK, "ARES-M2B-EMPTY-DATABASE")
    if _is_sqlite_runtime_generation_11(connection):
        return AdoptionResult(
            AdoptionExit.OK,
            "ARES-M2B-ADOPTION-READY:SQLITE:runtime-0011",
            "runtime-0011",
        )
    if _is_sqlite_runtime_generation_10(connection):
        return AdoptionResult(
            AdoptionExit.OK,
            "ARES-M2B-ADOPTION-READY:SQLITE:runtime-0010",
            "runtime-0010",
        )
    try:
        predecessor = _revision_module().classify_unversioned_catalog(connection)
    except (RuntimeError, sa.exc.SQLAlchemyError):
        raise _failure(
            AdoptionExit.UNRECOGNIZED,
            "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
        ) from None
    dialect = connection.dialect.name.upper()
    return AdoptionResult(
        AdoptionExit.OK,
        f"ARES-M2B-ADOPTION-READY:{dialect}:{predecessor}",
        predecessor,
    )


def verify_managed_connection(connection: Connection) -> AdoptionResult:
    result = inspect_connection(connection)
    if result.diagnostic == "ARES-M2B-ALREADY-MANAGED:0011":
        return result
    if result.exit_code == AdoptionExit.MIGRATION_REQUIRED:
        raise _failure(
            AdoptionExit.MIGRATION_REQUIRED,
            "ARES-M2B-E04:MIGRATION-REQUIRED",
        )
    raise _failure(
        AdoptionExit.POST_VERIFY,
        "ARES-M2B-E11:POST-VERIFY-FAILED",
    )


def _adoption_predecessor(result: AdoptionResult) -> str:
    if result.exit_code == AdoptionExit.MIGRATION_REQUIRED:
        raise _failure(
            AdoptionExit.MIGRATION_REQUIRED,
            "ARES-M2B-E04:MIGRATION-REQUIRED",
        )
    if result.predecessor not in {"0006", "0007", "runtime-0010", "runtime-0011"}:
        raise _failure(
            AdoptionExit.UNRECOGNIZED,
            "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
        )
    return result.predecessor


def _run_canonical_adoption(
    connection: Connection,
    predecessor: str,
) -> None:
    if predecessor not in {"0006", "0007", "runtime-0010", "runtime-0011"}:
        raise _failure(
            AdoptionExit.UNRECOGNIZED,
            "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
        )
    adoption_marker = "ares_m2b_adoption_transaction"
    marked_sqlite = connection.dialect.name == "sqlite"
    if marked_sqlite:
        connection.info[adoption_marker] = True
    try:
        with migration_config(connection) as cfg:
            if predecessor == "runtime-0011":
                connection.exec_driver_sql("DROP TABLE schema_version")
                command.stamp(cfg, "0011")
            elif predecessor == "runtime-0010":
                connection.exec_driver_sql("DROP TABLE schema_version")
                command.stamp(cfg, "0010")
                command.upgrade(cfg, "0011")
            else:
                command.stamp(cfg, predecessor)
                command.upgrade(cfg, "0011")
    finally:
        if marked_sqlite:
            connection.info.pop(adoption_marker, None)
    verify_managed_connection(connection)


def _database_url() -> str:
    try:
        from ares.core.config import DatabaseSettings

        value = DatabaseSettings(_env_file=".env").database_url
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError
        return value
    except (ImportError, OSError, TypeError, ValueError):
        raise _failure(
            AdoptionExit.CONFIGURATION,
            "ARES-M2B-E03:CONFIGURATION",
        ) from None


def _parsed_url(raw_url: str) -> URL:
    try:
        url = make_url(raw_url)
    except (sa.exc.SQLAlchemyError, TypeError, ValueError):
        raise _failure(
            AdoptionExit.CONFIGURATION,
            "ARES-M2B-E03:CONFIGURATION",
        ) from None
    backend = url.get_backend_name()
    if backend == "sqlite":
        return url.set(drivername="sqlite+pysqlite")
    if backend == "postgresql":
        return url.set(drivername="postgresql+asyncpg")
    raise _failure(
        AdoptionExit.CONFIGURATION,
        "ARES-M2B-E03:CONFIGURATION",
    )


def _sqlite_path(url: URL) -> Path:
    if url.get_backend_name() != "sqlite" or not url.database:
        raise _failure(
            AdoptionExit.CONFIGURATION,
            "ARES-M2B-E03:CONFIGURATION",
        )
    if url.query or url.database == ":memory:" or url.database.startswith("file:"):
        raise _failure(
            AdoptionExit.CONFIGURATION,
            "ARES-M2B-E03:CONFIGURATION",
        )
    path = Path(url.database)
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.is_symlink():
        raise _failure(
            AdoptionExit.UNRECOGNIZED,
            "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
        )
    return path.resolve(strict=False)


def _encode_value(value: Any) -> tuple[str, Any]:
    if value is None:
        return "null", None
    if isinstance(value, bytes):
        return "blob", value.hex()
    if isinstance(value, bool):
        return "integer", int(value)
    if isinstance(value, int):
        return "integer", value
    if isinstance(value, float):
        return "real", value.hex()
    if isinstance(value, str):
        return "text", value
    raise _failure(
        AdoptionExit.UNRECOGNIZED,
        "ARES-M2B-E06:UNRECOGNIZED-CATALOG",
    )


def sqlite_catalog_and_row_digest(connection: sqlite3.Connection) -> bytes:
    """Return a stable SHA-256 digest without exposing catalog or row values."""
    digest = hashlib.sha256()
    raw_schema_rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    schema_rows = tuple(
        row
        for row in raw_schema_rows
        if not (row[0] == "index" and row[3] is None)
    )
    tables = tuple(
        str(row[1])
        for row in schema_rows
        if row[0] == "table" and not str(row[1]).startswith("sqlite_")
    )
    payload: list[Any] = [
        tuple(tuple(_encode_value(value) for value in row) for row in schema_rows),
        tuple(
            (int(row[0]), str(row[1]))
            for row in connection.execute("PRAGMA database_list").fetchall()
        ),
        int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
    ]
    if any(row[0] == "table" and row[1] == "sqlite_sequence" for row in raw_schema_rows):
        payload.append(
            tuple(
                sorted(
                    (str(row[0]), int(row[1]))
                    for row in connection.execute(
                        "SELECT name, seq FROM sqlite_sequence"
                    ).fetchall()
                )
            )
        )
    for table in sorted(tables):
        quoted = '"' + table.replace('"', '""') + '"'
        columns = connection.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
        foreign_keys = connection.execute(
            f"PRAGMA foreign_key_list({quoted})"
        ).fetchall()
        indexes = connection.execute(f"PRAGMA index_list({quoted})").fetchall()
        index_details: list[Any] = []
        for row in indexes:
            index_name = str(row[1])
            index_quoted = '"' + index_name.replace('"', '""') + '"'
            details = connection.execute(
                f"PRAGMA index_xinfo({index_quoted})"
            ).fetchall()
            semantic_name = None if str(row[3]) in {"pk", "u"} else index_name
            index_details.append(
                (
                    semantic_name,
                    int(row[2]),
                    str(row[3]),
                    int(row[4]),
                    tuple(details),
                )
            )
        rows = connection.execute(
            f"SELECT * FROM {quoted}"  # noqa: S608 - identifier safely quoted
        ).fetchall()
        encoded_rows = sorted(
            json.dumps(
                tuple(_encode_value(value) for value in row),
                ensure_ascii=True,
                separators=(",", ":"),
            )
            for row in rows
        )
        payload.append(
            (
                table,
                tuple(columns),
                tuple(foreign_keys),
                tuple(index_details),
                tuple(encoded_rows),
            )
        )
    digest.update(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    )
    return digest.digest()


def _integrity_ok(path: Path) -> bool:
    try:
        connection = sqlite3.connect(path)
        try:
            return connection.execute("PRAGMA integrity_check").fetchall() == [
                ("ok",)
            ]
        finally:
            connection.close()
    except sqlite3.Error:
        return False


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(path),
        0x40000000,
        0x00000007,
        None,
        3,
        0x02000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in {None, invalid}:
        raise OSError
    try:
        if not ctypes.windll.kernel32.FlushFileBuffers(handle):
            raise OSError
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _durable(path: Path) -> None:
    _fsync_file(path)
    _fsync_directory(path.parent)


def _create_sqlite_backup(source: Path, backup: Path) -> bytes:
    if backup.exists() or source == backup.resolve(strict=False):
        raise _failure(AdoptionExit.BACKUP, "ARES-M2B-E08:BACKUP-FAILED")
    if not backup.parent.is_dir():
        raise _failure(AdoptionExit.BACKUP, "ARES-M2B-E08:BACKUP-FAILED")
    descriptor: int | None = None
    try:
        descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        descriptor = None
        source_connection = sqlite3.connect(source)
        backup_connection = sqlite3.connect(backup)
        try:
            source_connection.backup(backup_connection)
        finally:
            backup_connection.close()
            source_connection.close()
        if not _integrity_ok(backup):
            raise OSError
        _durable(backup)
        verified = sqlite3.connect(backup)
        try:
            verified.execute("PRAGMA foreign_keys=ON")
            return sqlite_catalog_and_row_digest(verified)
        finally:
            verified.close()
    except AdoptionFailure:
        raise
    except (OSError, sqlite3.Error):
        if descriptor is not None:
            os.close(descriptor)
        raise _failure(
            AdoptionExit.BACKUP,
            "ARES-M2B-E08:BACKUP-FAILED",
        ) from None


def _sqlite_engine(path: Path) -> sa.Engine:
    engine = sa.create_engine(
        URL.create("sqlite+pysqlite", database=os.fspath(path)),
        poolclass=sa.pool.NullPool,
    )

    @sa.event.listens_for(engine, "connect")
    def _configure(dbapi_connection: sqlite3.Connection, _record: Any) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    return engine


def inspect_sqlite_database(path: str | Path) -> AdoptionResult:
    engine = _sqlite_engine(Path(path).resolve(strict=False))
    try:
        with engine.connect() as connection:
            return inspect_connection(connection)
    finally:
        engine.dispose()


def adopt_sqlite(path: Path, backup: Path) -> AdoptionResult:
    initial = inspect_sqlite_database(path)
    if initial.diagnostic == "ARES-M2B-ALREADY-MANAGED:0011":
        return initial
    _adoption_predecessor(initial)
    backup_digest = _create_sqlite_backup(path, backup)
    engine = _sqlite_engine(path)
    rollback_attempted = False
    rollback_proven = False
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("BEGIN EXCLUSIVE")
            raw = connection.connection.driver_connection
            if not isinstance(raw, sqlite3.Connection):
                raise _failure(
                    AdoptionExit.RECOVERY_REQUIRED,
                    "ARES-M2B-E10:RECOVERY-REQUIRED",
                )
            if sqlite_catalog_and_row_digest(raw) != backup_digest:
                connection.rollback()
                raise _failure(
                    AdoptionExit.BACKUP,
                    "ARES-M2B-E08:BACKUP-FAILED",
                )
            classified = inspect_connection(connection)
            predecessor = _adoption_predecessor(classified)
            try:
                _run_canonical_adoption(connection, predecessor)
                connection.commit()
            except BaseException:
                connection.rollback()
                rollback_attempted = True
                try:
                    raw.execute("PRAGMA foreign_keys=ON")
                    foreign_keys = int(
                        raw.execute("PRAGMA foreign_keys").fetchone()[0]
                    )
                    rollback_proven = (
                        foreign_keys == 1
                        and sqlite_catalog_and_row_digest(raw) == backup_digest
                    )
                except (LookupError, sqlite3.Error, TypeError, ValueError):
                    rollback_proven = False
                raise
        _durable(path)
        return AdoptionResult(AdoptionExit.OK, "ARES-M2B-ADOPTED:SQLITE:0011")
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except AdoptionFailure:
        raise
    except Exception:
        if rollback_attempted and not rollback_proven:
            try:
                verification = sqlite3.connect(path)
                try:
                    verification.execute("PRAGMA foreign_keys=ON")
                    rollback_proven = (
                        int(
                            verification.execute(
                                "PRAGMA foreign_keys"
                            ).fetchone()[0]
                        )
                        == 1
                        and sqlite_catalog_and_row_digest(verification)
                        == backup_digest
                    )
                finally:
                    verification.close()
            except (LookupError, OSError, sqlite3.Error, TypeError, ValueError):
                rollback_proven = False
        if rollback_proven:
            raise _failure(
                AdoptionExit.ROLLED_BACK,
                "ARES-M2B-E09:ADOPTION-ROLLED-BACK",
            ) from None
        raise _failure(
            AdoptionExit.RECOVERY_REQUIRED,
            "ARES-M2B-E10:RECOVERY-REQUIRED",
        ) from None
    finally:
        engine.dispose()


def restore_sqlite(path: Path, backup: Path) -> AdoptionResult:
    if path == backup.resolve(strict=False) or not _integrity_ok(backup):
        raise _failure(AdoptionExit.BACKUP, "ARES-M2B-E08:BACKUP-FAILED")
    source = sqlite3.connect(path, isolation_level=None)
    verified_backup = sqlite3.connect(backup)
    try:
        source.execute("PRAGMA foreign_keys=ON")
        locking_mode = source.execute(
            "PRAGMA locking_mode=EXCLUSIVE"
        ).fetchone()
        if locking_mode != ("exclusive",):
            raise sqlite3.OperationalError
        source.execute("BEGIN EXCLUSIVE")
        source.rollback()
        verified_backup.backup(source)
        source.commit()
    except (OSError, sqlite3.Error):
        raise _failure(
            AdoptionExit.RECOVERY_REQUIRED,
            "ARES-M2B-E10:RECOVERY-REQUIRED",
        ) from None
    finally:
        verified_backup.close()
        source.close()
    if not _integrity_ok(path):
        raise _failure(
            AdoptionExit.RECOVERY_REQUIRED,
            "ARES-M2B-E10:RECOVERY-REQUIRED",
        )
    _durable(path)
    result = inspect_sqlite_database(path)
    if result.exit_code not in {AdoptionExit.OK, AdoptionExit.MIGRATION_REQUIRED}:
        raise _failure(
            AdoptionExit.POST_VERIFY,
            "ARES-M2B-E11:POST-VERIFY-FAILED",
        )
    return AdoptionResult(AdoptionExit.OK, "ARES-M2B-RESTORED:SQLITE")


def _sync_inspect(sync_connection: Connection) -> AdoptionResult:
    return inspect_connection(sync_connection)


def _sync_adopt(sync_connection: Connection, predecessor: str) -> None:
    _run_canonical_adoption(sync_connection, predecessor)


async def _postgres_operation(url: URL, operation: str) -> AdoptionResult:
    engine = create_async_engine(url, poolclass=sa.pool.NullPool)
    already_managed = False
    try:
        async with engine.connect() as connection:
            if operation == "verify-adoption":
                return await connection.run_sync(_sync_inspect)
            if operation == "verify-managed":
                return await connection.run_sync(verify_managed_connection)
            transaction = await connection.begin()
            try:
                locked = bool(
                    await connection.scalar(
                        sa.text("SELECT pg_try_advisory_xact_lock(:key)"),
                        {"key": _LOCK_KEY},
                    )
                )
                if not locked:
                    raise _failure(
                        AdoptionExit.OWNERSHIP,
                        "ARES-M2B-E07:OWNERSHIP-BUSY",
                    )
                classified = await connection.run_sync(_sync_inspect)
                if classified.diagnostic == "ARES-M2B-ALREADY-MANAGED:0011":
                    already_managed = True
                else:
                    predecessor = _adoption_predecessor(classified)
                    await connection.run_sync(
                        _sync_adopt,
                        predecessor,
                    )
                await transaction.commit()
            except BaseException:
                if transaction.is_active:
                    await transaction.rollback()
                raise
        async with engine.connect() as verification:
            await verification.run_sync(verify_managed_connection)
        if already_managed:
            return AdoptionResult(
                AdoptionExit.OK,
                "ARES-M2B-ALREADY-MANAGED:0011",
            )
        return AdoptionResult(AdoptionExit.OK, "ARES-M2B-ADOPTED:POSTGRESQL:0011")
    finally:
        await engine.dispose()


async def execute(
    operation: str,
    *,
    sqlite_backup: str | None = None,
    external_backup_confirmed: bool = False,
) -> AdoptionResult:
    """Execute one fixed operator action using canonical settings resolution."""
    url = _parsed_url(_database_url())
    if url.get_backend_name() == "postgresql":
        if operation == "adopt" and not external_backup_confirmed:
            raise _failure(AdoptionExit.USAGE, "ARES-M2B-E02:USAGE")
        return await _postgres_operation(url, operation)
    path = _sqlite_path(url)
    if operation == "verify-adoption":
        return await asyncio.to_thread(inspect_sqlite_database, path)
    if operation == "verify-managed":
        return await asyncio.to_thread(
            lambda: verify_managed_connection_from_path(path)
        )
    if sqlite_backup is None:
        raise _failure(AdoptionExit.USAGE, "ARES-M2B-E02:USAGE")
    backup = Path(sqlite_backup)
    if not backup.is_absolute():
        backup = Path.cwd() / backup
    backup = backup.resolve(strict=False)
    if operation == "adopt":
        return await asyncio.to_thread(adopt_sqlite, path, backup)
    if operation == "restore-sqlite":
        return await asyncio.to_thread(restore_sqlite, path, backup)
    raise _failure(AdoptionExit.USAGE, "ARES-M2B-E02:USAGE")


def verify_managed_connection_from_path(path: Path) -> AdoptionResult:
    engine = _sqlite_engine(path)
    try:
        with engine.connect() as connection:
            return verify_managed_connection(connection)
    finally:
        engine.dispose()


def safe_execute(
    operation: str,
    *,
    sqlite_backup: str | None = None,
    external_backup_confirmed: bool = False,
) -> AdoptionResult:
    try:
        return asyncio.run(
            execute(
                operation,
                sqlite_backup=sqlite_backup,
                external_backup_confirmed=external_backup_confirmed,
            )
        )
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except AdoptionFailure as exc:
        return AdoptionResult(exc.exit_code, exc.diagnostic)
    except (OSError, sqlite3.Error, sa.exc.SQLAlchemyError):
        return AdoptionResult(
            AdoptionExit.CONFIGURATION,
            "ARES-M2B-E03:CONFIGURATION",
        )


__all__ = [
    "AdoptionExit",
    "AdoptionResult",
    "RuntimeGeneration",
    "SUPPORTED_GENERATIONS",
    "execute",
    "inspect_connection",
    "inspect_sqlite_database",
    "migration_config",
    "safe_execute",
    "sqlite_catalog_and_row_digest",
    "verify_managed_connection",
]
